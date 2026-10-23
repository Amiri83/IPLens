"""IP-optimization suggestions derived from a snapshot, filtered through rules.

Most suggestions look at the snapshot alone. Three also use the account's snapshot
history (successful snapshots up to this one):

- ``detached_eni``: the ENI is detached in *every* snapshot of the last
  :data:`DETACHED_DAYS` days, shown with the date since when it has been.
- ``underused_subnet``: the subnet is under :data:`UNDERUSED_PCT` % used in every
  snapshot of the last :data:`UNDERUSED_DAYS` days; the suggested size is the smallest
  prefix whose usable IPs fit twice the peak.
- ``unused_endpoint``: an interface endpoint whose ENIs saw no traffic in the flow log
  queries (Visual → Extended view → Flow logs) of the last ``endpoint_days`` days, once
  those cover :data:`ENDPOINT_MIN_HOURS` hours over :data:`ENDPOINT_MIN_DAYS` days.

A check that cannot be made (history shorter than its window, no or too little flow log
data for a VPC) adds a line to :attr:`Context.notes` instead of a suggestion.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .queries import (
    AWS_RESERVED_HEAD,
    AWS_RESERVED_TAIL,
    SubnetStats,
    VpcNode,
    subnet_stats,
    vpc_tree,
)
from .rules import Rule
from .scope import UNSCOPED, ResolvedScope

# Services that support (free, IP-less) gateway endpoints.
GATEWAY_CAPABLE = (".s3", ".dynamodb")

AZ_IMBALANCE_RATIO = 2.0
AZ_IMBALANCE_MIN_DELTA = 16
VPC_SPACE_ALLOCATED_PCT = 90.0
VPC_CONSUMED_PCT = 70.0
# An ECS service is an "idle environment" candidate when its tasks hold at least
# this many IPs and it has not been deployed for this many days.
ECS_IDLE_MIN_IPS = 8
ECS_IDLE_DAYS = 30
# An ENI is suggested for deletion once it was detached in every snapshot of these days.
DETACHED_DAYS = 7
# A subnet under this share used in every snapshot of these days is "underused"; the
# suggested size fits UNDERUSED_HEADROOM times its peak usage.
UNDERUSED_PCT = 10.0
UNDERUSED_DAYS = 30
UNDERUSED_HEADROOM = 2
# AWS subnet sizes: /28 (smallest) to /16 (largest).
SMALLEST_PREFIX, LARGEST_PREFIX = 28, 16
# An interface endpoint without flow log traffic in this many days is "possibly unused",
# provided the VPC's flow log queries of those days cover at least this many hours (their
# windows merged) spread over at least this many distinct (UTC) days.
UNUSED_ENDPOINT_DAYS = 14
ENDPOINT_MIN_HOURS = 24
ENDPOINT_MIN_DAYS = 3
# A window counts as covered when its oldest snapshot is at most this far from its start
# (daily snapshots cover a 7-day window with 7 of them).
HISTORY_SLACK = timedelta(days=1)
# SQLite variables per IN (...) list.
_IN_BATCH = 500

KIND_LABELS = {
    "detached_eni": "Detached ENI",
    "underused_subnet": "Underused subnet",
    "unused_endpoint": "Unused endpoint",
    "lambda_sg_combo": "Lambda SG combos",
    "lambda_subnet_spread": "Lambda subnet spread",
    "lambda_detach_vpc": "Lambda outside VPC",
    "duplicate_endpoint": "Duplicate endpoint",
    "gateway_endpoint": "Gateway endpoint",
    "endpoint_via_nat": "Endpoints via NAT",
    "az_imbalance": "AZ imbalance",
    "secondary_cidr": "Secondary CIDR",
    "ecs_idle_service": "Idle ECS environment",
}


@dataclass
class Context:
    subnets: dict[str, SubnetStats]
    enis: dict[str, dict[str, Any]]
    eni_ip_count: dict[str, int]
    vpcs: list[VpcNode]
    lambdas: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]
    load_balancers: list[dict[str, Any]]
    ecs_services: list[dict[str, Any]] = field(default_factory=list)
    ecs_task_enis: list[dict[str, Any]] = field(default_factory=list)
    taken_at: datetime | None = None
    # Every subnet of the snapshot, in scope or not (rules tell "absent" from "out of scope").
    all_subnet_ids: set[str] = field(default_factory=set)
    # The account's successful snapshots up to this one (oldest first, this one included).
    history: list[tuple[int, datetime]] = field(default_factory=list)
    # ENI id -> snapshot id -> its status there (the ENIs detached in this snapshot).
    eni_status: dict[str, dict[int, str]] = field(default_factory=dict)
    # Subnet id -> snapshot id -> (IPs in use, usable IPs), over UNDERUSED_DAYS.
    subnet_usage: dict[str, dict[int, tuple[int, int]]] = field(default_factory=dict)
    # Flow log queries of the last ``endpoint_days`` days (see FlowRun).
    flow_runs: list[FlowRun] = field(default_factory=list)
    endpoint_days: int = UNUSED_ENDPOINT_DAYS
    # Checks that could not be made (filled by generate).
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FlowRun:
    """One stored flow log query of a VPC (flowlogs.run): the endpoint ENIs that existed
    in its snapshot and the ENIs it saw traffic of."""

    snapshot_id: int
    vpc_id: str
    ran_at: datetime
    window_minutes: int
    present: frozenset[str]
    seen: frozenset[str]


@dataclass
class Suggestion:
    key: str
    kind: str
    title: str
    detail: str
    vpc_id: str
    ips_saved: int = 0
    impact: str = ""
    subnet_ids: list[str] = field(default_factory=list)
    target_subnets: dict[str, int] = field(default_factory=dict)
    eni_ids: list[str] = field(default_factory=list)
    # Subnet id -> its usable IPs once resized (rules check the free share after it).
    resized: dict[str, int] = field(default_factory=dict)
    # detached_eni: the date of the first snapshot of its current detached run.
    since: str = ""
    flags: set[str] = field(default_factory=set)
    blocked_by: list[tuple[str, str]] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_by)

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


def build_context(
    conn: sqlite3.Connection,
    snap_id: int,
    scope: ResolvedScope = UNSCOPED,
    *,
    endpoint_days: int = UNUSED_ENDPOINT_DAYS,
) -> Context:
    """Everything suggestions and rules look at, limited to ``scope``.

    Out of scope: ENIs in other subnets (or, with IP ranges, without an address in
    range), Lambda functions without a subnet in scope (and every non-VPC function
    once a scope is set), endpoints / load balancers / ECS services without anything
    left in scope. IP counts only count in-scope addresses. ``endpoint_days``: the
    window of the unused endpoint check.
    """
    enis = {}
    for r in conn.execute("SELECT * FROM enis WHERE snapshot_id=?", (snap_id,)):
        d = dict(r)
        if not (scope.vpc_ok(d["vpc_id"]) and scope.subnet_ok(d["subnet_id"])):
            continue
        d["security_groups"] = json.loads(d.get("security_groups") or "[]")
        enis[d["eni_id"]] = d
    where, args = scope.sql("i")
    cond = "".join(f" AND {w}" for w in where)
    counts = {
        r["eni_id"]: r["n"]
        for r in conn.execute(
            "SELECT i.eni_id, COUNT(*) AS n FROM ips i "  # noqa: S608 - fixed SQL fragments
            f"WHERE i.snapshot_id=?{cond} GROUP BY i.eni_id",
            (snap_id, *args),
        )
    }
    if scope.ip_include or scope.ip_exclude:
        enis = {k: v for k, v in enis.items() if counts.get(k)}

    def rows(table: str, *json_cols: str) -> list[dict[str, Any]]:
        out = []
        for r in conn.execute(
            f"SELECT * FROM {table} WHERE snapshot_id=?",  # noqa: S608 - fixed names
            (snap_id,),
        ):
            d = dict(r)
            for c in json_cols:
                d[c] = json.loads(d.get(c) or "[]")
            out.append(d)
        return out

    lambdas = rows("lambdas", "subnet_ids", "security_groups")
    endpoints = rows("endpoints", "subnet_ids", "eni_ids")
    load_balancers = rows("load_balancers")
    ecs_services = rows("ecs_services")
    ecs_task_enis = rows("ecs_task_enis")
    if scope.active:
        lambdas = [f for f in lambdas if any(scope.subnet_ok(s) for s in f["subnet_ids"])]
        for ep in endpoints:
            ep["subnet_ids"] = [s for s in ep["subnet_ids"] if scope.subnet_ok(s)]
            ep["eni_ids"] = [e for e in ep["eni_ids"] if e in enis]
        endpoints = [ep for ep in endpoints if ep["eni_ids"] or ep["subnet_ids"]]
        load_balancers = [lb for lb in load_balancers if scope.vpc_ok(lb["vpc_id"])]
        ecs_task_enis = [m for m in ecs_task_enis if m["eni_id"] in enis]
        live = {(m["cluster"], m["service"]) for m in ecs_task_enis}
        ecs_services = [s for s in ecs_services if (s["cluster"], s["service"]) in live]

    snap = conn.execute(
        "SELECT taken_at, account_ref FROM snapshots WHERE id=?", (snap_id,)
    ).fetchone()
    taken_at = _parse_ts(snap["taken_at"] if snap else None)
    stats = subnet_stats(conn, snap_id)
    subnets = {s.subnet_id: s for s in stats if scope.subnet_ok(s.subnet_id)}
    history = _history(conn, snap_id, snap["account_ref"] if snap else None, taken_at)
    detached = [
        e["eni_id"]
        for e in enis.values()
        if e["status"] == "available" and not e["requester_managed"]
    ]
    return Context(
        subnets=subnets,
        all_subnet_ids={s.subnet_id for s in stats},
        enis=enis,
        eni_ip_count=counts,
        vpcs=vpc_tree(conn, snap_id, scope),
        lambdas=lambdas,
        endpoints=endpoints,
        load_balancers=load_balancers,
        ecs_services=ecs_services,
        ecs_task_enis=ecs_task_enis,
        taken_at=taken_at,
        history=history,
        eni_status=_eni_status(conn, history, detached),
        subnet_usage=_subnet_usage(
            conn, _window(history, taken_at, UNDERUSED_DAYS)[0], set(subnets)
        ),
        flow_runs=_flow_runs(
            conn,
            history,
            taken_at,
            endpoint_days,
            {e for ep in endpoints for e in ep["eni_ids"]},
        ),
        endpoint_days=endpoint_days,
    )


# -- history ------------------------------------------------------------------


def _history(
    conn: sqlite3.Connection, snap_id: int, account_ref: int | None, taken_at: datetime | None
) -> list[tuple[int, datetime]]:
    """(id, taken_at) of the account's successful snapshots up to ``snap_id``, oldest
    first; ``snap_id`` itself is always the last one."""
    out = []
    for r in conn.execute(
        "SELECT id, taken_at FROM snapshots WHERE account_ref IS ? AND status='ok' AND id<>?",
        (account_ref, snap_id),
    ):
        ts = _parse_ts(r["taken_at"])
        if ts is not None and taken_at is not None and ts <= taken_at:
            out.append((r["id"], ts))
    out.sort(key=lambda p: (p[1], p[0]))
    if taken_at is not None:
        out.append((snap_id, taken_at))
    return out


def _window(
    history: list[tuple[int, datetime]], taken_at: datetime | None, days: int
) -> tuple[list[tuple[int, datetime]], bool]:
    """The snapshots of the last ``days`` days (oldest first) and whether they span the
    window: its oldest snapshot is within :data:`HISTORY_SLACK` of the window start."""
    if taken_at is None:
        return [], False
    start = taken_at - timedelta(days=days)
    window = [(i, ts) for i, ts in history if ts >= start]
    return window, bool(window) and window[0][1] <= start + HISTORY_SLACK


def _batches(values: Iterable[Any]) -> Iterable[list[Any]]:
    items = sorted(set(values))
    for i in range(0, len(items), _IN_BATCH):
        yield items[i : i + _IN_BATCH]


def _eni_status(
    conn: sqlite3.Connection, history: list[tuple[int, datetime]], eni_ids: list[str]
) -> dict[str, dict[int, str]]:
    ids = {i for i, _ in history}
    out: dict[str, dict[int, str]] = defaultdict(dict)
    for batch in _batches(eni_ids):
        marks = ",".join("?" * len(batch))
        for r in conn.execute(
            f"SELECT snapshot_id, eni_id, status FROM enis WHERE eni_id IN ({marks})",  # noqa: S608
            batch,
        ):
            if r["snapshot_id"] in ids:
                out[r["eni_id"]][r["snapshot_id"]] = r["status"] or ""
    return dict(out)


def _usable(cidr: str) -> int:
    size = ipaddress.IPv4Network(cidr).num_addresses
    return max(size - AWS_RESERVED_HEAD - AWS_RESERVED_TAIL, 0)


def _subnet_usage(
    conn: sqlite3.Connection, window: list[tuple[int, datetime]], subnet_ids: set[str]
) -> dict[str, dict[int, tuple[int, int]]]:
    """Subnet -> snapshot -> (distinct IPs held, idle ENIs included; usable IPs) for the
    snapshots of ``window`` the subnet exists in."""
    out: dict[str, dict[int, tuple[int, int]]] = defaultdict(dict)
    for batch in _batches(i for i, _ in window):
        marks = ",".join("?" * len(batch))
        used = {
            (r["snapshot_id"], r["subnet_id"]): r["n"]
            for r in conn.execute(
                "SELECT snapshot_id, subnet_id, COUNT(DISTINCT ip) AS n FROM ips "  # noqa: S608
                f"WHERE snapshot_id IN ({marks}) GROUP BY snapshot_id, subnet_id",
                batch,
            )
        }
        for r in conn.execute(
            f"SELECT snapshot_id, subnet_id, cidr FROM subnets WHERE snapshot_id IN ({marks})",  # noqa: S608
            batch,
        ):
            if r["subnet_id"] in subnet_ids:
                key = (r["snapshot_id"], r["subnet_id"])
                out[r["subnet_id"]][r["snapshot_id"]] = (used.get(key, 0), _usable(r["cidr"]))
    return dict(out)


def _flow_runs(
    conn: sqlite3.Connection,
    history: list[tuple[int, datetime]],
    taken_at: datetime | None,
    days: int,
    endpoint_enis: set[str],
) -> list[FlowRun]:
    """The flow log queries run in the last ``days`` days on snapshots of ``history``."""
    if taken_at is None:
        return []
    ids = {i for i, _ in history}
    start = taken_at - timedelta(days=days)
    runs = []
    for r in conn.execute(
        "SELECT snapshot_id, vpc_id, ran_at, window_minutes FROM flow_runs ORDER BY ran_at"
    ):
        ran_at = _parse_ts(r["ran_at"])
        if r["snapshot_id"] in ids and ran_at is not None and ran_at >= start:
            runs.append((r["snapshot_id"], r["vpc_id"], ran_at, int(r["window_minutes"] or 0)))
    seen: dict[tuple[int, str], set[str]] = defaultdict(set)
    present: dict[int, set[str]] = defaultdict(set)
    for batch in _batches(s for s, *_ in runs):
        marks = ",".join("?" * len(batch))
        for r in conn.execute(
            "SELECT snapshot_id, vpc_id, src_eni, dst_eni FROM flow_aggregates "  # noqa: S608
            f"WHERE snapshot_id IN ({marks})",
            batch,
        ):
            seen[(r["snapshot_id"], r["vpc_id"])].update((r["src_eni"], r["dst_eni"]))
        if not endpoint_enis:
            continue
        for r in conn.execute(
            f"SELECT snapshot_id, eni_id FROM enis WHERE snapshot_id IN ({marks})",  # noqa: S608
            batch,
        ):
            if r["eni_id"] in endpoint_enis:
                present[r["snapshot_id"]].add(r["eni_id"])
    return [
        FlowRun(s, vpc, ran_at, minutes, frozenset(present[s]), frozenset(seen[(s, vpc)]))
        for s, vpc, ran_at, minutes in runs
    ]


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


# -- generators ---------------------------------------------------------------


def _day(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d")


def _short_history(what: str, days: int, window: list[tuple[int, datetime]]) -> str:
    back = f"only goes back to {_day(window[0][1])}" if window else "is empty"
    return (
        f"{what}: not checked yet; it needs snapshots spanning the last {days} days and "
        f"the account's history {back}."
    )


def _detached_enis(ctx: Context) -> list[Suggestion]:
    """ENIs detached in every snapshot of the last DETACHED_DAYS days."""
    detached = [
        e for e in ctx.enis.values() if e["status"] == "available" and not e["requester_managed"]
    ]
    if not detached:
        return []
    window, covered = _window(ctx.history, ctx.taken_at, DETACHED_DAYS)
    if not covered:
        ctx.notes.append(
            _short_history(f"Detached ENIs ({len(detached)} detached now)", DETACHED_DAYS, window)
        )
        return []
    out, recent = [], 0
    for eni in detached:
        status = ctx.eni_status.get(eni["eni_id"], {})
        if any(status.get(i) != "available" for i, _ in window):
            recent += 1
            continue
        # The first snapshot of the run of detached snapshots that ends with this one.
        since = window[-1][1]
        for i, ts in reversed(ctx.history):
            if status.get(i) != "available":
                break
            since = ts
        n = ctx.eni_ip_count.get(eni["eni_id"], 0)
        label = eni.get("name") or eni.get("description") or "no description"
        out.append(
            Suggestion(
                key=f"detached:{eni['eni_id']}",
                kind="detached_eni",
                title=f"Delete detached ENI {eni['eni_id']}",
                detail=f"ENI '{label}' in {eni['subnet_id']} is not attached to anything "
                f"(detached since {_day(since)}, in every snapshot of the last "
                f"{DETACHED_DAYS} days) but holds {n} private IP(s).",
                vpc_id=eni["vpc_id"] or "",
                ips_saved=n,
                subnet_ids=[eni["subnet_id"]] if eni["subnet_id"] else [],
                eni_ids=[eni["eni_id"]],
                since=_day(since),
            )
        )
    if recent:
        ctx.notes.append(
            f"Detached ENIs: {recent} ENI(s) detached now were attached (or absent) in a "
            f"snapshot of the last {DETACHED_DAYS} days; not suggested yet."
        )
    return out


def fit_prefix(need: int) -> int | None:
    """The longest (smallest) subnet prefix whose usable IPs hold ``need``; None if not
    even a /16 does."""
    for prefix in range(SMALLEST_PREFIX, LARGEST_PREFIX - 1, -1):
        if 2 ** (32 - prefix) - AWS_RESERVED_HEAD - AWS_RESERVED_TAIL >= need:
            return prefix
    return None


def _underused_subnets(ctx: Context) -> list[Suggestion]:
    """Subnets under UNDERUSED_PCT % used in every snapshot of the last UNDERUSED_DAYS."""
    if not ctx.subnets:
        return []
    window, covered = _window(ctx.history, ctx.taken_at, UNDERUSED_DAYS)
    if not covered:
        ctx.notes.append(_short_history("Underused subnets", UNDERUSED_DAYS, window))
        return []
    out = []
    for sid, st in sorted(ctx.subnets.items()):
        usage = ctx.subnet_usage.get(sid, {})
        points = [usage.get(i) for i, _ in window]
        if any(p is None or not p[1] or 100.0 * p[0] / p[1] >= UNDERUSED_PCT for p in points):
            continue  # missing from a snapshot (newer than the window) or used enough
        peak = max(p[0] for p in points if p)
        current = ipaddress.IPv4Network(st.cidr).prefixlen
        prefix = fit_prefix(peak * UNDERUSED_HEADROOM)
        if prefix is None or prefix <= current:
            continue
        usable_after = _usable(f"0.0.0.0/{prefix}")
        saved = st.usable - usable_after
        peak_pct = max(100.0 * p[0] / p[1] for p in points if p)
        out.append(
            Suggestion(
                key=f"underused:{sid}",
                kind="underused_subnet",
                title=f"Shrink underused subnet {sid} to a /{prefix}",
                detail=f"{sid} ({st.cidr}, {st.usable} usable IPs) used at most {peak} IP(s) "
                f"({peak_pct:.1f}%), under {UNDERUSED_PCT:g}% in each of {len(window)} "
                f"snapshot(s) of the last {UNDERUSED_DAYS} days. A /{prefix} "
                f"({usable_after} usable) fits {UNDERUSED_HEADROOM}× that peak; recreate the "
                f"subnet at that size (a subnet cannot be resized in place) to return "
                f"{saved} IPs to the VPC.",
                vpc_id=st.vpc_id,
                ips_saved=saved,
                subnet_ids=[sid],
                resized={sid: usable_after},
            )
        )
    return out


def flow_coverage(runs: Iterable[FlowRun]) -> tuple[float, int]:
    """(hours, distinct UTC days) of traffic the queries' windows cover, overlaps merged."""
    spans = sorted(
        (r.ran_at - timedelta(minutes=r.window_minutes), r.ran_at)
        for r in runs
        if r.window_minutes > 0
    )
    merged: list[list[datetime]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    seconds, days = 0.0, set()
    for start, end in merged:
        seconds += (end - start).total_seconds()
        last = (end - timedelta(microseconds=1)).astimezone(UTC).date()
        day = start.astimezone(UTC).date()
        while day <= last:
            days.add(day)
            day += timedelta(days=1)
    return seconds / 3600, len(days)


def _covered(hours: float, days: int) -> bool:
    return hours >= ENDPOINT_MIN_HOURS and days >= ENDPOINT_MIN_DAYS


def _coverage_text(hours: float, days: int) -> str:
    return f"{round(hours, 1):g}h over {days} day{'' if days == 1 else 's'}"


def _unused_endpoints(ctx: Context) -> list[Suggestion]:
    """Interface endpoints whose ENIs no flow log query of the window saw traffic of, once
    the queries that saw them cover ENDPOINT_MIN_HOURS over ENDPOINT_MIN_DAYS."""
    interface = [
        e
        for e in ctx.endpoints
        if (e["endpoint_type"] or "").lower() == "interface" and e["eni_ids"]
    ]
    days = ctx.endpoint_days
    need = f"need {ENDPOINT_MIN_HOURS}h over {ENDPOINT_MIN_DAYS} days"
    runs: dict[str, list[FlowRun]] = defaultdict(list)
    for r in ctx.flow_runs:
        runs[r.vpc_id].append(r)
    out = []
    skipped = set()
    for vpc_id in sorted({e["vpc_id"] for e in interface}):
        if vpc_id not in runs:
            ctx.notes.append(
                f"Unused endpoints in {vpc_id}: skipped, no flow log data from the last {days} "
                "days (flow logs not enabled for the VPC, or not queried yet: Visual → Extended "
                "view → Flow logs)."
            )
            skipped.add(vpc_id)
            continue
        cover = flow_coverage(runs[vpc_id])
        if not _covered(*cover):
            ctx.notes.append(
                f"Unused endpoints in {vpc_id}: not enough flow log coverage "
                f"({_coverage_text(*cover)}, {need})"
            )
            skipped.add(vpc_id)
    for ep in sorted(interface, key=lambda e: e["endpoint_id"]):
        if ep["vpc_id"] in skipped:
            continue
        enis = set(ep["eni_ids"])
        checked = [r for r in runs[ep["vpc_id"]] if enis & r.present]
        if any(enis & r.seen for r in checked):
            continue
        hours, n_days = flow_coverage(checked)
        if not _covered(hours, n_days):
            # Newer than most of the VPC's queries: they say nothing about it.
            ctx.notes.append(
                f"Unused endpoints: {ep['endpoint_id']} is newer than most flow log queries "
                f"of the last {days} days (it was there for {_coverage_text(hours, n_days)} "
                f"of them, {need}); not checked."
            )
            continue
        out.append(
            Suggestion(
                key=f"unused-endpoint:{ep['endpoint_id']}",
                kind="unused_endpoint",
                title=f"Possibly unused interface endpoint {ep['endpoint_id']} "
                f"({ep['service_name']})",
                detail=f"No flow log traffic to or from its {len(enis)} ENI(s) in "
                f"{len(checked)} flow log quer{'y' if len(checked) == 1 else 'ies'} of "
                f"{ep['vpc_id']} over the last {days} days, covering "
                f"{_coverage_text(hours, n_days)} (the first on {_day(checked[0].ran_at)}; "
                f"the check needs {ENDPOINT_MIN_HOURS}h over {ENDPOINT_MIN_DAYS} days). "
                "Traffic outside the covered hours is not seen: confirm before removing it.",
                vpc_id=ep["vpc_id"],
                ips_saved=_endpoint_ip_count(ctx, ep),
                subnet_ids=sorted(ep["subnet_ids"]),
                eni_ids=sorted(enis),
            )
        )
    return out


def _sg_key(eni: dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted(eni["security_groups"]))


def _lambda(ctx: Context) -> list[Suggestion]:
    out: list[Suggestion] = []
    by_vpc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for eni in ctx.enis.values():
        if eni["owner_type"] == "lambda" and eni["vpc_id"]:
            by_vpc[eni["vpc_id"]].append(eni)

    for vpc_id, enis in sorted(by_vpc.items()):
        by_subnet: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in enis:
            by_subnet[e["subnet_id"]].append(e)

        # 1) several SG sets in the same subnet -> one ENI per (subnet, SG set)
        saved, touched, eni_ids = 0, [], []
        for subnet_id, sub_enis in sorted(by_subnet.items()):
            combos = Counter(_sg_key(e) for e in sub_enis)
            if len(combos) > 1:
                dominant = combos.most_common(1)[0][0]
                saved += len(combos) - 1
                touched.append(subnet_id)
                eni_ids += [e["eni_id"] for e in sub_enis if _sg_key(e) != dominant]
        if saved:
            out.append(
                Suggestion(
                    key=f"lambda-sg:{vpc_id}",
                    kind="lambda_sg_combo",
                    title=f"Standardise Lambda security groups in {vpc_id}",
                    detail="Lambda creates one ENI per unique subnet + security-group combination. "
                    f"{len(touched)} subnet(s) host several SG combinations; sharing one SG "
                    "set per subnet removes the extra ENIs.",
                    vpc_id=vpc_id,
                    ips_saved=saved,
                    subnet_ids=touched,
                    eni_ids=eni_ids,
                )
            )

        # 2) Lambda spread across several subnets in the same AZ
        by_az: dict[str, list[str]] = defaultdict(list)
        for subnet_id in by_subnet:
            st = ctx.subnets.get(subnet_id)
            if st:
                by_az[st.az].append(subnet_id)
        for az, subnet_ids in sorted(by_az.items()):
            if len(subnet_ids) < 2:
                continue
            target = max(subnet_ids, key=lambda s: (ctx.subnets[s].free, s))
            target_sets = {_sg_key(e) for e in by_subnet[target]}
            moved, saved_here, src_enis = 0, 0, []
            for sid in sorted(set(subnet_ids) - {target}):
                for e in by_subnet[sid]:
                    src_enis.append(e["eni_id"])
                    if _sg_key(e) in target_sets:
                        saved_here += ctx.eni_ip_count.get(e["eni_id"], 1)
                    else:
                        target_sets.add(_sg_key(e))
                        moved += 1
            if saved_here:
                out.append(
                    Suggestion(
                        key=f"lambda-spread:{vpc_id}:{az}",
                        kind="lambda_subnet_spread",
                        title=f"Use a single Lambda subnet in {az} ({vpc_id})",
                        detail=f"Lambda ENIs are spread over {len(subnet_ids)} subnets in {az}. "
                        f"Pointing functions at {target} only removes duplicate ENIs.",
                        vpc_id=vpc_id,
                        ips_saved=saved_here,
                        subnet_ids=sorted(set(subnet_ids) - {target}),
                        target_subnets={target: moved} if moved else {target: 0},
                        eni_ids=src_enis,
                    )
                )

        # 3) the radical option: run functions outside the VPC
        total = sum(ctx.eni_ip_count.get(e["eni_id"], 1) for e in enis)
        out.append(
            Suggestion(
                key=f"lambda-novpc:{vpc_id}",
                kind="lambda_detach_vpc",
                title=f"Run Lambdas that need no private access outside {vpc_id}",
                detail="Functions that only call public AWS APIs do not need a VPC attachment; "
                "detaching them frees their Hyperplane ENIs.",
                vpc_id=vpc_id,
                ips_saved=total,
                subnet_ids=sorted(by_subnet),
                eni_ids=[e["eni_id"] for e in enis],
                flags={"lambda_detach_vpc"},
            )
        )
    return out


def _endpoint_ip_count(ctx: Context, ep: dict[str, Any]) -> int:
    return sum(ctx.eni_ip_count.get(e, 1) for e in ep["eni_ids"])


def _endpoints(ctx: Context) -> list[Suggestion]:
    out: list[Suggestion] = []
    interface = [e for e in ctx.endpoints if (e["endpoint_type"] or "").lower() == "interface"]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for ep in interface:
        groups[(ep["vpc_id"], ep["service_name"])].append(ep)

    for (vpc_id, service), eps in sorted(groups.items()):
        if len(eps) > 1:
            keep = max(eps, key=lambda e: (len(e["subnet_ids"]), e["endpoint_id"]))
            extra = [e for e in eps if e is not keep]
            out.append(
                Suggestion(
                    key=f"dup-endpoint:{vpc_id}:{service}",
                    kind="duplicate_endpoint",
                    title=f"Remove duplicate {service} endpoints in {vpc_id}",
                    detail=f"{len(eps)} interface endpoints serve {service}; keep "
                    f"{keep['endpoint_id']} and remove "
                    f"{', '.join(e['endpoint_id'] for e in extra)}.",
                    vpc_id=vpc_id,
                    ips_saved=sum(_endpoint_ip_count(ctx, e) for e in extra),
                    subnet_ids=sorted({s for e in extra for s in e["subnet_ids"]}),
                    eni_ids=[i for e in extra for i in e["eni_ids"]],
                )
            )
        if service.endswith(GATEWAY_CAPABLE):
            out.append(
                Suggestion(
                    key=f"gw-endpoint:{vpc_id}:{service}",
                    kind="gateway_endpoint",
                    title=f"Use a gateway endpoint for {service} in {vpc_id}",
                    detail="S3 and DynamoDB support gateway endpoints, which are free, stay "
                    "private and consume no subnet IPs.",
                    vpc_id=vpc_id,
                    ips_saved=sum(_endpoint_ip_count(ctx, e) for e in eps),
                    subnet_ids=sorted({s for e in eps for s in e["subnet_ids"]}),
                    eni_ids=[i for e in eps for i in e["eni_ids"]],
                )
            )

    nat_vpcs = {e["vpc_id"] for e in ctx.enis.values() if e["owner_type"] == "nat"}
    by_vpc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ep in interface:
        by_vpc[ep["vpc_id"]].append(ep)
    for vpc_id, eps in sorted(by_vpc.items()):
        if vpc_id not in nat_vpcs:
            continue
        out.append(
            Suggestion(
                key=f"endpoint-nat:{vpc_id}",
                kind="endpoint_via_nat",
                title=f"Reach AWS services through the NAT gateway in {vpc_id}",
                detail=f"Removing {len(eps)} interface endpoint(s) frees their ENIs, but traffic "
                "would leave the VPC over public service endpoints.",
                vpc_id=vpc_id,
                ips_saved=sum(_endpoint_ip_count(ctx, e) for e in eps),
                subnet_ids=sorted({s for e in eps for s in e["subnet_ids"]}),
                eni_ids=[i for e in eps for i in e["eni_ids"]],
                flags={"public_path:vpc_endpoint"},
            )
        )
    return out


def _az_imbalance(ctx: Context) -> list[Suggestion]:
    out = []
    for vpc in ctx.vpcs:
        per_az: dict[str, int] = defaultdict(int)
        for s in vpc.subnets:
            per_az[s.az] += s.consumed
        if len(per_az) < 2:
            continue
        azs = sorted(per_az)
        hot = max(azs, key=per_az.__getitem__)
        cold = min(azs, key=per_az.__getitem__)
        delta = per_az[hot] - per_az[cold]
        if delta < AZ_IMBALANCE_MIN_DELTA or per_az[hot] < AZ_IMBALANCE_RATIO * per_az[cold]:
            continue
        candidates = [s for s in vpc.subnets if s.az == cold]
        target = max(candidates, key=lambda s: (s.free, s.subnet_id))
        shift = delta // 2
        out.append(
            Suggestion(
                key=f"az:{vpc.vpc_id}",
                kind="az_imbalance",
                title=f"Rebalance IP usage across AZs in {vpc.vpc_id}",
                detail=f"{hot} uses {per_az[hot]} IPs vs {per_az[cold]} in {cold}. Shifting "
                f"~{shift} IPs of workload to {target.subnet_id} evens out exhaustion risk.",
                vpc_id=vpc.vpc_id,
                impact=f"~{shift} IPs headroom in {hot}",
                target_subnets={target.subnet_id: shift},
            )
        )
    return out


def _secondary_cidr(ctx: Context) -> list[Suggestion]:
    out = []
    for vpc in ctx.vpcs:
        usable = sum(s.usable for s in vpc.subnets)
        consumed = sum(s.consumed for s in vpc.subnets)
        if not usable:
            continue
        consumed_pct = 100.0 * consumed / usable
        if vpc.allocated_pct < VPC_SPACE_ALLOCATED_PCT or consumed_pct < VPC_CONSUMED_PCT:
            continue
        out.append(
            Suggestion(
                key=f"cidr:{vpc.vpc_id}",
                kind="secondary_cidr",
                title=f"Add a secondary CIDR to {vpc.vpc_id}",
                detail=f"{vpc.allocated_pct:.0f}% of the VPC range is carved into subnets and "
                f"{consumed_pct:.0f}% of subnet IPs are in use. A secondary CIDR (for example "
                "from 100.64.0.0/10 for non-routable workloads) adds room for new subnets.",
                vpc_id=vpc.vpc_id,
                impact="adds capacity",
            )
        )
    return out


def _ecs_idle(ctx: Context) -> list[Suggestion]:
    """Services whose tasks hold many IPs but have not been deployed recently."""
    if ctx.taken_at is None:
        return []
    by_service: dict[tuple[str, str], list[str]] = defaultdict(list)
    for m in ctx.ecs_task_enis:
        if m["service"] and m["eni_id"] in ctx.enis:
            by_service[(m["cluster"], m["service"])].append(m["eni_id"])

    out = []
    for svc in ctx.ecs_services:
        ref = f"{svc['cluster']}/{svc['service']}"
        eni_ids = sorted(by_service.get((svc["cluster"], svc["service"]), []))
        n = sum(ctx.eni_ip_count.get(e, 0) for e in eni_ids)
        last = _parse_ts(svc.get("last_deployment"))
        if n < ECS_IDLE_MIN_IPS or last is None:
            continue
        age = (ctx.taken_at - last).days
        if age < ECS_IDLE_DAYS:
            continue
        enis = [ctx.enis[e] for e in eni_ids]
        out.append(
            Suggestion(
                key=f"ecs-idle:{ref}",
                kind="ecs_idle_service",
                title=f"Scale down / delete idle environment: ECS service {ref}",
                detail=f"{len(eni_ids)} task ENI(s) of {ref} hold {n} private IP(s) and the "
                f"service has not been deployed for {age} days. If this environment is "
                "idle, scale it to zero or delete it.",
                vpc_id=enis[0]["vpc_id"] or "",
                ips_saved=n,
                subnet_ids=sorted({e["subnet_id"] for e in enis if e["subnet_id"]}),
                eni_ids=eni_ids,
                flags={f"ecs_scale_down:{ref}"},
            )
        )
    return out


GENERATORS = (
    _detached_enis,
    _lambda,
    _endpoints,
    _unused_endpoints,
    _az_imbalance,
    _secondary_cidr,
    _underused_subnets,
    _ecs_idle,
)


def generate(ctx: Context, rules: list[Rule]) -> list[Suggestion]:
    """Every suggestion, vetoed by ``rules``, allowed / most IPs first; the checks that
    could not be made are in ``ctx.notes`` afterwards."""
    ctx.notes = []
    suggestions: list[Suggestion] = []
    for gen in GENERATORS:
        suggestions.extend(gen(ctx))
    for s in suggestions:
        for rule in rules:
            reason = rule.blocks(s, ctx)
            if reason:
                s.blocked_by.append((rule.name, reason))
    suggestions.sort(key=lambda s: (s.blocked, -s.ips_saved, s.kind, s.key))
    return suggestions


def totals(suggestions: list[Suggestion]) -> dict[str, int]:
    return {
        "allowed": sum(s.ips_saved for s in suggestions if not s.blocked),
        "blocked": sum(s.ips_saved for s in suggestions if s.blocked),
    }
