"""The read-only tools of ``iplens mcp`` (see :mod:`iplens.mcpserver`).

Every tool reads the local SQLite database only, through a connection opened read-only
(``mode=ro`` plus ``PRAGMA query_only``): nothing here can write, and nothing here talks to
AWS. This module and everything it imports must never import boto3 / botocore; the tests
check that, and :func:`block_aws_sdk` makes the server process refuse the import outright.

A tool is a function ``(ctx, **arguments) -> dict``; :meth:`Tools.call` opens the
database, picks the account's latest successful snapshot, runs the tool and adds the
snapshot it is based on to the result. With ``redact`` every string of the result (and of
an error message) goes through :class:`Redactor`: account ids, ARNs, ENI / instance ids,
IPs and CIDRs are hidden, subnets / VPCs / security groups are shown by name.
"""

from __future__ import annotations

import importlib.abc
import ipaddress
import re
import sqlite3
import sys
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import diff as diff_mod
from . import fitcheck, headroom, queries, trends
from . import forecast as forecast_mod
from . import rules as rules_mod
from . import scope as scope_mod
from .attribution import OWNER_LABELS
from .checkcli import to_dict as check_to_dict
from .db import ACTIVE_ACCOUNT_KEY, BUSY_TIMEOUT
from .retention import parse_taken_at
from .settings import SettingsStore

# Page sizes of the list results.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
DEFAULT_TOP = 10
# The most IPs one fit question can ask for (a /16 has 65 531 usable addresses).
MAX_NEED = 65536
# Modules the MCP server must never load: it reads SQLite only.
AWS_SDK_MODULES = ("boto3", "botocore", "aiobotocore", "s3transfer")


class ToolInputError(ValueError):
    """A tool cannot answer (bad argument, unknown subnet, no snapshot): its message is
    shown to the client."""


class _AwsSdkBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
        if fullname.split(".")[0] in AWS_SDK_MODULES:
            raise ImportError(f"iplens mcp never talks to AWS: importing {fullname} is refused")
        return None


def block_aws_sdk() -> None:
    """Make any later import of the AWS SDK fail in this process; RuntimeError when it
    is already loaded."""
    loaded = sorted(m for m in sys.modules if m.split(".")[0] in AWS_SDK_MODULES)
    if loaded:
        raise RuntimeError(f"the AWS SDK is already loaded: {', '.join(loaded)}")
    if not any(isinstance(f, _AwsSdkBlocker) for f in sys.meta_path):
        sys.meta_path.insert(0, _AwsSdkBlocker())


def open_readonly(db_path: Path) -> sqlite3.Connection:
    """A connection that cannot write: SQLite read-only mode plus ``query_only``."""
    if not db_path.is_file():
        raise ToolInputError(
            f"no IPLens database at {db_path}: run `iplens`, add an account and Refresh it first"
        )
    conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=BUSY_TIMEOUT)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


class _ReadOnlySettings(SettingsStore):
    """The saved Settings, read through an existing (read-only) connection."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def _get(self, key: str) -> str:
        row = self._conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return (row["value"] if row else "") or ""

    def _set(self, key: str, value: str) -> None:
        raise RuntimeError("iplens mcp is read-only")


# -- accounts -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Account:
    ref: int  # IPLens account record (accounts.id)
    name: str
    aws_id: str
    region: str


def list_accounts(conn: sqlite3.Connection) -> list[Account]:
    return [
        Account(
            r["id"],
            r["display_name"] or "",
            r["last_seen_account_id"] or r["aws_account_id"] or "",
            r["region"] or "",
        )
        for r in conn.execute(
            "SELECT id, display_name, region, aws_account_id, last_seen_account_id FROM accounts "
            "ORDER BY id"
        )
    ]


def _account_label(a: Account) -> str:
    return f"{a.ref} ({', '.join(v for v in (a.name, a.aws_id, a.region) if v)})"


def resolve_account(conn: sqlite3.Connection, selector: str | None) -> int:
    """The IPLens account of ``--account``: its IPLens id, AWS account id or display name
    (case-insensitive). Default: the account active in the UI, else the one with the
    newest successful snapshot."""
    accounts = list_accounts(conn)
    if not accounts:
        raise ToolInputError("no account in the IPLens database: add one in the IPLens UI")
    if selector is None or not selector.strip():
        row = conn.execute(
            "SELECT value FROM settings WHERE key=?", (ACTIVE_ACCOUNT_KEY,)
        ).fetchone()
        value = (row["value"] if row else "") or ""
        if value.isdigit() and any(a.ref == int(value) for a in accounts):
            return int(value)
        snap = queries.latest_snapshot(conn)
        return snap["account_ref"] if snap and snap["account_ref"] else accounts[0].ref
    want = selector.strip()
    found = [
        a
        for a in accounts
        if (want.isdigit() and (str(a.ref) == want or a.aws_id == want))
        or (a.name and a.name.lower() == want.lower())
    ]
    if len(found) == 1:
        return found[0].ref
    choices = "; ".join(_account_label(a) for a in accounts)
    if found:
        raise ToolInputError(f"account {want!r} is ambiguous; pick by IPLens id: {choices}")
    raise ToolInputError(f"no account {want!r}; accounts: {choices}")


# -- redaction ------------------------------------------------------------------------------

_ARN = re.compile(r"\barn:aws[a-z-]*:[^\s\"',;()\]\[]*")
_ENI = re.compile(r"\beni-(?:[0-9a-f]{17}|[0-9a-f]{8})\b")
_INSTANCE = re.compile(r"\bi-(?:[0-9a-f]{17}|[0-9a-f]{8})\b")
_GENERIC = {
    "subnet": re.compile(r"\bsubnet-(?:[0-9a-f]{17}|[0-9a-f]{8})\b"),
    "vpc": re.compile(r"\bvpc-(?:[0-9a-f]{17}|[0-9a-f]{8})\b"),
    "sg": re.compile(r"\bsg-(?:[0-9a-f]{17}|[0-9a-f]{8})\b"),
}
_CIDR = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/(\d{1,2})(?![\w.])")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")


def unique_labels(items: Iterable[tuple[str, str]], unnamed: str) -> dict[str, str]:
    """id -> a unique display label: the name (``unnamed`` when blank), numbered ``#1``,
    ``#2``, ... (by id) when several share it."""
    by_base: dict[str, list[str]] = defaultdict(list)
    for item_id, name in sorted(set(items)):
        by_base[name.strip() or unnamed].append(item_id)
    out: dict[str, str] = {}
    for base, ids in by_base.items():
        for i, item_id in enumerate(ids, 1):
            out[item_id] = base if len(ids) == 1 else f"{base}#{i}"
    return out


@dataclass
class Redactor:
    """Hides account ids, ARNs, ENI / instance ids, IPs and CIDRs in every string;
    subnet, VPC and security group ids become their names (``labels``: id -> name).
    Disabled: returns everything unchanged."""

    enabled: bool = False
    labels: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        ids = sorted(self.labels, key=len, reverse=True)  # longest first: no prefix clash
        self._known = re.compile(
            "|".join(rf"(?<![\w-]){re.escape(i)}(?![\w-])" for i in ids) if ids else r"(?!)"
        )

    def text(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        value = _ARN.sub("<arn>", value)
        value = self._known.sub(lambda m: self.labels[m.group(0)], value)
        for kind, rx in _GENERIC.items():
            value = rx.sub(f"<{kind}>", value)
        value = _ENI.sub("<eni>", value)
        value = _INSTANCE.sub("<instance>", value)
        value = _CIDR.sub(lambda m: f"<cidr>/{m.group(1)}", value)
        value = _IPV4.sub("<ip>", value)
        return _ACCOUNT_ID.sub("<account-id>", value)

    def apply(self, data: Any) -> Any:
        """``data`` (JSON-like) with every string, dict keys included, redacted."""
        if not self.enabled:
            return data
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, dict):
            return {self.apply(k): self.apply(v) for k, v in data.items()}
        if isinstance(data, list | tuple):
            return [self.apply(v) for v in data]
        return data


# -- context --------------------------------------------------------------------------------


@dataclass
class Ctx:
    conn: sqlite3.Connection
    account_ref: int
    snap: sqlite3.Row
    scope: scope_mod.ResolvedScope
    env_keys: tuple[str, ...]
    own: Any  # ownership.OwnershipConfig
    subnet_labels: dict[str, str]  # subnet id -> unique label (name)
    vpc_labels: dict[str, str]
    sg_labels: dict[str, str]

    @property
    def snap_id(self) -> int:
        return self.snap["id"]

    @property
    def labels(self) -> dict[str, str]:
        """Every id -> label the redactor shows instead of the id."""
        return {**self.sg_labels, **self.vpc_labels, **self.subnet_labels}

    def subnets(self) -> list[queries.SubnetStats]:
        """The latest snapshot's subnets in the account's scope."""
        return [
            s
            for s in queries.subnet_stats(self.conn, self.snap_id)
            if self.scope.subnet_ok(s.subnet_id) and self.scope.vpc_ok(s.vpc_id)
        ]

    def resolve_subnet(self, value: str) -> str:
        """A subnet id from its id or (unique) name / label."""
        want = (value or "").strip()
        if not want:
            raise ToolInputError("subnet is required (an id or a name)")
        stats = self.subnets()
        if any(s.subnet_id == want for s in stats):
            return want
        by_label = [s.subnet_id for s in stats if self.subnet_labels.get(s.subnet_id) == want]
        by_name = [s.subnet_id for s in stats if s.name.lower() == want.lower()]
        hits = by_label or by_name
        if len(hits) == 1:
            return hits[0]
        if hits:
            names = ", ".join(sorted(self.subnet_labels[h] for h in hits))
            raise ToolInputError(f"several subnets are named {want!r}: use one of {names}")
        raise ToolInputError(
            f"no subnet {want!r} in the latest snapshot (or it is outside the account's scope)"
        )

    def resolve_vpc(self, value: str | None) -> str | None:
        want = (value or "").strip()
        if not want:
            return None
        vpcs = {
            r["vpc_id"]: r["name"] or ""
            for r in self.conn.execute(
                "SELECT vpc_id, name FROM vpcs WHERE snapshot_id=?", (self.snap_id,)
            )
            if self.scope.vpc_ok(r["vpc_id"])
        }
        if want in vpcs:
            return want
        hits = [v for v in vpcs if self.vpc_labels.get(v) == want]
        hits = hits or [v for v, name in vpcs.items() if name.lower() == want.lower()]
        if len(hits) == 1:
            return hits[0]
        if hits:
            raise ToolInputError(f"several VPCs are named {want!r}: use its id")
        raise ToolInputError(f"no VPC {want!r} in the latest snapshot")


def _vpc_labels(conn: sqlite3.Connection, snap_ids: Iterable[int]) -> dict[str, str]:
    rows: dict[str, str] = {}
    for sid in snap_ids:  # oldest first: the newest name wins
        for r in conn.execute("SELECT vpc_id, name FROM vpcs WHERE snapshot_id=?", (sid,)):
            rows[r["vpc_id"]] = r["name"] or ""
    return unique_labels(rows.items(), "unnamed-vpc")


def _subnet_labels(conn: sqlite3.Connection, snap_ids: Iterable[int]) -> dict[str, str]:
    rows: dict[str, str] = {}
    for sid in snap_ids:
        for r in conn.execute("SELECT subnet_id, name FROM subnets WHERE snapshot_id=?", (sid,)):
            rows[r["subnet_id"]] = r["name"] or ""
    return unique_labels(rows.items(), "unnamed-subnet")


def _sg_labels(conn: sqlite3.Connection, snap_ids: Iterable[int]) -> dict[str, str]:
    rows: dict[str, str] = {}
    for sid in snap_ids:
        rows.update(queries.sg_names(conn, sid))
    named = {g: n for g, n in rows.items() if n and n != g}
    return unique_labels(named.items(), "unnamed-sg")


def _snapshot_meta(snap: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": snap["id"],
        "taken_at": snap["taken_at"],
        "account": snap["account_name"] or snap["account_alias"] or "",
        "account_id": snap["account_id"] or "",
        "region": snap["region"] or "",
    }


def _page(items: list[Any], offset: int, limit: int) -> dict[str, Any]:
    offset = max(int(offset), 0)
    limit = min(max(int(limit), 1), MAX_LIMIT)
    more = offset + limit < len(items)
    return {
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "next_offset": offset + limit if more else None,
        "items": items[offset : offset + limit],
    }


def _subnet_ref(ctx: Ctx, subnet_id: str, name: str = "") -> dict[str, Any]:
    return {"id": subnet_id, "name": name or ctx.subnet_labels.get(subnet_id, "")}


# -- tools ----------------------------------------------------------------------------------


def _headroom_status(row: headroom.SubnetHeadroom) -> dict[str, Any]:
    return {
        "status": row.status,
        "demand_at_max_scale": row.demand,
        "left_at_max_scale": row.left,
        "left_pct": round(row.left_pct, 1),
    }


def _scaled(ctx: Ctx) -> headroom.Headroom:
    return headroom.for_snapshot(ctx.conn, ctx.snap_id, ctx.scope)


def list_subnets(
    ctx: Ctx,
    vpc: str | None = None,
    az: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    vpc_id = ctx.resolve_vpc(vpc)
    rows = _scaled(ctx).by_id
    items = []
    for s in ctx.subnets():
        if (vpc_id and s.vpc_id != vpc_id) or (az and s.az != az.strip()):
            continue
        hr = rows.get(s.subnet_id)
        items.append(
            {
                "id": s.subnet_id,
                "name": s.name,
                "vpc": s.vpc_id,
                "az": s.az,
                "cidr": s.cidr,
                "usable": s.usable,
                "used": s.used,
                "idle": s.idle,
                "free": hr.free if hr else s.free,
                "headroom": _headroom_status(hr) if hr else None,
            }
        )
    return {"filters": {"vpc": vpc_id, "az": az or None}, **_page(items, offset, limit)}


def find_subnet(
    ctx: Ctx,
    need_ips: int,
    vpc: str | None = None,
    az: str | None = None,
    limit: int = DEFAULT_TOP,
) -> dict[str, Any]:
    need = _need(need_ips)
    vpc_id = ctx.resolve_vpc(vpc)
    in_scope = {s.subnet_id for s in ctx.subnets()}
    fits = []
    for row in _scaled(ctx).subnets:
        s = row.subnet
        if s.subnet_id not in in_scope:
            continue
        if (vpc_id and s.vpc_id != vpc_id) or (az and s.az != az.strip()):
            continue
        # The fit check's own arithmetic: free - existing headroom demand - the request.
        fit = fitcheck.SubnetFit(s, row.contributors, fitcheck.need_demand(s.subnet_id, need).items)
        if fit.status != fitcheck.FITS:
            continue
        fits.append(
            {
                "id": s.subnet_id,
                "name": s.name,
                "vpc": s.vpc_id,
                "az": s.az,
                "cidr": s.cidr,
                "free": fit.free,
                "headroom_demand": fit.existing_demand,
                "headroom_left": fit.left,
                "headroom_left_pct": round(fit.left_pct, 1),
            }
        )
    fits.sort(key=lambda f: (-f["headroom_left"], -f["headroom_left_pct"], f["id"]))
    return {
        "need_ips": need,
        "filters": {"vpc": vpc_id, "az": az or None},
        "rule": "fits when free - headroom demand at max scale - need_ips >= 0; most left first",
        **_page(fits, 0, limit),
    }


def subnet_detail(ctx: Ctx, subnet: str, top: int = DEFAULT_TOP) -> dict[str, Any]:
    sid = ctx.resolve_subnet(subnet)
    st = queries.get_subnet(ctx.conn, ctx.snap_id, sid)
    assert st is not None  # resolve_subnet found it in this snapshot
    top = min(max(int(top), 1), MAX_LIMIT)
    rows = queries.ip_list(
        ctx.conn, ctx.snap_id, queries.IpFilter(subnet=sid), ctx.scope, ctx.env_keys, ctx.own
    )
    consumers: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = (r["owner_type"], r["resource_name"] or r["eni_id"])
        c = consumers.setdefault(
            key,
            {
                "resource": key[1],
                "type": queries.resource_type_label(r, OWNER_LABELS),
                "ownership": r["owner"]["text"],
                "environment": r["environment"] or "",
                "ips": 0,
                "idle_ips": 0,
                "_enis": set(),
            },
        )
        c["ips"] += 1
        c["idle_ips"] += r["status"] == "available"
        c["_enis"].add(r["eni_id"])
    ranked = sorted(consumers.values(), key=lambda c: (-c["ips"], c["resource"]))
    for c in ranked:
        c["enis"] = len(c.pop("_enis"))
    hr = _scaled(ctx).by_id.get(sid)
    window = forecast_mod.DEFAULT_WINDOW_DAYS
    history = trends.load(ctx.conn, ctx.account_ref, window, ctx.scope)
    series = next((s for ss in history.subnets.values() for s in ss if s.key == sid), None)
    fc = (
        forecast_mod.project(series.points, hr.free, hr.demand, window_days=window)
        if series is not None and hr is not None
        else None
    )
    return {
        "subnet": {
            "id": sid,
            "name": st.name,
            "vpc": st.vpc_id,
            "az": st.az,
            "cidr": st.cidr,
        },
        "usage": {
            "size": st.size,
            "aws_reserved": st.reserved,
            "usable": st.usable,
            "used": st.used,
            "idle": st.idle,
            "free": hr.free if hr else st.free,
            "free_pct": round(st.free_pct, 1),
            "aws_available_ip_count": st.aws_available,
        },
        "top_consumers": {"total": len(ranked), "items": ranked[:top]},
        "headroom": (
            {
                **_headroom_status(hr),
                "contributors": [
                    {"kind": c.kind, "name": c.name, "ips": c.ips, "assumption": c.assumption}
                    for c in hr.contributors[:top]
                ],
                "contributors_total": len(hr.contributors),
                "suggestion": hr.suggestion,
            }
            if hr
            else None
        ),
        "forecast": (
            {
                "window_days": window,
                "status": fc.status,
                "points": fc.points,
                "trend": fc.trend_text,
                "slope_ips_per_day": round(fc.slope_per_day, 3),
                "days_until_full": _days(fc.days_to_exhaustion),
                "days_until_headroom_does_not_fit": _days(fc.days_to_headroom),
                "min_points": forecast_mod.DEFAULT_MIN_POINTS,
            }
            if fc
            else None
        ),
    }


def _days(value: float | None) -> float | None:
    return None if value is None else round(value, 1)


def lookup_ip(ctx: Ctx, ip: str) -> dict[str, Any]:
    try:
        addr = ipaddress.IPv4Address((ip or "").strip())
    except ValueError:
        raise ToolInputError(f"not an IPv4 address: {ip!r}") from None
    text = str(addr)
    rows = [
        r
        for r in queries.ip_list(
            ctx.conn, ctx.snap_id, queries.IpFilter(q=text), ctx.scope, ctx.env_keys, ctx.own
        )
        if r["ip"] == text
    ]
    matches = [
        {
            "eni_id": r["eni_id"],
            "eni_status": r["status"] or "",
            "primary": bool(r["is_primary"]),
            "public_ip": r["public_ip"] or None,
            "owner_type": r["owner_type"],
            "type": queries.resource_type_label(r, OWNER_LABELS),
            "resource": r["resource_name"] or "",
            "owners": r["owner_names"],
            "instance_id": r["instance_id"] or None,
            "description": r["description"] or "",
            "security_groups": r["security_groups"],
            "ownership": r["owner"]["text"],
            "environment": r["environment"] or "",
            "subnet": _subnet_ref(ctx, r["subnet_id"], r["subnet_name"] or ""),
            "vpc": r["vpc_id"],
            "az": r["az"] or "",
        }
        for r in rows
    ]
    if matches:
        state = "idle" if all(m["eni_status"] == "available" for m in matches) else "used"
        return {"ip": text, "state": state, "matches": matches}
    # Not held by an ENI: free, reserved by AWS or outside every subnet (in scope).
    for s in ctx.subnets():
        net = ipaddress.IPv4Network(s.cidr)
        if addr in net:
            offset = int(addr) - int(net.network_address)
            reserved = offset < queries.AWS_RESERVED_HEAD or addr == net.broadcast_address
            return {
                "ip": text,
                "state": "reserved" if reserved else "free",
                "matches": [],
                "subnet": {**_subnet_ref(ctx, s.subnet_id, s.name), "cidr": s.cidr},
            }
    return {"ip": text, "state": "not-in-any-subnet", "matches": []}


def _ok_snapshots(conn: sqlite3.Connection, account_ref: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM snapshots WHERE account_ref=? AND status='ok' ORDER BY id DESC",
        (account_ref,),
    ).fetchall()


def resolve_since(conn: sqlite3.Connection, account_ref: int, since: str) -> sqlite3.Row:
    """The older snapshot of ``changes``: ``latest-N`` (N successful snapshots back), a
    snapshot id, or an ISO date / time (the newest snapshot taken at or before it)."""
    snaps = _ok_snapshots(conn, account_ref)
    if len(snaps) < 2:
        raise ToolInputError("the account has fewer than two successful snapshots: no diff yet")
    want = (since or "latest-1").strip().lower()
    m = re.fullmatch(r"latest\s*-\s*(\d+)", want)
    if m:
        n = int(m.group(1))
        if not 1 <= n < len(snaps):
            raise ToolInputError(f"latest-{n}: pick 1 to {len(snaps) - 1}")
        return snaps[n]
    if want.isdigit():
        hit = next((s for s in snaps[1:] if s["id"] == int(want)), None)
        if hit is None:
            ids = ", ".join(str(s["id"]) for s in snaps[1:])
            raise ToolInputError(f"no older successful snapshot {want}; choose from {ids}")
        return hit
    try:
        when = parse_taken_at(since.strip())
    except ValueError:
        raise ToolInputError(
            f"since {since!r}: use latest-N, a snapshot id or an ISO date / time"
        ) from None
    hit = next((s for s in snaps[1:] if parse_taken_at(s["taken_at"]) <= when), None)
    if hit is None:
        raise ToolInputError(f"no snapshot older than the latest taken at or before {since}")
    return hit


def changes(ctx: Ctx, since: str = "latest-1", limit: int = 20) -> dict[str, Any]:
    old = resolve_since(ctx.conn, ctx.account_ref, since)
    limit = min(max(int(limit), 1), MAX_LIMIT)
    d = diff_mod.diff_snapshots(
        ctx.conn, old["id"], ctx.snap_id, OWNER_LABELS, ctx.scope, ctx.env_keys, ctx.own
    )
    moved = [s for s in d.subnets if s.delta]
    eni_changes = [(g, c) for g in d.groups for c in g.enis]
    return {
        "from": {"id": old["id"], "taken_at": old["taken_at"]},
        "to": {"id": ctx.snap_id, "taken_at": ctx.snap["taken_at"]},
        "totals": d.totals,
        "subnets": {
            "total": len(moved),
            "items": [
                {
                    **_subnet_ref(ctx, s.subnet_id, s.name),
                    "old_ips": s.old,
                    "new_ips": s.new,
                    "delta": s.delta,
                }
                for s in moved[:limit]
            ],
        },
        "top_consumers": [
            {"resource": c.resource, "type": c.type_label, "old": c.old, "new": c.new}
            for c in d.consumers[:limit]
        ],
        "groups": {
            "total": len(d.groups),
            "items": [
                {
                    "type": g.type_label,
                    "ownership": g.owner,
                    "environment": g.env,
                    "enis_added": g.count("enis", diff_mod.ADDED),
                    "enis_removed": g.count("enis", diff_mod.REMOVED),
                    "enis_changed": g.count("enis", diff_mod.CHANGED),
                    "ip_delta": g.ip_delta,
                }
                for g in d.groups[:limit]
            ],
        },
        "eni_changes": {
            "total": len(eni_changes),
            "items": [
                {
                    "kind": c.kind,
                    "eni_id": c.eni_id,
                    "type": g.type_label,
                    "resource": c.resource,
                    "subnet": _subnet_ref(ctx, c.subnet_id),
                    "ips_before": len(c.old_ips),
                    "ips_after": len(c.new_ips),
                    "details": c.details,
                }
                for g, c in eni_changes[:limit]
            ],
        },
    }


def _need(value: int) -> int:
    n = int(value)
    if not 0 <= n <= MAX_NEED:
        raise ToolInputError(f"need must be 0 to {MAX_NEED}")
    return n


def fit_check(
    ctx: Ctx,
    subnet: str,
    need: int,
    min_free_pct: float = 0.0,
    include_surge: bool = True,
) -> dict[str, Any]:
    """``iplens check --subnet ID --need N`` against the latest snapshot (every subnet's
    headroom inputs, like the CI snapshot export) and the saved rules."""
    sid = ctx.resolve_subnet(subnet)
    n = _need(need)
    pct = float(min_free_pct)
    if not 0 <= pct <= 100:
        raise ToolInputError("min_free_pct must be between 0 and 100")
    snap = ctx.snap
    source = fitcheck.Source(
        kind="snapshot",
        label=f"IPLens snapshot {snap['id']} taken {snap['taken_at']}",
        account_ref=snap["account_ref"],
        taken_at=snap["taken_at"],
    )
    try:
        result = fitcheck.evaluate(
            headroom.load(ctx.conn, ctx.snap_id),
            fitcheck.need_demand(sid, n),
            source,
            mode="need",
            min_free_pct=pct,
            rules=rules_mod.list_rules(ctx.conn),
            include_surge=bool(include_surge),
        )
    except fitcheck.CheckError as exc:
        raise ToolInputError(str(exc)) from exc
    return check_to_dict(result)


TOOLS: dict[str, Callable[..., dict[str, Any]]] = {
    "list_subnets": list_subnets,
    "find_subnet": find_subnet,
    "subnet_detail": subnet_detail,
    "lookup_ip": lookup_ip,
    "changes": changes,
    "fit_check": fit_check,
}


class Tools:
    """The tools over one database: a fresh read-only connection per call, so a Refresh
    in the UI shows up in the next answer."""

    def __init__(self, db_path: Path, account: str | None = None, redact: bool = False):
        self.db_path = Path(db_path)
        self.account = account
        self.redact = redact

    def check(self) -> None:
        """Fail early (ToolInputError) on a missing database or an unknown --account."""
        try:
            conn = open_readonly(self.db_path)
            try:
                resolve_account(conn, self.account)
            finally:
                conn.close()
        except ToolInputError as exc:
            raise ToolInputError(Redactor(self.redact).text(str(exc))) from None

    def call(self, name: str, **arguments: Any) -> dict[str, Any]:
        tool = TOOLS[name]
        redactor = Redactor(self.redact)
        try:
            conn = open_readonly(self.db_path)
            try:
                ctx = self._context(conn)
                redactor = Redactor(self.redact, ctx.labels)
                result = tool(ctx, **arguments)
                meta = _snapshot_meta(ctx.snap)
            finally:
                conn.close()
        except ToolInputError as exc:
            raise ToolInputError(redactor.text(str(exc))) from None
        except sqlite3.Error as exc:
            raise ToolInputError(redactor.text(f"cannot read the IPLens database: {exc}")) from None
        return redactor.apply(
            {
                "snapshot_taken_at": meta["taken_at"],
                "snapshot": meta,
                "redacted": self.redact,
                **result,
                "answered_at": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        )

    def _context(self, conn: sqlite3.Connection) -> Ctx:
        ref = resolve_account(conn, self.account)
        snap = queries.latest_snapshot(conn, ref)
        if snap is None:
            raise ToolInputError(
                "the account has no successful snapshot yet: Refresh it in the IPLens UI"
            )
        settings = _ReadOnlySettings(conn).load()
        # Labels over the account's whole history (oldest first, the newest name wins):
        # the same subnet has the same label in every tool, ``changes`` included.
        history = [s["id"] for s in reversed(_ok_snapshots(conn, ref))]
        return Ctx(
            conn=conn,
            account_ref=ref,
            snap=snap,
            scope=scope_mod.resolve(conn, snap["id"], scope_mod.load(conn, ref)),
            env_keys=settings.env_keys,
            own=settings.ownership_config(),
            subnet_labels=_subnet_labels(conn, history),
            vpc_labels=_vpc_labels(conn, history),
            sg_labels=_sg_labels(conn, history),
        )
