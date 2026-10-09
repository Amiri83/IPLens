"""Per-account report: one self-contained HTML document (inline CSS and SVG, no scripts,
no external assets) to print to PDF or share.

:func:`build` gathers the sections from the modules behind the regular pages: the
summary and at-risk subnets (:mod:`iplens.queries`, :mod:`iplens.trends`), the top IP
consumers (:func:`iplens.queries.ip_list`), the used-IP trend, the suggestions split into
allowed / blocked by a rule (:mod:`iplens.suggestions`), CIDR headroom with a secondary
CIDR recommendation (:mod:`iplens.cidrplan`) and ownership coverage
(:mod:`iplens.ownership`). The web route renders ``templates/report.html``.

An environment filter limits the report to the subnets holding IPs of that environment;
the consumer tables then count only that environment's IPs.

:class:`Redactor` makes a report shareable outside the organisation: account ids, ARNs,
IPv4 addresses / CIDRs (``ip-10-0-1-5`` host names too) and AWS resource ids are replaced
by keyed-hash placeholders such as ``[ip:3fa2c1d0e4]/24``. The same input always gives the
same placeholder (the key is derived from the installation's secret), so relations inside
a report survive while the values cannot be reversed by hashing guesses.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import sqlite3
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import Any

from markupsafe import Markup

from . import cidrplan, environment, ownership, queries, trends
from . import suggestions as sugg_mod
from .attribution import OWNER_LABELS
from .queries import SubnetStats, VpcNode
from .rules import Rule
from .scope import UNSCOPED, ResolvedScope

# A subnet is at risk when forecast full within trends.SOON_DAYS or below this free share.
AT_RISK_FREE_PCT = 10.0
# A VPC whose CIDRs have less free space than this share gets a "needs room" flag.
LOW_HEADROOM_PCT = 20.0
TOP_CONSUMERS = 10
MAX_UNMANAGED_LISTED = 25
OTHER_LABEL = "(other)"

# -- redaction ------------------------------------------------------------------------------

# Well-known ranges quoted by the CIDR planner's explanations: not identifiers.
WELL_KNOWN_CIDRS = frozenset(
    str(n)
    for n in (
        *cidrplan.RFC1918,
        cidrplan.SHARED,
        cidrplan.AWS_RESERVED,
        cidrplan.DEFAULT_VPC_RANGE,
        *cidrplan.UNUSABLE,
        IPv4Network("0.0.0.0/0"),
    )
)
_RESOURCE_PREFIXES = (
    "tgw-attach|tgw|vpce|vpc|subnet|eni|sg|nat|pcx|rtb|igw|eigw|acl|eipalloc|eipassoc|i"
)
# One pass, most specific first: an ARN embeds an account id, a host name embeds an IP.
# ``&`` ends an ARN: the document is HTML, where quotes are escaped as ``&#39;``.
_REDACT_RE = re.compile(
    r"(?P<arn>\barn:aws[\w-]*:[^\s\"'<>(),;&]+)"
    r"|(?P<host>\bip-(?:\d{1,3}-){3}\d{1,3}\b)"
    r"|(?P<uscore>(?<![\d.])(?:\d{1,3}_){3}\d{1,3}(?!\d))"
    r"|(?P<ip>(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.]))"
    r"|(?P<account>(?<!\w)\d{12}(?!\w))"
    rf"|(?P<res>\b(?P<prefix>{_RESOURCE_PREFIXES})-(?=[a-z]*\d)[0-9a-z]{{4,32}}\b)"
)


class Redactor:
    """Deterministic, keyed placeholder substitution (see the module docstring)."""

    def __init__(self, key: bytes):
        self._key = key

    def token(self, kind: str, value: str) -> str:
        digest = hmac.new(self._key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
        return f"[{kind}:{digest[:10]}]"

    def name(self, value: str) -> str:
        """Placeholder for a free-text name (account alias / display name)."""
        return self.token("name", value) if value else value

    def _ip(self, text: str) -> str:
        addr, sep, prefix = text.partition("/")
        if text in WELL_KNOWN_CIDRS:
            return text
        try:
            ipaddress.IPv4Address(addr)
        except ValueError:
            return text  # e.g. a version number with an octet above 255
        return self.token("ip", addr) + sep + prefix

    def _sub(self, m: re.Match[str]) -> str:
        kind = m.lastgroup or ""
        text = m.group(0)
        if kind == "ip":
            return self._ip(text)
        if kind == "host":
            return self._ip(text.removeprefix("ip-").replace("-", "."))
        if kind == "uscore":  # identifiers derived from an address (10_0_1_5)
            return self._ip(text.replace("_", "."))
        if kind == "res":
            return self.token(m.group("prefix"), text)
        return self.token(kind, text)

    def redact(self, text: str) -> str:
        return _REDACT_RE.sub(self._sub, text)


def redaction_key(secret: bytes) -> bytes:
    """Per-installation redaction key derived from the app secret."""
    return hmac.new(secret, b"iplens-report-redaction", hashlib.sha256).digest()


# -- model ----------------------------------------------------------------------------------


@dataclass
class AtRisk:
    subnet: SubnetStats
    forecast: trends.Forecast | None


@dataclass
class Summary:
    vpcs: int
    subnets: int
    usable: int
    used: int
    idle: int

    @property
    def consumed(self) -> int:
        return self.used + self.idle

    @property
    def free(self) -> int:
        return max(self.usable - self.consumed, 0)

    @property
    def used_pct(self) -> float:
        return 100.0 * self.consumed / self.usable if self.usable else 0.0

    @property
    def free_pct(self) -> float:
        return 100.0 - self.used_pct if self.usable else 0.0


@dataclass
class Consumer:
    label: str
    ips: int
    pct: float


@dataclass
class VpcHeadroom:
    vpc: VpcNode
    maps: list[cidrplan.CidrMap]
    recommendation: cidrplan.Verdict | None
    terraform: str = ""

    @property
    def size(self) -> int:
        return sum(m.size for m in self.maps)

    @property
    def free(self) -> int:
        return sum(m.free_total for m in self.maps)

    @property
    def free_pct(self) -> float:
        return 100.0 * self.free / self.size if self.size else 0.0

    @property
    def low(self) -> bool:
        return self.free_pct < LOW_HEADROOM_PCT


@dataclass
class Report:
    account: str
    region: str
    taken_at: str
    generated_at: str
    env: str
    env_label: str
    redacted: bool
    summary: Summary
    at_risk: list[AtRisk]
    by_owner: list[Consumer]
    by_type: list[Consumer]
    by_env: list[Consumer]
    trend_total: trends.Series
    trend_vpcs: list[trends.Series]
    trend_window: int
    trend_snapshots: int
    allowed: list[sugg_mod.Suggestion]
    blocked: list[sugg_mod.Suggestion]
    totals: dict[str, int]
    headroom: list[VpcHeadroom]
    ownership: ownership.OwnershipReport | None
    secondary_prefix: int = cidrplan.DEFAULT_SECONDARY_PREFIX
    notes: list[str] = field(default_factory=list)

    @property
    def managed(self) -> int:
        if self.ownership is None:
            return 0
        return self.ownership.total - len(self.ownership.unmanaged)

    @property
    def managed_pct(self) -> float:
        total = self.ownership.total if self.ownership else 0
        return 100.0 * self.managed / total if total else 0.0


def _consumers(rows: Sequence[dict[str, Any]], key: Callable[[dict[str, Any]], str]) -> list:
    """Distinct IPs per group, largest first; the tail beyond TOP_CONSUMERS is "(other)"."""
    groups: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        groups[key(r)].add(r["ip"])
    total = len({r["ip"] for r in rows})
    ranked = sorted(((k, len(v)) for k, v in groups.items()), key=lambda kv: (-kv[1], kv[0]))
    head, tail = ranked[:TOP_CONSUMERS], ranked[TOP_CONSUMERS:]
    if tail:
        head.append((OTHER_LABEL, sum(n for _, n in tail)))
    return [Consumer(k, n, 100.0 * n / total if total else 0.0) for k, n in head]


def env_scope(rows: Sequence[dict[str, Any]], base: ResolvedScope) -> ResolvedScope:
    """``base`` narrowed to the subnets (and their VPCs) holding any of ``rows``."""
    subnets = frozenset(r["subnet_id"] for r in rows if r["subnet_id"])
    vpcs = frozenset(r["vpc_id"] for r in rows if r["vpc_id"])
    return ResolvedScope(
        subnet_ids=subnets, vpc_ids=vpcs, ip_include=base.ip_include, ip_exclude=base.ip_exclude
    )


def total_series(t: trends.Trends) -> trends.Series:
    """The account's used-IP series: every VPC's series summed per snapshot."""
    by_time: dict[datetime, int] = defaultdict(int)
    for v in t.vpcs:
        for when, n in v.points:
            by_time[when] += n
    points = sorted(by_time.items())
    capacity = sum(v.capacity for v in t.vpcs)
    s = trends.Series("account", "All VPCs", "", capacity, points=points)
    s.forecast = trends.forecast(points, capacity)
    return s


def _recommend(
    vpc: VpcNode, known: list[cidrplan.KnownNetwork], prefix: int, redacted: bool
) -> tuple[cidrplan.Verdict | None, str]:
    cidrs = [IPv4Network(c) for c in vpc.cidrs]
    pick = next(
        (
            c
            for c in cidrplan.secondary_candidates(vpc.vpc_id, cidrs, known, prefix)
            if c.status != "rejected"
        ),
        None,
    )
    if pick is None:
        return None, ""
    # The default resource label spells out the CIDR ("secondary_10_1_0_0_16").
    return pick, cidrplan.tf_secondary(vpc.vpc_id, pick.cidr, "secondary" if redacted else "")


def build(
    conn: sqlite3.Connection,
    snap: Any,
    account_ref: int,
    *,
    account: str,
    scope: ResolvedScope = UNSCOPED,
    env: str = "",
    env_keys: Sequence[str] = environment.DEFAULT_TAG_KEYS,
    own: ownership.OwnershipConfig | None = None,
    rules: Sequence[Rule] = (),
    window: int = trends.DEFAULT_WINDOW,
    secondary_prefix: int = cidrplan.DEFAULT_SECONDARY_PREFIX,
    redactor: Redactor | None = None,
    now: datetime | None = None,
) -> Report:
    """The report model of snapshot ``snap`` (the account's latest) in ``scope``.

    With a ``redactor`` the free-text names that the pattern pass of
    :meth:`Redactor.redact` cannot recognise (account labels, the account names of
    other accounts' networks) are replaced here; the caller still redacts the rendered
    document.
    """
    own = own or ownership.OwnershipConfig()
    now = now or datetime.now(UTC)
    snap_id = snap["id"]
    rows = queries.ip_list(conn, snap_id, scope=scope, env_keys=env_keys, own=own)
    env_label = ""
    if env:
        rows = [r for r in rows if environment.matches(r["environment"], env)]
        scope = env_scope(rows, scope)
        env_label = environment.NOT_SET_LABEL if env == environment.FILTER_NOT_SET else env

    tree = queries.vpc_tree(conn, snap_id, scope)
    subnets = [s for v in tree for s in v.subnets]
    summary = Summary(
        vpcs=len(tree),
        subnets=len(subnets),
        usable=sum(s.usable for s in subnets),
        used=sum(s.used for s in subnets),
        idle=sum(s.idle for s in subnets),
    )

    tr = trends.load(conn, account_ref, window, scope, now=now)
    forecasts = {s.key: s.forecast for ss in tr.subnets.values() for s in ss}
    at_risk = []
    for s in subnets:
        fc = forecasts.get(s.subnet_id)
        if (fc is not None and fc.soon) or s.free_pct < AT_RISK_FREE_PCT:
            at_risk.append(AtRisk(s, fc))
    at_risk.sort(key=lambda a: (a.subnet.free_pct, a.subnet.subnet_id))

    ctx = sugg_mod.build_context(conn, snap_id, scope)
    items = sugg_mod.generate(ctx, list(rules))

    known = cidrplan.known_networks(conn)
    if redactor is not None:
        known = [replace(k, account=redactor.name(k.account)) for k in known]
    # Every subnet counts toward free space (as on the CIDR planner); the scope picks VPCs.
    headroom = []
    for v in queries.vpc_tree(conn, snap_id, UNSCOPED):
        if not scope.vpc_ok(v.vpc_id):
            continue
        pick, tf = _recommend(v, known, secondary_prefix, redactor is not None)
        headroom.append(VpcHeadroom(v, cidrplan.cidr_maps(v), pick, tf))

    notes = []
    if scope.active and not env:
        notes.append("Limited to the account's active scope.")
    if env:
        notes.append(
            f"Environment {env_label}: the subnets holding IPs of this environment; "
            "the consumer tables count only its IPs. Ownership coverage is account-wide."
        )
    return Report(
        account=redactor.name(account) if redactor else account,
        region=snap["region"] or "",
        taken_at=str(snap["taken_at"]),
        generated_at=now.strftime("%Y-%m-%d %H:%M UTC"),
        env=env,
        env_label=env_label,
        redacted=redactor is not None,
        summary=summary,
        at_risk=at_risk,
        by_owner=_consumers(rows, lambda r: r["owner"]["text"]),
        by_type=_consumers(rows, lambda r: OWNER_LABELS.get(r["owner_type"], r["owner_type"])),
        by_env=_consumers(rows, lambda r: r["environment"] or environment.NOT_SET_LABEL),
        trend_total=total_series(tr),
        trend_vpcs=tr.vpcs,
        trend_window=window,
        trend_snapshots=tr.snapshots,
        allowed=[s for s in items if not s.blocked],
        blocked=[s for s in items if s.blocked],
        totals=sugg_mod.totals(items),
        headroom=headroom,
        ownership=ownership.report(conn, snap_id, own),
        secondary_prefix=secondary_prefix,
        notes=notes,
    )


# -- inline SVG helpers ---------------------------------------------------------------------


def svg_bar(pct: float, *, width: int = 160, height: int = 10, cls: str = "") -> Markup:
    """A horizontal percentage bar (SVG prints without "background graphics")."""
    pct = min(max(pct, 0.0), 100.0)
    return Markup(
        '<svg class="pbar{0}" role="img" aria-label="{1:.1f}%" width="{2}" height="{3}" '
        'viewBox="0 0 {2} {3}"><rect class="pbar-bg" width="{2}" height="{3}" rx="2"/>'
        '<rect class="pbar-fg" width="{4:.1f}" height="{3}" rx="2"/></svg>'
    ).format(f" {cls}" if cls else "", pct, width, height, width * pct / 100.0)
