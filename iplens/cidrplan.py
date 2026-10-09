"""CIDR planner: free space per VPC CIDR, subnet fitting and secondary CIDR proposals.

Everything here is read-only arithmetic over data IPLens already stored (the vpcs /
subnets of every account's latest snapshot and the route lines of the Extended crawl).
Nothing is created in AWS: proposals are shown with a Terraform snippet to copy.

* :func:`cidr_maps`: per VPC CIDR (primary first), the subnets and the free blocks
  between them, how many aligned /20 .. /28 blocks still fit and a fragmentation score.
* :func:`fit`: carve requested subnet sizes out of the free space, aligned on their size.
* :func:`secondary_candidates` / :func:`check_candidate`: secondary CIDR proposals checked
  against AWS association restrictions and against every network IPLens knows about
  (all accounts' VPCs, routes to Transit Gateways and VPC peering connections).
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from .queries import VpcNode

# Subnet sizes the planner reports and accepts (AWS subnets are /16 .. /28).
SIZES = tuple(range(20, 29))
FIT_SIZES = tuple(range(16, 29))
# Prefix lengths AWS accepts for a VPC CIDR block (primary or secondary).
VPC_MIN_PREFIX, VPC_MAX_PREFIX = 16, 28
DEFAULT_SECONDARY_PREFIX = 16
# Default quota of IPv4 CIDR blocks per VPC (adjustable through Service Quotas).
CIDRS_PER_VPC = 5
CANDIDATES_PER_POOL = 3
# AWS reserves the first four and the last address of every subnet.
SUBNET_RESERVED = 5

RFC1918 = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
SHARED = IPv4Network("100.64.0.0/10")  # RFC 6598 shared address space (carrier-grade NAT)
AWS_RESERVED = IPv4Network("198.19.0.0/16")  # never allowed as a secondary CIDR
DEFAULT_VPC_RANGE = IPv4Network("172.31.0.0/16")  # restricted when the primary is in 172.16/12
# Special-purpose ranges no VPC can use.
UNUSABLE = (
    IPv4Network("0.0.0.0/8"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("224.0.0.0/3"),  # multicast and the reserved class E space
)

# The destination of a route line stored by the Extended crawl (extended._route_tables):
# "route table <rtb> (<where>): <destination> → <target id>".
_ROUTE_DEST_RE = re.compile(r": (\S+) → (\S+)$")


# -- free space ---------------------------------------------------------------------------


def free_blocks(cidr: IPv4Network, used: list[IPv4Network]) -> list[IPv4Network]:
    """The free space of ``cidr`` once ``used`` is taken out, as maximal aligned blocks.

    The free address ranges between the used networks are split with
    :func:`ipaddress.summarize_address_range`, which yields the fewest CIDR blocks that
    cover a range, each aligned on its own size. Any aligned /n that is free lies inside
    exactly one of them, so counting per size needs no further search. Parts of ``used``
    outside ``cidr`` are ignored.
    """
    start, end = int(cidr.network_address), int(cidr.broadcast_address)
    taken = sorted(
        (max(int(n.network_address), start), min(int(n.broadcast_address), end))
        for n in used
        if n.overlaps(cidr)
    )
    out: list[IPv4Network] = []
    cursor = start
    for lo, hi in taken:
        if lo > cursor:
            out.extend(_summarize(cursor, lo - 1))
        cursor = max(cursor, hi + 1)
    if cursor <= end:
        out.extend(_summarize(cursor, end))
    return out


def _summarize(lo: int, hi: int) -> list[IPv4Network]:
    return list(
        ipaddress.summarize_address_range(ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi))
    )


def free_ranges(blocks: list[IPv4Network]) -> list[tuple[int, int]]:
    """Contiguous free address ranges ``(first, last)``: adjacent free blocks merged."""
    out: list[tuple[int, int]] = []
    for b in sorted(blocks):
        lo, hi = int(b.network_address), int(b.broadcast_address)
        if out and out[-1][1] + 1 == lo:
            out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def fragmentation(blocks: list[IPv4Network]) -> float:
    """How broken up the free space is, from 0.0 to just under 1.0.

    ``score = 1 - largest_contiguous_free_range / total_free``

    Free blocks that touch are merged into one range first, so a single contiguous free
    range scores 0.0 even when it is not a power-of-two block; free space scattered in
    many small gaps between subnets approaches 1.0. No free space at all scores 0.0.
    """
    ranges = free_ranges(blocks)
    total = sum(hi - lo + 1 for lo, hi in ranges)
    if not total:
        return 0.0
    largest = max(hi - lo + 1 for lo, hi in ranges)
    return 1.0 - largest / total


def fits_per_size(blocks: list[IPv4Network], sizes=SIZES) -> dict[int, tuple[int, str]]:
    """``{prefix: (how many aligned /prefix fit, the first one or '')}`` for each size."""
    out = {}
    for p in sizes:
        count, first = 0, ""
        for b in sorted(blocks):
            if b.prefixlen <= p:
                count += 2 ** (p - b.prefixlen)
                first = first or str(next(b.subnets(new_prefix=p)))
        out[p] = (count, first)
    return out


@dataclass
class Segment:
    """A run of a VPC CIDR: a subnet or a free block (for the map and the table)."""

    cidr: str
    free: bool
    subnet_id: str = ""
    name: str = ""
    az: str = ""
    pct: float = 0.0  # share of the VPC CIDR


@dataclass
class CidrMap:
    cidr: str
    primary: bool
    size: int
    allocated: int
    segments: list[Segment]
    free: list[IPv4Network]
    per_size: dict[int, tuple[int, str]]
    fragmentation: float

    @property
    def free_total(self) -> int:
        return sum(b.num_addresses for b in self.free)

    @property
    def largest_free(self) -> str:
        return str(min(self.free, key=lambda b: (b.prefixlen, b))) if self.free else ""

    @property
    def free_range_count(self) -> int:
        return len(free_ranges(self.free))


def cidr_maps(vpc: VpcNode) -> list[CidrMap]:
    """One map per VPC CIDR, the primary (the first association) first.

    Every subnet of the VPC counts, in scope or not: free space must never be
    reported where a subnet exists.
    """
    subnets = [(IPv4Network(s.cidr), s) for s in vpc.subnets]
    out = []
    for i, raw in enumerate(vpc.cidrs):
        cidr = IPv4Network(raw)
        inside = [(n, s) for n, s in subnets if n.subnet_of(cidr)]
        free = free_blocks(cidr, [n for n, _ in inside])
        size = cidr.num_addresses
        segments = [
            Segment(str(n), False, s.subnet_id, s.name, s.az, 100.0 * n.num_addresses / size)
            for n, s in inside
        ] + [Segment(str(b), True, pct=100.0 * b.num_addresses / size) for b in free]
        segments.sort(key=lambda g: int(IPv4Network(g.cidr).network_address))
        out.append(
            CidrMap(
                cidr=str(cidr),
                primary=i == 0,
                size=size,
                allocated=sum(n.num_addresses for n, _ in inside),
                segments=segments,
                free=free,
                per_size=fits_per_size(free),
                fragmentation=fragmentation(free),
            )
        )
    return out


# -- fit ----------------------------------------------------------------------------------


@dataclass
class FitRequest:
    prefix: int
    az: str = ""


@dataclass
class Placement:
    request: FitRequest
    cidr: str = ""  # '' when it does not fit

    @property
    def usable(self) -> int:
        return 2 ** (32 - self.request.prefix) - SUBNET_RESERVED


@dataclass
class FitResult:
    placements: list[Placement]

    @property
    def fits(self) -> bool:
        return all(p.cidr for p in self.placements)

    @property
    def missing(self) -> list[Placement]:
        return [p for p in self.placements if not p.cidr]

    def needed_prefix(self) -> int:
        """Smallest VPC CIDR (largest prefix length) that holds every missing request."""
        total = sum(2 ** (32 - p.request.prefix) for p in self.missing)
        prefix = 32 - max(total - 1, 1).bit_length()
        return max(min(prefix, VPC_MAX_PREFIX), VPC_MIN_PREFIX)


def fit(free: list[IPv4Network], requests: list[FitRequest]) -> FitResult:
    """Place each request in an aligned block of its size carved out of ``free``.

    Largest requests go first, each into the smallest free block that holds it (best
    fit), so big blocks stay whole for later requests. ``free`` is not modified.
    Results come back in request order.
    """
    pool = sorted(free)
    placements = [Placement(r) for r in requests]
    for pl in sorted(placements, key=lambda p: p.request.prefix):
        p = pl.request.prefix
        options = [b for b in pool if b.prefixlen <= p]
        if not options:
            continue
        block = max(options, key=lambda b: (b.prefixlen, -int(b.network_address)))
        chosen = next(block.subnets(new_prefix=p))
        pl.cidr = str(chosen)
        pool.remove(block)
        pool.extend(block.address_exclude(chosen))
        pool.sort()
    return FitResult(placements)


# -- known networks and secondary CIDR checks ---------------------------------------------


@dataclass(frozen=True)
class KnownNetwork:
    cidr: IPv4Network
    kind: str  # vpc | tgw-route | pcx-route
    vpc_id: str
    account: str
    via: str = ""  # tgw / pcx id of a route

    @property
    def label(self) -> str:
        if self.kind == "vpc":
            return f"{self.vpc_id} ({self.account})"
        what = "Transit Gateway" if self.kind == "tgw-route" else "VPC peering"
        return f"{what} route {self.cidr} → {self.via} in {self.vpc_id} ({self.account})"


def _account_name(row: sqlite3.Row) -> str:
    return (
        row["account_name"] or row["account_alias"] or row["account_id"] or f"#{row['account_ref']}"
    )


def known_networks(conn: sqlite3.Connection) -> list[KnownNetwork]:
    """Every network IPLens knows, across all accounts.

    * VPC CIDRs from each account's latest successful snapshot;
    * route destinations pointing to a Transit Gateway or a VPC peering connection,
      from each account's latest Extended crawl (route tables are only read there).
      Default routes (``0.0.0.0/0``) and prefix-list destinations are skipped.
    """
    out: set[KnownNetwork] = set()
    snaps = conn.execute(
        "SELECT s.* FROM snapshots s WHERE s.id IN "
        "(SELECT MAX(id) FROM snapshots WHERE status='ok' GROUP BY account_ref)"
    ).fetchall()
    for snap in snaps:
        for r in conn.execute("SELECT vpc_id, cidrs FROM vpcs WHERE snapshot_id=?", (snap["id"],)):
            for c in json.loads(r["cidrs"]):
                out.add(KnownNetwork(IPv4Network(c), "vpc", r["vpc_id"], _account_name(snap)))
    crawled = conn.execute(
        "SELECT s.* FROM snapshots s WHERE s.id IN (SELECT MAX(c.snapshot_id) FROM ext_crawls c "
        "JOIN snapshots s2 ON s2.id = c.snapshot_id GROUP BY s2.account_ref)"
    ).fetchall()
    for snap in crawled:
        rows = conn.execute(
            "SELECT source, target, detail FROM ext_edges WHERE snapshot_id=? AND label='route' "
            "AND (target LIKE 'tgw:%' OR target LIKE 'pcx:%')",
            (snap["id"],),
        )
        for r in rows:
            m = _ROUTE_DEST_RE.search(r["detail"])
            if not m:
                continue
            try:
                dest = IPv4Network(m.group(1))
            except ValueError:  # a prefix list or an IPv6 destination
                continue
            if dest.prefixlen == 0:
                continue
            kind = "tgw-route" if r["target"].startswith("tgw:") else "pcx-route"
            vpc_id = r["source"].removeprefix("vpc:")
            out.add(KnownNetwork(dest, kind, vpc_id, _account_name(snap), m.group(2)))
    return sorted(out, key=lambda k: (k.cidr, k.kind, k.vpc_id, k.via))


@dataclass
class Verdict:
    cidr: str
    pool: str = ""
    rejects: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "rejected" if self.rejects else "warning" if self.warnings else "ok"


def _range_class(net: IPv4Network) -> str:
    for block in RFC1918:
        if net.subnet_of(block):
            return str(block)
    if net.subnet_of(AWS_RESERVED):
        return str(AWS_RESERVED)
    return "public"  # publicly routable, or 100.64.0.0/10


def aws_restrictions(candidate: IPv4Network, vpc_cidrs: list[IPv4Network]) -> Verdict:
    """AWS rules for associating ``candidate`` with a VPC whose CIDRs are ``vpc_cidrs``
    (primary first), from the VPC User Guide "IPv4 CIDR block association restrictions".
    """
    v = Verdict(str(candidate))
    if not VPC_MIN_PREFIX <= candidate.prefixlen <= VPC_MAX_PREFIX:
        v.rejects.append(
            f"AWS VPC CIDR blocks must be /{VPC_MIN_PREFIX} to /{VPC_MAX_PREFIX} "
            f"(this is /{candidate.prefixlen})"
        )
    if any(candidate.overlaps(n) for n in UNUSABLE):
        v.rejects.append("reserved / special-purpose range (not usable in a VPC)")
        return v
    for c in vpc_cidrs:
        if candidate.overlaps(c):
            which = "primary" if c == vpc_cidrs[0] else "existing secondary"
            v.rejects.append(f"overlaps the VPC's {which} CIDR {c}")
    if len(vpc_cidrs) >= CIDRS_PER_VPC:
        v.warnings.append(
            f"the VPC already has {len(vpc_cidrs)} IPv4 CIDRs: the default quota is "
            f"{CIDRS_PER_VPC} (adjustable in Service Quotas)"
        )
    cls = _range_class(candidate)
    primary = _range_class(vpc_cidrs[0]) if vpc_cidrs else "public"
    if cls == str(AWS_RESERVED):
        v.rejects.append(f"{AWS_RESERVED} is reserved by AWS and cannot be a secondary CIDR")
    elif cls != "public":  # RFC 1918
        if primary != cls:
            v.rejects.append(
                f"AWS does not allow a secondary CIDR from {cls} when the primary CIDR "
                f"{vpc_cidrs[0]} is {'in ' + primary if primary != 'public' else 'not RFC 1918'}"
            )
        elif candidate.overlaps(DEFAULT_VPC_RANGE) and cls == "172.16.0.0/12":
            v.rejects.append(
                f"AWS does not allow a secondary CIDR from {DEFAULT_VPC_RANGE} in a VPC "
                "whose primary CIDR is in 172.16.0.0/12"
            )
    elif candidate.subnet_of(SHARED):
        v.warnings.append(
            "100.64.0.0/10 is RFC 6598 shared address space (carrier-grade NAT): not routable "
            "on the internet and not RFC 1918. AWS permits it as a secondary CIDR, but check "
            "that your region / services support it and that no ISP, VPN or on-premises "
            "network already uses it; typically kept non-routable (e.g. pod / private subnets "
            "behind a private NAT)"
        )
    else:
        v.warnings.append(
            "publicly routable range: unless you own it (BYOIP), internet hosts in this range "
            "become unreachable from the VPC"
        )
    return v


def check_candidate(
    candidate: IPv4Network, vpc_id: str, vpc_cidrs: list[IPv4Network], known: list[KnownNetwork]
) -> Verdict:
    """AWS restrictions plus overlap with every known network.

    * another VPC (any account) overlapping the candidate: rejected;
    * a TGW / peering route at least as specific as a VPC CIDR can be (/16 or longer)
      overlapping the candidate: rejected (a network reachable from here already uses
      those addresses; AWS also refuses a CIDR the same as or larger than a route of the
      VPC's own route tables);
    * a summary route broader than /16 (e.g. 10.0.0.0/8 → TGW) covering the candidate:
      a warning only. No single VPC is that large, and the VPC's local route is more
      specific. A summary *inside* the candidate is still rejected.
    """
    v = aws_restrictions(candidate, vpc_cidrs)
    for k in known:
        if not candidate.overlaps(k.cidr):
            continue
        if k.kind == "vpc":
            if k.vpc_id != vpc_id:
                v.rejects.append(f"overlaps {k.cidr} of {k.label}")
        elif _is_summary(k.cidr) and candidate.subnet_of(k.cidr):
            v.warnings.append(f"inside a broader summary route: {k.label}")
        else:
            v.rejects.append(f"overlaps {k.label}")
    return v


def _is_summary(route: IPv4Network) -> bool:
    return route.prefixlen < VPC_MIN_PREFIX


def _pool_free(
    pool: IPv4Network, prefix: int, vpc_cidrs: list[IPv4Network], known: list[KnownNetwork]
) -> list[IPv4Network]:
    """``pool`` minus everything an aligned /prefix candidate must not overlap: VPCs,
    non-summary routes and summary routes that would fit inside the candidate
    (summaries covering it only warn, see :func:`check_candidate`)."""
    blocked = list(vpc_cidrs) + [
        k.cidr
        for k in known
        if k.kind == "vpc" or not _is_summary(k.cidr) or k.cidr.prefixlen >= prefix
    ]
    if pool == RFC1918[1]:
        blocked.append(DEFAULT_VPC_RANGE)
    return free_blocks(pool, blocked)


def secondary_candidates(
    vpc_id: str,
    vpc_cidrs: list[IPv4Network],
    known: list[KnownNetwork],
    prefix: int = DEFAULT_SECONDARY_PREFIX,
    per_pool: int = CANDIDATES_PER_POOL,
) -> list[Verdict]:
    """Free aligned /prefix blocks to propose as a secondary CIDR, checked.

    Pools: the RFC 1918 block of the primary CIDR (other RFC 1918 blocks are refused by
    AWS) and 100.64.0.0/10 (shared address space, always offered and flagged).
    """
    pools: list[IPv4Network] = []
    if vpc_cidrs:
        cls = _range_class(vpc_cidrs[0])
        pools += [b for b in RFC1918 if str(b) == cls]
    pools.append(SHARED)
    out = []
    for pool in pools:
        taken = 0
        for block in _pool_free(pool, prefix, vpc_cidrs, known):
            if block.prefixlen > prefix:
                continue
            for cand in block.subnets(new_prefix=prefix):
                v = check_candidate(cand, vpc_id, vpc_cidrs, known)
                v.pool = str(pool)
                out.append(v)
                taken += 1
                if taken >= per_pool:
                    break
            if taken >= per_pool:
                break
    return out


# -- Terraform (generated text only) ------------------------------------------------------


def _tf_name(text: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", text.lower()).strip("_") or "planned"


def tf_secondary(vpc_id: str, cidr: str) -> str:
    name = _tf_name(f"secondary_{cidr}")
    return (
        f'resource "aws_vpc_ipv4_cidr_block_association" "{name}" {{\n'
        f'  vpc_id     = "{vpc_id}"\n'
        f'  cidr_block = "{cidr}"\n'
        "}\n"
    )


def tf_subnets(vpc_id: str, placements: list[Placement], association: str = "") -> str:
    """``aws_subnet`` blocks; with ``association`` (a secondary CIDR) they reference the
    association resource so Terraform creates it first."""
    vpc_ref = (
        f"aws_vpc_ipv4_cidr_block_association.{_tf_name(f'secondary_{association}')}.vpc_id"
        if association
        else f'"{vpc_id}"'
    )
    out = []
    for i, p in enumerate(x for x in placements if x.cidr):
        lines = [
            f'resource "aws_subnet" "{_tf_name(f"planned_{i + 1}_{p.request.az}")}" {{',
            f"  vpc_id            = {vpc_ref}",
            f'  cidr_block        = "{p.cidr}"',
        ]
        if p.request.az:
            lines.append(f'  availability_zone = "{p.request.az}"')
        out.append("\n".join([*lines, "}"]) + "\n")
    return "\n".join(out)


# -- page model ---------------------------------------------------------------------------


@dataclass
class Plan:
    vpc: VpcNode
    maps: list[CidrMap]
    azs: list[str]
    fit: FitResult | None = None
    fit_tf: str = ""
    # When the request does not fit: the secondary CIDR used and the rest placed in it.
    overflow: Verdict | None = None
    overflow_fit: FitResult | None = None
    overflow_tf: str = ""
    candidates: list[Verdict] = field(default_factory=list)
    custom: Verdict | None = None


def plan(
    vpc: VpcNode,
    known: list[KnownNetwork],
    requests: list[FitRequest] | None = None,
    prefix: int = DEFAULT_SECONDARY_PREFIX,
    custom: str = "",
) -> Plan:
    """Everything the planner page shows for one VPC. ``custom`` is a CIDR typed by the
    user to check (raises ValueError when it is not an IPv4 network)."""
    maps = cidr_maps(vpc)
    cidrs = [IPv4Network(c) for c in vpc.cidrs]
    out = Plan(vpc, maps, sorted({s.az for s in vpc.subnets if s.az}))
    out.candidates = secondary_candidates(vpc.vpc_id, cidrs, known, prefix)
    if custom:
        out.custom = check_candidate(
            IPv4Network(custom.strip(), strict=True), vpc.vpc_id, cidrs, known
        )
    if requests:
        free = [b for m in maps for b in m.free]
        out.fit = fit(free, requests)
        out.fit_tf = tf_subnets(vpc.vpc_id, out.fit.placements)
        if not out.fit.fits:
            need = min(out.fit.needed_prefix(), prefix)
            pick = next(
                (
                    c
                    for c in secondary_candidates(vpc.vpc_id, cidrs, known, need)
                    if c.status != "rejected"
                ),
                None,
            )
            if pick is not None:
                missing = [p.request for p in out.fit.missing]
                out.overflow = pick
                out.overflow_fit = fit([IPv4Network(pick.cidr)], missing)
                out.overflow_tf = (
                    tf_secondary(vpc.vpc_id, pick.cidr)
                    + "\n"
                    + tf_subnets(vpc.vpc_id, out.overflow_fit.placements, association=pick.cidr)
                )
    return out
