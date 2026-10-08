"""Per-account scope: the VPCs, subnets and IP ranges every view works on.

A :class:`Scope` is what the user saved (include/exclude lists); :func:`resolve`
turns it into a :class:`ResolvedScope` against one snapshot: the concrete set of
subnets in scope plus IP ranges. Every view, the IP list, suggestions, rules and
exports read through the resolved scope.

Semantics per dimension (an empty list means "no filter"):

* VPCs: ``include`` keeps only the listed VPCs, ``exclude`` drops them.
* Subnets: a subnet matches when its id is listed or its Name tag matches one of
  the wildcard patterns (``*``, ``?``, ``[..]``; case-insensitive). ``include``
  keeps only matching subnets, ``exclude`` drops them.
* IP ranges (IPv4 CIDRs): ``include`` keeps only addresses inside a range (and the
  subnets overlapping one); ``exclude`` drops addresses inside a range (and subnets
  entirely inside one).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

MODES = ("include", "exclude")
MAX_ITEMS = 500
MAX_PATTERN = 128
_VPC_RX = re.compile(r"^vpc-[0-9a-z]{1,32}$")
_SUBNET_RX = re.compile(r"^subnet-[0-9a-z]{1,32}$")


@dataclass
class Scope:
    vpc_mode: str = "include"
    vpcs: list[str] = field(default_factory=list)
    subnet_mode: str = "include"
    subnets: list[str] = field(default_factory=list)
    subnet_patterns: list[str] = field(default_factory=list)
    cidr_mode: str = "include"
    cidrs: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Number of filters (selected VPCs, subnets, name patterns and CIDRs)."""
        return len(self.vpcs) + len(self.subnets) + len(self.subnet_patterns) + len(self.cidrs)

    @property
    def is_empty(self) -> bool:
        return self.count == 0

    def summary(self) -> list[str]:
        """Plain-English lines describing the scope."""
        out = []
        if self.vpcs:
            out.append(f"{_verb(self.vpc_mode)} VPCs: {', '.join(self.vpcs)}")
        if self.subnets or self.subnet_patterns:
            parts = self.subnets + [f"name ~ {p}" for p in self.subnet_patterns]
            out.append(f"{_verb(self.subnet_mode)} subnets: {', '.join(parts)}")
        if self.cidrs:
            out.append(f"{_verb(self.cidr_mode)} IP ranges: {', '.join(self.cidrs)}")
        return out

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str | None) -> Scope:
        try:
            doc = json.loads(raw or "{}")
        except ValueError:
            return cls()
        if not isinstance(doc, dict):
            return cls()
        try:
            return validate(doc)
        except ValueError:
            return cls()


def _verb(mode: str) -> str:
    return "only" if mode == "include" else "excluding"


def _items(value: Any) -> list[str]:
    """A list from a multi-select (list) and/or a free-text box (lines / commas)."""
    if value is None:
        return []
    values = [value] if isinstance(value, str) else list(value)
    out: list[str] = []
    for v in values:
        for part in re.split(r"[\n,]+", str(v)):
            part = part.strip()
            if part and part not in out:
                out.append(part)
    return out


def _mode(value: Any, what: str) -> str:
    mode = value or "include"
    if mode not in MODES:
        raise ValueError(f"{what} mode must be include or exclude")
    return mode


def validate(doc: Mapping[str, Any]) -> Scope:
    """Build a Scope from form/JSON values; raise ValueError with a safe message."""
    vpcs = _items(doc.get("vpcs"))
    subnets = _items(doc.get("subnets"))
    patterns = _items(doc.get("subnet_patterns"))
    cidrs = _items(doc.get("cidrs"))
    if sum(map(len, (vpcs, subnets, patterns, cidrs))) > MAX_ITEMS:
        raise ValueError(f"a scope can have at most {MAX_ITEMS} filters")
    bad = [v for v in vpcs if not _VPC_RX.match(v)]
    if bad:
        raise ValueError(f"invalid VPC id(s): {', '.join(bad[:5])}")
    bad = [s for s in subnets if not _SUBNET_RX.match(s)]
    if bad:
        raise ValueError(f"invalid subnet id(s): {', '.join(bad[:5])}")
    if any(len(p) > MAX_PATTERN for p in patterns):
        raise ValueError(f"name patterns must be at most {MAX_PATTERN} characters")
    nets = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            raise ValueError(f"invalid CIDR: {c[:64]}") from None
        if net.version != 4:
            raise ValueError(f"only IPv4 ranges are supported: {c[:64]}")
        nets.append(str(net))
    return Scope(
        vpc_mode=_mode(doc.get("vpc_mode"), "VPC"),
        vpcs=vpcs,
        subnet_mode=_mode(doc.get("subnet_mode"), "subnet"),
        subnets=subnets,
        subnet_patterns=patterns,
        cidr_mode=_mode(doc.get("cidr_mode"), "IP range"),
        cidrs=list(dict.fromkeys(nets)),
    )


# -- storage ---------------------------------------------------------------------------


def load(conn: sqlite3.Connection, account_ref: int | None) -> Scope:
    if account_ref is None:
        return Scope()
    row = conn.execute("SELECT config FROM scopes WHERE account_ref=?", (account_ref,)).fetchone()
    return Scope.from_json(row["config"]) if row else Scope()


def save(conn: sqlite3.Connection, account_ref: int, scope: Scope) -> None:
    if scope.is_empty:
        clear(conn, account_ref)
        return
    conn.execute(
        "INSERT INTO scopes(account_ref, config) VALUES(?, ?) "
        "ON CONFLICT(account_ref) DO UPDATE SET config=excluded.config",
        (account_ref, scope.to_json()),
    )


def clear(conn: sqlite3.Connection, account_ref: int) -> bool:
    return conn.execute("DELETE FROM scopes WHERE account_ref=?", (account_ref,)).rowcount > 0


# -- resolution against a snapshot ----------------------------------------------------------

Range = tuple[int, int]


def _ranges(cidrs: Iterable[str]) -> tuple[Range, ...]:
    nets = [ipaddress.IPv4Network(c, strict=False) for c in cidrs]
    return tuple((int(n.network_address), int(n.broadcast_address)) for n in nets)


@dataclass(frozen=True)
class ResolvedScope:
    """A scope applied to one snapshot. ``None`` sets mean "no restriction"."""

    subnet_ids: frozenset[str] | None = None
    vpc_ids: frozenset[str] | None = None
    ip_include: tuple[Range, ...] = ()
    ip_exclude: tuple[Range, ...] = ()

    @property
    def active(self) -> bool:
        return (
            self.subnet_ids is not None
            or self.vpc_ids is not None
            or bool(self.ip_include or self.ip_exclude)
        )

    def vpc_ok(self, vpc_id: str | None) -> bool:
        return self.vpc_ids is None or vpc_id in self.vpc_ids

    def subnet_ok(self, subnet_id: str | None) -> bool:
        return self.subnet_ids is None or subnet_id in self.subnet_ids

    def ip_ok(self, ip: int | str) -> bool:
        n = ip if isinstance(ip, int) else int(ipaddress.IPv4Address(ip))
        if self.ip_include and not any(lo <= n <= hi for lo, hi in self.ip_include):
            return False
        return not any(lo <= n <= hi for lo, hi in self.ip_exclude)

    def sql(self, alias: str = "i") -> tuple[list[str], list[Any]]:
        """WHERE fragments (and bound args) over an ``ips`` table aliased ``alias``."""
        where: list[str] = []
        args: list[Any] = []
        if self.subnet_ids is not None:
            if self.subnet_ids:
                marks = ",".join("?" * len(self.subnet_ids))
                where.append(f"{alias}.subnet_id IN ({marks})")
                args.extend(sorted(self.subnet_ids))
            else:
                where.append("0")
        if self.ip_include:
            where.append(
                "(" + " OR ".join(f"{alias}.ip_int BETWEEN ? AND ?" for _ in self.ip_include) + ")"
            )
            args.extend(v for r in self.ip_include for v in r)
        for lo, hi in self.ip_exclude:
            where.append(f"{alias}.ip_int NOT BETWEEN ? AND ?")
            args.extend((lo, hi))
        return where, args


UNSCOPED = ResolvedScope()


def resolve(conn: sqlite3.Connection, snap_id: int, scope: Scope) -> ResolvedScope:
    """Apply ``scope`` to the VPCs and subnets of snapshot ``snap_id``."""
    if scope.is_empty:
        return UNSCOPED
    include = _ranges(scope.cidrs) if scope.cidr_mode == "include" else ()
    exclude = _ranges(scope.cidrs) if scope.cidr_mode == "exclude" else ()
    vpc_set = set(scope.vpcs)

    def vpc_match(vpc_id: str) -> bool:
        if not vpc_set:
            return True
        return (vpc_id in vpc_set) == (scope.vpc_mode == "include")

    patterns = [p.lower() for p in scope.subnet_patterns]
    subnet_set = set(scope.subnets)
    subnet_filter = bool(subnet_set or patterns)

    def subnet_match(subnet_id: str, name: str) -> bool:
        if not subnet_filter:
            return True
        hit = subnet_id in subnet_set or any(fnmatch.fnmatchcase(name.lower(), p) for p in patterns)
        return hit == (scope.subnet_mode == "include")

    def cidr_match(cidr: str) -> bool:
        net = ipaddress.IPv4Network(cidr, strict=False)
        lo, hi = int(net.network_address), int(net.broadcast_address)
        if include and not any(lo <= b and a <= hi for a, b in include):
            return False
        return not any(a <= lo and hi <= b for a, b in exclude)

    vpcs = {
        r["vpc_id"]
        for r in conn.execute("SELECT vpc_id FROM vpcs WHERE snapshot_id=?", (snap_id,))
        if vpc_match(r["vpc_id"])
    }
    kept = {
        r["subnet_id"]: r["vpc_id"]
        for r in conn.execute(
            "SELECT subnet_id, vpc_id, name, cidr FROM subnets WHERE snapshot_id=?", (snap_id,)
        )
        if r["vpc_id"] in vpcs
        and subnet_match(r["subnet_id"], r["name"] or "")
        and cidr_match(r["cidr"])
    }
    if subnet_filter or include or exclude:
        # Subnet-level filters: a VPC without any subnet in scope is out of scope too.
        vpcs &= set(kept.values())
    return ResolvedScope(
        subnet_ids=frozenset(kept),
        vpc_ids=frozenset(vpcs),
        ip_include=include,
        ip_exclude=exclude,
    )
