"""Diff of two snapshots of one account: ENIs and IPs added / removed / changed.

ENIs are matched by id and IPs by address. Changes are grouped by owner type and the
ownership / environment of the owning resource (:func:`iplens.queries.ip_list`; a
removed ENI is described as it was in the older snapshot, everything else as it is in
the newer one). The diff also has the net IP delta per subnet and the "top consumers":
resources whose IP count grew the most.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from . import environment, ownership, queries
from .scope import UNSCOPED, ResolvedScope

ADDED, REMOVED, CHANGED = "added", "removed", "changed"
TOP_CONSUMERS = 10


@dataclass
class EniChange:
    kind: str  # added | removed | changed
    eni_id: str
    subnet_id: str
    resource: str
    old_ips: list[str] = field(default_factory=list)
    new_ips: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)  # what changed ("status: a → b")


@dataclass
class IpChange:
    kind: str
    ip: str
    subnet_id: str
    resource: str
    old_eni: str = ""
    new_eni: str = ""
    detail: str = ""


@dataclass
class Group:
    owner_type: str
    type_label: str
    owner: str  # ownership text ("CloudFormation: stack-a" / "unmanaged")
    env: str  # environment ('' = not set)
    enis: list[EniChange] = field(default_factory=list)
    ips: list[IpChange] = field(default_factory=list)

    def count(self, what: str, kind: str) -> int:
        items = self.enis if what == "enis" else self.ips
        return sum(1 for c in items if c.kind == kind)

    @property
    def ip_delta(self) -> int:
        return self.count("ips", ADDED) - self.count("ips", REMOVED)


@dataclass(frozen=True)
class SubnetDelta:
    subnet_id: str
    name: str
    cidr: str
    old: int
    new: int

    @property
    def delta(self) -> int:
        return self.new - self.old


@dataclass(frozen=True)
class Consumer:
    owner_type: str
    type_label: str
    resource: str
    old: int
    new: int

    @property
    def delta(self) -> int:
        return self.new - self.old


@dataclass
class SnapshotDiff:
    old_id: int
    new_id: int
    groups: list[Group]
    subnets: list[SubnetDelta]
    consumers: list[Consumer]
    totals: dict[str, int]

    @property
    def empty(self) -> bool:
        return not self.groups


def _eni_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """ENI id -> its first IP row plus ``ips`` (every address of the ENI)."""
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        e = out.setdefault(r["eni_id"], {**r, "ips": []})
        e["ips"].append(r["ip"])
    return out


def _resource(row: dict[str, Any]) -> str:
    return row.get("resource_name") or row["eni_id"]


def _group_key(row: dict[str, Any], labels: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        row["owner_type"],
        queries.resource_type_label(row, labels),
        row["owner"]["text"],
        row.get("environment") or "",
    )


def _eni_details(old: dict[str, Any], new: dict[str, Any], labels: dict[str, str]) -> list[str]:
    out = []
    for key, name in (("status", "status"), ("owner_ref", "owner"), ("description", "description")):
        if (old.get(key) or "") != (new.get(key) or ""):
            out.append(f"{name}: {old.get(key) or '–'} → {new.get(key) or '–'}")
    if old["owner_type"] != new["owner_type"]:
        out.append(
            f"type: {queries.resource_type_label(old, labels)} → "
            f"{queries.resource_type_label(new, labels)}"
        )
    if sorted(old["security_groups"]) != sorted(new["security_groups"]):
        gone = sorted(set(old["security_groups"]) - set(new["security_groups"]))
        came = sorted(set(new["security_groups"]) - set(old["security_groups"]))
        out.append(
            "security groups: " + ", ".join([*(f"+{g}" for g in came), *(f"−{g}" for g in gone)])
        )
    if old["owner"]["text"] != new["owner"]["text"]:
        out.append(f"ownership: {old['owner']['text']} → {new['owner']['text']}")
    if (old.get("environment") or "") != (new.get("environment") or ""):
        out.append(
            f"environment: {old.get('environment') or environment.NOT_SET_LABEL} → "
            f"{new.get('environment') or environment.NOT_SET_LABEL}"
        )
    came_ips = sorted(set(new["ips"]) - set(old["ips"]), key=_ip_key)
    gone_ips = sorted(set(old["ips"]) - set(new["ips"]), key=_ip_key)
    if came_ips or gone_ips:
        out.append(
            "IPs: " + ", ".join([*(f"+{ip}" for ip in came_ips), *(f"−{ip}" for ip in gone_ips)])
        )
    return out


def _ip_key(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def diff_rows(
    old_rows: list[dict[str, Any]],
    new_rows: list[dict[str, Any]],
    labels: dict[str, str],
    subnets: Sequence[tuple[str, str, str]] = (),
    top: int = TOP_CONSUMERS,
    old_id: int = 0,
    new_id: int = 0,
) -> SnapshotDiff:
    """Diff of two :func:`iplens.queries.ip_list` results. ``subnets``: (id, name, cidr)
    of every subnet to report a net delta for (subnets only seen in rows are added)."""
    old_enis, new_enis = _eni_rows(old_rows), _eni_rows(new_rows)
    groups: dict[tuple[str, str, str, str], Group] = {}

    def group(row: dict[str, Any]) -> Group:
        key = _group_key(row, labels)
        if key not in groups:
            groups[key] = Group(*key)
        return groups[key]

    for eni_id in sorted(new_enis.keys() - old_enis.keys()):
        e = new_enis[eni_id]
        group(e).enis.append(EniChange(ADDED, eni_id, e["subnet_id"], _resource(e), [], e["ips"]))
    for eni_id in sorted(old_enis.keys() - new_enis.keys()):
        e = old_enis[eni_id]
        group(e).enis.append(EniChange(REMOVED, eni_id, e["subnet_id"], _resource(e), e["ips"], []))
    for eni_id in sorted(old_enis.keys() & new_enis.keys()):
        o, n = old_enis[eni_id], new_enis[eni_id]
        details = _eni_details(o, n, labels)
        if details:
            group(n).enis.append(
                EniChange(
                    CHANGED, eni_id, n["subnet_id"], _resource(n), o["ips"], n["ips"], details
                )
            )

    # IPs by address (an address is held by one ENI at a time).
    old_ips = {r["ip"]: r for r in old_rows}
    new_ips = {r["ip"]: r for r in new_rows}
    for ip in sorted(new_ips.keys() - old_ips.keys(), key=_ip_key):
        r = new_ips[ip]
        group(r).ips.append(IpChange(ADDED, ip, r["subnet_id"], _resource(r), new_eni=r["eni_id"]))
    for ip in sorted(old_ips.keys() - new_ips.keys(), key=_ip_key):
        r = old_ips[ip]
        group(r).ips.append(
            IpChange(REMOVED, ip, r["subnet_id"], _resource(r), old_eni=r["eni_id"])
        )
    for ip in sorted(old_ips.keys() & new_ips.keys(), key=_ip_key):
        o, n = old_ips[ip], new_ips[ip]
        if o["eni_id"] != n["eni_id"]:
            detail = f"moved {o['eni_id']} → {n['eni_id']}"
        elif o["owner_type"] != n["owner_type"]:
            detail = (
                f"type {queries.resource_type_label(o, labels)} → "
                f"{queries.resource_type_label(n, labels)}"
            )
        else:
            continue
        group(n).ips.append(
            IpChange(CHANGED, ip, n["subnet_id"], _resource(n), o["eni_id"], n["eni_id"], detail)
        )

    # Net IP delta per subnet.
    old_count = Counter(r["subnet_id"] for r in old_rows)
    new_count = Counter(r["subnet_id"] for r in new_rows)
    meta = {sid: (name, cidr) for sid, name, cidr in subnets}
    for r in (*old_rows, *new_rows):
        meta.setdefault(r["subnet_id"], (r.get("subnet_name") or "", r.get("subnet_cidr") or ""))
    subnet_deltas = sorted(
        (
            SubnetDelta(sid, name, cidr, old_count.get(sid, 0), new_count.get(sid, 0))
            for sid, (name, cidr) in meta.items()
        ),
        key=lambda d: (-abs(d.delta), -d.delta, d.subnet_id),
    )

    # Top consumers: IPs per owning resource, largest growth first.
    def per_resource(rows: list[dict[str, Any]]) -> dict[tuple[str, str], int]:
        out: dict[tuple[str, str], int] = defaultdict(int)
        for r in rows:
            out[(r["owner_type"], _resource(r))] += 1
        return out

    before, after = per_resource(old_rows), per_resource(new_rows)
    type_labels = {
        (r["owner_type"], _resource(r)): queries.resource_type_label(r, labels)
        for r in (*old_rows, *new_rows)
    }
    consumers = sorted(
        (
            Consumer(t, type_labels[(t, res)], res, before.get((t, res), 0), n)
            for (t, res), n in after.items()
            if n > before.get((t, res), 0)
        ),
        key=lambda c: (-c.delta, -c.new, c.resource),
    )[:top]

    ordered = sorted(groups.values(), key=lambda g: (g.type_label.lower(), g.owner, g.env))
    totals = {
        f"{what}_{kind}": sum(g.count(what, kind) for g in ordered)
        for what in ("enis", "ips")
        for kind in (ADDED, REMOVED, CHANGED)
    }
    totals["ip_delta"] = len(new_rows) - len(old_rows)
    return SnapshotDiff(old_id, new_id, ordered, subnet_deltas, consumers, totals)


def diff_snapshots(
    conn: sqlite3.Connection,
    old_id: int,
    new_id: int,
    labels: dict[str, str],
    scope: ResolvedScope = UNSCOPED,
    env_keys: Sequence[str] = environment.DEFAULT_TAG_KEYS,
    own: ownership.OwnershipConfig | None = None,
    top: int = TOP_CONSUMERS,
) -> SnapshotDiff:
    """Diff of snapshot ``old_id`` -> ``new_id`` (both of one account) within ``scope``."""
    old_rows = queries.ip_list(conn, old_id, None, scope, env_keys, own)
    new_rows = queries.ip_list(conn, new_id, None, scope, env_keys, own)
    subnets = [
        (r["subnet_id"], r["name"] or "", r["cidr"])
        for r in conn.execute(
            "SELECT subnet_id, name, cidr FROM subnets WHERE snapshot_id IN (?, ?) "
            "ORDER BY snapshot_id",
            (old_id, new_id),
        )
        if scope.subnet_ok(r["subnet_id"])
    ]
    return diff_rows(old_rows, new_rows, labels, subnets, top, old_id, new_id)


def default_pair(conn: sqlite3.Connection, account_ref: int) -> tuple[int | None, int | None]:
    """(previous, latest) successful snapshot ids of the account."""
    ids = [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM snapshots WHERE account_ref=? AND status='ok' ORDER BY id DESC LIMIT 2",
            (account_ref,),
        )
    ]
    return (ids[1] if len(ids) > 1 else None), (ids[0] if ids else None)
