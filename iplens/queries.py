"""Read model over snapshots: VPC tree, subnet grid, IP search."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

# AWS reserves the first four addresses and the last address of every subnet.
AWS_RESERVED_HEAD = 4
AWS_RESERVED_TAIL = 1
GRID_PAGE_SIZE = 1024


def latest_snapshot(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM snapshots WHERE status='ok' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def recent_snapshots(conn: sqlite3.Connection, limit: int = 10) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def prune_snapshots(conn: sqlite3.Connection, keep: int = 10) -> int:
    cur = conn.execute(
        "DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT ?)",
        (keep,),
    )
    return cur.rowcount


@dataclass
class SubnetStats:
    subnet_id: str
    vpc_id: str
    name: str
    cidr: str
    az: str
    size: int
    reserved: int
    used: int
    idle: int
    aws_available: int | None

    @property
    def consumed(self) -> int:
        return self.used + self.idle

    @property
    def free(self) -> int:
        return max(self.size - self.reserved - self.consumed, 0)

    @property
    def usable(self) -> int:
        return max(self.size - self.reserved, 0)

    @property
    def free_pct(self) -> float:
        return 100.0 * self.free / self.usable if self.usable else 0.0

    def pct(self, n: int) -> float:
        return 100.0 * n / self.size if self.size else 0.0


@dataclass
class VpcNode:
    vpc_id: str
    name: str
    cidrs: list[str]
    is_default: bool
    subnets: list[SubnetStats] = field(default_factory=list)

    @property
    def size(self) -> int:
        return sum(ipaddress.IPv4Network(c).num_addresses for c in self.cidrs)

    @property
    def subnet_capacity(self) -> int:
        return sum(s.size for s in self.subnets)

    @property
    def consumed(self) -> int:
        return sum(s.consumed + s.reserved for s in self.subnets)

    @property
    def used_pct(self) -> float:
        return 100.0 * self.consumed / self.size if self.size else 0.0

    @property
    def allocated_pct(self) -> float:
        return 100.0 * self.subnet_capacity / self.size if self.size else 0.0


def _subnet_stats(row: sqlite3.Row, used: int, idle: int) -> SubnetStats:
    net = ipaddress.IPv4Network(row["cidr"])
    return SubnetStats(
        subnet_id=row["subnet_id"],
        vpc_id=row["vpc_id"],
        name=row["name"] or "",
        cidr=row["cidr"],
        az=row["az"] or "",
        size=net.num_addresses,
        reserved=min(AWS_RESERVED_HEAD + AWS_RESERVED_TAIL, net.num_addresses),
        used=used,
        idle=idle,
        aws_available=row["available_ip_count"],
    )


def _usage_counts(conn: sqlite3.Connection, snap_id: int) -> dict[str, tuple[int, int]]:
    rows = conn.execute(
        """
        SELECT i.subnet_id,
               COUNT(DISTINCT CASE WHEN e.status = 'available' THEN NULL ELSE i.ip END) AS used,
               COUNT(DISTINCT CASE WHEN e.status = 'available' THEN i.ip END) AS idle
        FROM ips i JOIN enis e ON e.snapshot_id = i.snapshot_id AND e.eni_id = i.eni_id
        WHERE i.snapshot_id = ?
        GROUP BY i.subnet_id
        """,
        (snap_id,),
    ).fetchall()
    return {r["subnet_id"]: (r["used"], r["idle"]) for r in rows}


def subnet_stats(conn: sqlite3.Connection, snap_id: int) -> list[SubnetStats]:
    counts = _usage_counts(conn, snap_id)
    rows = conn.execute(
        "SELECT * FROM subnets WHERE snapshot_id=? ORDER BY vpc_id, az, cidr", (snap_id,)
    ).fetchall()
    return [_subnet_stats(r, *counts.get(r["subnet_id"], (0, 0))) for r in rows]


def vpc_tree(conn: sqlite3.Connection, snap_id: int) -> list[VpcNode]:
    nodes = {
        r["vpc_id"]: VpcNode(
            vpc_id=r["vpc_id"],
            name=r["name"] or "",
            cidrs=json.loads(r["cidrs"]),
            is_default=bool(r["is_default"]),
        )
        for r in conn.execute("SELECT * FROM vpcs WHERE snapshot_id=? ORDER BY vpc_id", (snap_id,))
    }
    for s in subnet_stats(conn, snap_id):
        if s.vpc_id in nodes:
            nodes[s.vpc_id].subnets.append(s)
    for n in nodes.values():
        n.subnets.sort(key=lambda s: int(ipaddress.IPv4Network(s.cidr).network_address))
    return list(nodes.values())


def owner_breakdown(conn: sqlite3.Connection, snap_id: int) -> dict[str, int]:
    rows = conn.execute(
        "SELECT owner_type, COUNT(DISTINCT ip) AS n FROM ips WHERE snapshot_id=? "
        "GROUP BY owner_type ORDER BY n DESC",
        (snap_id,),
    ).fetchall()
    return {r["owner_type"]: r["n"] for r in rows}


def get_subnet(conn: sqlite3.Connection, snap_id: int, subnet_id: str) -> SubnetStats | None:
    row = conn.execute(
        "SELECT * FROM subnets WHERE snapshot_id=? AND subnet_id=?", (snap_id, subnet_id)
    ).fetchone()
    if row is None:
        return None
    used, idle = _usage_counts(conn, snap_id).get(subnet_id, (0, 0))
    return _subnet_stats(row, used, idle)


def subnet_grid(
    conn: sqlite3.Connection, snap_id: int, subnet: SubnetStats, page: int = 0
) -> dict[str, Any]:
    """Return one page of grid cells: each address with its state."""
    net = ipaddress.IPv4Network(subnet.cidr)
    first, last = int(net.network_address), int(net.broadcast_address)
    pages = max((net.num_addresses + GRID_PAGE_SIZE - 1) // GRID_PAGE_SIZE, 1)
    page = min(max(page, 0), pages - 1)
    start = first + page * GRID_PAGE_SIZE
    end = min(start + GRID_PAGE_SIZE - 1, last)

    occupied: dict[int, dict[str, Any]] = {}
    for r in conn.execute(
        """
        SELECT i.ip, i.ip_int, i.eni_id, i.owner_type, e.status, e.owner_ref
        FROM ips i JOIN enis e ON e.snapshot_id = i.snapshot_id AND e.eni_id = i.eni_id
        WHERE i.snapshot_id=? AND i.subnet_id=? AND i.ip_int BETWEEN ? AND ?
        """,
        (snap_id, subnet.subnet_id, start, end),
    ):
        occupied[r["ip_int"]] = dict(r)

    cells = []
    for n in range(start, end + 1):
        ip = str(ipaddress.IPv4Address(n))
        if n - first < AWS_RESERVED_HEAD or n == last:
            cells.append({"ip": ip, "state": "reserved", "title": f"{ip} reserved by AWS"})
        elif n in occupied:
            o = occupied[n]
            state = "idle" if o["status"] == "available" else "used"
            ref = f" {o['owner_ref']}" if o["owner_ref"] else ""
            cells.append(
                {
                    "ip": ip,
                    "state": state,
                    "owner": o["owner_type"],
                    "eni": o["eni_id"],
                    "title": f"{ip} {o['owner_type']}{ref} ({o['eni_id']}, {o['status']})",
                }
            )
        else:
            cells.append({"ip": ip, "state": "free", "title": f"{ip} free"})
    return {
        "cells": cells,
        "page": page,
        "pages": pages,
        "start": str(ipaddress.IPv4Address(start)),
        "end": str(ipaddress.IPv4Address(end)),
    }


def subnet_enis(conn: sqlite3.Connection, snap_id: int, subnet_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT e.*, COUNT(i.ip) AS ip_count
        FROM enis e LEFT JOIN ips i ON i.snapshot_id = e.snapshot_id AND i.eni_id = e.eni_id
        WHERE e.snapshot_id=? AND e.subnet_id=?
        GROUP BY e.eni_id ORDER BY e.owner_type, e.eni_id
        """,
        (snap_id, subnet_id),
    ).fetchall()
    return [_eni_dict(r) for r in rows]


def _eni_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["security_groups"] = json.loads(d.get("security_groups") or "[]")
    return d


def eni_detail(conn: sqlite3.Connection, snap_id: int, eni_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM enis WHERE snapshot_id=? AND eni_id=?", (snap_id, eni_id)
    ).fetchone()
    if row is None:
        return None
    d = _eni_dict(row)
    d["ips"] = [
        dict(r)
        for r in conn.execute(
            "SELECT ip, is_primary, public_ip FROM ips WHERE snapshot_id=? AND eni_id=? "
            "ORDER BY ip_int",
            (snap_id, eni_id),
        )
    ]
    return d


def search_ips(
    conn: sqlite3.Connection,
    snap_id: int,
    q: str = "",
    owner: str = "",
    state: str = "",
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    where = ["i.snapshot_id = ?"]
    args: list[Any] = [snap_id]
    if q:
        like = f"%{q.strip()}%"
        where.append(
            "(i.ip LIKE ? OR i.eni_id LIKE ? OR e.owner_ref LIKE ? OR e.description LIKE ? "
            "OR i.subnet_id LIKE ? OR i.vpc_id LIKE ? OR e.instance_id LIKE ? OR e.name LIKE ? "
            "OR i.public_ip LIKE ?)"
        )
        args.extend([like] * 9)
    if owner:
        where.append("i.owner_type = ?")
        args.append(owner)
    if state == "idle":
        where.append("e.status = 'available'")
    elif state == "used":
        where.append("e.status != 'available'")
    # The WHERE clause is assembled from the fixed fragments above; all values are bound.
    base = f"{_IP_JOIN} WHERE {' AND '.join(where)}"
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]  # noqa: S608
    sql = f"SELECT {_IP_COLUMNS} {base} ORDER BY i.ip_int LIMIT ? OFFSET ?"  # noqa: S608
    rows = conn.execute(sql, [*args, limit, offset]).fetchall()
    return [dict(r) for r in rows], total


_IP_JOIN = "FROM ips i JOIN enis e ON e.snapshot_id = i.snapshot_id AND e.eni_id = i.eni_id"
_IP_COLUMNS = (
    "i.ip, i.eni_id, i.subnet_id, i.vpc_id, i.is_primary, i.public_ip, i.owner_type, "
    "e.owner_ref, e.status, e.description, e.az, e.instance_id"
)
