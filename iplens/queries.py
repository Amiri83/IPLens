"""Read model over snapshots: VPC tree, subnet grid, IP search."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from .visual import EDGE_TYPES, LABEL_MAX, ellipsize, visual_edges

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


# -- flat IP list ----------------------------------------------------------------


@dataclass(frozen=True)
class IpFilter:
    """Filters for :func:`ip_list`; empty strings mean "no filter"."""

    vpc: str = ""
    subnet: str = ""
    owner: str = ""  # an attribution OWNER_TYPES value
    state: str = ""  # "used" | "idle"
    q: str = ""


_IP_FROM = """
FROM ips i
JOIN enis e ON e.snapshot_id = i.snapshot_id AND e.eni_id = i.eni_id
LEFT JOIN subnets s ON s.snapshot_id = i.snapshot_id AND s.subnet_id = i.subnet_id
LEFT JOIN vpcs v ON v.snapshot_id = i.snapshot_id AND v.vpc_id = i.vpc_id
LEFT JOIN load_balancers lb
       ON lb.snapshot_id = i.snapshot_id AND i.owner_type = 'elb' AND lb.name = e.owner_ref
LEFT JOIN endpoints ep
       ON ep.snapshot_id = i.snapshot_id AND i.owner_type = 'vpc_endpoint'
      AND ep.endpoint_id = e.owner_ref
"""
_IP_COLUMNS = (
    "i.ip, i.ip_int, i.eni_id, i.subnet_id, i.vpc_id, i.is_primary, i.public_ip, i.owner_type, "
    "e.owner_ref, e.status, e.description, e.az, e.instance_id, e.interface_type, "
    "e.name AS eni_name, s.name AS subnet_name, s.cidr AS subnet_cidr, v.name AS vpc_name, "
    "lb.lb_type, ep.service_name"
)
_IP_SEARCH_COLUMNS = (
    "i.ip",
    "i.eni_id",
    "i.subnet_id",
    "s.name",
    "i.vpc_id",
    "v.name",
    "i.public_ip",
    "e.owner_ref",
    "e.description",
    "e.instance_id",
    "e.name",
    "ep.service_name",
)

_LB_KIND_BY_INTERFACE = {
    "network_load_balancer": "network",
    "gateway_load_balancer": "gateway",
}
_LB_LABELS = {"application": "ALB", "network": "NLB", "gateway": "GWLB"}


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def lb_kind(row: dict[str, Any]) -> str:
    """``application`` / ``network`` / ``gateway`` for a load-balancer ENI row, else ''."""
    if row.get("owner_type") != "elb":
        return ""
    return row.get("lb_type") or _LB_KIND_BY_INTERFACE.get(
        (row.get("interface_type") or "").lower(), ""
    )


def resource_type_label(row: dict[str, Any], labels: dict[str, str]) -> str:
    """Human label for the owning resource type, refining load balancers to ALB/NLB/GWLB."""
    kind = lb_kind(row)
    if kind:
        return _LB_LABELS.get(kind, labels.get("elb", "elb"))
    return labels.get(row["owner_type"], row["owner_type"])


def endpoint_service_short(service_name: str) -> str:
    """``com.amazonaws.<region>.s3`` -> ``s3``; other names are returned unchanged."""
    parts = service_name.split(".")
    if len(parts) >= 4 and parts[0] == "com" and parts[1] == "amazonaws":
        return ".".join(parts[3:])
    return service_name


def resource_name(row: dict[str, Any]) -> str:
    """Best display name for the owning resource: Name tag, endpoint service, then ref."""
    if row.get("eni_name"):
        return row["eni_name"]
    if row.get("service_name"):
        return endpoint_service_short(row["service_name"])
    return row.get("owner_ref") or ""


def ip_list(
    conn: sqlite3.Connection, snap_id: int, flt: IpFilter | None = None
) -> list[dict[str, Any]]:
    """Every private IP of a snapshot matching ``flt``, ordered numerically by address.

    Each row carries the IP/ENI columns plus subnet/VPC names, ``lb_type`` and
    endpoint ``service_name`` (when applicable) and a derived ``resource_name``.
    """
    flt = flt or IpFilter()
    where = ["i.snapshot_id = ?"]
    args: list[Any] = [snap_id]
    if flt.vpc:
        where.append("i.vpc_id = ?")
        args.append(flt.vpc)
    if flt.subnet:
        where.append("i.subnet_id = ?")
        args.append(flt.subnet)
    if flt.owner:
        where.append("i.owner_type = ?")
        args.append(flt.owner)
    if flt.state == "idle":
        where.append("e.status = 'available'")
    elif flt.state == "used":
        where.append("e.status != 'available'")
    q = flt.q.strip()
    if q:
        like = f"%{_like_escape(q)}%"
        where.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in _IP_SEARCH_COLUMNS) + ")")
        args.extend([like] * len(_IP_SEARCH_COLUMNS))
    # The SQL is assembled from the fixed fragments above; all values are bound.
    sql = (
        f"SELECT {_IP_COLUMNS} {_IP_FROM} WHERE {' AND '.join(where)} "  # noqa: S608
        "ORDER BY i.ip_int, i.eni_id"
    )
    rows = [dict(r) for r in conn.execute(sql, args)]
    for r in rows:
        r["resource_name"] = resource_name(r)
    return rows


# -- visual diagram ---------------------------------------------------------------

# More than this many nodes of one type in a subnet are collapsed into a group node.
VISUAL_GROUP_THRESHOLD = 10

# Display order of resource types inside a subnet box.
VISUAL_TYPE_ORDER = (
    "vpc_endpoint",
    "elb",
    "nat",
    "lambda",
    "ecs",
    "ec2",
    "rds",
    "elasticache",
    "opensearch",
    "other",
)

# Files under static/icons/aws/ (official AWS Architecture Icons).
VPC_ICON = "Virtual-private-cloud-VPC_32.svg"
TYPE_ICONS = {
    "vpc_endpoint": "Res_Amazon-VPC_Endpoints_48.svg",
    "elb": "Arch_Elastic-Load-Balancing_48.svg",
    "nat": "Res_Amazon-VPC_NAT-Gateway_48.svg",
    "lambda": "Arch_AWS-Lambda_48.svg",
    "ecs": "Arch_Amazon-Elastic-Container-Service_48.svg",
    "ec2": "Arch_Amazon-EC2_48.svg",
    "rds": "Arch_Amazon-RDS_48.svg",
    "elasticache": "Arch_Amazon-ElastiCache_48.svg",
    "opensearch": "Arch_Amazon-OpenSearch-Service_48.svg",
    "other": "Res_Amazon-VPC_Elastic-Network-Interface_48.svg",
}
LB_ICONS = {
    "application": "Res_Elastic-Load-Balancing_Application-Load-Balancer_48.svg",
    "network": "Res_Elastic-Load-Balancing_Network-Load-Balancer_48.svg",
    "gateway": "Res_Elastic-Load-Balancing_Gateway-Load-Balancer_48.svg",
}


def _icon_for(row: dict[str, Any]) -> str:
    return LB_ICONS.get(lb_kind(row)) or TYPE_ICONS.get(row["owner_type"], TYPE_ICONS["other"])


def _type_rank(owner_type: str) -> int:
    try:
        return VISUAL_TYPE_ORDER.index(owner_type)
    except ValueError:
        return len(VISUAL_TYPE_ORDER)


def _resource_nodes(rows: list[dict[str, Any]], labels: dict[str, str]) -> list[dict[str, Any]]:
    """One node per ENI (rows are already ordered by IP)."""
    nodes: dict[str, dict[str, Any]] = {}
    for r in rows:
        node = nodes.get(r["eni_id"])
        if node is None:
            name = r["resource_name"] or r["eni_id"]
            node = nodes[r["eni_id"]] = {
                "kind": "resource",
                "id": r["eni_id"],
                "eni_id": r["eni_id"],
                "subnet_id": r["subnet_id"],
                "type": r["owner_type"],
                "type_label": resource_type_label(r, labels),
                "name": name,
                "label_name": ellipsize(name, LABEL_MAX["name"]),
                "ref": r["owner_ref"] or "",
                "status": r["status"] or "",
                "icon": _icon_for(r),
                "ips": [],
                "_first_ip": r["ip_int"],
            }
        node["ips"].append(r["ip"])
    out = sorted(
        nodes.values(), key=lambda n: (_type_rank(n["type"]), n["name"].lower(), n["_first_ip"])
    )
    for n in out:
        del n["_first_ip"]
    return out


def _group_items(
    subnet_id: str, nodes: list[dict[str, Any]], labels: dict[str, str]
) -> list[dict[str, Any]]:
    """Collapse runs of more than VISUAL_GROUP_THRESHOLD same-type nodes into a group node."""
    by_type: dict[str, list[dict[str, Any]]] = {}
    for n in nodes:
        by_type.setdefault(n["type"], []).append(n)
    items: list[dict[str, Any]] = []
    for owner_type, members in by_type.items():  # insertion order == display order
        if len(members) <= VISUAL_GROUP_THRESHOLD:
            items.extend(members)
            continue
        items.append(
            {
                "kind": "group",
                "id": f"group:{subnet_id}:{owner_type}",
                "type": owner_type,
                "type_label": labels.get(owner_type, owner_type),
                "name": f"{len(members)} × {labels.get(owner_type, owner_type)}",
                "count": len(members),
                "ip_count": sum(len(m["ips"]) for m in members),
                "icon": TYPE_ICONS.get(owner_type, TYPE_ICONS["other"]),
                "members": members,
            }
        )
    return items


def visual_data(
    conn: sqlite3.Connection,
    snap_id: int,
    vpc_id: str = "",
    labels: dict[str, str] | None = None,
    edge_types: tuple[str, ...] = EDGE_TYPES,
) -> dict[str, Any] | None:
    """Nested VPC -> subnets -> resource nodes, plus resource edges, for the Visual page.

    ``vpc_id`` defaults to the first VPC. Returns None if ``vpc_id`` is unknown.
    Only edges of ``edge_types`` are returned (see :mod:`iplens.visual`).
    """
    labels = labels or {}
    tree = vpc_tree(conn, snap_id)
    vpcs = [{"vpc_id": v.vpc_id, "name": v.name} for v in tree]
    if not tree:
        return {"snapshot_id": snap_id, "vpcs": [], "vpc": None, "icons": {"vpc": VPC_ICON}}
    vpc = next((v for v in tree if v.vpc_id == vpc_id), None) if vpc_id else tree[0]
    if vpc is None:
        return None

    by_subnet: dict[str, list[dict[str, Any]]] = {}
    by_ip: dict[str, str] = {}
    for r in ip_list(conn, snap_id, IpFilter(vpc=vpc.vpc_id)):
        by_subnet.setdefault(r["subnet_id"], []).append(r)
        by_ip[r["ip"]] = r["eni_id"]

    subnets = []
    resources: dict[str, dict[str, Any]] = {}
    for s in vpc.subnets:
        nodes = _resource_nodes(by_subnet.get(s.subnet_id, []), labels)
        resources.update((n["eni_id"], n) for n in nodes)
        subnets.append(
            {
                "subnet_id": s.subnet_id,
                "name": s.name,
                "label_name": ellipsize(s.name or s.subnet_id, LABEL_MAX["subnet"]),
                "label_meta": ellipsize(f"{s.subnet_id} · {s.cidr} · {s.az}", LABEL_MAX["cidr"]),
                "cidr": s.cidr,
                "az": s.az,
                "size": s.size,
                "reserved": s.reserved,
                "used": s.used,
                "idle": s.idle,
                "free": s.free,
                "resource_count": len(nodes),
                "items": _group_items(s.subnet_id, nodes, labels),
            }
        )
    return {
        "snapshot_id": snap_id,
        "vpcs": vpcs,
        "vpc": {
            "vpc_id": vpc.vpc_id,
            "name": vpc.name,
            "label_name": ellipsize(vpc.name or vpc.vpc_id, LABEL_MAX["subnet"]),
            "label_cidrs": ellipsize(", ".join(vpc.cidrs), LABEL_MAX["cidr"]),
            "cidrs": vpc.cidrs,
            "subnets": subnets,
        },
        "icons": {"vpc": VPC_ICON},
        **visual_edges(conn, snap_id, vpc.vpc_id, resources, by_ip, edge_types),
    }
