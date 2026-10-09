"""Read model over snapshots: VPC tree, subnet grid, IP search."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from . import environment, ownership, terraform
from .scope import UNSCOPED, ResolvedScope
from .visual import EDGE_TYPES, visual_edges

# AWS reserves the first four addresses and the last address of every subnet.
AWS_RESERVED_HEAD = 4
AWS_RESERVED_TAIL = 1
GRID_PAGE_SIZE = 1024


def latest_snapshot(conn: sqlite3.Connection, account_ref: int | None = None) -> sqlite3.Row | None:
    """Newest successful snapshot of ``account_ref`` (any account when None)."""
    if account_ref is None:
        sql, args = "SELECT * FROM snapshots WHERE status='ok' ORDER BY id DESC LIMIT 1", ()
    else:
        sql = "SELECT * FROM snapshots WHERE status='ok' AND account_ref=? ORDER BY id DESC LIMIT 1"
        args = (account_ref,)
    return conn.execute(sql, args).fetchone()


def recent_snapshots(
    conn: sqlite3.Connection, limit: int = 10, account_ref: int | None = None
) -> list[sqlite3.Row]:
    if account_ref is None:
        return conn.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return conn.execute(
        "SELECT * FROM snapshots WHERE account_ref=? ORDER BY id DESC LIMIT ?", (account_ref, limit)
    ).fetchall()


def protected_snapshot_ids(conn: sqlite3.Connection) -> set[int]:
    """The latest successful snapshot of every account: never deleted by history actions."""
    rows = conn.execute(
        "SELECT MAX(id) AS id FROM snapshots WHERE status='ok' GROUP BY account_ref"
    ).fetchall()
    return {r["id"] for r in rows}


def prune_snapshots(conn: sqlite3.Connection, keep: int = 10) -> int:
    """Keep the newest ``keep`` snapshots per account (and each account's latest good one)."""
    keep_ids = protected_snapshot_ids(conn) | {
        r["id"]
        for r in conn.execute(
            "SELECT id FROM (SELECT id, ROW_NUMBER() OVER "
            "(PARTITION BY account_ref ORDER BY id DESC) AS n FROM snapshots) WHERE n <= ?",
            (keep,),
        )
    }
    return _delete_snapshots(conn, _all_snapshot_ids(conn) - keep_ids)


def _all_snapshot_ids(conn: sqlite3.Connection, account_ref: int | None = None) -> set[int]:
    if account_ref is None:
        rows = conn.execute("SELECT id FROM snapshots WHERE status != 'running'")
    else:
        rows = conn.execute(
            "SELECT id FROM snapshots WHERE status != 'running' AND account_ref=?", (account_ref,)
        )
    return {r["id"] for r in rows}


def _delete_snapshots(conn: sqlite3.Connection, ids: set[int]) -> int:
    # Child tables are removed by ON DELETE CASCADE.
    conn.executemany("DELETE FROM snapshots WHERE id=?", [(i,) for i in sorted(ids)])
    return len(ids)


def delete_snapshots(
    conn: sqlite3.Connection, ids: set[int], account_ref: int
) -> tuple[int, set[int]]:
    """Delete the selected snapshots of one account; returns (deleted, kept ids).

    The account's latest successful snapshot and collections still running are kept.
    """
    candidates = _all_snapshot_ids(conn, account_ref) & ids
    kept = candidates & protected_snapshot_ids(conn)
    return _delete_snapshots(conn, candidates - kept), kept


def clear_history(conn: sqlite3.Connection, account_ref: int | None = None) -> int:
    """Delete every snapshot except each account's latest successful one.

    ``account_ref=None`` clears the history of all accounts.
    """
    ids = _all_snapshot_ids(conn, account_ref) - protected_snapshot_ids(conn)
    return _delete_snapshots(conn, ids)


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


def vpc_tree(
    conn: sqlite3.Connection, snap_id: int, scope: ResolvedScope = UNSCOPED
) -> list[VpcNode]:
    """VPCs with their subnets, limited to ``scope``."""
    nodes = {
        r["vpc_id"]: VpcNode(
            vpc_id=r["vpc_id"],
            name=r["name"] or "",
            cidrs=json.loads(r["cidrs"]),
            is_default=bool(r["is_default"]),
        )
        for r in conn.execute("SELECT * FROM vpcs WHERE snapshot_id=? ORDER BY vpc_id", (snap_id,))
        if scope.vpc_ok(r["vpc_id"])
    }
    for s in subnet_stats(conn, snap_id):
        if s.vpc_id in nodes and scope.subnet_ok(s.subnet_id):
            nodes[s.vpc_id].subnets.append(s)
    for n in nodes.values():
        n.subnets.sort(key=lambda s: int(ipaddress.IPv4Network(s.cidr).network_address))
    return list(nodes.values())


def owner_breakdown(
    conn: sqlite3.Connection, snap_id: int, scope: ResolvedScope = UNSCOPED
) -> dict[str, int]:
    where, args = scope.sql("i")
    cond = "".join(f" AND {w}" for w in where)
    rows = conn.execute(
        "SELECT i.owner_type, COUNT(DISTINCT i.ip) AS n FROM ips i "  # noqa: S608 - fixed SQL
        f"WHERE i.snapshot_id=?{cond} GROUP BY i.owner_type ORDER BY n DESC",
        (snap_id, *args),
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


def owner_names(row: dict[str, Any]) -> list[str]:
    """Every owning resource of an ENI row (several functions can share a Lambda ENI)."""
    names = json.loads(row.get("owner_names") or "[]")
    if not names and row.get("owner_ref"):
        names = [row["owner_ref"]]
    return names


def _eni_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["security_groups"] = json.loads(d.get("security_groups") or "[]")
    d["owner_names"] = owner_names(d)
    return d


def eni_detail(
    conn: sqlite3.Connection,
    snap_id: int,
    eni_id: str,
    own: ownership.OwnershipConfig | None = None,
) -> dict[str, Any] | None:
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
    tf_index = terraform.load_index(conn)
    names = sg_names(conn, snap_id)
    d["tags"] = resource_tags(tag_index(conn, snap_id), d)
    d["tf"] = terraform.ownership(tf_index, terraform.resource_keys(d))
    _add_ownership(d, ownership.load_index(conn, snap_id, own, tf_index))
    d["subnet_tf"] = terraform.ownership(tf_index, [("subnet", d["subnet_id"] or "")])
    d["sg_details"] = [
        {
            "id": sg,
            "name": names.get(sg, ""),
            "tf": terraform.ownership(tf_index, [("sg", sg)]),
        }
        for sg in d["security_groups"]
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
    tag_key: str = ""  # rows whose resource carries this tag key...
    tag_value: str = ""  # ...with this value (any value when empty)
    tf: str = ""  # TF_MANAGED | TF_UNMANAGED | a Terraform root name
    env: str = ""  # an environment, or environment.FILTER_NOT_SET
    own: str = ""  # an ownership source, or ownership.FILTER_UNMANAGED


TF_MANAGED, TF_UNMANAGED = "managed", "unmanaged"


def _add_ownership(row: dict[str, Any], idx: ownership.OwnershipIndex) -> None:
    """``owner`` (source / value, see :mod:`iplens.ownership`) and ``own_labels`` (the
    configured project / environment / team / owner tag values) of an ENI row."""
    keys = terraform.resource_keys(row)
    row["owner"] = idx.resolve(keys, row.get("tags")).as_dict()
    row["own_labels"] = idx.labels(keys, row.get("tags"))


# -- resource context: tags, security group names, Terraform ownership ---------------


def sg_names(conn: sqlite3.Connection, snap_id: int) -> dict[str, str]:
    """Security group id -> display name: Name tag, else group name, else the id."""
    return {
        r["group_id"]: r["name"] or r["group_name"] or r["group_id"]
        for r in conn.execute(
            "SELECT group_id, name, group_name FROM security_groups WHERE snapshot_id=?",
            (snap_id,),
        )
    }


TagIndex = dict[tuple[str, str], dict[str, str]]


def tag_index(conn: sqlite3.Connection, snap_id: int) -> TagIndex:
    """``(resource_type, resource_id) -> {key: value}`` for one snapshot."""
    out: TagIndex = {}
    for r in conn.execute(
        "SELECT resource_type, resource_id, key, value FROM resource_tags WHERE snapshot_id=? "
        "ORDER BY resource_type, resource_id, key",
        (snap_id,),
    ):
        out.setdefault((r["resource_type"], r["resource_id"]), {})[r["key"]] = r["value"]
    return out


def owner_tag_keys(row: dict[str, Any]) -> list[tuple[str, str]]:
    """``resource_tags`` keys of the resource owning an ENI row (shared Lambda: every owner)."""
    otype, ref = row.get("owner_type"), row.get("owner_ref") or ""
    if otype == "elb" and ref:
        return [("lb", ref)]
    if otype == "lambda":
        return [("lambda", n) for n in (row.get("owner_names") or ([ref] if ref else []))]
    if otype == "ecs" and ref.count("/") == 2:
        return [("ecs_service", ref.rsplit("/", 1)[0])]
    if otype == "vpc_endpoint" and ref:
        return [("endpoint", ref)]
    return []


def resource_tags(index: TagIndex, row: dict[str, Any]) -> dict[str, str]:
    """Tags of an ENI row: its owning resource's tags, overridden by the ENI's own TagSet."""
    tags: dict[str, str] = {}
    for key in reversed(owner_tag_keys(row)):  # the first owner wins on conflicts
        tags.update(index.get(key, {}))
    tags.update(index.get(("eni", row["eni_id"]), {}))
    return dict(sorted(tags.items()))


def tag_keys(conn: sqlite3.Connection, snap_id: int) -> list[str]:
    """Every tag key of an ENI-owning resource in a snapshot (security group, VPC and
    subnet tags excluded)."""
    return [
        r["key"]
        for r in conn.execute(
            "SELECT DISTINCT key FROM resource_tags WHERE snapshot_id=? "
            "AND resource_type NOT IN ('sg', 'vpc', 'subnet') ORDER BY key",
            (snap_id,),
        )
    ]


def tf_label(m: dict[str, str]) -> str:
    return f"managed by {m['root']}: {m['address']}"


def _row_matches(row: dict[str, Any], flt: IpFilter) -> bool:
    if not environment.matches(row["environment"], flt.env):
        return False
    if not ownership.matches(row["owner"], flt.own):
        return False
    if flt.tag_key:
        if flt.tag_key not in row["tags"]:
            return False
        if flt.tag_value and row["tags"][flt.tag_key] != flt.tag_value:
            return False
    if flt.tf == TF_MANAGED:
        return bool(row["tf"])
    if flt.tf == TF_UNMANAGED:
        return not row["tf"]
    if flt.tf:
        return any(m["root"] == flt.tf for m in row["tf"])
    return True


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
    "e.owner_ref, e.owner_names, e.status, e.description, e.az, e.instance_id, "
    "e.interface_type, e.security_groups, "
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
    "e.owner_names",
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
    """Best display name for the owning resource: Name tag, endpoint service, then the
    owner(s) - every function of a shared Lambda ENI, comma-separated."""
    if row.get("eni_name"):
        return row["eni_name"]
    if row.get("service_name"):
        return endpoint_service_short(row["service_name"])
    names = row["owner_names"] if isinstance(row.get("owner_names"), list) else owner_names(row)
    return ", ".join(names) if len(names) > 1 else row.get("owner_ref") or ""


def short_owner_label(names: list[str]) -> str:
    """``"fn-a +2 more"`` for a shared ENI, else the single name."""
    if len(names) > 1:
        return f"{names[0]} +{len(names) - 1} more"
    return names[0] if names else ""


def ip_list(
    conn: sqlite3.Connection,
    snap_id: int,
    flt: IpFilter | None = None,
    scope: ResolvedScope = UNSCOPED,
    env_keys: Sequence[str] = environment.DEFAULT_TAG_KEYS,
    own: ownership.OwnershipConfig | None = None,
) -> list[dict[str, Any]]:
    """Every private IP of a snapshot in ``scope`` matching ``flt``, ordered by address.

    Each row carries the IP/ENI columns plus subnet/VPC names, ``lb_type`` and
    endpoint ``service_name`` (when applicable), a derived ``resource_name``, the
    ENI's ``security_groups`` (ids), the resource's ``tags``, ``tf`` (Terraform
    roots/addresses managing the ENI or its owning resource; empty = unmanaged) and
    its ``environment`` / ``env_source`` (:mod:`iplens.environment`, tag keys
    ``env_keys``), plus ``owner`` / ``own_labels`` (:mod:`iplens.ownership`, ``own``).
    """
    flt = flt or IpFilter()
    where = ["i.snapshot_id = ?"]
    args: list[Any] = [snap_id]
    scope_where, scope_args = scope.sql("i")
    where += scope_where
    args += scope_args
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
    tags = tag_index(conn, snap_id)
    tf_index = terraform.load_index(conn)
    envs = environment.EnvResolver(conn, snap_id, env_keys, tags=tags, tf_index=tf_index)
    owners = ownership.load_index(conn, snap_id, own, tf_index)
    for r in rows:
        r["owner_names"] = owner_names(r)
        r["resource_name"] = resource_name(r)
        r["security_groups"] = json.loads(r.get("security_groups") or "[]")
        r["tags"] = resource_tags(tags, r)
        r["tf"] = terraform.ownership(tf_index, terraform.resource_keys(r))
        r["environment"], r["env_source"] = envs.for_row(r)
        _add_ownership(r, owners)
    return [r for r in rows if _row_matches(r, flt)]


# -- visual diagram ---------------------------------------------------------------

# More than this many nodes of one type in a subnet are collapsed into a group node.
VISUAL_GROUP_THRESHOLD = 10
# Member names listed in a group node's label before the ellipsis.
GROUP_LABEL_MEMBERS = 3

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
            owners = r["owner_names"]
            if len(owners) > 1 and not r.get("eni_name"):
                name = short_owner_label(owners)
            else:
                name = r["resource_name"] or r["eni_id"]
            node = nodes[r["eni_id"]] = {
                "kind": "resource",
                "id": r["eni_id"],
                "eni_id": r["eni_id"],
                "subnet_id": r["subnet_id"],
                "type": r["owner_type"],
                "type_label": resource_type_label(r, labels),
                "name": name,
                "label_name": name,
                "ref": r["owner_ref"] or "",
                "owners": owners,
                "sgs": r["security_groups"],
                "tags": r["tags"],
                "tf": r["tf"],
                "environment": r["environment"],
                "env_source": r["env_source"],
                "owner": r["owner"],
                "team": r["own_labels"]["team"],
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


def group_name(count: int, type_label: str, member_names: list[str]) -> str:
    """``"14 × VPC endpoint: lambda, sts, …"``: the first GROUP_LABEL_MEMBERS distinct
    member names, then an ellipsis when there are more."""
    distinct = list(dict.fromkeys(n for n in member_names if n))
    shown = distinct[:GROUP_LABEL_MEMBERS]
    if not shown:
        return f"{count} × {type_label}"
    more = ", …" if len(distinct) > len(shown) else ""
    return f"{count} × {type_label}: {', '.join(shown)}{more}"


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
        type_label = labels.get(owner_type, owner_type)
        member_names = list(dict.fromkeys(m["name"] for m in members if m["name"]))
        items.append(
            {
                "kind": "group",
                "id": f"group:{subnet_id}:{owner_type}",
                "type": owner_type,
                "type_label": type_label,
                "name": group_name(len(members), type_label, member_names),
                "member_names": member_names,
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
    scope: ResolvedScope = UNSCOPED,
    env_keys: Sequence[str] = environment.DEFAULT_TAG_KEYS,
    own: ownership.OwnershipConfig | None = None,
) -> dict[str, Any] | None:
    """Nested VPC -> subnets -> resource nodes, plus resource edges, for the Visual page.

    ``vpc_id`` defaults to the first VPC. Returns None if ``vpc_id`` is unknown.
    Only edges of ``edge_types`` are returned (see :mod:`iplens.visual`).
    """
    labels = labels or {}
    tree = vpc_tree(conn, snap_id, scope)
    vpcs = [{"vpc_id": v.vpc_id, "name": v.name} for v in tree]
    if not tree:
        return {"snapshot_id": snap_id, "vpcs": [], "vpc": None, "icons": {"vpc": VPC_ICON}}
    vpc = next((v for v in tree if v.vpc_id == vpc_id), None) if vpc_id else tree[0]
    if vpc is None:
        return None

    by_subnet: dict[str, list[dict[str, Any]]] = {}
    by_ip: dict[str, str] = {}
    for r in ip_list(conn, snap_id, IpFilter(vpc=vpc.vpc_id), scope, env_keys, own):
        by_subnet.setdefault(r["subnet_id"], []).append(r)
        by_ip[r["ip"]] = r["eni_id"]

    subnets = []
    resources: dict[str, dict[str, Any]] = {}
    names = sg_names(conn, snap_id)
    for s in vpc.subnets:
        nodes = _resource_nodes(by_subnet.get(s.subnet_id, []), labels)
        resources.update((n["eni_id"], n) for n in nodes)
        subnets.append(
            {
                "subnet_id": s.subnet_id,
                "name": s.name,
                "label_name": s.name or s.subnet_id,
                "label_meta": f"{s.subnet_id} · {s.cidr} · {s.az}",
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
            "label_name": vpc.name or vpc.vpc_id,
            "label_cidrs": ", ".join(vpc.cidrs),
            "cidrs": vpc.cidrs,
            "subnets": subnets,
        },
        "icons": {"vpc": VPC_ICON},
        # Context for the "Group by" options (security group / tag / Terraform root).
        "sg_names": {
            sg: names.get(sg, sg)
            for sg in sorted({g for n in resources.values() for g in n["sgs"]})
        },
        "tag_keys": sorted({k for n in resources.values() for k in n["tags"]}),
        "tf_roots": sorted({m["root"] for n in resources.values() for m in n["tf"]}),
        **visual_edges(conn, snap_id, vpc.vpc_id, resources, by_ip, edge_types, names),
    }
