"""Visual page helpers: connections between resource nodes and label truncation.

Edges are derived from the stored snapshot only:

- ``targets``: load balancer -> registered target (EC2 instance, IP, Lambda, ALB)
- ``ecs_lb``: ECS service task ENI -> load balancer the service forwards through
- ``sg``: a security group rule on one resource that names a security group held
  by another resource (drawn dashed)

Resources with one ENI per AZ (load balancers, VPC endpoints) are one node per
ENI. An edge picks the far-side ENI in the same AZ when there is one, so a two-AZ
ALB with four targets yields four edges rather than eight.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

EDGE_TYPES = ("targets", "ecs_lb", "sg")
EDGE_TYPE_LABELS = {"targets": "LB→targets", "ecs_lb": "ECS→LB", "sg": "SG refs"}

# Security groups shared by many ENIs can reference each other N×M times; stop there.
MAX_SG_EDGES = 400

# Maximum characters of a label line before it is cut with an ellipsis.
LABEL_MAX = {"name": 24, "subnet": 32, "cidr": 40, "edge": 28}


def ellipsize(text: str | None, limit: int) -> str:
    """``text`` cut to at most ``limit`` characters, ending in "…" when cut."""
    text = text or ""
    if len(text) <= limit:
        return text
    if limit <= 1:
        return "…"[:limit]
    return text[: limit - 1].rstrip() + "…"


def parse_edge_types(values: Iterable[str] | None) -> tuple[str, ...]:
    """Edge types selected by an ``edges`` query parameter.

    ``None`` (parameter absent) selects every type. Otherwise values may be repeated
    and/or comma-separated; unknown names are ignored, so ``edges=`` selects none.
    """
    if values is None:
        return EDGE_TYPES
    wanted = {part.strip() for v in values for part in v.split(",")}
    return tuple(t for t in EDGE_TYPES if t in wanted)


@dataclass(frozen=True)
class _Node:
    eni_id: str
    az: str
    owner_type: str
    owner_ref: str
    instance_id: str
    sgs: tuple[str, ...]
    name: str

    @property
    def resource_key(self) -> tuple[str, str]:
        """ENIs of one resource (e.g. the per-AZ ENIs of an ALB) share this key."""
        return (self.owner_type, self.owner_ref) if self.owner_ref else ("eni", self.eni_id)


def _nearest(candidates: list[_Node], az: str) -> _Node:
    return next((c for c in candidates if c.az == az), candidates[0])


class _EdgeSet:
    def __init__(self) -> None:
        self._edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add(self, etype: str, source: _Node, target: _Node, label: str, title: str) -> None:
        if source.eni_id == target.eni_id:
            return
        key = (etype, source.eni_id, target.eni_id)
        edge = self._edges.get(key)
        if edge is None:
            self._edges[key] = {
                "id": f"{etype}:{source.eni_id}>{target.eni_id}",
                "type": etype,
                "source": source.eni_id,
                "target": target.eni_id,
                "label": ellipsize(label, LABEL_MAX["edge"]),
                "title": title,
            }
        elif title not in edge["title"].split("\n"):
            edge["title"] += "\n" + title

    def count(self, etype: str) -> int:
        return sum(1 for k in self._edges if k[0] == etype)

    def values(self) -> list[dict[str, Any]]:
        return list(self._edges.values())


def _load_nodes(
    conn: sqlite3.Connection, snap_id: int, vpc_id: str, resources: dict[str, dict[str, Any]]
) -> dict[str, _Node]:
    nodes = {}
    for r in conn.execute(
        "SELECT eni_id, az, instance_id, security_groups FROM enis "
        "WHERE snapshot_id=? AND vpc_id=? ORDER BY eni_id",
        (snap_id, vpc_id),
    ):
        res = resources.get(r["eni_id"])
        if res is None:  # ENI without addresses: not drawn
            continue
        nodes[r["eni_id"]] = _Node(
            eni_id=r["eni_id"],
            az=r["az"] or "",
            owner_type=res["type"],
            owner_ref=res["ref"],
            instance_id=r["instance_id"] or "",
            sgs=tuple(json.loads(r["security_groups"] or "[]")),
            name=res["name"],
        )
    return nodes


def _lb_edges(
    conn: sqlite3.Connection,
    snap_id: int,
    nodes: dict[str, _Node],
    by_ip: dict[str, str],
    lb_enis: dict[str, list[_Node]],
    edges: _EdgeSet,
) -> None:
    by_instance: dict[str, list[_Node]] = {}
    by_lambda: dict[str, list[_Node]] = {}
    for n in nodes.values():
        if n.instance_id:
            by_instance.setdefault(n.instance_id, []).append(n)
        if n.owner_type == "lambda" and n.owner_ref:
            by_lambda.setdefault(n.owner_ref, []).append(n)

    for r in conn.execute(
        "SELECT lb_name, target_group, target_type, target_id, port FROM lb_targets "
        "WHERE snapshot_id=? ORDER BY lb_name, target_group, target_id, port",
        (snap_id,),
    ):
        sources = lb_enis.get(r["lb_name"])
        if not sources:
            continue
        ttype, tid = r["target_type"], r["target_id"]
        if ttype == "instance":
            targets = by_instance.get(tid, [])
        elif ttype == "ip":
            targets = [nodes[by_ip[tid]]] if tid in by_ip else []
        elif ttype == "lambda":
            targets = by_lambda.get(tid, [])
        elif ttype == "alb":
            targets = lb_enis.get(tid, [])
        else:
            targets = []
        port = f":{r['port']}" if r["port"] else ""
        for t in targets:
            edges.add(
                "targets",
                _nearest(sources, t.az),
                t,
                f"{r['target_group']}{port}",
                f"{r['lb_name']} → {t.name} (target group {r['target_group']}{port})",
            )


def _ecs_edges(
    conn: sqlite3.Connection,
    snap_id: int,
    nodes: dict[str, _Node],
    lb_enis: dict[str, list[_Node]],
    edges: _EdgeSet,
) -> None:
    tasks: dict[tuple[str, str], list[_Node]] = {}
    for r in conn.execute(
        "SELECT eni_id, cluster, service FROM ecs_task_enis "
        "WHERE snapshot_id=? AND service != '' ORDER BY eni_id",
        (snap_id,),
    ):
        if r["eni_id"] in nodes:
            tasks.setdefault((r["cluster"], r["service"]), []).append(nodes[r["eni_id"]])

    for r in conn.execute(
        "SELECT cluster, service, lb_name, target_group FROM ecs_service_lbs "
        "WHERE snapshot_id=? ORDER BY cluster, service, lb_name, target_group",
        (snap_id,),
    ):
        targets = lb_enis.get(r["lb_name"])
        if not targets:
            continue
        via = f" via {r['target_group']}" if r["target_group"] else ""
        for s in tasks.get((r["cluster"], r["service"]), []):
            edges.add(
                "ecs_lb",
                s,
                _nearest(targets, s.az),
                f"ecs→lb {r['service']}",
                f"ECS service {r['cluster']}/{r['service']} → {r['lb_name']}{via}",
            )


def _sg_edges(
    conn: sqlite3.Connection, snap_id: int, nodes: dict[str, _Node], edges: _EdgeSet
) -> bool:
    """Add SG reference edges; True if MAX_SG_EDGES cut the list short."""
    holders: dict[str, list[_Node]] = {}
    for n in nodes.values():
        for sg in n.sgs:
            holders.setdefault(sg, []).append(n)

    for r in conn.execute(
        "SELECT group_id, direction, ref_group_id, ports FROM sg_refs "
        "WHERE snapshot_id=? AND group_id != ref_group_id "
        "ORDER BY group_id, direction, ref_group_id, ports",
        (snap_id,),
    ):
        group, ref = r["group_id"], r["ref_group_id"]
        if group not in holders or ref not in holders:
            continue
        ref_resources: dict[tuple[str, str], list[_Node]] = {}
        for b in holders[ref]:
            ref_resources.setdefault(b.resource_key, []).append(b)
        for a in holders[group]:
            for key, candidates in ref_resources.items():
                if key == a.resource_key:
                    continue
                if edges.count("sg") >= MAX_SG_EDGES:
                    return True
                b = _nearest(candidates, a.az)
                if r["direction"] == "ingress":
                    edges.add(
                        "sg",
                        b,
                        a,
                        f"from {ref} of {b.name}",
                        f"{group} on {a.name} allows {r['ports']} from {ref} on {b.name}",
                    )
                else:
                    to = (
                        b.owner_ref
                        if b.owner_type == "vpc_endpoint" and b.owner_ref.startswith("vpce-")
                        else f"{ref} of {b.name}"
                    )
                    edges.add(
                        "sg",
                        a,
                        b,
                        f"to {to}",
                        f"{group} on {a.name} allows {r['ports']} to {ref} on {b.name}",
                    )
    return False


def visual_edges(
    conn: sqlite3.Connection,
    snap_id: int,
    vpc_id: str,
    resources: dict[str, dict[str, Any]],
    by_ip: dict[str, str],
    edge_types: Iterable[str] = EDGE_TYPES,
) -> dict[str, Any]:
    """Edges between the resource nodes of one VPC.

    ``resources`` maps ENI id -> resource node (as built for the Visual page) and
    ``by_ip`` maps private IP -> ENI id. Returns ``edges`` (only ``edge_types``),
    per-type ``edge_types`` metadata with unfiltered counts, and ``edges_truncated``.
    """
    nodes = _load_nodes(conn, snap_id, vpc_id, resources)
    lb_enis: dict[str, list[_Node]] = {}
    for n in nodes.values():
        if n.owner_type == "elb" and n.owner_ref:
            lb_enis.setdefault(n.owner_ref, []).append(n)

    edges = _EdgeSet()
    _lb_edges(conn, snap_id, nodes, by_ip, lb_enis, edges)
    _ecs_edges(conn, snap_id, nodes, lb_enis, edges)
    truncated = _sg_edges(conn, snap_id, nodes, edges)

    selected = set(edge_types)
    return {
        "edges": [e for e in edges.values() if e["type"] in selected],
        "edge_types": [
            {
                "type": t,
                "label": EDGE_TYPE_LABELS[t],
                "count": edges.count(t),
                "selected": t in selected,
            }
            for t in EDGE_TYPES
        ],
        "edges_truncated": truncated,
    }
