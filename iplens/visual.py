"""Visual page helpers: connections between resource nodes and label shortening.

Edges are derived from the stored snapshot only:

- ``targets``: load balancer -> registered target (EC2 instance, IP, Lambda, ALB)
- ``ecs_lb``: ECS service task ENI -> load balancer the service forwards through
- ``reach``: resource -> VPC endpoint whose security group ingress allows tcp/443
  (or all traffic) from a security group on the resource or from a CIDR containing
  one of the resource's private IPs (drawn dashed)
- ``sg``: a security group rule on one resource that names a security group held
  by another resource (drawn dashed)

Resources with one ENI per AZ (load balancers, VPC endpoints) are one node per
ENI. An edge picks the far-side ENI in the same AZ when there is one, so a two-AZ
ALB with four targets yields four edges rather than eight.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

EDGE_TYPES = ("targets", "ecs_lb", "reach", "sg")
EDGE_TYPE_LABELS = {
    "targets": "LB→targets",
    "ecs_lb": "ECS→LB",
    "reach": "Endpoint reach",
    "sg": "SG refs",
}
# Ticked on the Visual page when the URL names no edge types (SG refs are noisy).
DEFAULT_EDGE_TYPES = ("targets", "ecs_lb", "reach")

# Security groups shared by many ENIs can reference each other N×M times; stop there.
MAX_SG_EDGES = 400
# A wide CIDR rule (e.g. the VPC CIDR) lets every resource reach every endpoint.
MAX_REACH_EDGES = 400

# VPC interface endpoints are reached over HTTPS.
ENDPOINT_PORT = 443
REACH_LABEL = "can reach (SG)"

# Labels are sent in full; the Visual page's "Shorten long names" option cuts names
# longer than this in the browser (``middleEllipsize`` in static/visual.js mirrors
# :func:`middle_ellipsize`).
SHORT_NAME_MAX = 32
# Characters a long name may be wrapped or cut after.
NAME_SEPARATORS = "-_./"


def ellipsize(text: str | None, limit: int) -> str:
    """``text`` cut to at most ``limit`` characters, ending in "…" when cut."""
    text = text or ""
    if len(text) <= limit:
        return text
    if limit <= 1:
        return "…"[:limit]
    return text[: limit - 1].rstrip() + "…"


def middle_ellipsize(text: str | None, limit: int = SHORT_NAME_MAX) -> str:
    """``text`` cut to at most ``limit`` characters by replacing its middle with "…".

    The start and the (slightly longer) end are kept, so names sharing a long prefix
    stay distinguishable: "datalab-…-kafka-producer". Each side is trimmed back to a
    separator (``- _ . /``) when one lies in its outer half.
    """
    text = text or ""
    if len(text) <= limit:
        return text
    if limit <= 2:
        return "…"[:limit]
    budget = limit - 1
    head_n = budget * 2 // 5
    tail_n = budget - head_n
    head, tail = text[:head_n], text[-tail_n:]
    cut = max(head.rfind(c) for c in NAME_SEPARATORS)
    if cut >= head_n // 2:
        head = head[: cut + 1]
    starts = [i for i in (tail.find(c) for c in NAME_SEPARATORS) if i >= 0]
    if starts and min(starts) <= tail_n // 2:
        tail = tail[min(starts) :]
    return head + "…" + tail


def parse_edge_types(
    values: Iterable[str] | None, default: tuple[str, ...] = EDGE_TYPES
) -> tuple[str, ...]:
    """Edge types selected by an ``edges`` query parameter.

    ``None`` (parameter absent) selects ``default``. Otherwise values may be repeated
    and/or comma-separated; unknown names are ignored, so ``edges=`` selects none.
    """
    if values is None:
        return default
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
    ips: tuple[str, ...]
    owners: tuple[str, ...] = ()

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
                "label": label,
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
            ips=tuple(res["ips"]),
            owners=tuple(res.get("owners") or ()),
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
        if n.owner_type == "lambda":
            # A shared Lambda ENI is a target of every function that uses it.
            for fn in n.owners or ((n.owner_ref,) if n.owner_ref else ()):
                by_lambda.setdefault(fn, []).append(n)

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


def allows_endpoint_port(protocol: str, from_port: int | None, to_port: int | None) -> bool:
    """True if a rule for ``protocol`` and the port range admits tcp/ENDPOINT_PORT."""
    proto = str(protocol).lower()
    if proto in ("-1", "all"):
        return True
    if proto not in ("tcp", "6"):
        return False
    if from_port is None:
        return True
    return from_port <= ENDPOINT_PORT <= (from_port if to_port is None else to_port)


def _ports_allow_endpoint(ports: str) -> bool:
    """:func:`allows_endpoint_port` for an ``sg_refs.ports`` string ("tcp/400-500", "all")."""
    proto, _, span = ports.partition("/")
    if not span:
        return allows_endpoint_port(proto, None, None)
    lo, _, hi = span.partition("-")
    return allows_endpoint_port(proto, int(lo), int(hi or lo))


def _rule_ports(protocol: str, from_port: int | None, to_port: int | None) -> str:
    if protocol in ("-1", "all"):
        return "all"
    if from_port is None:
        return protocol
    if from_port == to_port:
        return f"{protocol}/{from_port}"
    return f"{protocol}/{from_port}-{to_port}"


def _reach_edges(
    conn: sqlite3.Connection, snap_id: int, nodes: dict[str, _Node], edges: _EdgeSet
) -> bool:
    """Add resource -> VPC endpoint reach edges; True if MAX_REACH_EDGES cut the list short."""
    endpoints: dict[tuple[str, str], list[_Node]] = {}
    for n in nodes.values():
        if n.owner_type == "vpc_endpoint":
            endpoints.setdefault(n.resource_key, []).append(n)
    if not endpoints:
        return False

    # Ingress rules admitting tcp/443, keyed by the security group that holds them.
    from_sg: dict[str, list[tuple[str, str]]] = {}  # group -> [(source group, ports)]
    for r in conn.execute(
        "SELECT group_id, ref_group_id, ports FROM sg_refs "
        "WHERE snapshot_id=? AND direction='ingress' ORDER BY group_id, ref_group_id, ports",
        (snap_id,),
    ):
        if _ports_allow_endpoint(r["ports"]):
            from_sg.setdefault(r["group_id"], []).append((r["ref_group_id"], r["ports"]))
    from_cidr: dict[str, list[tuple[Any, str]]] = {}  # group -> [(network, ports)]
    for r in conn.execute(
        "SELECT group_id, cidr, ip_protocol, from_port, to_port FROM sg_cidr_rules "
        "WHERE snapshot_id=? ORDER BY group_id, cidr, ip_protocol, from_port, to_port",
        (snap_id,),
    ):
        if not allows_endpoint_port(r["ip_protocol"], r["from_port"], r["to_port"]):
            continue
        try:
            net = ipaddress.ip_network(r["cidr"], strict=False)
        except ValueError:
            continue
        ports = _rule_ports(r["ip_protocol"], r["from_port"], r["to_port"])
        from_cidr.setdefault(r["group_id"], []).append((net, ports))

    sources = [n for n in nodes.values() if n.owner_type != "vpc_endpoint"]
    addrs = {n.eni_id: [ipaddress.ip_address(ip) for ip in n.ips] for n in sources}
    added = 0
    for enis in endpoints.values():
        ep_sgs = sorted({sg for e in enis for sg in e.sgs})
        sg_rules = [(sg, src, ports) for sg in ep_sgs for src, ports in from_sg.get(sg, [])]
        cidr_rules = [(sg, net, ports) for sg in ep_sgs for net, ports in from_cidr.get(sg, [])]
        if not sg_rules and not cidr_rules:
            continue
        for a in sources:
            reasons = [
                f"{sg} allows {ports} from {src} on {a.name}"
                for sg, src, ports in sg_rules
                if src in a.sgs
            ]
            reasons += [
                f"{sg} allows {ports} from {net} ({ip})"
                for sg, net, ports in cidr_rules
                for ip in addrs[a.eni_id]
                if ip in net
            ]
            if not reasons:
                continue
            if added >= MAX_REACH_EDGES:
                return True
            b = _nearest(enis, a.az)
            for reason in reasons:
                edges.add("reach", a, b, REACH_LABEL, f"{a.name} can reach {b.name}: {reason}")
            added += 1
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
    per-type ``edge_types`` metadata with unfiltered counts and a ``truncated`` flag,
    and ``edges_truncated`` (true if any type was truncated).
    """
    nodes = _load_nodes(conn, snap_id, vpc_id, resources)
    lb_enis: dict[str, list[_Node]] = {}
    for n in nodes.values():
        if n.owner_type == "elb" and n.owner_ref:
            lb_enis.setdefault(n.owner_ref, []).append(n)

    edges = _EdgeSet()
    _lb_edges(conn, snap_id, nodes, by_ip, lb_enis, edges)
    _ecs_edges(conn, snap_id, nodes, lb_enis, edges)
    truncated = {
        "reach": _reach_edges(conn, snap_id, nodes, edges),
        "sg": _sg_edges(conn, snap_id, nodes, edges),
    }

    selected = set(edge_types)
    return {
        "edges": [e for e in edges.values() if e["type"] in selected],
        "edge_types": [
            {
                "type": t,
                "label": EDGE_TYPE_LABELS[t],
                "count": edges.count(t),
                "selected": t in selected,
                "truncated": truncated.get(t, False),
            }
            for t in EDGE_TYPES
        ],
        "edges_truncated": any(truncated.values()),
    }
