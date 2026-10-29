"""Visual page Logical view: one node per logical resource instead of one per ENI.

The IP view draws one node per ENI, so a resource with an ENI in several AZs (a Lambda
function, an ECS service, a load balancer, a VPC endpoint, a Multi-AZ database, ...)
appears once per AZ. The Logical view collapses those ENIs into one node per owner
identity, taken from the ENI owner data already stored (:func:`identity`):

- Lambda: the functions sharing the ENI (Hyperplane ENIs of one subnet + security
  group set are shared, so the functions with one VPC config are one node);
- ECS: the service (``cluster/service``; a standalone task stays one node per task);
- every other type with an owner reference (load balancer name, endpoint / NAT gateway /
  TGW attachment id, RDS / ElastiCache / OpenSearch cluster or instance, EC2 instance):
  that reference;
- an ENI without owner reference, or of type "other", stays a node of its own.

Logical nodes sit straight in the VPC box (no subnet boxes) and carry no IPs or ENI ids:
name, type icon and the AZs they span. Edges between two collapsed nodes are merged into
one edge per type. Built from the IP view's data (:func:`iplens.queries.visual_data`),
so the page's filters, "Group by" options and layouts apply unchanged.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from .queries import VISUAL_TYPE_ORDER
from .visual import EDGE_TYPES

# Node ids are stored with dragged positions (viewstate.MAX_NODE_ID, "res:" prefix
# included); a longer id (many functions sharing one ENI) is cut and hashed.
MAX_ID = 120


def logical_ref(resource: dict[str, Any]) -> str:
    """The owner reference of the logical resource: an ECS task ENI's ``cluster/service``
    (its ``owner_ref`` is ``cluster/service/task``), else the ENI's owner reference."""
    ref = resource.get("ref") or ""
    if resource["type"] == "ecs" and ref.count("/") == 2:
        return ref.rsplit("/", 1)[0]
    return ref


def identity(resource: dict[str, Any]) -> tuple[str, str]:
    """``(type, key)`` shared by every ENI of one logical resource; ``("eni", eni id)``
    for an ENI that stays a node of its own."""
    otype = resource["type"]
    if otype == "lambda" and resource.get("owners"):
        return otype, ",".join(sorted(resource["owners"]))
    ref = logical_ref(resource)
    if ref and otype != "other":
        return otype, ref
    return "eni", resource["eni_id"]


def node_id(ident: tuple[str, str]) -> str:
    text = f"{ident[0]}:{ident[1]}"
    if len(text) <= MAX_ID:
        return text
    digest = hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()[:12]
    return f"{text[: MAX_ID - 13]}#{digest}"


def _type_rank(owner_type: str) -> int:
    if owner_type in VISUAL_TYPE_ORDER:
        return VISUAL_TYPE_ORDER.index(owner_type)
    return len(VISUAL_TYPE_ORDER)


def _new_node(nid: str, r: dict[str, Any]) -> dict[str, Any]:
    ref = logical_ref(r)
    # A name derived from the owner reference (an ECS task's cluster/service/task)
    # names the logical resource instead.
    name = ref if r["name"] == r.get("ref") and ref else r["name"]
    return {
        "kind": "resource",
        "id": nid,
        "type": r["type"],
        "type_label": r["type_label"],
        "name": name,
        "label_name": name,
        "ref": ref,
        # Name filter / tooltip: the functions of a Lambda node, else the logical ref.
        "owners": list(r.get("owners") or []) if r["type"] == "lambda" else [ref] if ref else [],
        "sgs": [],
        "tags": r.get("tags") or {},
        "tag_values": {},
        "tf": [],
        "environment": r.get("environment"),
        "env_source": r.get("env_source"),
        "owner": r.get("owner"),
        "team": r.get("team"),
        "status": r.get("status") or "",
        "icon": r["icon"],
        "ips": [],  # never shown in this view
        "zones": [],
        "eni_count": 0,
    }


def _merge(node: dict[str, Any], r: dict[str, Any], az: str) -> None:
    node["eni_count"] += 1
    if az and az not in node["zones"]:
        node["zones"].append(az)
    node["sgs"].extend(g for g in r.get("sgs") or [] if g not in node["sgs"])
    node["tf"].extend(m for m in r.get("tf") or [] if m not in node["tf"])
    values = node["tag_values"]
    for k, vs in (r.get("tag_values") or {}).items():
        values[k] = sorted({*values.get(k, []), *vs})
    # Idle only when every ENI of the resource is idle.
    if r.get("status") != "available":
        node["status"] = r.get("status") or ""


def _resources(vpc: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for s in vpc["subnets"]:
        for item in s["items"]:
            yield from item["members"] if item["kind"] == "group" else [item]


def logical_nodes(vpc: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Logical nodes of the IP view's ``vpc`` (subnets with resource items, groups
    included), ordered like the IP view (type, then name), and ``{ENI id: node id}``."""
    az_of = {s["subnet_id"]: s.get("az") or "" for s in vpc["subnets"]}
    nodes: dict[str, dict[str, Any]] = {}
    of_eni: dict[str, str] = {}
    for r in _resources(vpc):
        nid = node_id(identity(r))
        of_eni[r["eni_id"]] = nid
        node = nodes.get(nid)
        if node is None:
            node = nodes[nid] = _new_node(nid, r)
        _merge(node, r, az_of.get(r["subnet_id"], ""))
    out = sorted(nodes.values(), key=lambda n: (_type_rank(n["type"]), n["name"].lower(), n["id"]))
    for n in out:
        n["zones"].sort()
        n["tag_values"] = dict(sorted(n["tag_values"].items()))
    return out, of_eni


def logical_edges(edges: Iterable[dict[str, Any]], of_eni: dict[str, str]) -> list[dict[str, Any]]:
    """IP view edges between logical nodes: one edge per type and node pair (and one
    more for its blocked ENI edges), ``label`` the distinct labels, ``title`` / ``access``
    the distinct lines, ``merged`` the ENI edges it stands for. Edges inside one logical
    resource are dropped."""
    merged: dict[tuple[str, str, str, bool], dict[str, Any]] = {}
    for e in edges:
        s, t = of_eni.get(e["source"]), of_eni.get(e["target"])
        if s is None or t is None or s == t:
            continue
        blocked = bool(e.get("blocked"))
        m = merged.setdefault(
            (e["type"], s, t, blocked),
            {
                "id": f"{e['type']}:{s}>{t}" + ("!blocked" if blocked else ""),
                "type": e["type"],
                "source": s,
                "target": t,
                "blocked": blocked,
                "blocked_by": [],
                "access": [],
                "labels": [],
                "titles": [],
                "merged": 0,
            },
        )
        m["merged"] += 1
        if e["label"] not in m["labels"]:
            m["labels"].append(e["label"])
        m["titles"].extend(ln for ln in e["title"].split("\n") if ln not in m["titles"])
        m["access"].extend(ln for ln in e.get("access") or [] if ln not in m["access"])
        m["blocked_by"].extend(x for x in e.get("blocked_by") or [] if x not in m["blocked_by"])
    out = []
    for m in merged.values():
        labels, titles = m.pop("labels"), m.pop("titles")
        out.append({**m, "label": ", ".join(labels), "title": "\n".join(titles)})
    return out


def annotate_zones(data: dict[str, Any]) -> dict[str, Any]:
    """IP / Extended view: give each resource node the AZs of its logical resource
    (``zones_all``), so that an ENI of a Multi-AZ resource carries the same "3 AZ" badge
    as its Logical view node. Changes ``data`` in place and returns it."""
    vpc = data.get("vpc")
    if not vpc:
        return data
    nodes, of_eni = logical_nodes(vpc)
    zones = {n["id"]: n["zones"] for n in nodes}
    for r in _resources(vpc):
        r["zones_all"] = zones[of_eni[r["eni_id"]]]
    return data


def logical_view(data: dict[str, Any], edge_types: Iterable[str] = EDGE_TYPES) -> dict[str, Any]:
    """The Logical view of :func:`iplens.queries.visual_data` output.

    The VPC's ``subnets`` become empty and its ``items`` the logical nodes; ``edges``
    are the merged edges of ``edge_types``, ``edge_types`` counts the merged edges of
    every type in ``data`` (build ``data`` with every edge type for unfiltered counts),
    and ``logical`` sums up ``{resources, enis, zones}``."""
    vpc = data.get("vpc")
    if not vpc:
        return data
    nodes, of_eni = logical_nodes(vpc)
    edges = logical_edges(data.get("edges") or [], of_eni)
    selected = set(edge_types)
    return {
        **data,
        "vpc": {**vpc, "subnets": [], "items": nodes},
        "edges": [e for e in edges if e["type"] in selected],
        "edge_types": [
            {
                **t,
                "count": sum(1 for e in edges if e["type"] == t["type"] and not e["blocked"]),
                "blocked": sum(1 for e in edges if e["type"] == t["type"] and e["blocked"]),
                "selected": t["type"] in selected,
            }
            for t in data.get("edge_types") or []
        ],
        "logical": {
            "resources": len(nodes),
            "enis": len(of_eni),
            "zones": len({z for n in nodes for z in n["zones"]}),
        },
    }
