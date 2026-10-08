"""Extended view payload: regional / external nodes and evidence-ranked edges.

Built on top of the IP view's data for one VPC (:func:`iplens.queries.visual_data`).
Stored ``ext_edges`` endpoints are resolved onto the diagram:

- ``vpc:<id>`` -> the VPC box when it is the VPC shown (else the edge is dropped)
- ``eni:<id>`` -> that ENI's resource node when it is drawn (else dropped)
- ``lambda:<fn>`` / ``ecs:<cluster>/<service>`` -> the resource's first ENI node in
  this VPC when it has one, else a node in the "Regional services" area
- anything else -> a node in the "Regional services" or "External" area

Flow log aggregates become ``observed`` ENI<->ENI edges. All evidence lines between
the same two nodes are merged into one edge whose ``evidence`` is the strongest level
(:data:`iplens.extended.EVIDENCE_LEVELS`); the detail panel lists every line. In the
Extended view the IP view's own edges carry evidence too: load balancer targets and
ECS services are ``configured``, security group reach / references ``permitted``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Any

from .extended import (
    EVIDENCE_HELP,
    EVIDENCE_LABELS,
    EVIDENCE_LEVELS,
    EVIDENCE_RANK,
    EXTERNAL_SERVICES,
    SERVICE_LABELS,
    latest_crawl,
)
from .flowlogs import INTERNET, OUTSIDE, human_bytes, latest_run
from .queries import TYPE_ICONS

BASE_EVIDENCE = {
    "targets": "configured",
    "ecs_lb": "configured",
    "reach": "permitted",
    "sg": "permitted",
}
EXT_PREFIX = "x:"
VPC_NODE = "vpc"
AREAS = {
    "regional": "Regional services (outside the VPC)",
    "external": "External: Transit Gateway · peering · internet",
}
# Self-drawn service badges in static/icons/ext/; Lambda and ECS reuse the AWS icons.
EXT_ICONS = {
    **{s: f"ext/{s}.svg" for s in SERVICE_LABELS if s not in ("lambda", "ecs")},
    "lambda": TYPE_ICONS["lambda"],
    "ecs": TYPE_ICONS["ecs"],
}
FLOW_NODES = {
    INTERNET: ("internet", "public peers (flow logs)"),
    OUTSIDE: ("internet", "private peers outside this snapshot (flow logs)"),
}


def _iter_resources(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for s in data["vpc"]["subnets"]:
        for item in s["items"]:
            if item["kind"] == "group":
                yield from item["members"]
            else:
                yield item


def annotate_base_edges(edges: list[dict[str, Any]]) -> None:
    """Give the IP view's edges an evidence level and evidence lines (in place)."""
    for e in edges:
        level = BASE_EVIDENCE.get(e["type"], "configured")
        e["evidence"] = level
        e["lines"] = [
            {"evidence": level, "label": e["label"], "text": line}
            for line in (e.get("title") or e["label"]).split("\n")
        ]


class _Resolver:
    def __init__(self, data: dict[str, Any]):
        self.vpc_id = data["vpc"]["vpc_id"]
        self.enis: set[str] = set()
        self.lambda_enis: dict[str, list[str]] = {}
        self.ecs_enis: dict[str, list[str]] = {}
        for r in _iter_resources(data):
            self.enis.add(r["eni_id"])
            if r["type"] == "lambda":
                for fn in r.get("owners") or ([r["ref"]] if r["ref"] else []):
                    self.lambda_enis.setdefault(fn, []).append(r["eni_id"])
            elif r["type"] == "ecs" and r["ref"].count("/") >= 2:
                key = r["ref"].rsplit("/", 1)[0]  # cluster/service/task -> cluster/service
                self.ecs_enis.setdefault(key, []).append(r["eni_id"])

    def __call__(self, token: str) -> str | None:
        kind, _, rest = token.partition(":")
        if kind == "vpc":
            return VPC_NODE if rest == self.vpc_id else None
        if kind == "eni":
            return rest if rest in self.enis else None
        if kind == "lambda" and rest in self.lambda_enis:
            return sorted(self.lambda_enis[rest])[0]
        if kind == "ecs" and rest in self.ecs_enis:
            return sorted(self.ecs_enis[rest])[0]
        return EXT_PREFIX + token


def _flow_lines(
    conn: sqlite3.Connection, snap_id: int, vpc_id: str, run: dict[str, Any] | None
) -> Iterator[tuple[str, str, str, str, str]]:
    if run is None:
        return
    window = f"{run['window_minutes']} min"
    for r in conn.execute(
        "SELECT src_eni, dst_eni, protocol, port, flows, bytes FROM flow_aggregates "
        "WHERE snapshot_id=? AND vpc_id=? ORDER BY flows DESC",
        (snap_id, vpc_id),
    ):
        ends = []
        for side in (r["src_eni"], r["dst_eni"]):
            if side in FLOW_NODES:
                ends.append(f"internet:{side}")
            else:
                ends.append(f"eni:{side}")
        port = f"{r['protocol']}/{r['port']}" if r["port"] else r["protocol"]
        yield (
            ends[0],
            ends[1],
            "observed",
            port,
            f"flow logs (last {window} before {run['ran_at']}): {r['flows']} flow(s), "
            f"{human_bytes(r['bytes'])} on {port}",
        )


def extended_data(conn: sqlite3.Connection, snap_id: int, data: dict[str, Any]) -> dict[str, Any]:
    """The ``extended`` part of the Visual page data for the VPC in ``data``."""
    vpc_id = data["vpc"]["vpc_id"]
    resolve = _Resolver(data)
    annotate_base_edges(data.get("edges") or [])

    rows = [
        (r["source"], r["target"], r["evidence"], r["label"], r["detail"])
        for r in conn.execute(
            "SELECT source, target, evidence, label, detail FROM ext_edges WHERE snapshot_id=? "
            "ORDER BY source, target, evidence, detail",
            (snap_id,),
        )
    ]
    run = latest_run(conn, snap_id, vpc_id)
    rows += list(_flow_lines(conn, snap_id, vpc_id, run))

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    used: set[str] = set()
    for source, target, evidence, label, detail in rows:
        s, t = resolve(source), resolve(target)
        if not s or not t or s == t or evidence not in EVIDENCE_RANK:
            continue
        edge = merged.setdefault(
            (s, t),
            {"id": f"ext:{len(merged)}", "type": "ext", "source": s, "target": t, "lines": []},
        )
        edge["lines"].append({"evidence": evidence, "label": label, "text": detail})
        used.update(x[len(EXT_PREFIX) :] for x in (s, t) if x.startswith(EXT_PREFIX))
    edges = []
    for edge in merged.values():
        edge["lines"].sort(key=lambda ln: (EVIDENCE_RANK[ln["evidence"]], ln["text"]))
        best = edge["lines"][0]
        edge["evidence"] = best["evidence"]
        edge["label"] = best["label"]
        edge["title"] = "\n".join(f"[{ln['evidence']}] {ln['text']}" for ln in edge["lines"])
        edges.append(edge)

    facts: dict[str, list[str]] = {}
    for r in conn.execute(
        "SELECT subject, detail FROM ext_facts WHERE snapshot_id=? ORDER BY subject, detail",
        (snap_id,),
    ):
        facts.setdefault(r["subject"], []).append(r["detail"])

    stored = {
        r["node_id"]: r
        for r in conn.execute(
            "SELECT node_id, service, name, arn, area, broad_access FROM ext_nodes "
            "WHERE snapshot_id=?",
            (snap_id,),
        )
    }
    nodes = []
    for nid in sorted(used):
        row = stored.get(nid)
        service, _, name = nid.partition(":")
        if row is not None:
            service, name = row["service"], row["name"]
        flow = FLOW_NODES.get(name) if service == "internet" else None
        label = {"nat": "Internet via NAT", "igw": "Internet (IGW)"}.get(name, name)
        if flow:
            label = f"Internet / outside: {flow[1]}"
        nodes.append(
            {
                "id": EXT_PREFIX + nid,
                "node_id": nid,
                "service": service,
                "service_label": SERVICE_LABELS.get(service, service),
                "name": name,
                "label_name": label,
                "arn": row["arn"] if row is not None else "",
                "area": row["area"]
                if row is not None
                else ("external" if service in EXTERNAL_SERVICES else "regional"),
                "icon": EXT_ICONS.get(service, EXT_ICONS["other"]),
                "broad_access": bool(row["broad_access"]) if row is not None else False,
                "facts": facts.get(nid, []),
            }
        )

    services: dict[str, int] = {}
    for n in nodes:
        services[n["service"]] = services.get(n["service"], 0) + 1
    all_edges = (data.get("edges") or []) + edges
    return {
        "crawl": latest_crawl(conn, snap_id),
        "flow": run,
        "areas": AREAS,
        "nodes": nodes,
        "edges": edges,
        "hidden_nodes": len(set(stored) - used),
        "subnet_facts": {
            k.split(":", 1)[1]: v for k, v in facts.items() if k.startswith("subnet:")
        },
        "services": [
            {"service": s, "label": SERVICE_LABELS.get(s, s), "count": c}
            for s, c in sorted(services.items())
        ],
        "evidence_levels": [
            {
                "level": level,
                "label": EVIDENCE_LABELS[level],
                "help": EVIDENCE_HELP[level],
                "count": sum(
                    1 for e in all_edges if any(ln["evidence"] == level for ln in e["lines"])
                ),
            }
            for level in EVIDENCE_LEVELS
        ],
    }
