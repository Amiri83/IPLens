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

The page then declutters this payload without changing it (:mod:`iplens.declutter`):
one edge per node pair, evidence filter, service / compute groups, focus mode.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator, Sequence
from typing import Any

from . import access, environment
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
# Regional services whose environment can be derived: (Terraform kind, resource_tags type).
ENV_KEYS = {"lambda": ("lambda", "lambda"), "ecs": ("ecs_service", "ecs_service")}
# Crawled nodes not linked to the VPC shown, listed in the side panel at most.
MAX_HIDDEN_LISTED = 1000
FLOW_NODES = {
    INTERNET: ("internet", "public peers (flow logs)"),
    OUTSIDE: ("internet", "private peers outside this snapshot (flow logs)"),
}


# IP view: Transit Gateway links come from discovery (every Refresh calls
# DescribeTransitGatewayAttachments and DescribeRouteTables); an Extended crawl adds
# what discovery does not see (TGW route table propagations).
TGW_NO_CRAWL = "Run Extended crawl to also see Transit Gateway route table propagations"
TGW_SOURCES = ("ec2:DescribeRouteTables", "ec2:DescribeTransitGatewayAttachments")
# Error codes of a denied call (EC2 answers UnauthorizedOperation).
DENIED_CODES = ("AccessDenied", "UnauthorizedOperation")
TGW_DENIED = "Transit Gateway links may be incomplete: {what} was denied access."


def _tgw_denials(warnings: Sequence[Any]) -> list[str]:
    return [
        str(w)
        for w in warnings
        if str(w).startswith(TGW_SOURCES) and any(c in str(w) for c in DENIED_CODES)
    ]


def _tgw_line(label: str, text: str) -> dict[str, str]:
    return {"evidence": "configured", "label": label, "text": text}


def _discovered_tgw_lines(
    conn: sqlite3.Connection, snap_id: int, vpc_id: str
) -> dict[tuple[str, str], list[dict[str, str]]]:
    """``{(source node, TGW id): [lines]}`` from discovery: each Transit Gateway
    attachment ENI of the VPC -> its TGW (an attachment of the VPC without an ENI found:
    the VPC box), each subnet -> the TGWs its route table (explicit, else the VPC's main
    one) routes to."""
    out: dict[tuple[str, str], list[dict[str, str]]] = {}
    atts = {
        r["attachment_id"]: r
        for r in conn.execute(
            "SELECT attachment_id, tgw_id, resource_type, resource_id, state "
            "FROM tgw_attachments WHERE snapshot_id=? ORDER BY attachment_id",
            (snap_id,),
        )
    }
    own = [a for a in atts.values() if a["resource_type"] == "vpc" and a["resource_id"] == vpc_id]
    linked: set[str] = set()
    for e in conn.execute(
        "SELECT eni_id, owner_ref FROM enis WHERE snapshot_id=? AND vpc_id=? "
        "AND owner_type='tgw_attachment' ORDER BY eni_id",
        (snap_id, vpc_id),
    ):
        # The ENI's description names its attachment; without it, the VPC's only one.
        ref = e["owner_ref"] or ""
        att = atts.get(ref) if ref else (own[0] if len(own) == 1 else None)
        if att is None:
            continue
        linked.add(att["attachment_id"])
        text = f"TGW attachment {att['attachment_id']} ({att['state'] or '?'})"
        out.setdefault((f"res:{e['eni_id']}", att["tgw_id"]), []).append(
            _tgw_line("attachment", text)
        )
    for a in own:
        if a["attachment_id"] not in linked:
            text = f"TGW attachment {a['attachment_id']} ({a['state'] or '?'}), no ENI found"
            out.setdefault((VPC_NODE, a["tgw_id"]), []).append(_tgw_line("attachment", text))

    tables = list(
        conn.execute(
            "SELECT route_table_id, is_main, subnet_ids FROM route_tables "
            "WHERE snapshot_id=? AND vpc_id=?",
            (snap_id, vpc_id),
        )
    )
    main = next((t["route_table_id"] for t in tables if t["is_main"]), None)
    table_of = {s: t["route_table_id"] for t in tables for s in json.loads(t["subnet_ids"] or "[]")}
    routes: dict[str, list[sqlite3.Row]] = {}
    for r in conn.execute(
        "SELECT route_table_id, destination, tgw_id, state FROM tgw_routes "
        "WHERE snapshot_id=? ORDER BY route_table_id, tgw_id, destination",
        (snap_id,),
    ):
        routes.setdefault(r["route_table_id"], []).append(r)
    for s in conn.execute(
        "SELECT subnet_id FROM subnets WHERE snapshot_id=? AND vpc_id=? ORDER BY subnet_id",
        (snap_id, vpc_id),
    ):
        rtb = table_of.get(s["subnet_id"], main)
        for r in routes.get(rtb or "", []):
            state = f" ({r['state']})" if r["state"] not in ("", "active", None) else ""
            text = f"route table {rtb}: {r['destination']} → {r['tgw_id']}{state}"
            out.setdefault((f"subnet:{s['subnet_id']}", r["tgw_id"]), []).append(
                _tgw_line("route", text)
            )
    return out


_TGW_LINE_IDS = re.compile(r"\b(?:tgw-attach|rtb)-\w+")


def _crawl_tgw_lines(
    conn: sqlite3.Connection, snap_id: int, vpc_id: str, known: set[str]
) -> dict[tuple[str, str], list[dict[str, str]]]:
    """``{("vpc", TGW id): [lines]}`` of the Extended crawl (VPC -> TGW evidence), without
    the lines discovery already draws: attachment / route lines whose attachment or
    route table ids are all in ``known``."""
    out: dict[tuple[str, str], list[dict[str, str]]] = {}
    for r in conn.execute(
        "SELECT target, evidence, label, detail FROM ext_edges WHERE snapshot_id=? "
        "AND source=? AND target LIKE 'tgw:%' ORDER BY target, label, detail",
        (snap_id, f"vpc:{vpc_id}"),
    ):
        ids = set(_TGW_LINE_IDS.findall(r["detail"]))
        if r["label"] in ("attachment", "route") and ids and ids <= known:
            continue
        out.setdefault((VPC_NODE, r["target"].partition(":")[2]), []).append(
            {"evidence": r["evidence"], "label": r["label"], "text": r["detail"]}
        )
    return out


def _tgw_node(tgw_id: str) -> dict[str, Any]:
    return {
        "id": f"{EXT_PREFIX}tgw:{tgw_id}",
        "node_id": f"tgw:{tgw_id}",
        "service": "tgw",
        "service_label": SERVICE_LABELS["tgw"],
        "name": tgw_id,
        "label_name": tgw_id,
        "arn": "",
        "icon": EXT_ICONS["tgw"],
        "broad_access": False,
        "facts": [],
    }


def _tgw_edge_label(source: str, items: list[dict[str, str]]) -> str:
    """An attachment ENI's edge: "<attachment id> · <state>"; else the line kinds."""
    if source.startswith("res:"):
        m = re.match(r"TGW attachment (\S+) \(([^)]*)\)", items[0]["text"])
        if m:
            return f"{m[1]} · {m[2]}"
    return " · ".join(dict.fromkeys(ln["label"] for ln in items))


def tgw_links(conn: sqlite3.Connection, snap_id: int, vpc_id: str) -> dict[str, Any]:
    """The IP view's Transit Gateway part for one VPC: ``nodes`` (one per TGW, drawn
    outside the VPC box) and ``edges`` to them from discovery (attachment ENI -> TGW,
    labelled with the attachment id and state; subnet -> TGW for its route table's
    routes) and from the Extended crawl when there is one (VPC -> TGW, without the
    lines discovery already draws). ``source`` / ``target`` are diagram node ids
    ("res:<ENI>", "subnet:<id>", "vpc", "x:tgw:<id>"). ``note`` / ``warnings``: no crawl
    yet, or discovery or the crawl was denied DescribeRouteTables /
    DescribeTransitGatewayAttachments (the links may then be incomplete)."""
    snap = conn.execute("SELECT warnings FROM snapshots WHERE id=?", (snap_id,)).fetchone()
    found = _tgw_denials(json.loads((snap and snap["warnings"]) or "[]"))
    lines = _discovered_tgw_lines(conn, snap_id, vpc_id)
    crawl = latest_crawl(conn, snap_id)
    crawled: list[str] = []
    if crawl is not None:
        crawled = _tgw_denials(crawl["warnings"])
        known = {
            i for items in lines.values() for ln in items for i in _TGW_LINE_IDS.findall(ln["text"])
        }
        for key, items in _crawl_tgw_lines(conn, snap_id, vpc_id, known).items():
            lines.setdefault(key, []).extend(items)
    edges = []
    for i, ((source, tgw), items) in enumerate(sorted(lines.items())):
        edges.append(
            {
                "id": f"tgw:{i}",
                "type": "tgw",
                "source": source,
                "target": f"{EXT_PREFIX}tgw:{tgw}",
                "label": _tgw_edge_label(source, items),
                "lines": items,
                "title": "\n".join(f"[{ln['label']}] {ln['text']}" for ln in items),
            }
        )
    notes = []
    if found:
        notes.append(TGW_DENIED.format(what="discovery"))
    if crawl is None:
        notes.append(TGW_NO_CRAWL)
    elif crawled:
        notes.append(TGW_DENIED.format(what="the Extended crawl"))
    return {
        "nodes": [_tgw_node(t) for t in sorted({tgw for _source, tgw in lines})],
        "edges": edges,
        "note": " ".join(notes),
        "warnings": found + crawled,
    }


def _iter_resources(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for s in data["vpc"]["subnets"]:
        for item in s["items"]:
            if item["kind"] == "group":
                yield from item["members"]
            else:
                yield item


def annotate_base_edges(edges: list[dict[str, Any]]) -> None:
    """Give the IP view's edges an evidence level and evidence lines (in place); the
    lines of a blocked / unverified edge carry its access reasons and every line its
    ``state``."""
    for e in edges:
        level = BASE_EVIDENCE.get(e["type"], "configured")
        e["evidence"] = level
        blocked = bool(e.get("blocked"))
        state = e.get("state") or (access.BLOCKED if blocked else access.VERIFIED)
        why = " · " + "; ".join(e.get("access") or []) if state != access.VERIFIED else ""
        e["lines"] = [
            {
                "evidence": level,
                "label": e["label"],
                "text": line + why,
                "blocked": blocked,
                "state": state,
            }
            for line in (e.get("title") or e["label"]).split("\n")
        ]


def _ext_access(
    iam: access.IamIndex,
    path: access.PathCheck,
    arns: dict[str, str],
    source: str,
    target: str,
    drawn_source: str,
) -> access.Verdict | None:
    """The verdict of a crawled connection (e.g. a function sending to a queue): IAM, KMS
    and SCPs and, when the sender is drawn as one of its VPC ENIs, the route (and the
    NACLs to the VPC endpoint) to the service. An event source mapping (queue ->
    function) is polled by the Lambda service, not over the function's ENI."""
    req = access.ext_request(source, target)
    if req is None or not arns.get(req[2]):
        return None
    holder, action, resource = req
    identity = iam.check(holder, action, arns[resource]) or access.not_checked(
        access.IAM, f"IAM: {action} not checked (run the Extended crawl)"
    )
    network = None
    if holder == source and not drawn_source.startswith(EXT_PREFIX):
        network = path.to_service(drawn_source, resource.partition(":")[0]) or (
            access.not_checked(access.ROUTE, "route not checked (run the Extended crawl)")
        )
    return access.combine([identity, network])


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


def extended_data(
    conn: sqlite3.Connection,
    snap_id: int,
    data: dict[str, Any],
    env_keys: Sequence[str] = environment.DEFAULT_TAG_KEYS,
) -> dict[str, Any]:
    """The ``extended`` part of the Visual page data for the VPC in ``data``."""
    vpc_id = data["vpc"]["vpc_id"]
    envs = environment.EnvResolver(conn, snap_id, env_keys)

    def env_of(service: str, name: str) -> str:
        if service in ENV_KEYS:
            tf_kind, tag_type = ENV_KEYS[service]
            return envs.for_resource(tf_kind, tag_type, name)
        return environment.NOT_SET

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

    iam = access.IamIndex(conn, snap_id)
    path = access.PathCheck(conn, snap_id, None)
    arns = {
        r["node_id"]: r["arn"]
        for r in conn.execute("SELECT node_id, arn FROM ext_nodes WHERE snapshot_id=?", (snap_id,))
    }
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
        verdict = _ext_access(iam, path, arns, source, target, s)
        # A line without a verdict (not an access-checked connection) has no state.
        line = {"evidence": evidence, "label": label, "text": detail, "blocked": False}
        if verdict is not None:
            line["blocked"] = not verdict.allowed
            line["blocked_by"] = verdict.layers
            line["state"] = access.state(verdict)
            line["text"] += " · " + "; ".join(access.reasons(verdict))
        edge["lines"].append(line)
        used.update(x[len(EXT_PREFIX) :] for x in (s, t) if x.startswith(EXT_PREFIX))
    edges = []
    for edge in merged.values():
        edge["lines"].sort(key=lambda ln: (EVIDENCE_RANK[ln["evidence"]], ln["text"]))
        best = edge["lines"][0]
        edge["evidence"] = best["evidence"]
        edge["label"] = best["label"]
        edge["blocked"] = all(ln["blocked"] for ln in edge["lines"])
        edge["blocked_by"] = list(
            dict.fromkeys(
                x for ln in edge["lines"] if edge["blocked"] for x in ln.get("blocked_by") or []
            )
        )
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

    def node(nid: str) -> dict[str, Any]:
        row = stored.get(nid)
        service, _, name = nid.partition(":")
        if row is not None:
            service, name = row["service"], row["name"]
        flow = FLOW_NODES.get(name) if service == "internet" else None
        label = {"nat": "Internet via NAT", "igw": "Internet (IGW)"}.get(name, name)
        if flow:
            label = f"Internet / outside: {flow[1]}"
        elif service == "kafka":
            label = f"Kafka: {name}"
        return {
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
            "environment": env_of(service, name),
        }

    nodes = [node(nid) for nid in sorted(used)]
    # Crawled, but linked to nothing drawn for this VPC: listed in the side panel and
    # drawn on demand ("show all crawled nodes"), never linked.
    hidden = sorted(
        (node(nid) for nid in set(stored) - used),
        key=lambda n: (n["service_label"], n["label_name"].lower()),
    )
    for n in hidden:
        n["linked"] = False

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
        "hidden_nodes": len(hidden),
        "hidden": hidden[:MAX_HIDDEN_LISTED],
        "subnet_facts": {
            k.split(":", 1)[1]: v for k, v in facts.items() if k.startswith("subnet:")
        },
        "environments": environment.summary(n["environment"] for n in nodes),
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
