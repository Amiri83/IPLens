"""Export of the Visual page's current view as SVG or draw.io (mxGraph XML).

The browser posts the view exactly as drawn (see ``currentView`` in static/visual.js):
every visible node with its absolute top-left position and size, its parent box,
label and icon, plus every visible edge and the border toggles. Both exporters work
from that description only, so collapsed groups, edge filters, dragged positions
and hidden borders are reproduced as-is. Output is built with ElementTree, so all
text is XML-escaped and the documents are well-formed.
"""

from __future__ import annotations

import base64
import html
import json
import math
import re
import xml.etree.ElementTree as ET  # noqa: S405 - building XML only, never parsing
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from .queries import LB_ICONS, TYPE_ICONS, VPC_ICON
from .visual import EDGE_TYPES

ICON_DIR = Path(__file__).parent / "static" / "icons" / "aws"
ALLOWED_ICONS = frozenset({*TYPE_ICONS.values(), *LB_ICONS.values(), VPC_ICON})
NODE_KINDS = ("vpc", "subnet", "res", "group")
CONTAINER_KINDS = ("vpc", "subnet")

MAX_NODES = 5000
MAX_EDGES = 20000
MAX_LABEL = 600
MAX_COORD = 1e7

# Colours and sizes mirror the cytoscape style in static/visual.js.
VPC_STROKE, VPC_FILL = "#8c4fff", "#f7f3ff"
SUBNET_STROKE, SUBNET_FILL = "#7aa116", "#ffffff"
IDLE_STROKE, GROUP_STROKE = "#e8a33a", "#2457c5"
TEXT = "#1f2933"
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
FONT_SIZE = {"vpc": 14, "subnet": 11, "res": 10, "group": 10}
EDGE_STYLES: dict[str, dict[str, Any]] = {
    "targets": {"color": "#2457c5", "width": 2, "dash": "", "head": "triangle"},
    "ecs_lb": {"color": "#2f8f4e", "width": 2, "dash": "", "head": "triangle"},
    "reach": {"color": "#b0469b", "width": 1.6, "dash": "3 3", "head": "vee"},
    "sg": {"color": "#8a94a3", "width": 1.2, "dash": "6 4", "head": "vee"},
}


# -- view model -----------------------------------------------------------------------


@dataclass
class ViewNode:
    id: str
    kind: str
    label: str
    x: float
    y: float
    w: float
    h: float
    parent: str | None = None
    icon: str = ""
    idle: bool = False

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2


@dataclass
class ViewEdge:
    source: str
    target: str
    type: str
    label: str = ""


@dataclass
class View:
    vpc_id: str = ""
    show_vpc: bool = True
    show_subnets: bool = True
    nodes: list[ViewNode] = field(default_factory=list)
    edges: list[ViewEdge] = field(default_factory=list)


def _num(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError(f"{what} must be a finite number")
    if abs(value) > MAX_COORD:
        raise ValueError(f"{what} is out of range")
    return float(value)


def _text(value: Any, limit: int = MAX_LABEL) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("labels must be strings")
    return value[:limit]


def parse_view(raw: str) -> View:
    """Validate the JSON view posted by the Visual page; raise ValueError if bad."""
    try:
        doc = json.loads(raw or "")
    except ValueError:
        raise ValueError("view must be JSON") from None
    if not isinstance(doc, dict):
        raise ValueError("view must be a JSON object")
    raw_nodes, raw_edges = doc.get("nodes") or [], doc.get("edges") or []
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise ValueError("nodes and edges must be lists")
    if len(raw_nodes) > MAX_NODES or len(raw_edges) > MAX_EDGES:
        raise ValueError("view is too large")
    view = View(
        vpc_id=_text(doc.get("vpc_id"), 64),
        show_vpc=doc.get("show_vpc", True) is not False,
        show_subnets=doc.get("show_subnets", True) is not False,
    )
    seen: dict[str, ViewNode] = {}
    for n in raw_nodes:
        if not isinstance(n, dict):
            raise ValueError("nodes must be objects")
        node_id = _text(n.get("id"), 200)
        if not node_id or node_id in seen:
            raise ValueError("node ids must be unique and non-empty")
        kind = n.get("kind")
        if kind not in NODE_KINDS:
            raise ValueError(f"node kind must be one of {', '.join(NODE_KINDS)}")
        icon = _text(n.get("icon"), 120)
        if icon and icon not in ALLOWED_ICONS:
            raise ValueError("unknown icon")
        node = ViewNode(
            id=node_id,
            kind=kind,
            label=_text(n.get("label")),
            x=_num(n.get("x"), "x"),
            y=_num(n.get("y"), "y"),
            w=max(_num(n.get("w"), "w"), 1.0),
            h=max(_num(n.get("h"), "h"), 1.0),
            parent=_text(n.get("parent"), 200) or None,
            icon=icon,
            idle=n.get("idle") is True,
        )
        seen[node_id] = node
        view.nodes.append(node)
    for node in view.nodes:
        parent = seen.get(node.parent or "")
        if node.parent and (parent is None or parent.kind not in CONTAINER_KINDS):
            raise ValueError("a node's parent must be a VPC or subnet node of the view")
    for e in raw_edges:
        if not isinstance(e, dict):
            raise ValueError("edges must be objects")
        edge = ViewEdge(
            source=_text(e.get("source"), 200),
            target=_text(e.get("target"), 200),
            type=e.get("type") if e.get("type") in EDGE_TYPES else "",
            label=_text(e.get("label"), 200),
        )
        if not edge.type:
            raise ValueError(f"edge type must be one of {', '.join(EDGE_TYPES)}")
        if edge.source not in seen or edge.target not in seen:
            raise ValueError("edges must connect nodes of the view")
        view.edges.append(edge)
    return view


def export_filename(view: View, ext: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "", view.vpc_id) or "diagram"
    return f"iplens-{safe}.{ext}"


def _depth(node: ViewNode, by_id: dict[str, ViewNode]) -> int:
    d = 0
    while node.parent and d < 10:
        node = by_id[node.parent]
        d += 1
    return d


def _ordered(view: View) -> list[ViewNode]:
    """Parents before children (draw order and draw.io's parent-first requirement)."""
    by_id = {n.id: n for n in view.nodes}
    return sorted(view.nodes, key=lambda n: _depth(n, by_id))


# -- SVG ------------------------------------------------------------------------------


@cache
def _icon_data_uri(name: str) -> str:
    data = (ICON_DIR / name).read_bytes()
    return "data:image/svg+xml;base64," + base64.b64encode(data).decode("ascii")


def _line_height(kind: str) -> float:
    return FONT_SIZE[kind] * 1.25


def _lines(label: str) -> list[str]:
    return label.split("\n") if label else []


def _clip(node: ViewNode, toward_x: float, toward_y: float) -> tuple[float, float]:
    """Where the segment from the node centre toward (x, y) leaves the node's box."""
    dx, dy = toward_x - node.cx, toward_y - node.cy
    if dx == 0 and dy == 0:
        return node.cx, node.cy
    tx = (node.w / 2) / abs(dx) if dx else math.inf
    ty = (node.h / 2) / abs(dy) if dy else math.inf
    t = min(tx, ty, 1.0)
    return node.cx + dx * t, node.cy + dy * t


def _fmt(v: float) -> str:
    return f"{v:.1f}".rstrip("0").rstrip(".")


def _text_el(
    parent: ET.Element, x: float, y: float, lines: list[str], kind: str, *, anchor="middle"
) -> None:
    if not lines:
        return
    fs = FONT_SIZE[kind]
    t = ET.SubElement(
        parent,
        "text",
        {
            "x": _fmt(x),
            "y": _fmt(y),
            "font-size": str(fs),
            "text-anchor": anchor,
            "fill": TEXT,
            "font-family": FONT,
        },
    )
    if kind == "vpc":
        t.set("font-weight", "bold")
    for i, line in enumerate(lines):
        span = ET.SubElement(t, "tspan", {"x": _fmt(x)})
        if i:
            span.set("dy", _fmt(_line_height(kind)))
        span.text = line


def view_to_svg(view: View) -> str:
    """Standalone SVG document of the view (icons embedded as data URIs)."""
    nodes = _ordered(view)
    by_id = {n.id: n for n in nodes}
    pad = 20.0
    if nodes:
        x0 = min(n.x for n in nodes) - pad
        x1 = max(n.x + n.w for n in nodes) + pad
        y0 = min(
            n.y - (len(_lines(n.label)) + 1) * _line_height(n.kind)
            if n.kind in CONTAINER_KINDS
            else n.y
            for n in nodes
        )
        y0 -= pad
        y1 = max(
            n.y + n.h + (len(_lines(n.label)) + 1) * _line_height(n.kind)
            if n.kind not in CONTAINER_KINDS
            else n.y + n.h
            for n in nodes
        )
        y1 += pad
    else:
        x0, y0, x1, y1 = 0.0, 0.0, 100.0, 100.0
    w, h = x1 - x0, y1 - y0
    svg = ET.Element(
        "svg",
        {
            "xmlns": "http://www.w3.org/2000/svg",
            "xmlns:xlink": "http://www.w3.org/1999/xlink",
            "version": "1.1",
            "width": _fmt(w),
            "height": _fmt(h),
            "viewBox": f"{_fmt(x0)} {_fmt(y0)} {_fmt(w)} {_fmt(h)}",
        },
    )
    ET.SubElement(svg, "title").text = f"IPLens {view.vpc_id}".strip()
    defs = ET.SubElement(svg, "defs")
    for etype, st in EDGE_STYLES.items():
        marker = ET.SubElement(
            defs,
            "marker",
            {
                "id": f"arrow-{etype}",
                "viewBox": "0 0 10 10",
                "refX": "10",
                "refY": "5",
                "markerWidth": "7",
                "markerHeight": "7",
                "orient": "auto",
            },
        )
        d = "M0,0 L10,5 L0,10 z" if st["head"] == "triangle" else "M0,0 L10,5 L0,10 L3,5 z"
        ET.SubElement(marker, "path", {"d": d, "fill": st["color"]})
    ET.SubElement(
        svg,
        "rect",
        {"x": _fmt(x0), "y": _fmt(y0), "width": _fmt(w), "height": _fmt(h), "fill": "#ffffff"},
    )

    boxes = ET.SubElement(svg, "g", {"class": "boxes"})
    for n in nodes:
        if n.kind not in CONTAINER_KINDS:
            continue
        shown = view.show_vpc if n.kind == "vpc" else view.show_subnets
        g = ET.SubElement(boxes, "g", {"class": n.kind, "data-id": n.id})
        if shown:
            stroke, fill = (
                (VPC_STROKE, VPC_FILL) if n.kind == "vpc" else (SUBNET_STROKE, SUBNET_FILL)
            )
            ET.SubElement(
                g,
                "rect",
                {
                    "x": _fmt(n.x),
                    "y": _fmt(n.y),
                    "width": _fmt(n.w),
                    "height": _fmt(n.h),
                    "fill": fill,
                    "stroke": stroke,
                    "stroke-width": "2" if n.kind == "vpc" else "1.5",
                },
            )
            if n.icon:
                _image(g, n.icon, n.x, n.y, 32, 32)
        lines = _lines(n.label)
        margin = 6 if n.kind == "vpc" else 4
        first = n.y - margin - (len(lines) - 1) * _line_height(n.kind) - 3
        _text_el(g, n.cx, first, lines, n.kind)

    edges = ET.SubElement(svg, "g", {"class": "edges"})
    for e in view.edges:
        s, t = by_id[e.source], by_id[e.target]
        st = EDGE_STYLES[e.type]
        sx, sy = _clip(s, t.cx, t.cy)
        tx, ty = _clip(t, s.cx, s.cy)
        g = ET.SubElement(edges, "g", {"class": f"edge edge-{e.type}"})
        attrs = {
            "x1": _fmt(sx),
            "y1": _fmt(sy),
            "x2": _fmt(tx),
            "y2": _fmt(ty),
            "stroke": st["color"],
            "stroke-width": str(st["width"]),
            "marker-end": f"url(#arrow-{e.type})",
        }
        if st["dash"]:
            attrs["stroke-dasharray"] = st["dash"]
        ET.SubElement(g, "line", attrs)
        if e.label:
            mx, my = (sx + tx) / 2, (sy + ty) / 2
            lw = len(e.label) * 5.2 + 4
            ET.SubElement(
                g,
                "rect",
                {
                    "x": _fmt(mx - lw / 2),
                    "y": _fmt(my - 7),
                    "width": _fmt(lw),
                    "height": "12",
                    "fill": "#ffffff",
                    "fill-opacity": "0.85",
                },
            )
            label = ET.SubElement(
                g,
                "text",
                {
                    "x": _fmt(mx),
                    "y": _fmt(my + 3),
                    "font-size": "9",
                    "text-anchor": "middle",
                    "fill": TEXT,
                    "font-family": FONT,
                },
            )
            label.text = e.label

    leaves = ET.SubElement(svg, "g", {"class": "nodes"})
    for n in nodes:
        if n.kind in CONTAINER_KINDS:
            continue
        g = ET.SubElement(leaves, "g", {"class": n.kind, "data-id": n.id})
        ET.SubElement(
            g,
            "rect",
            {
                "x": _fmt(n.x),
                "y": _fmt(n.y),
                "width": _fmt(n.w),
                "height": _fmt(n.h),
                "rx": "6",
                "fill": "#ffffff",
            },
        )
        if n.icon:
            _image(g, n.icon, n.x, n.y, n.w, n.h)
        if n.kind == "group":
            for inset in (0.0, 3.0):
                _outline(g, n, inset, GROUP_STROKE, 1)
        elif n.idle:
            _outline(g, n, 0.0, IDLE_STROKE, 3)
        _text_el(g, n.cx, n.y + n.h + 5 + FONT_SIZE[n.kind], _lines(n.label), n.kind)

    ET.indent(svg)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(svg, encoding="unicode")


def _image(parent: ET.Element, icon: str, x: float, y: float, w: float, h: float) -> None:
    uri = _icon_data_uri(icon)
    ET.SubElement(
        parent,
        "image",
        {
            "x": _fmt(x),
            "y": _fmt(y),
            "width": _fmt(w),
            "height": _fmt(h),
            "href": uri,
            "xlink:href": uri,
            "preserveAspectRatio": "xMidYMid meet",
        },
    )


def _outline(parent: ET.Element, n: ViewNode, inset: float, color: str, width: float) -> None:
    ET.SubElement(
        parent,
        "rect",
        {
            "x": _fmt(n.x + inset),
            "y": _fmt(n.y + inset),
            "width": _fmt(n.w - 2 * inset),
            "height": _fmt(n.h - 2 * inset),
            "rx": "6",
            "fill": "none",
            "stroke": color,
            "stroke-width": str(width),
        },
    )


# -- draw.io --------------------------------------------------------------------------

_DRAWIO_RES = (
    "sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;strokeColor=#ffffff;"
    "dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;"
    "fontSize=10;fontStyle=0;aspect=fixed;"
)
_RES_ICON = "shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4."
_COMPUTE, _NETWORK, _DATABASE = "#ED7100", "#8C4FFF", "#C925D1"
# Icon file (as used on the Visual page) -> draw.io AWS 4 shape.
DRAWIO_SHAPES = {
    TYPE_ICONS["vpc_endpoint"]: f"shape=mxgraph.aws4.endpoints;fillColor={_NETWORK};",
    TYPE_ICONS["elb"]: f"{_RES_ICON}elastic_load_balancing;fillColor={_NETWORK};",
    TYPE_ICONS["nat"]: f"shape=mxgraph.aws4.nat_gateway;fillColor={_NETWORK};",
    TYPE_ICONS["lambda"]: f"{_RES_ICON}lambda;fillColor={_COMPUTE};",
    TYPE_ICONS["ecs"]: f"{_RES_ICON}ecs;fillColor={_COMPUTE};",
    TYPE_ICONS["ec2"]: f"{_RES_ICON}ec2;fillColor={_COMPUTE};",
    TYPE_ICONS["rds"]: f"{_RES_ICON}rds;fillColor={_DATABASE};",
    TYPE_ICONS["elasticache"]: f"{_RES_ICON}elasticache;fillColor={_DATABASE};",
    TYPE_ICONS["opensearch"]: f"{_RES_ICON}elasticsearch_service;fillColor={_NETWORK};",
    TYPE_ICONS["other"]: f"shape=mxgraph.aws4.elastic_network_interface;fillColor={_NETWORK};",
    LB_ICONS["application"]: f"shape=mxgraph.aws4.application_load_balancer;fillColor={_NETWORK};",
    LB_ICONS["network"]: f"shape=mxgraph.aws4.network_load_balancer;fillColor={_NETWORK};",
    LB_ICONS["gateway"]: f"shape=mxgraph.aws4.gateway_load_balancer;fillColor={_NETWORK};",
}
_DRAWIO_GROUP = (
    "points=[[0,0],[0.25,0],[0.5,0],[0.75,0],[1,0],[1,0.25],[1,0.5],[1,0.75],[1,1],"
    "[0.75,1],[0.5,1],[0.25,1],[0,1],[0,0.75],[0,0.5],[0,0.25]];outlineConnect=0;"
    "gradientColor=none;html=1;whiteSpace=wrap;fontSize=12;fontStyle=0;container=1;"
    "pointerEvents=0;collapsible=0;recursiveResize=0;shape=mxgraph.aws4.group;"
    "verticalAlign=top;align=left;spacingLeft=30;dashed=0;"
)
DRAWIO_VPC = (
    f"{_DRAWIO_GROUP}grIcon=mxgraph.aws4.group_vpc2;strokeColor=#8C4FFF;fillColor=none;"
    "fontColor=#AAB7B8;"
)
DRAWIO_SUBNET = (
    f"{_DRAWIO_GROUP}grIcon=mxgraph.aws4.group_security_group;grStroke=0;"
    "strokeColor=#7AA116;fillColor=#F2F6E8;fontColor=#248814;"
)
DRAWIO_HIDDEN_BOX = "strokeColor=none;fillColor=none;grIcon=none;"
DRAWIO_EDGE = "html=1;rounded=0;edgeStyle=none;fontSize=9;labelBackgroundColor=#FFFFFF;"
DRAWIO_EDGE_STYLES = {
    "targets": "endArrow=block;endFill=1;strokeColor=#2457C5;strokeWidth=2;",
    "ecs_lb": "endArrow=block;endFill=1;strokeColor=#2F8F4E;strokeWidth=2;",
    "reach": "endArrow=open;dashed=1;dashPattern=3 3;strokeColor=#B0469B;strokeWidth=1.6;",
    "sg": "endArrow=open;dashed=1;dashPattern=6 4;strokeColor=#8A94A3;strokeWidth=1.2;",
}


def _html_value(label: str) -> str:
    return "<br>".join(html.escape(line) for line in _lines(label))


def drawio_style(node: ViewNode, view: View) -> str:
    if node.kind == "vpc":
        return DRAWIO_VPC + ("" if view.show_vpc else DRAWIO_HIDDEN_BOX)
    if node.kind == "subnet":
        return DRAWIO_SUBNET + ("" if view.show_subnets else DRAWIO_HIDDEN_BOX)
    style = _DRAWIO_RES + DRAWIO_SHAPES.get(node.icon, DRAWIO_SHAPES[TYPE_ICONS["other"]])
    if node.kind == "group":
        style += "fontStyle=1;"
    if node.idle:
        style += "labelBorderColor=#E8A33A;"
    return style


def view_to_drawio(view: View) -> str:
    """draw.io file: VPC and subnets are containers, resources are mxgraph.aws4 shapes."""
    nodes = _ordered(view)
    by_id = {n.id: n for n in nodes}
    cell_ids = {n.id: f"n{i}" for i, n in enumerate(nodes, 1)}
    mxfile = ET.Element("mxfile", {"host": "IPLens", "type": "device"})
    diagram = ET.SubElement(mxfile, "diagram", {"id": "iplens", "name": view.vpc_id or "IPLens"})
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        {
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "0",
            "pageScale": "1",
            "math": "0",
            "shadow": "0",
        },
    )
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
    for n in nodes:
        parent = by_id.get(n.parent or "")
        # mxGraph child geometry is relative to the parent container's top-left corner.
        x, y = (n.x - parent.x, n.y - parent.y) if parent else (n.x, n.y)
        cell = ET.SubElement(
            root,
            "mxCell",
            {
                "id": cell_ids[n.id],
                "value": _html_value(n.label),
                "style": drawio_style(n, view),
                "vertex": "1",
                "parent": cell_ids[parent.id] if parent else "1",
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": _fmt(x),
                "y": _fmt(y),
                "width": _fmt(n.w),
                "height": _fmt(n.h),
                "as": "geometry",
            },
        )
    for i, e in enumerate(view.edges, 1):
        cell = ET.SubElement(
            root,
            "mxCell",
            {
                "id": f"e{i}",
                "value": html.escape(e.label),
                "style": DRAWIO_EDGE + DRAWIO_EDGE_STYLES[e.type],
                "edge": "1",
                "parent": "1",
                "source": cell_ids[e.source],
                "target": cell_ids[e.target],
            },
        )
        ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
    ET.indent(mxfile)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(mxfile, encoding="unicode")
