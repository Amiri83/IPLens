"""Export of the Visual page's current view as SVG or draw.io (mxGraph XML).

The browser posts the view exactly as drawn (see ``currentView`` in static/visual.js):
every visible node with its absolute top-left position and size, its parent box,
label and icon, plus every visible edge and the border toggles. Both exporters work
from that description only, so edge filters, dragged positions and hidden borders
are reproduced as-is. Output is built with ElementTree, so all text is XML-escaped
and the documents are well-formed.

With ``expand_groups`` (the "Expand all groups" export option) each collapsed group
node carries its ``members``; :func:`expand_groups` replaces the group box with the
member nodes, laid out in rows appended to the group's subnet (everything below is
moved down). Context boxes (``ctx``: "Group by" security group / tag / Terraform
root) are dashed boxes around their ``members`` and are refitted after expansion.

The Extended view (``mode: "extended"``) adds ``area`` containers drawn beside the
VPC ("Regional services", "External") holding service / gateway nodes, and edges typed
by their strongest evidence level (``ev_observed`` ... ``ev_referenced``).
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

from .extended import EVIDENCE_LEVELS
from .extgraph import EXT_ICONS
from .queries import LB_ICONS, TYPE_ICONS, VPC_ICON
from .visual import EDGE_TYPES

ICON_ROOT = Path(__file__).parent / "static" / "icons"
ICON_DIR = ICON_ROOT / "aws"
ALLOWED_ICONS = frozenset({*TYPE_ICONS.values(), *LB_ICONS.values(), VPC_ICON, *EXT_ICONS.values()})
# Extended view: "area" boxes ("Regional services", "External") sit beside the VPC.
NODE_KINDS = ("vpc", "subnet", "res", "group", "ctx", "area")
CONTAINER_KINDS = ("vpc", "subnet", "area")
# Extended view edges are drawn by their strongest evidence level.
EXT_EDGE_TYPES = tuple(f"ev_{level}" for level in EVIDENCE_LEVELS)
ALL_EDGE_TYPES = EDGE_TYPES + EXT_EDGE_TYPES
VIEW_MODES = ("ip", "extended")
LEAF_KINDS = ("res", "group")

MAX_NODES = 5000
MAX_EDGES = 20000
MAX_LABEL = 600
MAX_COORD = 1e7
MAX_MEMBERS = 5000
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# Expanded group members: grid cells sized like the Visual page's grid layout.
EXPAND_CELL_W, EXPAND_CELL_H, EXPAND_COLS, EXPAND_PAD = 190.0, 120.0, 4, 28.0
CTX_PAD = 12.0

# Colours and sizes mirror the cytoscape style in static/visual.js.
VPC_STROKE, VPC_FILL = "#8c4fff", "#f7f3ff"
SUBNET_STROKE, SUBNET_FILL = "#7aa116", "#ffffff"
IDLE_STROKE, GROUP_STROKE = "#e8a33a", "#2457c5"
CTX_STROKE = "#5b6573"
AREA_STROKE, AREA_FILL = "#5b6573", "#f6f7f9"
TEXT = "#1f2933"
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
FONT_SIZE = {"vpc": 14, "subnet": 11, "res": 10, "group": 10, "ctx": 10, "area": 12}
EDGE_STYLES: dict[str, dict[str, Any]] = {
    "targets": {"color": "#2457c5", "width": 2, "dash": "", "head": "triangle"},
    "ecs_lb": {"color": "#2f8f4e", "width": 2, "dash": "", "head": "triangle"},
    "reach": {"color": "#b0469b", "width": 1.6, "dash": "3 3", "head": "vee"},
    "sg": {"color": "#8a94a3", "width": 1.2, "dash": "6 4", "head": "vee"},
    # Extended view evidence levels (mirrors the ev-* styles in static/visual.js).
    "ev_observed": {"color": "#1a7f37", "width": 3, "dash": "", "head": "triangle"},
    "ev_configured": {"color": "#2457c5", "width": 2, "dash": "", "head": "triangle"},
    "ev_permitted": {"color": "#c2410c", "width": 1.8, "dash": "7 4", "head": "vee"},
    "ev_referenced": {"color": "#6b7280", "width": 1.5, "dash": "2 3", "head": "vee"},
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
    color: str = ""  # outline (res/group) or box colour (ctx), "#rrggbb"
    members: list[ViewNode] = field(default_factory=list)  # group: its resources
    member_ids: list[str] = field(default_factory=list)  # ctx: resource node ids inside

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2

    @property
    def bottom(self) -> float:
        return self.y + self.h

    def label_height(self) -> float:
        """Height of the label drawn under a leaf node."""
        return 5 + len(_lines(self.label)) * _line_height(self.kind)

    def label_width(self) -> float:
        return max((len(line) for line in _lines(self.label)), default=0) * 6.0


@dataclass
class ViewEdge:
    source: str
    target: str
    type: str
    label: str = ""


@dataclass
class View:
    vpc_id: str = ""
    mode: str = "ip"  # ip | extended
    show_vpc: bool = True
    show_subnets: bool = True
    expand_groups: bool = False
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
        mode=doc.get("mode") if doc.get("mode") in VIEW_MODES else "ip",
        show_vpc=doc.get("show_vpc", True) is not False,
        show_subnets=doc.get("show_subnets", True) is not False,
        expand_groups=doc.get("expand_groups") is True,
    )
    seen: dict[str, ViewNode] = {}
    members: dict[str, ViewNode] = {}  # group members, drawable only after expansion
    n_members = 0

    def claim(node_id: str) -> None:
        if not node_id or node_id in seen or node_id in members:
            raise ValueError("node ids must be unique and non-empty")

    for n in raw_nodes:
        node = _parse_node(n)
        claim(node.id)
        if node.kind == "group" and view.expand_groups:
            raw_members = n.get("members") or []
            if not isinstance(raw_members, list):
                raise ValueError("group members must be a list")
            n_members += len(raw_members)
            if n_members > MAX_MEMBERS:
                raise ValueError("view is too large")
            for m in raw_members:
                member = _parse_node(m, kind="res")
                claim(member.id)
                member.parent = node.parent
                node.members.append(member)
                members[member.id] = member
        seen[node.id] = node
        view.nodes.append(node)
    for node in view.nodes:
        parent = seen.get(node.parent or "")
        if node.parent and (parent is None or parent.kind not in CONTAINER_KINDS):
            raise ValueError("a node's parent must be a VPC or subnet node of the view")
        if node.kind == "ctx" and node.parent:
            raise ValueError("a context box cannot have a parent")
    for e in raw_edges:
        if not isinstance(e, dict):
            raise ValueError("edges must be objects")
        edge = ViewEdge(
            source=_text(e.get("source"), 200),
            target=_text(e.get("target"), 200),
            type=e.get("type") if e.get("type") in ALL_EDGE_TYPES else "",
            label=_text(e.get("label"), 200),
        )
        if not edge.type:
            raise ValueError(f"edge type must be one of {', '.join(ALL_EDGE_TYPES)}")
        ends = (
            (seen.get(edge.source) or members.get(edge.source)),
            (seen.get(edge.target) or members.get(edge.target)),
        )
        if None in ends or any(n.kind == "ctx" for n in ends if n):
            raise ValueError("edges must connect nodes of the view")
        view.edges.append(edge)
    if view.expand_groups:
        expand_groups(view)
    return view


def _parse_node(n: Any, kind: str | None = None) -> ViewNode:
    """One posted node (``kind`` forces the kind of group members)."""
    if not isinstance(n, dict):
        raise ValueError("nodes must be objects")
    kind = kind or n.get("kind")
    if kind not in NODE_KINDS:
        raise ValueError(f"node kind must be one of {', '.join(NODE_KINDS)}")
    icon = _text(n.get("icon"), 120)
    if icon and icon not in ALLOWED_ICONS:
        raise ValueError("unknown icon")
    color = _text(n.get("color"), 7)
    if color and not COLOR_RE.match(color):
        raise ValueError("colors must be #rrggbb")
    raw_ids = (n.get("member_ids") or []) if kind == "ctx" else []
    if not isinstance(raw_ids, list) or len(raw_ids) > MAX_MEMBERS:
        raise ValueError("context box members must be a list")
    has_box = kind != "res" or "x" in n  # members may omit their (unknown) position
    return ViewNode(
        id=_text(n.get("id"), 200),
        kind=kind,
        label=_text(n.get("label")),
        x=_num(n.get("x"), "x") if has_box else 0.0,
        y=_num(n.get("y"), "y") if has_box else 0.0,
        w=max(_num(n.get("w", 44), "w"), 1.0),
        h=max(_num(n.get("h", 44), "h"), 1.0),
        parent=_text(n.get("parent"), 200) or None,
        icon=icon,
        idle=n.get("idle") is True,
        color=color,
        member_ids=[_text(i, 200) for i in raw_ids],
    )


# -- "Expand all groups" ----------------------------------------------------------------


def _chain(node: ViewNode, by_id: dict[str, ViewNode]) -> list[ViewNode]:
    """``node``'s ancestors, nearest first."""
    out: list[ViewNode] = []
    while node.parent and node.parent in by_id and len(out) < 10:
        node = by_id[node.parent]
        out.append(node)
    return out


def expand_groups(view: View) -> int:
    """Replace every group node that carries members by its member nodes; returns the
    number of groups expanded.

    Members are laid out in rows of up to EXPAND_COLS appended at the bottom of the
    group's subnet box. The subnet and its ancestors grow by the added height and
    every other node starting below the old bottom moves down by as much, so nothing
    overlaps. Edges into a group keep pointing at the group only if it had no
    members (the browser sends member-level edges when expanding). Context boxes are
    refitted around their member nodes afterwards.
    """
    groups = [n for n in view.nodes if n.kind == "group" and n.members]
    if not groups:
        return 0
    for g in sorted(groups, key=lambda n: (n.y, n.x)):
        by_id = {n.id: n for n in view.nodes}
        parent = by_id.get(g.parent or "")
        box_x, box_w = (parent.x, parent.w) if parent else (g.x, EXPAND_CELL_W * EXPAND_COLS)
        top = parent.bottom if parent else g.bottom + g.label_height()
        cell_w = max(EXPAND_CELL_W, *(m.w + 20 for m in g.members))
        cell_w = max(cell_w, *(m.label_width() + 16 for m in g.members))
        cell_h = max(EXPAND_CELL_H, *(m.h + m.label_height() + 16 for m in g.members))
        fit = int((box_w - 2 * EXPAND_PAD) // cell_w) if parent else EXPAND_COLS
        cols = max(1, min(EXPAND_COLS, len(g.members), fit))
        rows = math.ceil(len(g.members) / cols)
        delta = rows * cell_h
        family = {g.id, *(a.id for a in _chain(g, by_id))}
        below = top - 0.5
        for n in view.nodes:
            if n.id in family or n.kind == "ctx" or n.y < below:
                continue
            # A node inside a box that stays put (e.g. a taller subnet beside this
            # one) stays put with it.
            if all(a.y >= below for a in _chain(n, by_id) if a.id not in family):
                n.y += delta
        for a in _chain(g, by_id):
            a.h += delta
        for i, m in enumerate(g.members):
            col, row = i % cols, i // cols
            m.x = box_x + EXPAND_PAD + col * cell_w + (cell_w - m.w) / 2
            m.y = top - EXPAND_PAD / 2 + row * cell_h
        idx = view.nodes.index(g)
        view.nodes[idx : idx + 1] = g.members
    gone = {g.id for g in groups}
    view.edges = [e for e in view.edges if e.source not in gone and e.target not in gone]
    _refit_context_boxes(view)
    return len(groups)


def _refit_context_boxes(view: View) -> None:
    by_id = {n.id: n for n in view.nodes}
    for box in (n for n in view.nodes if n.kind == "ctx" and n.member_ids):
        inside = [by_id[i] for i in box.member_ids if i in by_id and by_id[i].kind in LEAF_KINDS]
        if not inside:
            continue
        x0 = min(min(n.x, n.cx - n.label_width() / 2) for n in inside) - CTX_PAD
        x1 = max(max(n.x + n.w, n.cx + n.label_width() / 2) for n in inside) + CTX_PAD
        y0 = min(n.y for n in inside) - CTX_PAD - _line_height("ctx")
        y1 = max(n.bottom + n.label_height() for n in inside) + CTX_PAD
        box.x, box.y, box.w, box.h = x0, y0, x1 - x0, y1 - y0


def export_filename(view: View, ext: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "", view.vpc_id) or "diagram"
    suffix = "-extended" if view.mode == "extended" else ""
    return f"iplens-{safe}{suffix}.{ext}"


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
    # Only names from ALLOWED_ICONS get here (checked when the view is parsed).
    data = (ICON_ROOT / name if name.startswith("ext/") else ICON_DIR / name).read_bytes()
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
        shown = {"vpc": view.show_vpc, "subnet": view.show_subnets}.get(n.kind, True)
        g = ET.SubElement(boxes, "g", {"class": n.kind, "data-id": n.id})
        if shown:
            stroke, fill = {
                "vpc": (VPC_STROKE, VPC_FILL),
                "subnet": (SUBNET_STROKE, SUBNET_FILL),
                "area": (AREA_STROKE, AREA_FILL),
            }[n.kind]
            attrs = {
                "x": _fmt(n.x),
                "y": _fmt(n.y),
                "width": _fmt(n.w),
                "height": _fmt(n.h),
                "fill": fill,
                "stroke": stroke,
                "stroke-width": "1.5" if n.kind == "subnet" else "2",
            }
            if n.kind == "area":
                attrs["stroke-dasharray"] = "8 5"
            ET.SubElement(g, "rect", attrs)
            if n.icon:
                _image(g, n.icon, n.x, n.y, 32, 32)
        lines = _lines(n.label)
        margin = 6 if n.kind == "vpc" else 4
        first = n.y - margin - (len(lines) - 1) * _line_height(n.kind) - 3
        _text_el(g, n.cx, first, lines, n.kind)

    contexts = ET.SubElement(svg, "g", {"class": "contexts"})
    for n in nodes:
        if n.kind != "ctx":
            continue
        color = n.color or CTX_STROKE
        g = ET.SubElement(contexts, "g", {"class": "ctx", "data-id": n.id})
        ET.SubElement(
            g,
            "rect",
            {
                "x": _fmt(n.x),
                "y": _fmt(n.y),
                "width": _fmt(n.w),
                "height": _fmt(n.h),
                "rx": "8",
                "fill": color,
                "fill-opacity": "0.05",
                "stroke": color,
                "stroke-width": "1.5",
                "stroke-dasharray": "6 4",
            },
        )
        _text_el(g, n.x + 6, n.y + 12, _lines(n.label), "ctx", anchor="start")

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
        if n.kind not in LEAF_KINDS:
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
        if n.color:
            _outline(g, n, -3.0, n.color, 2)
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
_INTEGRATION, _STORAGE, _SECURITY = "#E7157B", "#7AA116", "#DD344C"
# Extended view service badges -> draw.io AWS 4 shapes.
DRAWIO_SHAPES.update(
    {
        EXT_ICONS["sns"]: f"{_RES_ICON}sns;fillColor={_INTEGRATION};",
        EXT_ICONS["sqs"]: f"{_RES_ICON}sqs;fillColor={_INTEGRATION};",
        EXT_ICONS["dynamodb"]: f"{_RES_ICON}dynamodb;fillColor={_DATABASE};",
        EXT_ICONS["events"]: f"{_RES_ICON}eventbridge;fillColor={_INTEGRATION};",
        EXT_ICONS["s3"]: f"{_RES_ICON}s3;fillColor={_STORAGE};",
        EXT_ICONS["apigateway"]: f"{_RES_ICON}api_gateway;fillColor={_INTEGRATION};",
        EXT_ICONS["states"]: f"{_RES_ICON}step_functions;fillColor={_INTEGRATION};",
        EXT_ICONS["secretsmanager"]: f"{_RES_ICON}secrets_manager;fillColor={_SECURITY};",
        EXT_ICONS["kinesis"]: f"{_RES_ICON}kinesis;fillColor={_NETWORK};",
        EXT_ICONS["tgw"]: f"shape=mxgraph.aws4.transit_gateway;fillColor={_NETWORK};",
        EXT_ICONS[
            "tgw-attachment"
        ]: f"shape=mxgraph.aws4.transit_gateway_attachment;fillColor={_NETWORK};",
        EXT_ICONS["pcx"]: f"shape=mxgraph.aws4.peering;fillColor={_NETWORK};",
        EXT_ICONS["internet"]: f"shape=mxgraph.aws4.internet_gateway;fillColor={_NETWORK};",
        EXT_ICONS["route53"]: f"{_RES_ICON}route_53;fillColor={_NETWORK};",
        EXT_ICONS["resolver"]: f"shape=mxgraph.aws4.route_53_resolver;fillColor={_NETWORK};",
        EXT_ICONS["other"]: f"{_RES_ICON}general;fillColor=#5B6573;",
    }
)
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
DRAWIO_CTX = (
    "rounded=1;arcSize=4;dashed=1;dashPattern=6 4;fillColor=none;html=1;whiteSpace=wrap;"
    "verticalAlign=top;align=left;spacingLeft=6;fontSize=10;strokeWidth=1.5;"
)
DRAWIO_EDGE = "html=1;rounded=0;edgeStyle=none;fontSize=9;labelBackgroundColor=#FFFFFF;"
DRAWIO_EDGE_STYLES = {
    "targets": "endArrow=block;endFill=1;strokeColor=#2457C5;strokeWidth=2;",
    "ecs_lb": "endArrow=block;endFill=1;strokeColor=#2F8F4E;strokeWidth=2;",
    "reach": "endArrow=open;dashed=1;dashPattern=3 3;strokeColor=#B0469B;strokeWidth=1.6;",
    "sg": "endArrow=open;dashed=1;dashPattern=6 4;strokeColor=#8A94A3;strokeWidth=1.2;",
    "ev_observed": "endArrow=block;endFill=1;strokeColor=#1A7F37;strokeWidth=3;",
    "ev_configured": "endArrow=block;endFill=1;strokeColor=#2457C5;strokeWidth=2;",
    "ev_permitted": "endArrow=open;dashed=1;dashPattern=7 4;strokeColor=#C2410C;strokeWidth=1.8;",
    "ev_referenced": "endArrow=open;dashed=1;dashPattern=2 3;strokeColor=#6B7280;strokeWidth=1.5;",
}
DRAWIO_AREA = (
    "rounded=0;dashed=1;dashPattern=8 5;strokeColor=#5B6573;fillColor=#F6F7F9;html=1;"
    "whiteSpace=wrap;verticalAlign=bottom;labelPosition=center;verticalLabelPosition=top;"
    "align=center;fontSize=12;container=1;collapsible=0;recursiveResize=0;"
)


def _html_value(label: str) -> str:
    return "<br>".join(html.escape(line) for line in _lines(label))


def drawio_style(node: ViewNode, view: View) -> str:
    if node.kind == "vpc":
        return DRAWIO_VPC + ("" if view.show_vpc else DRAWIO_HIDDEN_BOX)
    if node.kind == "subnet":
        return DRAWIO_SUBNET + ("" if view.show_subnets else DRAWIO_HIDDEN_BOX)
    if node.kind == "area":
        return DRAWIO_AREA
    if node.kind == "ctx":
        color = (node.color or CTX_STROKE).upper()
        return f"{DRAWIO_CTX}strokeColor={color};fontColor={color};"
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
