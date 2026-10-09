"""Per-account Visual page state: border/label/legend toggles, the Extended view's
evidence filter, and per view ("ip" | "extended") the chosen layout, the expanded groups
and the dragged node positions."""

from __future__ import annotations

import json
import math
import sqlite3
from typing import Any

from .declutter import DEFAULT_EVIDENCE, parse_evidence

# Saved layouts are bounded: a VPC diagram with more nodes than this is not sensible.
MAX_POSITIONS = 5000
MAX_NODE_ID = 200
MAX_COORD = 1e7

DEFAULT_PREFS = {
    "show_vpc": True,
    "show_subnets": True,
    "shorten_names": False,
    "show_legend": True,
}

VIEWS = ("ip", "extended")
# Layout choices of the Visual page (both views): "dagre" is the vendored hierarchical
# layout, the others are cytoscape.js built-ins applied box by box (see visual.js).
LAYOUTS = {
    "grid": "Grid",
    "dagre": "Hierarchy (dagre)",
    "circle": "Circle",
    "concentric": "Concentric",
    "breadthfirst": "Breadthfirst",
}
DEFAULT_LAYOUT = "grid"
# The Extended view's dragged positions are stored under "<vpc id>:extended", so that
# dragging in one view never moves nodes in the other (the IP view keeps the bare id).
EXT_LAYOUT_SUFFIX = ":extended"
# A saved layout row holds {"layouts": {layout name: {node id: {x, y}}}}: dragged positions
# belong to the layout they were dragged in and are restored only for that layout.
LAYOUTS_FIELD = "layouts"


def get_prefs(conn: sqlite3.Connection, account_ref: int) -> dict[str, bool]:
    row = conn.execute(
        "SELECT show_vpc, show_subnets, shorten_names, show_legend FROM visual_prefs "
        "WHERE account_ref=?",
        (account_ref,),
    ).fetchone()
    if row is None:
        return dict(DEFAULT_PREFS)
    return {k: bool(row[k]) for k in DEFAULT_PREFS}


def save_prefs(conn: sqlite3.Connection, account_ref: int, **changes: bool) -> None:
    """Update the prefs named in ``changes`` (keys of DEFAULT_PREFS); others keep their value."""
    unknown = set(changes) - set(DEFAULT_PREFS)
    if unknown:
        raise ValueError(f"unknown visual prefs: {', '.join(sorted(unknown))}")
    prefs = {**get_prefs(conn, account_ref), **changes}
    conn.execute(
        "INSERT INTO visual_prefs(account_ref, show_vpc, show_subnets, shorten_names, "
        "show_legend) VALUES(?,?,?,?,?) ON CONFLICT(account_ref) DO UPDATE SET "
        "show_vpc=excluded.show_vpc, show_subnets=excluded.show_subnets, "
        "shorten_names=excluded.shorten_names, show_legend=excluded.show_legend",
        (account_ref, *(int(prefs[k]) for k in DEFAULT_PREFS)),
    )


def get_evidence(conn: sqlite3.Connection, account_ref: int) -> tuple[str, ...]:
    """The Extended view's evidence filter (default: observed + configured)."""
    row = conn.execute(
        "SELECT evidence FROM visual_prefs WHERE account_ref=?", (account_ref,)
    ).fetchone()
    try:
        return parse_evidence(row["evidence"] if row is not None else None)
    except ValueError:  # a level that no longer exists
        return DEFAULT_EVIDENCE


def save_evidence(conn: sqlite3.Connection, account_ref: int, levels: tuple[str, ...]) -> None:
    """Store the ticked levels (validated by :func:`iplens.declutter.parse_evidence`)."""
    conn.execute(
        "INSERT INTO visual_prefs(account_ref, evidence) VALUES(?,?) "
        "ON CONFLICT(account_ref) DO UPDATE SET evidence=excluded.evidence",
        (account_ref, ",".join(parse_evidence(",".join(levels)))),
    )


def parse_positions(raw: str) -> dict[str, dict[str, float]]:
    """Validate ``{"node id": {"x": n, "y": n}, ...}`` posted by the Visual page."""
    try:
        doc = json.loads(raw or "{}")
    except ValueError:
        raise ValueError("positions must be JSON") from None
    if not isinstance(doc, dict):
        raise ValueError("positions must be a JSON object")
    if len(doc) > MAX_POSITIONS:
        raise ValueError(f"at most {MAX_POSITIONS} positions")
    out: dict[str, dict[str, float]] = {}
    for node_id, pos in doc.items():
        if not node_id or len(node_id) > MAX_NODE_ID or not isinstance(pos, dict):
            raise ValueError("invalid position entry")
        x, y = pos.get("x"), pos.get("y")
        if not all(_coord(v) for v in (x, y)):
            raise ValueError("invalid coordinates")
        out[node_id] = {"x": round(float(x), 1), "y": round(float(y), 1)}  # type: ignore[arg-type]
    return out


def _coord(v: Any) -> bool:
    return (
        isinstance(v, int | float)
        and not isinstance(v, bool)
        and math.isfinite(v)
        and abs(v) <= MAX_COORD
    )


def get_layouts(
    conn: sqlite3.Connection, account_ref: int, vpc_id: str, legacy_layout: str = DEFAULT_LAYOUT
) -> dict[str, dict[str, Any]]:
    """Dragged positions of ``vpc_id`` per layout name: ``{layout: {node id: {x, y}}}``.

    Rows written before positions were kept per layout hold a bare ``{node id: {x, y}}``
    and are read as positions of ``legacy_layout`` (the view's chosen layout)."""
    row = conn.execute(
        "SELECT positions FROM visual_layouts WHERE account_ref=? AND vpc_id=?",
        (account_ref, vpc_id),
    ).fetchone()
    doc = json.loads(row["positions"]) if row else {}
    if not isinstance(doc, dict):
        return {}
    if LAYOUTS_FIELD in doc:
        return {k: v for k, v in doc[LAYOUTS_FIELD].items() if k in LAYOUTS}
    return {legacy_layout: doc} if doc else {}


def get_layout(
    conn: sqlite3.Connection, account_ref: int, vpc_id: str, layout: str = DEFAULT_LAYOUT
) -> dict[str, Any]:
    """Dragged positions of ``vpc_id`` saved under ``layout``."""
    return get_layouts(conn, account_ref, vpc_id, layout).get(layout, {})


def save_layout(
    conn: sqlite3.Connection,
    account_ref: int,
    vpc_id: str,
    positions: dict[str, Any],
    layout: str = DEFAULT_LAYOUT,
) -> None:
    """Store ``positions`` as the dragged positions of ``layout``; other layouts keep theirs."""
    if layout not in LAYOUTS:
        raise ValueError(f"unknown layout: {layout!r}")
    layouts = {**get_layouts(conn, account_ref, vpc_id, layout), layout: positions}
    conn.execute(
        "INSERT INTO visual_layouts(account_ref, vpc_id, positions) VALUES(?,?,?) "
        "ON CONFLICT(account_ref, vpc_id) DO UPDATE SET positions=excluded.positions",
        (account_ref, vpc_id, json.dumps({LAYOUTS_FIELD: layouts})),
    )


def reset_layout(conn: sqlite3.Connection, account_ref: int, vpc_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM visual_layouts WHERE account_ref=? AND vpc_id=?", (account_ref, vpc_id)
    )
    return cur.rowcount > 0


def layout_key(vpc_id: str, view: str) -> str:
    """Key of the saved positions of ``vpc_id`` in ``view``."""
    return f"{vpc_id}{EXT_LAYOUT_SUFFIX}" if vpc_id and view == "extended" else vpc_id


def _view(view: str) -> str:
    if view not in VIEWS:
        raise ValueError(f"unknown view: {view!r}")
    return view


def get_view_layout(conn: sqlite3.Connection, account_ref: int, view: str) -> str:
    """The layout chosen in ``view`` (default: grid)."""
    row = conn.execute(
        "SELECT layout FROM visual_view_prefs WHERE account_ref=? AND view=?",
        (account_ref, _view(view)),
    ).fetchone()
    return row["layout"] if row is not None and row["layout"] in LAYOUTS else DEFAULT_LAYOUT


def save_view_layout(conn: sqlite3.Connection, account_ref: int, view: str, layout: str) -> None:
    if layout not in LAYOUTS:
        raise ValueError(f"unknown layout: {layout!r}")
    conn.execute(
        "INSERT INTO visual_view_prefs(account_ref, view, layout) VALUES(?,?,?) "
        "ON CONFLICT(account_ref, view) DO UPDATE SET layout=excluded.layout",
        (account_ref, _view(view), layout),
    )


def parse_expanded(raw: str) -> list[str]:
    """Validate the ``["group id", ...]`` list of expanded groups posted by the page."""
    try:
        doc = json.loads(raw or "[]")
    except ValueError:
        raise ValueError("expanded groups must be JSON") from None
    if not isinstance(doc, list):
        raise ValueError("expanded groups must be a JSON list")
    if len(doc) > MAX_POSITIONS:
        raise ValueError(f"at most {MAX_POSITIONS} groups")
    if not all(isinstance(g, str) and 0 < len(g) <= MAX_NODE_ID for g in doc):
        raise ValueError("invalid group id")
    return sorted(set(doc))


def get_expanded(conn: sqlite3.Connection, account_ref: int, view: str, vpc_id: str) -> list[str]:
    row = conn.execute(
        "SELECT expanded FROM visual_groups WHERE account_ref=? AND view=? AND vpc_id=?",
        (account_ref, _view(view), vpc_id),
    ).fetchone()
    return json.loads(row["expanded"]) if row else []


def save_expanded(
    conn: sqlite3.Connection, account_ref: int, view: str, vpc_id: str, groups: list[str]
) -> None:
    conn.execute(
        "INSERT INTO visual_groups(account_ref, view, vpc_id, expanded) VALUES(?,?,?,?) "
        "ON CONFLICT(account_ref, view, vpc_id) DO UPDATE SET expanded=excluded.expanded",
        (account_ref, _view(view), vpc_id, json.dumps(sorted(set(groups)))),
    )
