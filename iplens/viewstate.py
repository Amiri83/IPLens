"""Per-account Visual page state: border/label toggles, the Extended view's evidence
filter and dragged node positions."""

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

DEFAULT_PREFS = {"show_vpc": True, "show_subnets": True, "shorten_names": False}


def get_prefs(conn: sqlite3.Connection, account_ref: int) -> dict[str, bool]:
    row = conn.execute(
        "SELECT show_vpc, show_subnets, shorten_names FROM visual_prefs WHERE account_ref=?",
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
        "INSERT INTO visual_prefs(account_ref, show_vpc, show_subnets, shorten_names) "
        "VALUES(?,?,?,?) ON CONFLICT(account_ref) DO UPDATE SET show_vpc=excluded.show_vpc, "
        "show_subnets=excluded.show_subnets, shorten_names=excluded.shorten_names",
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


def get_layout(conn: sqlite3.Connection, account_ref: int, vpc_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT positions FROM visual_layouts WHERE account_ref=? AND vpc_id=?",
        (account_ref, vpc_id),
    ).fetchone()
    return json.loads(row["positions"]) if row else {}


def save_layout(
    conn: sqlite3.Connection, account_ref: int, vpc_id: str, positions: dict[str, Any]
) -> None:
    conn.execute(
        "INSERT INTO visual_layouts(account_ref, vpc_id, positions) VALUES(?,?,?) "
        "ON CONFLICT(account_ref, vpc_id) DO UPDATE SET positions=excluded.positions",
        (account_ref, vpc_id, json.dumps(positions)),
    )


def reset_layout(conn: sqlite3.Connection, account_ref: int, vpc_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM visual_layouts WHERE account_ref=? AND vpc_id=?", (account_ref, vpc_id)
    )
    return cur.rowcount > 0
