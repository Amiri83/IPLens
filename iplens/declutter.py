"""Extended view decluttering rules: evidence defaults, edge dedupe, focus, aggregation.

The Visual page applies these in the browser (``static/declutter.js`` mirrors every
function here one to one; ``tests/test_declutter.py`` checks that both agree):

- Evidence filter: ``observed`` and ``configured`` are shown by default, ``permitted``
  and ``referenced`` are opt-in (:data:`DEFAULT_EVIDENCE`; the selection is kept per
  account, see :mod:`iplens.viewstate`).
- :func:`merge_edges` draws ONE edge per node pair (direction ignored), styled by the
  strongest evidence line among the shown levels. ``extra`` ("+N" badge) counts the
  evidence lines beyond the drawn ones; ``lines`` keeps every line for the detail panel.
  The same function merges the edges of collapsed groups: ``endpoint`` maps a member
  onto its group, ``count`` is the number of member pairs behind the edge and ``width``
  grows with it (:func:`edge_width`).
- :func:`neighbourhood` is the node set of focus mode (N hops over the drawn edges).
- :func:`service_tier` ranks nodes for the left-to-right layout: sources
  (EventBridge / SNS / API Gateway / S3) -> compute (Lambda / ECS) -> targets.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from .extended import EVIDENCE_LEVELS, EVIDENCE_RANK

DEFAULT_EVIDENCE = ("observed", "configured")
FOCUS_HOPS = (1, 2)
# Regional services of one type (and Lambda / ECS ENIs of a subnet) are aggregated into a
# collapsible group from this many nodes on.
AGG_MIN = 2
EDGE_W_UNIT = 2.0
EDGE_W_MAX = 12.0

SOURCE_SERVICES = frozenset({"events", "apigateway"})
# Both a trigger and a target: a source when it feeds compute, else a target.
DUAL_SERVICES = frozenset({"sns", "s3"})
COMPUTE_SERVICES = frozenset({"lambda", "ecs"})
TIER_SOURCE, TIER_COMPUTE, TIER_TARGET = 0, 1, 2


def parse_evidence(raw: str | None) -> tuple[str, ...]:
    """``"observed,configured"`` -> levels in strength order; None means the default.

    An empty string is a valid "nothing ticked"; an unknown level raises ValueError.
    """
    if raw is None:
        return DEFAULT_EVIDENCE
    levels = {part.strip() for part in raw.split(",") if part.strip()}
    unknown = levels - set(EVIDENCE_LEVELS)
    if unknown:
        raise ValueError(f"unknown evidence level(s): {', '.join(sorted(unknown))}")
    return tuple(level for level in EVIDENCE_LEVELS if level in levels)


def edge_width(count: int) -> float:
    """Stroke width of an edge standing for ``count`` connections (capped)."""
    return min(EDGE_W_MAX, EDGE_W_UNIT * max(1, count))


def _pair(a: str, b: str) -> str:
    return f"{a}\x00{b}" if a < b else f"{b}\x00{a}"


def merge_edges(
    edges: Iterable[dict[str, Any]],
    levels: Iterable[str],
    endpoint: Callable[[str], str | None] | None = None,
) -> list[dict[str, Any]]:
    """One drawn edge per unordered node pair (see the module docstring).

    ``edges`` carry ``source``, ``target``, ``type`` and evidence ``lines``
    (``{"evidence", "label", "text"}``). ``endpoint`` maps an edge end onto the node it
    is drawn on (None drops the edge); by default ends are drawn as they are.
    A pair without any line of the shown ``levels`` is left out.
    """
    shown_levels = set(levels)
    merged: dict[str, dict[str, Any]] = {}
    for e in edges:
        s = endpoint(e["source"]) if endpoint else e["source"]
        t = endpoint(e["target"]) if endpoint else e["target"]
        if not s or not t or s == t:
            continue
        m = merged.setdefault(_pair(s, t), {"lines": [], "types": set()})
        m["types"].add(e.get("type") or "ext")
        for ln in e.get("lines") or []:
            m["lines"].append(
                {
                    "evidence": ln["evidence"],
                    "label": ln.get("label") or "",
                    "text": ln.get("text") or "",
                    "source": e["source"],
                    "target": e["target"],
                    "drawn_source": s,
                    "drawn_target": t,
                    "shown": ln["evidence"] in shown_levels,
                }
            )
    out = []
    for m in merged.values():
        lines = sorted(m["lines"], key=lambda ln: (EVIDENCE_RANK[ln["evidence"]], ln["text"]))
        shown = [ln for ln in lines if ln["shown"]]
        if not shown:
            continue
        best = shown[0]
        s, t = best["drawn_source"], best["drawn_target"]
        count = len({_pair(ln["source"], ln["target"]) for ln in shown})
        for ln in lines:
            ln["reverse"] = ln.pop("drawn_source") != s
            del ln["drawn_target"]
        out.append(
            {
                "source": s,
                "target": t,
                "evidence": best["evidence"],
                "label": best["label"],
                "types": sorted(m["types"]),
                "count": count,
                "extra": len(lines) - count,
                "width": edge_width(count),
                "bidir": any(ln["reverse"] for ln in shown),
                "lines": lines,
            }
        )
    return out


def neighbourhood(edges: Iterable[dict[str, Any]], start: str, hops: int = 1) -> set[str]:
    """``start`` and every node at most ``hops`` drawn edges away (direction ignored)."""
    adjacent: dict[str, set[str]] = {}
    for e in edges:
        adjacent.setdefault(e["source"], set()).add(e["target"])
        adjacent.setdefault(e["target"], set()).add(e["source"])
    seen, frontier = {start}, {start}
    for _ in range(max(0, hops)):
        frontier = {n for f in frontier for n in adjacent.get(f, ())} - seen
        seen |= frontier
    return seen


def service_tier(service: str, feeds_compute: bool = False) -> int:
    """Left-to-right rank of a service node: 0 source, 1 compute, 2 target."""
    if service in COMPUTE_SERVICES:
        return TIER_COMPUTE
    if service in SOURCE_SERVICES or (service in DUAL_SERVICES and feeds_compute):
        return TIER_SOURCE
    return TIER_TARGET
