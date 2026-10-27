"""Visual page tag filters: which resource nodes, subnets and VPC boxes are drawn.

The Visual page filters in the browser, over the data it already loaded (nothing is
re-discovered); ``static/tagfilter.js`` mirrors these functions one by one and
tests/test_tagfilter.py runs both on the same input. Only the diagram is filtered:
compliance rules, findings, suggestions and data exports always see every resource.

A filter is ``{resource_type, tag_key, values, include_untagged}``:

- it affects only resources of its ``resource_type`` (a node's ``type``, e.g. "ec2");
  other types are drawn as without filters;
- a resource matches when one of its tags has the key ``tag_key`` (case-insensitive)
  and a value in ``values`` (exact): values are OR'd;
- a resource without that tag key is "untagged" for the filter and matches only with
  ``include_untagged`` (default false);
- every filter on a type must match (filters on the same type are AND'd).

VPC and subnet boxes are always drawn, unless "hide empty containers" is on: then a
subnet without a shown resource is hidden, and the VPC when none of its subnets is shown.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

MAX_FILTERS = 50
MAX_VALUES = 200
MAX_TYPE = 64
MAX_KEY = 128
MAX_VALUE = 256


@dataclass(frozen=True)
class TagFilter:
    resource_type: str
    tag_key: str
    values: tuple[str, ...] = ()
    include_untagged: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "values": list(self.values)}


def _text(doc: Mapping[str, Any], field: str, limit: int) -> str:
    value = doc.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{field} must be a non-empty string of at most {limit} characters")
    return value.strip()


def parse_filter(doc: Any) -> TagFilter:
    """One filter from its JSON object; raises ValueError when it is not valid."""
    if not isinstance(doc, dict):
        raise ValueError("a filter must be a JSON object")
    values = doc.get("values", [])
    if not isinstance(values, list) or len(values) > MAX_VALUES:
        raise ValueError(f"values must be a list of at most {MAX_VALUES} strings")
    if not all(isinstance(v, str) and len(v) <= MAX_VALUE for v in values):
        raise ValueError(f"each value must be a string of at most {MAX_VALUE} characters")
    untagged = doc.get("include_untagged", False)
    if not isinstance(untagged, bool):
        raise ValueError("include_untagged must be true or false")
    if not values and not untagged:
        raise ValueError("a filter needs at least one value or include_untagged")
    return TagFilter(
        resource_type=_text(doc, "resource_type", MAX_TYPE),
        tag_key=_text(doc, "tag_key", MAX_KEY),
        values=tuple(dict.fromkeys(values)),  # values match exactly: no stripping
        include_untagged=untagged,
    )


def parse_filters(raw: str | list[Any] | None) -> list[TagFilter]:
    """Filters from a JSON list (or the decoded list); raises ValueError when not valid."""
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise ValueError("filters must be JSON") from None
    if not isinstance(raw, list):
        raise ValueError("filters must be a JSON list")
    if len(raw) > MAX_FILTERS:
        raise ValueError(f"at most {MAX_FILTERS} filters")
    return [parse_filter(doc) for doc in raw]


def key_values(tags: Mapping[str, str] | None, key: str) -> list[str]:
    """Values of every tag whose key equals ``key`` ignoring case."""
    wanted = key.lower()
    return [v for k, v in (tags or {}).items() if k.lower() == wanted]


def matches(flt: TagFilter, tags: Mapping[str, str] | None) -> bool:
    found = key_values(tags, flt.tag_key)
    if not found:
        return flt.include_untagged
    return any(v in flt.values for v in found)


def resource_visible(resource: Mapping[str, Any], filters: Iterable[TagFilter]) -> bool:
    """True if every filter on the resource's type matches it (no filter: True)."""
    return all(
        matches(f, resource.get("tags")) for f in filters if f.resource_type == resource.get("type")
    )


def type_counts(
    resources: Iterable[Mapping[str, Any]], shown: Callable[[Mapping[str, Any]], bool]
) -> dict[str, list[int]]:
    """``{type: [shown, total]}`` for the "X of Y shown" line; ``shown`` says whether a
    resource is drawn (the page also applies its environment filter)."""
    counts: dict[str, list[int]] = {}
    for r in resources:
        c = counts.setdefault(r["type"], [0, 0])
        c[0] += int(shown(r))
        c[1] += 1
    return dict(sorted(counts.items()))


def hidden_containers(
    subnets: Iterable[Mapping[str, Any]],
    shown: Callable[[Mapping[str, Any]], bool],
    hide_empty: bool,
) -> dict[str, Any]:
    """Boxes to hide: ``{"subnets": [ids], "vpc": bool}``.

    ``subnets`` are ``{"subnet_id", "resources": [...]}``; ``shown`` says whether a
    resource is drawn. Nothing is hidden unless ``hide_empty``."""
    subnets = list(subnets)
    if not hide_empty:
        return {"subnets": [], "vpc": False}
    empty = [s["subnet_id"] for s in subnets if not any(shown(r) for r in s["resources"])]
    return {"subnets": empty, "vpc": len(empty) == len(subnets)}


def discovered_tags(resources: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, list[str]]]:
    """``{type: {tag key: [values]}}`` offered by the filter panel. Keys differing only in
    case are one entry, spelled as first seen; values are sorted."""
    out: dict[str, dict[str, set[str]]] = {}
    spelling: dict[tuple[str, str], str] = {}
    for r in resources:
        keys = out.setdefault(r["type"], {})
        for k, v in (r.get("tags") or {}).items():
            key = spelling.setdefault((r["type"], k.lower()), k)
            keys.setdefault(key, set()).add(v)
    return {
        t: {k: sorted(vs) for k, vs in sorted(keys.items(), key=lambda kv: kv[0].lower())}
        for t, keys in sorted(out.items())
    }
