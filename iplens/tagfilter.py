"""Visual page view filters: which resource nodes, subnets and VPC boxes are drawn.

The Visual page filters in the browser, over the data it already loaded (nothing is
re-discovered); ``static/tagfilter.js`` mirrors these functions one by one and
tests/test_tagfilter.py runs both on the same input. Only the diagram is filtered:
compliance rules, findings, suggestions and data exports always see every resource.

A tag filter is ``{tag_key, values, include_untagged}`` and applies to every resource
node, whatever its type:

- a resource matches when one of its tags has the key ``tag_key`` (case-insensitive)
  and a value in ``values`` (exact): values are OR'd. A resource's tags for filtering
  are its ``tag_values`` (``{key: [values]}``: every value of the ENI and of all its
  owners, so an ENI shared by several Lambda functions matches any function's value),
  else its ``tags``;
- a resource without that tag key is "untagged" for the filter and matches only with
  ``include_untagged`` (default false);
- every filter must match (filters are AND'd).

The name filter is a text of terms, ``,`` = OR and ``+`` = AND (AND binds tighter:
``dev+lambda,uat`` is (dev AND lambda) OR uat): a term matches when it is a
case-insensitive substring of the resource's name, of one of its owners' names (every
function of a shared Lambda ENI), of its ENI id, of one of its tag values or of its type
(or type label). It is AND'd with the tag filters.

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
MAX_KEY = 128
MAX_VALUE = 256
MAX_NAME_FILTER = 512


@dataclass(frozen=True)
class TagFilter:
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
    """One filter from its JSON object; raises ValueError when it is not valid. A
    ``resource_type`` (presets saved before filters applied to every type) is ignored."""
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


def parse_name_filter(raw: str | None) -> str:
    """The name filter text as saved (stripped); raises ValueError when too long."""
    text = (raw or "").strip()
    if len(text) > MAX_NAME_FILTER:
        raise ValueError(f"the name filter is at most {MAX_NAME_FILTER} characters")
    return text


Tags = Mapping[str, str | list[str]]


def filter_tags(resource: Mapping[str, Any]) -> Tags:
    """The tags a resource is filtered on: ``tag_values`` when present, else ``tags``."""
    values = resource.get("tag_values")
    if values is None:
        return resource.get("tags") or {}
    return values


def key_values(tags: Tags | None, key: str) -> list[str]:
    """Values of every tag whose key equals ``key`` ignoring case (a key may hold one
    value or a list of them)."""
    wanted = key.lower()
    out: list[str] = []
    for k, v in (tags or {}).items():
        if k.lower() == wanted:
            out.extend(v if isinstance(v, list) else [v])
    return out


def matches(flt: TagFilter, tags: Tags | None) -> bool:
    found = key_values(tags, flt.tag_key)
    if not found:
        return flt.include_untagged
    return any(v in flt.values for v in found)


def name_terms(text: str | None) -> list[list[str]]:
    """The OR'd groups (``,``) of AND'd terms (``+``) of a name filter: lower-cased,
    trimmed, empty terms and groups dropped. ``"dev+lambda,uat"``: ``[["dev", "lambda"],
    ["uat"]]``."""
    groups = (
        [t for t in (p.strip().lower() for p in g.split("+")) if t] for g in (text or "").split(",")
    )
    return [g for g in groups if g]


def name_matches(resource: Mapping[str, Any], terms: list[list[str]]) -> bool:
    """True if every term of one group is part of the resource's name, an owner's name,
    its ENI id, a tag value, its type or type label (no group: True)."""
    if not terms:
        return True
    values = [
        v for vs in filter_tags(resource).values() for v in (vs if isinstance(vs, list) else [vs])
    ]
    fields = [
        resource.get("name"),
        *(resource.get("owners") or []),
        resource.get("eni_id"),
        *values,
        resource.get("type"),
        resource.get("type_label"),
    ]
    texts = [f.lower() for f in fields if f]
    return any(all(any(t in f for f in texts) for t in group) for group in terms)


def resource_visible(
    resource: Mapping[str, Any], filters: Iterable[TagFilter], name: str = ""
) -> bool:
    """True if every tag filter and the name filter match the resource (none: True)."""
    tags = filter_tags(resource)
    return all(matches(f, tags) for f in filters) and name_matches(resource, name_terms(name))


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


def discovered_tags(resources: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    """``{tag key: [values]}`` over every resource, offered by the filter panel. Keys
    differing only in case are one entry, spelled as first seen; values are sorted."""
    out: dict[str, set[str]] = {}
    spelling: dict[str, str] = {}
    for r in resources:
        for k, v in filter_tags(r).items():
            key = spelling.setdefault(k.lower(), k)
            out.setdefault(key, set()).update(v if isinstance(v, list) else [v])
    return {k: sorted(vs) for k, vs in sorted(out.items(), key=lambda kv: kv[0].lower())}
