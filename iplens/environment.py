"""Environment of a resource (dev / staging / prod / ...).

Most specific source first:

1. **Terraform**: the resource is managed by a repo root whose environment is known
   (the root x environment pair of a Terraform repo, see :mod:`iplens.tfrepo`). The
   placeholder environment ``default`` (a root without environments) does not count.
2. **Tags**: the first configured tag key present on the resource (owner / ENI tags),
   then on its subnet, then on its VPC. The keys are configured in Settings (default
   ``Environment``, ``env``, ``stage``) and match case-insensitively.

Resources without either have no environment (``""``, shown as "(not set)").
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Sequence
from typing import Any

from . import terraform

DEFAULT_TAG_KEYS = ("Environment", "env", "stage")
MAX_TAG_KEYS = 10
MAX_TAG_KEY = 128
NOT_SET = ""
NOT_SET_LABEL = "(not set)"
# IP list filter value for "no environment".
FILTER_NOT_SET = "-"
SOURCE_LABELS = {
    "terraform": "Terraform root",
    "tag": "tag",
    "subnet tag": "subnet tag",
    "vpc tag": "VPC tag",
}
_DEFAULT_ENV = "default"  # tfrepo.DEFAULT_ENV (not imported: tfrepo imports heavier modules)


def parse_tag_keys(text: str | Iterable[str] | None) -> tuple[str, ...]:
    """Configured tag keys from a comma / whitespace separated string (or a list)."""
    if text is None:
        return DEFAULT_TAG_KEYS
    parts = re.split(r"[,\s]+", text) if isinstance(text, str) else list(text)
    keys: list[str] = []
    for p in parts:
        p = str(p).strip()[:MAX_TAG_KEY]
        if p and p.lower() not in {k.lower() for k in keys}:
            keys.append(p)
    return tuple(keys[:MAX_TAG_KEYS])


def from_tags(tags: dict[str, str] | None, keys: Sequence[str]) -> str:
    """Value of the first of ``keys`` present in ``tags`` (case-insensitive key match)."""
    if not tags:
        return NOT_SET
    lower = {k.lower(): v for k, v in tags.items()}
    for key in keys:
        value = lower.get(key.lower(), "").strip()
        if value:
            return value[:128]
    return NOT_SET


def root_environments(conn: sqlite3.Connection) -> dict[str, str]:
    """``tf_roots`` name -> environment, for the roots written by Terraform repo syncs."""
    return {
        r["root_name"]: r["env"]
        for r in conn.execute(
            "SELECT root_name, env FROM tf_repo_envs WHERE root_name != '' AND env != ?",
            (_DEFAULT_ENV,),
        )
    }


class EnvResolver:
    """Derives environments for one snapshot (see the module docstring)."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        snap_id: int,
        keys: Sequence[str] = DEFAULT_TAG_KEYS,
        *,
        tags: dict[tuple[str, str], dict[str, str]] | None = None,
        tf_index: terraform.TfIndex | None = None,
    ):
        self.keys = tuple(keys) or DEFAULT_TAG_KEYS
        self.root_env = root_environments(conn)
        if tags is None:
            tags = {}
            for r in conn.execute(
                "SELECT resource_type, resource_id, key, value FROM resource_tags "
                "WHERE snapshot_id=?",
                (snap_id,),
            ):
                tags.setdefault((r["resource_type"], r["resource_id"]), {})[r["key"]] = r["value"]
        self.tags = tags
        self._tf_index = tf_index
        self._conn = conn

    @property
    def tf_index(self) -> terraform.TfIndex:
        if self._tf_index is None:
            self._tf_index = terraform.load_index(self._conn)
        return self._tf_index

    def _from_tf(self, managed: Iterable[dict[str, str]]) -> str:
        for m in managed:
            env = self.root_env.get(m["root"])
            if env:
                return env
        return NOT_SET

    def for_row(self, row: dict[str, Any]) -> tuple[str, str]:
        """``(environment, source)`` of an IP list row (``tf`` and ``tags`` filled in)."""
        env = self._from_tf(row.get("tf") or [])
        if env:
            return env, "terraform"
        env = from_tags(row.get("tags"), self.keys)
        if env:
            return env, "tag"
        env = from_tags(self.tags.get(("subnet", row.get("subnet_id") or "")), self.keys)
        if env:
            return env, "subnet tag"
        env = from_tags(self.tags.get(("vpc", row.get("vpc_id") or "")), self.keys)
        if env:
            return env, "vpc tag"
        return NOT_SET, ""

    def for_resource(self, tf_kind: str, tag_type: str, resource_id: str) -> str:
        """Environment of a resource known by its Terraform kind / tag type and id
        (Extended view Lambda functions and ECS services)."""
        env = self._from_tf(self.tf_index.get((tf_kind, resource_id), []))
        return env or from_tags(self.tags.get((tag_type, resource_id)), self.keys)


def matches(environment: str, wanted: str) -> bool:
    """IP list filter: ``wanted`` is an environment, or :data:`FILTER_NOT_SET`."""
    if not wanted:
        return True
    if wanted == FILTER_NOT_SET:
        return environment == NOT_SET
    return environment.lower() == wanted.lower()


def summary(values: Iterable[str]) -> list[dict[str, Any]]:
    """``[{"value", "label", "count"}]`` of the environments seen, "(not set)" last."""
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return [
        {"value": v, "label": v or NOT_SET_LABEL, "count": n}
        for v, n in sorted(counts.items(), key=lambda kv: (kv[0] == NOT_SET, kv[0].lower()))
    ]
