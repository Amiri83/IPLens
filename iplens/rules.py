"""Company rules: storage, validation, YAML round-trip and evaluation.

Rules do two things:
* ``violations`` - report where the current snapshot breaks a rule.
* ``blocks``     - veto optimization suggestions that would break a rule.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from .suggestions import Context, Suggestion

RULE_KINDS: dict[str, str] = {
    "lambda_vpc_required": "Lambda functions must be VPC-attached",
    "internal_only": "Load balancers / VPC endpoints must stay internal-only",
    "subnet_reserved": "Subnet is reserved: no changes or new placements",
    "min_free_pct": "Subnets must keep a minimum percentage of free IPs",
    "protected_eni": "ENIs matching a pattern must never be removed",
    "ecs_scale_down": "ECS scale-down / delete-idle-environment suggestions: allow or deny",
}

INTERNAL_SCOPES = ("load_balancer", "vpc_endpoint", "both")
# deny:  block scale-down suggestions for services matching the pattern (blank = all)
# allow: block scale-down suggestions for every service NOT matching the pattern
ECS_MODES = ("deny", "allow")


@dataclass
class Rule:
    name: str
    kind: str
    params: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    description: str = ""
    id: int | None = None

    @property
    def kind_label(self) -> str:
        return RULE_KINDS.get(self.kind, self.kind)

    def summary(self) -> str:
        p = self.params
        if self.kind == "min_free_pct":
            scope = ", ".join(p.get("subnet_ids") or []) or "all subnets"
            return f">= {p.get('percent')}% free ({scope})"
        if self.kind == "subnet_reserved":
            return ", ".join(p.get("subnet_ids") or [])
        if self.kind == "internal_only":
            return f"scope: {p.get('scope', 'both')}"
        if self.kind == "protected_eni":
            return f"pattern: {p.get('pattern', '')}"
        if self.kind == "ecs_scale_down":
            return f"{p.get('mode', 'deny')}: {p.get('pattern') or 'all services'}"
        return ""

    # -- suggestion veto -------------------------------------------------
    def blocks(self, s: Suggestion, ctx: Context) -> str | None:
        """Return a human-readable reason if this rule forbids the suggestion."""
        if not self.enabled:
            return None
        p = self.params
        if self.kind == "lambda_vpc_required":
            if "lambda_detach_vpc" in s.flags:
                return "Lambda functions must remain VPC-attached"
        elif self.kind == "internal_only":
            scope = p.get("scope", "both")
            scopes = {"load_balancer", "vpc_endpoint"} if scope == "both" else {scope}
            hit = {f.split(":", 1)[1] for f in s.flags if f.startswith("public_path:")}
            if hit & scopes:
                return f"{' / '.join(sorted(hit & scopes))} must stay internal-only"
        elif self.kind == "subnet_reserved":
            reserved = set(p.get("subnet_ids") or [])
            touched = (set(s.subnet_ids) | set(s.target_subnets)) & reserved
            if touched:
                return f"reserved subnet(s): {', '.join(sorted(touched))}"
        elif self.kind == "min_free_pct":
            pct = float(p.get("percent", 0))
            scope = set(p.get("subnet_ids") or [])
            for subnet_id, added in s.target_subnets.items():
                if scope and subnet_id not in scope:
                    continue
                st = ctx.subnets.get(subnet_id)
                if st is None or not st.usable:
                    continue
                after = 100.0 * (st.free - added) / st.usable
                if after < pct:
                    return f"{subnet_id} would drop to {after:.1f}% free (< {pct:g}%)"
        elif self.kind == "protected_eni":
            rx = _compile(p.get("pattern", ""))
            if rx is None:
                return None
            for eni_id in s.eni_ids:
                eni = ctx.enis.get(eni_id)
                hay = [eni_id]
                if eni:
                    hay += [
                        eni.get("description") or "",
                        eni.get("name") or "",
                        eni.get("owner_ref") or "",
                    ]
                if any(rx.search(h) for h in hay):
                    return f"{eni_id} is protected"
        elif self.kind == "ecs_scale_down":
            rx = _compile(p.get("pattern", ""))
            for f in sorted(s.flags):
                if not f.startswith("ecs_scale_down:"):
                    continue
                ref = f.split(":", 1)[1]
                matched = rx is None or bool(rx.search(ref))
                if p.get("mode", "deny") == "allow":
                    if not matched:
                        return f"{ref} is not on the ECS scale-down allow-list"
                elif matched:
                    return f"scaling down {ref} is not allowed"
        return None

    # -- compliance --------------------------------------------------------
    def violations(self, ctx: Context) -> list[str]:
        if not self.enabled:
            return []
        p = self.params
        out: list[str] = []
        if self.kind == "lambda_vpc_required":
            out += [
                f"Lambda {fn['name']} is not VPC-attached"
                for fn in ctx.lambdas
                if not fn.get("vpc_id")
            ]
        elif self.kind == "internal_only" and p.get("scope", "both") in ("load_balancer", "both"):
            out += [
                f"Load balancer {lb['name']} is {lb['scheme']}"
                for lb in ctx.load_balancers
                if lb.get("scheme") == "internet-facing"
            ]
        elif self.kind == "min_free_pct":
            pct = float(p.get("percent", 0))
            scope = set(p.get("subnet_ids") or [])
            for st in ctx.subnets.values():
                if scope and st.subnet_id not in scope:
                    continue
                if st.free_pct < pct:
                    out.append(
                        f"{st.subnet_id} ({st.cidr}) has {st.free_pct:.1f}% free (< {pct:g}%)"
                    )
        elif self.kind == "subnet_reserved":
            known = set(ctx.subnets)
            out += [
                f"reserved subnet {sid} not found in snapshot"
                for sid in p.get("subnet_ids") or []
                if known and sid not in known
            ]
        return out


def _compile(pattern: str) -> re.Pattern[str] | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(pattern), re.IGNORECASE)


# -- validation -------------------------------------------------------------

_SUBNET_RX = re.compile(r"^subnet-[0-9a-f]{8,17}$")


def _id_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        value = re.split(r"[\s,]+", value)
    return [str(v).strip() for v in value if str(v).strip()]


def normalize_params(kind: str, params: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalise the params for a rule kind; raise ValueError if bad."""
    if kind not in RULE_KINDS:
        raise ValueError(f"unknown rule kind {kind!r}")
    params = dict(params or {})
    if kind == "lambda_vpc_required":
        return {}
    if kind == "internal_only":
        scope = params.get("scope") or "both"
        if scope not in INTERNAL_SCOPES:
            raise ValueError(f"scope must be one of {INTERNAL_SCOPES}")
        return {"scope": scope}
    if kind == "subnet_reserved":
        ids = _id_list(params.get("subnet_ids"))
        if not ids:
            raise ValueError("subnet_reserved needs at least one subnet id")
        bad = [i for i in ids if not _SUBNET_RX.match(i)]
        if bad:
            raise ValueError(f"invalid subnet id(s): {', '.join(bad)}")
        return {"subnet_ids": ids}
    if kind == "min_free_pct":
        try:
            pct = float(params.get("percent"))  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError("percent must be a number") from exc
        if not 0 <= pct <= 100:
            raise ValueError("percent must be between 0 and 100")
        ids = _id_list(params.get("subnet_ids"))
        bad = [i for i in ids if not _SUBNET_RX.match(i)]
        if bad:
            raise ValueError(f"invalid subnet id(s): {', '.join(bad)}")
        return {"percent": pct, "subnet_ids": ids}
    if kind == "protected_eni":
        pattern = str(params.get("pattern") or "").strip()
        if not pattern:
            raise ValueError("protected_eni needs a pattern")
        return {"pattern": pattern}
    if kind == "ecs_scale_down":
        mode = params.get("mode") or "deny"
        if mode not in ECS_MODES:
            raise ValueError(f"mode must be one of {ECS_MODES}")
        pattern = str(params.get("pattern") or "").strip()
        if mode == "allow" and not pattern:
            raise ValueError("allow mode needs a pattern of cluster/service names to allow")
        return {"mode": mode, "pattern": pattern}
    return params  # pragma: no cover


def validate(rule: Rule) -> Rule:
    rule.name = (rule.name or "").strip()
    if not rule.name:
        raise ValueError("rule name is required")
    rule.params = normalize_params(rule.kind, rule.params)
    rule.description = (rule.description or "").strip()
    return rule


# -- storage ----------------------------------------------------------------


def _row_to_rule(r: sqlite3.Row) -> Rule:
    return Rule(
        id=r["id"],
        name=r["name"],
        kind=r["kind"],
        params=json.loads(r["params"]),
        enabled=bool(r["enabled"]),
        description=r["description"] or "",
    )


def list_rules(conn: sqlite3.Connection) -> list[Rule]:
    return [_row_to_rule(r) for r in conn.execute("SELECT * FROM rules ORDER BY name")]


def get_rule(conn: sqlite3.Connection, rule_id: int) -> Rule | None:
    r = conn.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    return _row_to_rule(r) if r else None


def save_rule(conn: sqlite3.Connection, rule: Rule) -> int:
    validate(rule)
    try:
        if rule.id is None:
            cur = conn.execute(
                "INSERT INTO rules(name, kind, params, enabled, description) VALUES(?,?,?,?,?)",
                (
                    rule.name,
                    rule.kind,
                    json.dumps(rule.params),
                    int(rule.enabled),
                    rule.description,
                ),
            )
            rule.id = int(cur.lastrowid or 0)
        else:
            conn.execute(
                "UPDATE rules SET name=?, kind=?, params=?, enabled=?, description=? WHERE id=?",
                (
                    rule.name,
                    rule.kind,
                    json.dumps(rule.params),
                    int(rule.enabled),
                    rule.description,
                    rule.id,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"a rule named {rule.name!r} already exists") from exc
    return rule.id


def delete_rule(conn: sqlite3.Connection, rule_id: int) -> None:
    conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))


# -- YAML -------------------------------------------------------------------


def export_yaml(rules: Iterable[Rule]) -> str:
    doc = {
        "rules": [
            {
                "name": r.name,
                "kind": r.kind,
                "enabled": r.enabled,
                "description": r.description,
                "params": r.params,
            }
            for r in rules
        ]
    }
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def parse_yaml(text: str) -> list[Rule]:
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    items = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise ValueError("expected a top-level 'rules:' list")
    rules: list[Rule] = []
    seen: set[str] = set()
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise ValueError(f"rule #{i} must be a mapping")
        try:
            rule = validate(
                Rule(
                    name=str(item.get("name") or ""),
                    kind=str(item.get("kind") or ""),
                    params=item.get("params") or {},
                    enabled=bool(item.get("enabled", True)),
                    description=str(item.get("description") or ""),
                )
            )
        except ValueError as exc:
            raise ValueError(f"rule #{i} ({item.get('name', '?')}): {exc}") from exc
        if rule.name in seen:
            raise ValueError(f"duplicate rule name {rule.name!r}")
        seen.add(rule.name)
        rules.append(rule)
    return rules


def import_rules(conn: sqlite3.Connection, rules: list[Rule], *, replace: bool = False) -> int:
    """Upsert rules by name; with ``replace`` drop all existing rules first."""
    if replace:
        conn.execute("DELETE FROM rules")
    existing = {r.name: r.id for r in list_rules(conn)}
    for rule in rules:
        rule.id = existing.get(rule.name)
        save_rule(conn, rule)
    return len(rules)
