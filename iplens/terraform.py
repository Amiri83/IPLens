"""Terraform ownership from local state files (read-only).

Accepts both the raw state format (``.tfstate``, ``"version": 4``) and the output
of ``terraform show -json``. Only three things are taken from each managed resource
instance: its address, its type and a normalised resource id (``subnet-…``, a load
balancer name, ``cluster/service``, …). Attribute values, outputs, sensitive
values and everything else in the file are never stored, logged or displayed; the
parsed document is dropped as soon as the ids are extracted. Files are only read.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# A state file larger than this is refused (uploads are also capped by Flask).
MAX_STATE_BYTES = 64 * 1024 * 1024
MAX_ROOT_NAME = 64
ROOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
# Resource ids kept from a state file: short, printable, no whitespace.
_ID_RE = re.compile(r"^[A-Za-z0-9._:/@+=-]{1,256}$")
_ADDRESS_RE = re.compile(r"^[\w.\[\]\"/:@+=-]{1,512}$")


def _lb_name(value: str) -> str:
    """ALB/NLB ARN ``…:loadbalancer/app/<name>/<hash>`` -> ``<name>``; a name stays."""
    if ":loadbalancer/" in value:
        parts = value.split("/")
        return parts[-2] if len(parts) >= 4 else ""
    return value


def _lambda_name(value: str) -> str:
    if ":function:" in value:
        return value.split(":function:", 1)[1].split(":", 1)[0]
    return value


def _ecs_service(value: str) -> str:
    """``…:service/<cluster>/<service>`` -> ``cluster/service`` (old ARNs lack the cluster)."""
    if ":service/" in value:
        parts = value.split(":service/", 1)[1].split("/")
        return "/".join(parts) if len(parts) == 2 else ""
    return ""


@dataclass(frozen=True)
class _Kind:
    kind: str
    prefix: str = ""  # required id prefix ("" = any)
    normalise: Callable[[str], str] | None = None  # id -> matched id (e.g. ARN -> name)


# Terraform resource type -> what IPLens matches it against.
MANAGED_TYPES: dict[str, _Kind] = {
    "aws_vpc": _Kind("vpc", "vpc-"),
    "aws_subnet": _Kind("subnet", "subnet-"),
    "aws_network_interface": _Kind("eni", "eni-"),
    "aws_security_group": _Kind("sg", "sg-"),
    "aws_vpc_endpoint": _Kind("vpce", "vpce-"),
    "aws_nat_gateway": _Kind("nat", "nat-"),
    "aws_instance": _Kind("instance", "i-"),
    "aws_lb": _Kind("lb", "", _lb_name),
    "aws_alb": _Kind("lb", "", _lb_name),
    "aws_elb": _Kind("lb"),
    "aws_lambda_function": _Kind("lambda", "", _lambda_name),
    "aws_ecs_service": _Kind("ecs_service", "", _ecs_service),
}
KIND_LABELS = {
    "vpc": "VPC",
    "subnet": "subnet",
    "eni": "network interface",
    "sg": "security group",
    "vpce": "VPC endpoint",
    "nat": "NAT gateway",
    "instance": "EC2 instance",
    "lb": "load balancer",
    "lambda": "Lambda function",
    "ecs_service": "ECS service",
}


@dataclass(frozen=True)
class TfResource:
    address: str
    type: str
    kind: str
    resource_id: str


def _index_suffix(key: Any) -> str:
    if key is None:
        return ""
    if isinstance(key, bool):
        return ""
    if isinstance(key, int):
        return f"[{key}]"
    return "[" + json.dumps(str(key)) + "]"


def _id_is_sensitive(sensitive: Any) -> bool:
    """True if the instance marks its ``id`` attribute as sensitive (then it is skipped).

    ``terraform show -json`` uses ``sensitive_values: {"id": true}``; raw state v4
    uses ``sensitive_attributes: [[{"type": "get_attr", "value": "id"}], …]``.
    """
    if isinstance(sensitive, dict):
        return sensitive.get("id") is True
    if isinstance(sensitive, list):
        for path in sensitive:
            if (
                isinstance(path, list)
                and len(path) == 1
                and isinstance(path[0], dict)
                and path[0].get("value") == "id"
            ):
                return True
    return False


def _resource(address: str, rtype: str, values: Any, sensitive: Any) -> TfResource | None:
    """The kept fields of one managed instance, or None if it is not mapped / not safe."""
    kind = MANAGED_TYPES.get(rtype)
    if kind is None or not isinstance(values, dict) or _id_is_sensitive(sensitive):
        return None
    raw = values.get("id")
    if not isinstance(raw, str):
        return None
    rid = kind.normalise(raw) if kind.normalise else raw
    if rtype == "aws_ecs_service" and not rid:
        # Old ARNs (``service/<name>``) lack the cluster: take it from ``cluster``.
        cluster, name = values.get("cluster"), values.get("name")
        if isinstance(cluster, str) and isinstance(name, str):
            rid = f"{cluster.rsplit('/', 1)[-1]}/{name}"
    if not rid or not _ID_RE.match(rid) or not rid.startswith(kind.prefix):
        return None
    if not _ADDRESS_RE.match(address):
        return None
    return TfResource(address=address, type=rtype, kind=kind.kind, resource_id=rid)


def _from_state_v4(doc: dict[str, Any]) -> Iterator[TfResource]:
    for res in doc.get("resources") or []:
        if not isinstance(res, dict) or res.get("mode") != "managed":
            continue
        rtype, name = res.get("type"), res.get("name")
        if not isinstance(rtype, str) or not isinstance(name, str):
            continue
        module = res.get("module")
        base = f"{module}.{rtype}.{name}" if isinstance(module, str) and module else ""
        base = base or f"{rtype}.{name}"
        for inst in res.get("instances") or []:
            if not isinstance(inst, dict):
                continue
            address = base + _index_suffix(inst.get("index_key"))
            found = _resource(
                address, rtype, inst.get("attributes"), inst.get("sensitive_attributes")
            )
            if found:
                yield found


def _from_show_json(module: Any, depth: int = 0) -> Iterator[TfResource]:
    if not isinstance(module, dict) or depth > 50:
        return
    for res in module.get("resources") or []:
        if not isinstance(res, dict) or res.get("mode") != "managed":
            continue
        address, rtype = res.get("address"), res.get("type")
        if isinstance(address, str) and isinstance(rtype, str):
            found = _resource(address, rtype, res.get("values"), res.get("sensitive_values"))
            if found:
                yield found
    for child in module.get("child_modules") or []:
        yield from _from_show_json(child, depth + 1)


def parse_state(text: str | bytes) -> list[TfResource]:
    """Managed AWS resources of a ``.tfstate`` (v4) or ``terraform show -json`` document.

    Raises ValueError for anything that is neither. Never returns attribute values.
    """
    if len(text) > MAX_STATE_BYTES:
        raise ValueError("state file is too large")
    try:
        doc = json.loads(text)
    except ValueError:
        raise ValueError("not a JSON document") from None
    if not isinstance(doc, dict):
        raise ValueError("not a Terraform state document")
    if "values" in doc or "format_version" in doc:  # terraform show -json
        values = doc.get("values") or {}
        found = _from_show_json(values.get("root_module") if isinstance(values, dict) else None)
    elif isinstance(doc.get("version"), int) and isinstance(doc.get("resources"), list):
        if doc["version"] < 4:
            raise ValueError("only Terraform state format version 4 is supported")
        found = _from_state_v4(doc)
    else:
        raise ValueError("not a Terraform state or 'terraform show -json' document")
    del doc  # nothing but the extracted ids outlives parsing
    return sorted(set(found), key=lambda r: (r.address, r.kind, r.resource_id))


def read_state_file(path: str) -> tuple[str, list[TfResource]]:
    """Parse a local state file (opened read-only); returns (resolved path, resources)."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError("no such file")
    if p.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("state file is too large")
    with p.open("rb") as fh:
        return str(p.resolve()), parse_state(fh.read())


def validate_root_name(name: str) -> str:
    name = (name or "").strip()
    if not name or len(name) > MAX_ROOT_NAME or not ROOT_NAME_RE.match(name):
        raise ValueError(
            f"root name must be 1-{MAX_ROOT_NAME} characters: letters, digits, space . _ -"
        )
    return name


def root_name_from_filename(filename: str) -> str:
    stem = Path(filename or "").name
    for suffix in (".json", ".tfstate", ".backup"):
        stem = stem.removesuffix(suffix)
    stem = re.sub(r"[^A-Za-z0-9 ._-]", "-", stem).strip(" .-_")
    return stem[:MAX_ROOT_NAME] or "root"


# -- storage --------------------------------------------------------------------------


def save_root(
    conn: sqlite3.Connection,
    name: str,
    resources: Iterable[TfResource],
    *,
    source: str = "",
    source_path: str = "",
) -> int:
    """Create or replace the root ``name`` with ``resources``; returns its id."""
    name = validate_root_name(name)
    now = datetime.now(UTC).isoformat(timespec="seconds")
    row = conn.execute("SELECT id FROM tf_roots WHERE name=?", (name,)).fetchone()
    if row:
        root_id = row["id"]
        conn.execute(
            "UPDATE tf_roots SET source=?, source_path=?, loaded_at=? WHERE id=?",
            (source[:300], source_path[:1000], now, root_id),
        )
        conn.execute("DELETE FROM tf_resources WHERE root_id=?", (root_id,))
    else:
        cur = conn.execute(
            "INSERT INTO tf_roots(name, source, source_path, loaded_at) VALUES(?,?,?,?)",
            (name, source[:300], source_path[:1000], now),
        )
        root_id = int(cur.lastrowid or 0)
    conn.executemany(
        "INSERT OR IGNORE INTO tf_resources(root_id, kind, resource_id, address, type) "
        "VALUES(?,?,?,?,?)",
        [(root_id, r.kind, r.resource_id, r.address, r.type) for r in resources],
    )
    return root_id


def list_roots(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in conn.execute(
            "SELECT r.id, r.name, r.source, r.source_path, r.loaded_at, "
            "COUNT(t.resource_id) AS resources FROM tf_roots r "
            "LEFT JOIN tf_resources t ON t.root_id = r.id GROUP BY r.id ORDER BY r.name"
        )
    ]


def get_root(conn: sqlite3.Connection, root_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM tf_roots WHERE id=?", (root_id,)).fetchone()
    return dict(row) if row else None


def delete_root(conn: sqlite3.Connection, root_id: int) -> bool:
    return conn.execute("DELETE FROM tf_roots WHERE id=?", (root_id,)).rowcount > 0


# -- ownership ------------------------------------------------------------------------

TfIndex = dict[tuple[str, str], list[dict[str, str]]]


def load_index(conn: sqlite3.Connection) -> TfIndex:
    """``(kind, resource id) -> [{"root", "address", "type"}, …]`` over every root."""
    index: TfIndex = {}
    for r in conn.execute(
        "SELECT t.kind, t.resource_id, t.address, t.type, r.name AS root FROM tf_resources t "
        "JOIN tf_roots r ON r.id = t.root_id ORDER BY r.name, t.address"
    ):
        index.setdefault((r["kind"], r["resource_id"]), []).append(
            {"root": r["root"], "address": r["address"], "type": r["type"]}
        )
    return index


def resource_keys(row: dict[str, Any]) -> list[tuple[str, str]]:
    """Index keys that identify the resource owning an ENI row, most specific first."""
    keys = [("eni", row["eni_id"])] if row.get("eni_id") else []
    otype, ref = row.get("owner_type"), row.get("owner_ref") or ""
    if otype == "elb" and ref:
        keys.append(("lb", ref))
    elif otype == "lambda":
        names = row.get("owner_names")
        names = names if isinstance(names, list) and names else ([ref] if ref else [])
        keys += [("lambda", n) for n in names]
    elif otype == "ecs" and ref.count("/") == 2:
        keys.append(("ecs_service", ref.rsplit("/", 1)[0]))
    elif otype == "vpc_endpoint" and ref:
        keys.append(("vpce", ref))
    elif otype == "nat" and ref:
        keys.append(("nat", ref))
    instance = row.get("instance_id") or (ref if otype == "ec2" else "")
    if instance and instance.startswith("i-"):
        keys.append(("instance", instance))
    return keys


def ownership(index: TfIndex, keys: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    """Every (root, address) managing one of ``keys``, without duplicates."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for key in keys:
        for m in index.get(key, []):
            if (m["root"], m["address"]) not in seen:
                seen.add((m["root"], m["address"]))
                out.append(m)
    return out
