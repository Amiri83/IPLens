"""Pre-deploy IP fit check (``iplens check``): does a Terraform plan, or N more IPs, fit
the subnets it lands in?

Per subnet: ``left = free - existing headroom demand - plan demand``. The existing demand
is the :mod:`iplens.headroom` worst case (everything at max scale); the plan demand comes
from the new / changed resources of a ``terraform show -json`` plan, one
:class:`PlanItem` per resource and subnet, each with its assumption:

- ``aws_instance``: 1 ENI per instance (its primary network interface).
- ``aws_network_interface``: 1.
- ``aws_lb``: application: :data:`iplens.headroom.ALB_RESERVE` per subnet (AWS needs them
  free to scale the ALB); network / gateway: 1 ENI per subnet.
- ``aws_vpc_endpoint`` (Interface, GatewayLoadBalancer): 1 ENI per subnet.
- ``aws_nat_gateway``: 1.
- ``aws_ecs_service`` (awsvpc): ``desired_count`` tasks spread over its subnets, plus the
  rolling-deployment surge of :func:`iplens.headroom.ecs_surge`.
- ``aws_autoscaling_group``: ``max_size`` instances spread over its subnets, 1 ENI each.
- ``aws_lambda_function``: 1 per subnet / security-group combination that has no Lambda
  ENI yet (and is not already counted for another function of the plan).
- ``aws_db_instance``: 1 (2 with Multi-AZ); AWS picks the subnet among the DB subnet
  group's, so each candidate subnet must fit 1.

An update counts only what it adds (the demand after the change minus the demand before,
per subnet); a replacement that destroys first likewise, one that creates first counts in
full. A subnet id that is unknown until apply makes the demand *unresolved*: listed and
warned about, never a failure.

The data comes from a "snapshot for CI" file exported by the UI
(:func:`export_snapshot` / :func:`load_snapshot`) or live from AWS
(:mod:`iplens.fitlive`). Everything here is pure; no AWS call is made.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, headroom
from . import rules as rules_mod
from .headroom import ALB_RESERVE, Contributor, EcsService, Inputs, Subnet

SNAPSHOT_FORMAT = "iplens-ci-snapshot"
SNAPSHOT_VERSION = 1

# Exit codes of ``iplens check``.
EXIT_FITS, EXIT_FAILS, EXIT_ERROR = 0, 1, 2
FITS, SHORT, BELOW_MIN = "fits", "short", "below-min"
STATUS_LABELS = {FITS: "fits", SHORT: "SHORT", BELOW_MIN: "below min"}

# Plan resource types with an IP demand (the Lambda and DB rules are special-cased).
LAMBDA_TYPE = "aws_lambda_function"
DB_TYPE = "aws_db_instance"
DB_SUBNET_GROUP_TYPE = "aws_db_subnet_group"
# Rule kinds that only veto optimization suggestions; a plan cannot break them.
SUGGESTION_ONLY_RULES = ("ecs_scale_down",)


class CheckError(Exception):
    """The check cannot be done (bad input file, unknown subnet, AWS error): exit 2."""


# -- snapshot for CI ------------------------------------------------------------------------


def inputs_to_dict(inputs: Inputs) -> dict[str, Any]:
    """:class:`iplens.headroom.Inputs` as plain JSON data (see :func:`inputs_from_dict`)."""
    return {
        "subnets": [asdict(s) for s in inputs.subnets],
        "asgs": [
            {
                **asdict(a),
                "subnet_ids": list(a.subnet_ids),
                "instances": [list(i) for i in a.instances],
            }
            for a in inputs.asgs
        ],
        "ecs_services": [
            {**asdict(s), "subnet_ids": None if s.subnet_ids is None else list(s.subnet_ids)}
            for s in inputs.ecs
        ],
        "ecs_max": [
            {"cluster": c, "service": s, "max": n} for (c, s), n in sorted(inputs.ecs_max.items())
        ],
        "load_balancers": [
            {**asdict(b), "subnet_ids": None if b.subnet_ids is None else list(b.subnet_ids)}
            for b in inputs.lbs
        ],
        "lambdas": [
            {
                "name": f.name,
                "subnet_ids": list(f.subnet_ids),
                "security_groups": list(f.security_groups),
            }
            for f in inputs.lambdas
        ],
        "instance_enis": {k: list(v) for k, v in sorted(inputs.instance_enis.items())},
        "task_subnets": [
            {"cluster": c, "service": s, "subnets": dict(sorted(n.items()))}
            for (c, s), n in sorted(inputs.task_subnets.items())
        ],
        "lb_eni_subnets": {k: sorted(v) for k, v in sorted(inputs.lb_eni_subnets.items())},
        "lambda_combos": [[sid, list(sgs)] for sid, sgs in sorted(inputs.lambda_combos)],
        "missing": sorted(inputs.missing),
    }


def _ids(value: Any) -> tuple[str, ...] | None:
    return None if value is None else tuple(str(v) for v in value)


def inputs_from_dict(data: dict[str, Any]) -> Inputs:
    """The inverse of :func:`inputs_to_dict`; ValueError on a malformed document."""
    try:
        return Inputs(
            subnets=[
                Subnet(
                    subnet_id=str(s["subnet_id"]),
                    vpc_id=str(s.get("vpc_id") or ""),
                    az=str(s.get("az") or ""),
                    cidr=str(s.get("cidr") or ""),
                    name=str(s.get("name") or ""),
                    free=int(s["free"]),
                    usable=int(s.get("usable") or 0),
                    consumed=int(s.get("consumed") or 0),
                )
                for s in data["subnets"]
            ],
            asgs=[
                headroom.Asg(
                    name=str(a["name"]),
                    min_size=int(a.get("min_size") or 0),
                    desired=int(a.get("desired") or 0),
                    max_size=int(a.get("max_size") or 0),
                    subnet_ids=_ids(a.get("subnet_ids")) or (),
                    instances=tuple((str(i), str(az)) for i, az in a.get("instances") or []),
                )
                for a in data.get("asgs") or []
            ],
            ecs=[
                EcsService(
                    cluster=str(s["cluster"]),
                    service=str(s["service"]),
                    desired=int(s.get("desired") or 0),
                    running=int(s.get("running") or 0),
                    subnet_ids=_ids(s.get("subnet_ids")),
                    max_percent=s.get("max_percent"),
                    controller=s.get("controller"),
                )
                for s in data.get("ecs_services") or []
            ],
            ecs_max={
                (str(m["cluster"]), str(m["service"])): int(m["max"])
                for m in data.get("ecs_max") or []
            },
            lbs=[
                headroom.LoadBalancer(
                    str(b["name"]), str(b.get("lb_type") or ""), _ids(b.get("subnet_ids"))
                )
                for b in data.get("load_balancers") or []
            ],
            lambdas=[
                headroom.LambdaFn(
                    str(f["name"]),
                    _ids(f.get("subnet_ids")) or (),
                    _ids(f.get("security_groups")) or (),
                )
                for f in data.get("lambdas") or []
            ],
            instance_enis={
                str(k): [str(s) for s in v] for k, v in (data.get("instance_enis") or {}).items()
            },
            task_subnets={
                (str(t["cluster"]), str(t["service"])): {
                    str(k): int(n) for k, n in (t.get("subnets") or {}).items()
                }
                for t in data.get("task_subnets") or []
            },
            lb_eni_subnets={
                str(k): {str(s) for s in v} for k, v in (data.get("lb_eni_subnets") or {}).items()
            },
            lambda_combos={
                (str(sid), tuple(sorted(str(g) for g in sgs)))
                for sid, sgs in data.get("lambda_combos") or []
            },
            missing=frozenset(str(m) for m in data.get("missing") or [] if m in headroom.SOURCES),
        )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"malformed snapshot data: {type(exc).__name__}: {exc}") from exc


def export_snapshot(conn: Any, snap: Any) -> dict[str, Any]:
    """The "snapshot for CI" document of snapshot row ``snap``: every subnet's free IPs
    and the headroom inputs (all subnets: a plan may touch any of them). No credentials
    or other secrets: only what :func:`iplens.headroom.load` reads."""
    return {
        "format": SNAPSHOT_FORMAT,
        "version": SNAPSHOT_VERSION,
        "iplens_version": __version__,
        "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "snapshot": {
            "id": snap["id"],
            "taken_at": snap["taken_at"],
            "region": snap["region"] or "",
            "account_id": snap["account_id"] or "",
            # IPLens's own account record: rules limited to an account apply to it.
            "account_ref": snap["account_ref"],
        },
        "inputs": inputs_to_dict(headroom.load(conn, snap["id"])),
    }


@dataclass
class Source:
    """Where the check's data came from (shown in every output format)."""

    kind: str  # snapshot | live
    label: str
    account_ref: int | None = None  # the IPLens account of a snapshot (for scoped rules)
    taken_at: str = ""

    @property
    def notes_label(self) -> str:
        return "the CI snapshot" if self.kind == "snapshot" else "the live check"


def load_snapshot(path: str | Path) -> tuple[Inputs, Source]:
    """A "snapshot for CI" file; CheckError when unreadable or not one."""
    doc = _read_json(path, "snapshot")
    if not isinstance(doc, dict) or doc.get("format") != SNAPSHOT_FORMAT:
        raise CheckError(f"{path}: not an IPLens snapshot for CI (format {SNAPSHOT_FORMAT!r})")
    if doc.get("version") != SNAPSHOT_VERSION:
        raise CheckError(
            f"{path}: snapshot format version {doc.get('version')!r} is not supported "
            f"(expected {SNAPSHOT_VERSION}); export it again"
        )
    try:
        inputs = inputs_from_dict(doc.get("inputs") or {})
    except ValueError as exc:
        raise CheckError(f"{path}: {exc}") from exc
    meta = doc.get("snapshot") or {}
    ref = meta.get("account_ref")
    where = ", ".join(str(v) for v in (meta.get("account_id"), meta.get("region")) if v)
    taken = str(meta.get("taken_at") or "")
    label = f"snapshot {Path(path).name}" + (f" taken {taken}" if taken else "")
    return inputs, Source(
        kind="snapshot",
        label=label + (f" ({where})" if where else ""),
        account_ref=ref if isinstance(ref, int) else None,
        taken_at=taken,
    )


def _read_json(path: str | Path, what: str) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CheckError(f"cannot read {what} file {path}: {exc.strerror or exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CheckError(f"{path}: invalid JSON: {exc}") from exc


def load_rules(path: str | Path) -> list[rules_mod.Rule]:
    """A rules export of the UI (YAML; JSON works too); CheckError when invalid."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CheckError(f"cannot read rules file {path}: {exc.strerror or exc}") from exc
    try:
        return rules_mod.parse_yaml(text)
    except ValueError as exc:
        raise CheckError(f"{path}: {exc}") from exc


# -- Terraform plan -------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanResource:
    """One ``resource_changes`` entry of a ``terraform show -json`` plan."""

    address: str
    type: str
    actions: tuple[str, ...]
    before: dict[str, Any]
    after: dict[str, Any]
    after_unknown: Any  # same shape as ``after``; True where known after apply

    @property
    def creates(self) -> bool:
        return "create" in self.actions

    @property
    def updates(self) -> bool:
        return "update" in self.actions

    @property
    def deletes(self) -> bool:
        return "delete" in self.actions

    @property
    def counts_in_full(self) -> bool:
        """New, or replaced create-before-destroy: old and new exist together."""
        return self.creates and (not self.deletes or self.actions[0] == "create")


@dataclass
class Plan:
    resources: list[PlanResource]
    # DB subnet group name -> its subnets (None: known after apply).
    subnet_groups: dict[str, tuple[str, ...] | None] = field(default_factory=dict)


def parse_plan(doc: Any) -> Plan:
    """The managed resource changes of a ``terraform show -json`` plan document."""
    if not isinstance(doc, dict) or not isinstance(doc.get("resource_changes"), list):
        raise CheckError(
            "not a Terraform plan: expected the JSON of `terraform show -json <planfile>` "
            "with a resource_changes list"
        )
    resources = []
    for rc in doc["resource_changes"]:
        if not isinstance(rc, dict) or rc.get("mode", "managed") != "managed":
            continue
        change = rc.get("change") or {}
        resources.append(
            PlanResource(
                address=str(rc.get("address") or rc.get("type") or "?"),
                type=str(rc.get("type") or ""),
                actions=tuple(change.get("actions") or ()),
                before=change.get("before") if isinstance(change.get("before"), dict) else {},
                after=change.get("after") if isinstance(change.get("after"), dict) else {},
                after_unknown=change.get("after_unknown") or {},
            )
        )
    groups: dict[str, tuple[str, ...] | None] = {}
    for values in _state_resources(doc.get("prior_state"), DB_SUBNET_GROUP_TYPE):
        if values.get("name"):
            groups[values["name"]] = tuple(values.get("subnet_ids") or ())
    for r in resources:
        if r.type != DB_SUBNET_GROUP_TYPE or r.actions == ("delete",):
            continue
        name = r.after.get("name")
        if isinstance(name, str) and name:
            ids, unknown = _strings(r.after, r.after_unknown, "subnet_ids")
            groups[name] = None if unknown else tuple(ids)
    return Plan(resources, groups)


def load_plan(path: str | Path) -> Plan:
    return parse_plan(_read_json(path, "plan"))


def _state_resources(state: Any, rtype: str) -> Iterator[dict[str, Any]]:
    """The ``values`` of every ``rtype`` resource of a state (all modules)."""
    if not isinstance(state, dict):
        return
    stack = [(state.get("values") or {}).get("root_module") or {}]
    while stack:
        module = stack.pop()
        for r in module.get("resources") or []:
            if r.get("type") == rtype and isinstance(r.get("values"), dict):
                yield r["values"]
        stack.extend(module.get("child_modules") or [])


def _strings(value: Any, unknown: Any, *path: str) -> tuple[list[str], int]:
    """The strings at ``path`` (keys; lists of nested blocks are walked) and how many
    values there are known after apply (at least 1 when a whole list is)."""
    if unknown is True:
        return [], 1
    if isinstance(value, list):
        found: list[str] = []
        unknowns = 0
        for i, item in enumerate(value):
            u = unknown[i] if isinstance(unknown, list) and i < len(unknown) else None
            ids, n = _strings(item, u, *path)
            found += [s for s in ids if s not in found]
            unknowns += n
        return found, unknowns
    if path:
        if not isinstance(value, dict):
            return [], 1 if isinstance(unknown, dict) and unknown.get(path[0]) is True else 0
        sub = unknown.get(path[0]) if isinstance(unknown, dict) else None
        return _strings(value.get(path[0]), sub, *path[1:])
    return ([value], 0) if isinstance(value, str) and value else ([], 0)


def _is_unknown(unknown: Any, key: str) -> bool:
    return isinstance(unknown, dict) and unknown.get(key) is True


# -- plan demand ----------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanItem:
    address: str
    type: str
    subnet_id: str
    ips: int
    assumption: str

    @property
    def text(self) -> str:
        return f"{self.address}: +{self.ips} ({self.assumption})"


@dataclass(frozen=True)
class Unresolved:
    address: str
    type: str
    reason: str
    ips: int | None  # what it would need, when known

    @property
    def text(self) -> str:
        need = f"needs {self.ips} IP{'' if self.ips == 1 else 's'}, " if self.ips else ""
        return f"{self.address}: {self.reason} ({need}not counted)"


@dataclass
class Demand:
    items: list[PlanItem] = field(default_factory=list)
    unresolved: list[Unresolved] = field(default_factory=list)

    @property
    def subnet_ids(self) -> list[str]:
        return sorted({i.subnet_id for i in self.items})


Placement = tuple[str, int, str]  # (subnet id, IPs, assumption)


@dataclass
class _Found:
    placed: list[Placement] = field(default_factory=list)
    unresolved: list[tuple[str, int | None]] = field(default_factory=list)  # (reason, IPs)


@dataclass
class _Ctx:
    inputs: Inputs
    groups: dict[str, tuple[str, ...] | None]
    include_surge: bool

    @property
    def az_of(self) -> dict[str, str]:
        return {s.subnet_id: s.az for s in self.inputs.subnets}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _single(v: dict[str, Any], u: Any, ips: int, text: str) -> _Found:
    """A resource in one ``subnet_id``."""
    ids, unknown = _strings(v, u, "subnet_id")
    if unknown:
        return _Found(unresolved=[("subnet_id is known after apply", ips)])
    if not ids:
        return _Found(unresolved=[("no subnet_id: AWS picks a default subnet", ips)])
    return _Found([(ids[0], ips, text)])


def _instance(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    if not v.get("subnet_id") and not _is_unknown(u, "subnet_id") and v.get("network_interface"):
        return _Found()  # attaches aws_network_interface ENIs: counted there
    return _single(v, u, 1, "1 ENI per instance: its primary network interface")


def _network_interface(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    return _single(v, u, 1, "1 IP: the interface's primary private IP")


def _nat_gateway(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    return _single(v, u, 1, "1 IP for the NAT gateway's ENI")


def _per_subnet(ids: list[str], unknown: int, ips: int, text: str, what: str) -> _Found:
    found = _Found([(sid, ips, text) for sid in ids])
    if unknown:
        found.unresolved.append((f"{_plural(unknown, what)} known after apply", ips * unknown))
    return found


def _either(a: tuple[list[str], int], b: tuple[list[str], int]) -> tuple[list[str], int]:
    """Subnets set by one of two attributes, the other computed from it (``subnets`` /
    ``subnet_mapping``): the known ids win over the computed side's "known after apply"."""
    (ids_a, unknown_a), (ids_b, unknown_b) = a, b
    if ids_a and ids_b:
        return ids_a + [s for s in ids_b if s not in ids_a], min(unknown_a, unknown_b)
    if ids_a or ids_b:
        return (ids_a, unknown_a) if ids_a else (ids_b, unknown_b)
    return [], max(unknown_a, unknown_b)


def _lb(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    lb_type = v.get("load_balancer_type") or "application"
    ids, unknown = _either(_strings(v, u, "subnets"), _strings(v, u, "subnet_mapping", "subnet_id"))
    if lb_type == "application":
        per, text = ALB_RESERVE, f"ALB: AWS needs ≥ {ALB_RESERVE} free IPs per subnet to scale"
    else:
        per, text = 1, f"{'NLB' if lb_type == 'network' else 'GWLB'}: 1 ENI per subnet"
    return _per_subnet(ids, unknown, per, text, "subnet")


def _vpc_endpoint(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    kind = v.get("vpc_endpoint_type") or "Gateway"
    if kind not in ("Interface", "GatewayLoadBalancer"):
        return _Found()  # Gateway endpoints (S3, DynamoDB) are route table entries
    ids, unknown = _either(
        _strings(v, u, "subnet_ids"), _strings(v, u, "subnet_configuration", "subnet_id")
    )
    return _per_subnet(ids, unknown, 1, f"{kind} endpoint: 1 ENI per subnet", "subnet")


def _spread(count: int, ids: list[str], text: Any) -> list[Placement]:
    """``count`` units spread evenly over ``ids`` (iplens.headroom.spread);
    ``text(k)`` is the assumption for a subnet that gets ``k``."""
    return [(sid, k, text(k)) for sid, k in headroom.spread(count, ids, {}).items()]


def _ecs_service(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    ids, unknown = _strings(v, u, "network_configuration", "subnets")
    if not ids and not unknown:
        return _Found()  # not awsvpc: its tasks take no IPs of their own
    desired = int(v.get("desired_count") or 0)
    controller = next(
        (c.get("type") for c in v.get("deployment_controller") or [] if isinstance(c, dict)), None
    )
    pct = v.get("deployment_maximum_percent")
    svc = EcsService(
        cluster="",
        service=str(v.get("name") or ""),
        desired=desired,
        running=0,
        subnet_ids=tuple(ids) or ("?",),
        max_percent=int(pct) if isinstance(pct, int | float) else None,
        controller=controller,
    )
    # The headroom surge rule, at max = desired_count.
    surge_inputs = Inputs(subnets=[], ecs_max={(svc.cluster, svc.service): desired})
    surge = headroom.ecs_surge(svc, surge_inputs) if ctx.include_surge else {}
    if unknown:
        need = desired + sum(c.ips for c in surge.values())
        return _Found(unresolved=[("network_configuration subnets are known after apply", need)])
    n = len(ids)
    placed = _spread(
        desired,
        ids,
        lambda k: (
            f"desired_count {desired}: {_plural(k, 'task')} here of {desired} over "
            f"{_plural(n, 'subnet')}, 1 IP each"
        ),
    )
    placed += [(sid, c.ips, f"deploy surge: {c.assumption}") for sid, c in surge.items()]
    return _Found(placed)


def _asg(v: dict[str, Any], u: Any, ctx: _Ctx) -> _Found:
    ids, unknown = _strings(v, u, "vpc_zone_identifier")
    top = int(v.get("max_size") or 0)
    if unknown:
        return _Found(unresolved=[("vpc_zone_identifier is known after apply", top)])
    if not ids:
        return _Found(unresolved=[("no vpc_zone_identifier: AWS uses default subnets", top)])
    n = len(ids)
    return _Found(
        _spread(
            top,
            ids,
            lambda k: (
                f"max_size {top}: {_plural(k, 'instance')} here of {top} over "
                f"{_plural(n, 'subnet')}, 1 ENI per instance assumed"
            ),
        )
    )


HANDLERS = {
    "aws_instance": _instance,
    "aws_network_interface": _network_interface,
    "aws_lb": _lb,
    "aws_alb": _lb,  # the older alias of aws_lb
    "aws_vpc_endpoint": _vpc_endpoint,
    "aws_nat_gateway": _nat_gateway,
    "aws_ecs_service": _ecs_service,
    "aws_autoscaling_group": _asg,
}
DEMAND_TYPES = (*HANDLERS, LAMBDA_TYPE, DB_TYPE)


def _net(res: PlanResource, after: _Found, before: _Found) -> list[PlanItem]:
    """What the change adds per subnet: the demand after it minus the demand before."""
    was: Counter[str] = Counter()
    for sid, n, _text in before.placed:
        was[sid] += n
    by_subnet: dict[str, list[Placement]] = defaultdict(list)
    for p in after.placed:
        by_subnet[p[0]].append(p)
    items = []
    for sid, placed in by_subnet.items():
        if not was[sid]:
            items += [PlanItem(res.address, res.type, sid, n, t) for _s, n, t in placed if n]
            continue
        net = sum(n for _s, n, _t in placed) - was[sid]
        if net > 0:
            text = "; ".join(t for _s, _n, t in placed)
            items.append(
                PlanItem(
                    res.address, res.type, sid, net, f"{text}; was {was[sid]} here, net +{net}"
                )
            )
    return items


def _db_candidates(v: dict[str, Any], u: Any, ctx: _Ctx) -> tuple[list[str], str]:
    """The subnets a DB instance may land in, or ([], why they are unknown)."""
    group = v.get("db_subnet_group_name")
    if _is_unknown(u, "db_subnet_group_name"):
        return [], "db_subnet_group_name is known after apply"
    if not group:
        return [], "no db_subnet_group_name: the default DB subnet group's subnets are unknown"
    if group not in ctx.groups:
        return [], f"DB subnet group {group} is not in the plan, so its subnets are unknown"
    ids = ctx.groups[group]
    if ids is None:
        return [], f"the subnets of DB subnet group {group} are known after apply"
    az = v.get("availability_zone")
    az_of = ctx.az_of
    if isinstance(az, str) and az and any(az_of.get(s) == az for s in ids):
        ids = tuple(s for s in ids if az_of.get(s) == az)
    return sorted(set(ids)), ""


def _db_count(values: dict[str, Any]) -> int:
    return 2 if values.get("multi_az") else 1


def _db_demand(res: PlanResource, ctx: _Ctx) -> tuple[list[PlanItem], list[Unresolved]]:
    count = _db_count(res.after)
    group = res.after.get("db_subnet_group_name")
    # Replaced into another subnet group: its old IPs are freed elsewhere.
    moved = res.creates and res.before.get("db_subnet_group_name") != group
    full = res.counts_in_full or moved or not res.before
    added = count if full else count - _db_count(res.before)
    if added <= 0:
        return [], []
    cands, why = _db_candidates(res.after, res.after_unknown, ctx)
    if not cands:
        return [], [Unresolved(res.address, res.type, why, added)]
    what = "primary + Multi-AZ standby" if count == 2 else "1 IP for the DB instance's ENI"
    if added == 1 and count == 2 and not full:
        what = "Multi-AZ turned on: 1 IP for the standby"
    if len(cands) == 1:
        return [PlanItem(res.address, res.type, cands[0], added, what)], []
    return [
        PlanItem(
            res.address,
            res.type,
            sid,
            1,
            f"{what}; AWS picks the subnet among the {len(cands)} of DB subnet group {group} "
            "(Multi-AZ: different AZs), so each must fit 1",
        )
        for sid in cands
    ], []


def _lambda_combos(values: dict[str, Any], u: Any) -> tuple[list[str], tuple[str, ...] | None, int]:
    """(known subnets, sorted security groups or None when known after apply, unknown
    subnets) of a function's vpc_config."""
    ids, unknown = _strings(values, u, "vpc_config", "subnet_ids")
    sgs, sg_unknown = _strings(values, u, "vpc_config", "security_group_ids")
    return ids, None if sg_unknown else tuple(sorted(sgs)), unknown


def _lambda_demand(
    res: PlanResource, ctx: _Ctx, seen: set[tuple[str, tuple[str, ...]]]
) -> tuple[list[PlanItem], list[Unresolved]]:
    ids, sgs, unknown = _lambda_combos(res.after, res.after_unknown)
    if not res.counts_in_full and res.before:
        old_ids, old_sgs, _ = _lambda_combos(res.before, {})
        had = {(s, old_sgs) for s in old_ids if old_sgs is not None}
    else:
        had = set()
    items = []
    for sid in ids:
        if sgs is None:
            text = "security groups known after apply: a new subnet / security group combination"
            items.append(PlanItem(res.address, res.type, sid, 1, f"{text} needs a Hyperplane ENI"))
            continue
        combo = (sid, sgs)
        if combo in ctx.inputs.lambda_combos or combo in seen or combo in had:
            continue
        seen.add(combo)
        groups = ", ".join(sgs) or "no security group"
        items.append(
            PlanItem(
                res.address,
                res.type,
                sid,
                1,
                f"new subnet / security group combination ({groups}) needs a Hyperplane ENI",
            )
        )
    unresolved = (
        [Unresolved(res.address, res.type, "vpc_config subnets are known after apply", unknown)]
        if unknown
        else []
    )
    return items, unresolved


def plan_demand(plan: Plan, inputs: Inputs, include_surge: bool = True) -> Demand:
    """The IPs the plan's new / changed resources need, per subnet."""
    ctx = _Ctx(inputs, plan.subnet_groups, include_surge)
    demand = Demand()
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for res in plan.resources:
        if not (res.creates or res.updates) or res.type not in DEMAND_TYPES:
            continue
        if res.type == LAMBDA_TYPE:
            items, unresolved = _lambda_demand(res, ctx, seen)
        elif res.type == DB_TYPE:
            items, unresolved = _db_demand(res, ctx)
        else:
            handler = HANDLERS[res.type]
            after = handler(res.after, res.after_unknown, ctx)
            before = (
                _Found() if res.counts_in_full or not res.before else handler(res.before, {}, ctx)
            )
            items = _net(res, after, before)
            unresolved = [Unresolved(res.address, res.type, r, n) for r, n in after.unresolved]
        demand.items += items
        demand.unresolved += unresolved
    return demand


def need_demand(subnet_id: str, need: int) -> Demand:
    """``--subnet ID --need N``: N more IPs in one subnet."""
    return Demand([PlanItem("--need", "request", subnet_id, need, f"{need} more IPs requested")])


# -- result ---------------------------------------------------------------------------------


@dataclass
class SubnetFit:
    subnet: Subnet
    existing: list[Contributor]
    plan: list[PlanItem]
    min_free_pct: float = 0.0

    @property
    def free(self) -> int:
        return self.subnet.free

    @property
    def existing_demand(self) -> int:
        return sum(c.ips for c in self.existing)

    @property
    def plan_demand(self) -> int:
        return sum(i.ips for i in self.plan)

    @property
    def left(self) -> int:
        return self.free - self.existing_demand - self.plan_demand

    @property
    def left_pct(self) -> float:
        return 100.0 * self.left / self.subnet.usable if self.subnet.usable else 0.0

    @property
    def status(self) -> str:
        if self.left < 0:
            return SHORT
        if self.min_free_pct and self.left_pct < self.min_free_pct:
            return BELOW_MIN
        return FITS

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]


@dataclass(frozen=True)
class Violation:
    rule: str
    kind: str
    message: str

    @property
    def text(self) -> str:
        return f"{self.rule} ({self.kind}): {self.message}"


@dataclass
class CheckResult:
    mode: str  # plan | need
    source: Source
    subnets: list[SubnetFit]
    unresolved: list[Unresolved] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    min_free_pct: float = 0.0
    include_surge: bool = True

    @property
    def failing(self) -> list[SubnetFit]:
        return [s for s in self.subnets if s.status != FITS]

    @property
    def ok(self) -> bool:
        return not self.failing and not self.violations

    @property
    def exit_code(self) -> int:
        return EXIT_FITS if self.ok else EXIT_FAILS

    @property
    def summary(self) -> str:
        if self.ok:
            if not self.subnets:
                text = "FITS: the plan needs no new IPs in known subnets"
            else:
                text = f"FITS: {_plural(len(self.subnets), 'subnet')} checked"
        else:
            parts = []
            short = sum(s.status == SHORT for s in self.subnets)
            low = sum(s.status == BELOW_MIN for s in self.subnets)
            if short:
                parts.append(f"{_plural(short, 'subnet')} short of IPs")
            if low:
                parts.append(f"{_plural(low, 'subnet')} below {self.min_free_pct:g}% free")
            if self.violations:
                parts.append(_plural(len(self.violations), "rule violation"))
            text = "DOES NOT FIT: " + ", ".join(parts)
        if self.unresolved:
            text += f" ({len(self.unresolved)} unresolved, not counted)"
        return text


def evaluate(
    inputs: Inputs,
    demand: Demand,
    source: Source,
    *,
    mode: str = "plan",
    plan: Plan | None = None,
    min_free_pct: float = 0.0,
    rules: Iterable[rules_mod.Rule] = (),
    include_surge: bool = True,
) -> CheckResult:
    """Every subnet the demand lands in: free - existing headroom demand - plan demand.
    CheckError when a subnet is not in the data (stale snapshot, wrong account)."""
    known = {s.subnet_id for s in inputs.subnets}
    missing = [sid for sid in demand.subnet_ids if sid not in known]
    if missing:
        raise CheckError(
            f"subnet(s) not found in {source.notes_label}: {', '.join(missing)} "
            "(a stale snapshot, or another account / region?)"
        )
    scale = headroom.analyze(inputs, include_surge, source.notes_label)
    by_id = scale.by_id
    items: dict[str, list[PlanItem]] = defaultdict(list)
    for item in demand.items:
        items[item.subnet_id].append(item)
    fits = [
        SubnetFit(by_id[sid].subnet, list(by_id[sid].contributors), items[sid], min_free_pct)
        for sid in demand.subnet_ids
    ]
    fits.sort(key=lambda f: (f.status == FITS, f.left_pct, f.subnet.subnet_id))
    violations, notes = rule_violations(rules, fits, plan, source.account_ref)
    return CheckResult(
        mode=mode,
        source=source,
        subnets=fits,
        unresolved=list(demand.unresolved),
        violations=violations,
        notes=scale.notes + notes,
        min_free_pct=min_free_pct,
        include_surge=include_surge,
    )


# -- company rules --------------------------------------------------------------------------


def _changing(plan: Plan | None, rtype: str) -> list[PlanResource]:
    if plan is None:
        return []
    return [r for r in plan.resources if r.type == rtype and (r.creates or r.updates)]


def _rule_violations(rule: rules_mod.Rule, fits: list[SubnetFit], plan: Plan | None) -> list[str]:
    p = rule.params
    out: list[str] = []
    if rule.kind == "min_free_pct":
        pct = float(p.get("percent", 0))
        out += [
            f"{f.subnet.subnet_id} would have {f.left_pct:.1f}% free at max scale after the "
            f"change (< {pct:g}%)"
            for f in fits
            if rule._free_scope(f.subnet) and f.left_pct < pct
        ]
    elif rule.kind == "subnet_reserved":
        reserved = set(p.get("subnet_ids") or [])
        for f in fits:
            if f.subnet.subnet_id in reserved and f.plan_demand:
                who = ", ".join(sorted({i.address for i in f.plan}))
                out.append(
                    f"places {f.plan_demand} IPs in reserved subnet {f.subnet.subnet_id} ({who})"
                )
    elif rule.kind == "internal_only" and p.get("scope", "both") in ("load_balancer", "both"):
        only = set(p.get("lb_names") or [])
        for r in _changing(plan, "aws_lb") + _changing(plan, "aws_alb"):
            name = r.after.get("name") or ""
            if r.after.get("internal") is False and (not only or name in only):
                out.append(f"{r.address} would be internet-facing")
    elif rule.kind == "lambda_vpc_required":
        for r in _changing(plan, LAMBDA_TYPE):
            ids, _sgs, unknown = _lambda_combos(r.after, r.after_unknown)
            if not ids and not unknown:
                out.append(f"{r.address} is not VPC-attached")
    elif rule.kind == "protected_eni" and plan is not None:
        rx = rules_mod._compile(p.get("pattern", ""))
        for r in plan.resources:
            if r.type != "aws_network_interface" or not r.deletes or rx is None:
                continue
            hay = [
                str(r.before.get("id") or ""),
                str(r.before.get("description") or ""),
                str((r.before.get("tags") or {}).get("Name") or ""),
                r.address,
            ]
            if any(rx.search(h) for h in hay if h):
                out.append(f"{r.address} ({r.before.get('id') or 'ENI'}) would be removed")
    return out


def rule_violations(
    rules: Iterable[rules_mod.Rule],
    fits: list[SubnetFit],
    plan: Plan | None,
    account_ref: int | None,
) -> tuple[list[Violation], list[str]]:
    """Saved company rules the change breaks, and notes on rules not evaluated."""
    violations: list[Violation] = []
    notes: list[str] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.kind in SUGGESTION_ONLY_RULES:
            notes.append(f"Rule {rule.name} ({rule.kind}) only applies to suggestions: skipped.")
            continue
        if rule.account_ref is not None and rule.account_ref != account_ref:
            if account_ref is None:
                notes.append(
                    f"Rule {rule.name} is limited to IPLens account {rule.account_ref}; the data "
                    "has no account to match: skipped."
                )
            continue
        violations += [
            Violation(rule.name, rule.kind, msg) for msg in _rule_violations(rule, fits, plan)
        ]
    return violations, notes
