"""Scale headroom: free IPs of each subnet vs. the worst-case demand if everything that
can scale out does so to its maximum.

Demand rules (one :class:`Contributor` per resource and subnet, each with its assumption):

- **ASG**: ``max - current`` instances spread evenly over the group's subnets (the
  remainder goes to the subnets with the fewest instances now, as AWS balances AZs),
  times the ENIs per instance of the group's current instances in the snapshot (1 when
  none is known).
- **ECS** (awsvpc services): ``max - running`` tasks spread the same way over the
  service's subnets, 1 IP per task. The maximum is the Application Auto Scaling target's
  ``MaxCapacity``; without a target the service does not scale and its maximum is the
  desired count.
- **ECS deploy surge** (optional, on by default): a rolling deployment starts new tasks
  before stopping old ones, up to ``maximumPercent`` of the desired count, so a service at
  its maximum needs ``ceil(max * (maximumPercent - 100) / 100)`` extra tasks, spread like
  the scale-out. ``maximumPercent`` defaults to :data:`DEFAULT_MAX_PERCENT`; not counted
  for blue/green or external deployment controllers, nor at ``maximumPercent`` <= 100.
- **ALB**: AWS needs at least :data:`ALB_RESERVE` free IPs in each subnet of an
  Application Load Balancer to scale it, so that many are reserved per ALB subnet.
- **Lambda**: invocations take no IPs; a function only needs a new (Hyperplane) ENI when
  one of its subnet / security-group combinations has none yet, which costs 1 IP.

:func:`analyze` is pure and deterministic (same inputs, same result); :func:`load`
reads its inputs from a snapshot. A source the snapshot skipped (missing permission,
timeout) is listed in :attr:`Headroom.notes` and the demand uses what is known.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from . import queries
from .cidrplan import SUBNET_RESERVED
from .scope import UNSCOPED, ResolvedScope

# AWS: "your load balancer subnets must have at least eight free IP addresses" to scale.
ALB_RESERVE = 8
# ECS's maximumPercent when a service's deploymentConfiguration does not set it.
DEFAULT_MAX_PERCENT = 200
# The deployment controller doing rolling updates (the others replace a whole task set).
ROLLING_CONTROLLER = "ECS"
# Less than this share of the subnet's usable IPs left at max scale is "tight".
TIGHT_PCT = 20.0
# The resource types (collector names) the demand comes from.
ASG_SOURCE = "autoscaling:DescribeAutoScalingGroups"
SCALING_SOURCE = "application-autoscaling:DescribeScalableTargets"
ECS_SOURCE = "ECS services and tasks"
LB_SOURCE = "elasticloadbalancing:DescribeLoadBalancers"
LAMBDA_SOURCE = "lambda:ListFunctions"
SOURCES = (ASG_SOURCE, SCALING_SOURCE, ECS_SOURCE, LB_SOURCE, LAMBDA_SOURCE)
# What the demand lacks without each source.
_MISSING_EFFECT = {
    ASG_SOURCE: "Auto Scaling groups are not counted",
    SCALING_SOURCE: "ECS services are assumed not to scale beyond their desired count",
    ECS_SOURCE: "ECS services are not counted",
    LB_SOURCE: "ALB reserves are not counted",
    LAMBDA_SOURCE: "Lambda functions are not counted",
}

OK, TIGHT, OVER = "ok", "tight", "over"
STATUS_LABELS = {OK: "OK", TIGHT: "tight", OVER: "over"}
_STATUS_RANK = {OVER: 0, TIGHT: 1, OK: 2}

# -- inputs ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Subnet:
    subnet_id: str
    vpc_id: str
    az: str
    cidr: str
    name: str = ""
    free: int = 0  # free IPs now
    usable: int = 0  # addresses minus the 5 AWS reserves
    consumed: int = 0  # IPs in use (idle ENIs included)


@dataclass(frozen=True)
class Asg:
    name: str
    min_size: int
    desired: int
    max_size: int
    subnet_ids: tuple[str, ...]
    instances: tuple[tuple[str, str], ...] = ()  # (instance id, AZ)


@dataclass(frozen=True)
class EcsService:
    cluster: str
    service: str
    desired: int
    running: int
    subnet_ids: tuple[str, ...] | None  # None: unknown (a snapshot from before this field)
    max_percent: int | None = None  # deploymentConfiguration.maximumPercent; None: unset
    controller: str | None = None  # deploymentController.type; None: unknown (rolling)


@dataclass(frozen=True)
class LoadBalancer:
    name: str
    lb_type: str
    subnet_ids: tuple[str, ...] | None  # None: unknown (a snapshot from before this field)


@dataclass(frozen=True)
class LambdaFn:
    name: str
    subnet_ids: tuple[str, ...]
    security_groups: tuple[str, ...]


@dataclass
class Inputs:
    subnets: list[Subnet]
    asgs: list[Asg] = field(default_factory=list)
    ecs: list[EcsService] = field(default_factory=list)
    # (cluster, service) -> MaxCapacity of its ecs:service:DesiredCount scalable target.
    ecs_max: dict[tuple[str, str], int] = field(default_factory=dict)
    lbs: list[LoadBalancer] = field(default_factory=list)
    lambdas: list[LambdaFn] = field(default_factory=list)
    # From the snapshot's ENIs: instance id -> its ENIs' subnets (one entry per ENI).
    instance_enis: dict[str, list[str]] = field(default_factory=dict)
    # (cluster, service) -> subnet -> task ENIs there now.
    task_subnets: dict[tuple[str, str], dict[str, int]] = field(default_factory=dict)
    # Load balancer name -> subnets of its ENIs (subnets of older snapshots' LBs).
    lb_eni_subnets: dict[str, set[str]] = field(default_factory=dict)
    # (subnet, sorted security groups) of every existing Lambda ENI.
    lambda_combos: set[tuple[str, tuple[str, ...]]] = field(default_factory=set)
    # Resource types the snapshot skipped (see SOURCES).
    missing: frozenset[str] = frozenset()


# -- result ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Contributor:
    kind: str  # asg | ecs | surge | alb | lambda
    name: str
    ips: int
    assumption: str

    @property
    def label(self) -> str:
        return {
            "asg": "ASG",
            "ecs": "ECS service",
            "surge": "ECS service",
            "alb": "ALB",
            "lambda": "Lambda",
        }[self.kind]

    @property
    def text(self) -> str:
        """e.g. "ASG web: +12 (max 20, now 8)", or for a surge "ECS service c/api deploy
        surge: +4, maxPercent 200 (...)"."""
        if self.kind == "surge":
            return f"{self.label} {self.name} deploy surge: +{self.ips}, {self.assumption}"
        return f"{self.label} {self.name}: +{self.ips} ({self.assumption})"


@dataclass
class SubnetHeadroom:
    subnet: Subnet
    contributors: list[Contributor] = field(default_factory=list)

    @property
    def free(self) -> int:
        return self.subnet.free

    @property
    def demand(self) -> int:
        return sum(c.ips for c in self.contributors)

    @property
    def left(self) -> int:
        """Free IPs left at max scale (negative: short by that many)."""
        return self.free - self.demand

    @property
    def left_pct(self) -> float:
        """``left`` as a share of the subnet's usable IPs."""
        return 100.0 * self.left / self.subnet.usable if self.subnet.usable else 0.0

    @property
    def status(self) -> str:
        if self.left < 0:
            return OVER
        if self.left_pct < TIGHT_PCT:
            return TIGHT
        return OK

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]

    @property
    def needed_prefix(self) -> int | None:
        """Over: the smallest subnet (prefix length) holding today's IPs plus the
        demand, for "move to a bigger subnet"; None when not over or beyond a /16."""
        if self.status != OVER:
            return None
        return required_prefix(self.subnet.consumed + self.demand)

    @property
    def suggestion(self) -> str:
        """Over: what to do about it (the pages link the CIDR planner next to it)."""
        if self.status != OVER:
            return ""
        prefix = self.needed_prefix
        size = f"a /{prefix} or larger subnet" if prefix else "a larger subnet"
        where = f" in {self.subnet.az}" if self.subnet.az else ""
        return (
            f"Short by {-self.left} IPs at max scale: move the scaling resources to {size}"
            f"{where}, or add a secondary CIDR to {self.subnet.vpc_id} and create one there."
        )


@dataclass
class AzHeadroom:
    vpc_id: str
    az: str
    subnets: list[SubnetHeadroom]

    @property
    def free(self) -> int:
        return sum(s.free for s in self.subnets)

    @property
    def demand(self) -> int:
        return sum(s.demand for s in self.subnets)

    @property
    def left(self) -> int:
        return self.free - self.demand

    @property
    def usable(self) -> int:
        return sum(s.subnet.usable for s in self.subnets)

    @property
    def left_pct(self) -> float:
        return 100.0 * self.left / self.usable if self.usable else 0.0

    @property
    def status(self) -> str:
        """The worst subnet's status."""
        return min((s.status for s in self.subnets), key=_STATUS_RANK.__getitem__, default=OK)


@dataclass
class VpcAzs:
    vpc_id: str
    azs: list[AzHeadroom]

    @property
    def imbalanced(self) -> bool:
        """Some AZ runs out (or nearly) at max scale while another has room."""
        statuses = {a.status for a in self.azs}
        return OK in statuses and len(statuses) > 1


@dataclass
class Headroom:
    subnets: list[SubnetHeadroom]  # worst first
    notes: list[str] = field(default_factory=list)

    @property
    def by_id(self) -> dict[str, SubnetHeadroom]:
        return {s.subnet.subnet_id: s for s in self.subnets}

    @property
    def counts(self) -> dict[str, int]:
        c = Counter(s.status for s in self.subnets)
        return {status: c.get(status, 0) for status in (OVER, TIGHT, OK)}

    @property
    def by_az(self) -> list[VpcAzs]:
        groups: dict[str, dict[str, list[SubnetHeadroom]]] = defaultdict(lambda: defaultdict(list))
        for s in self.subnets:
            groups[s.subnet.vpc_id][s.subnet.az].append(s)
        return [
            VpcAzs(vpc, [AzHeadroom(vpc, az, groups[vpc][az]) for az in sorted(groups[vpc])])
            for vpc in sorted(groups)
        ]


def required_prefix(ips: int) -> int | None:
    """The longest prefix (smallest subnet) whose usable addresses hold ``ips``."""
    for prefix in range(28, 15, -1):
        if 2 ** (32 - prefix) - SUBNET_RESERVED >= ips:
            return prefix
    return None


# -- demand rules ---------------------------------------------------------------------------


def spread(count: int, subnet_ids: Iterable[str], current: Mapping[str, int]) -> dict[str, int]:
    """``count`` new units spread evenly over ``subnet_ids``; the remainder goes one each
    to the subnets with the fewest units now (``current``), ties by subnet id."""
    ids = sorted(set(subnet_ids))
    if count <= 0 or not ids:
        return {}
    base, rem = divmod(count, len(ids))
    out = dict.fromkeys(ids, base)
    for sid in sorted(ids, key=lambda s: (current.get(s, 0), s))[:rem]:
        out[sid] += 1
    return {sid: n for sid, n in out.items() if n}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def asg_demand(asg: Asg, inputs: Inputs) -> dict[str, Contributor]:
    """ASG: (max - current) instances over its subnets, times ENIs per instance."""
    current = len(asg.instances)
    more = max(asg.max_size - current, 0)
    if not more or not asg.subnet_ids:
        return {}
    az_of = {s.subnet_id: s.az for s in inputs.subnets}
    # Where each current instance runs: its ENIs' subnet among the group's, else its AZ.
    placed: Counter[str] = Counter()
    eni_counts = []
    for instance_id, az in asg.instances:
        enis = inputs.instance_enis.get(instance_id, [])
        if enis:
            eni_counts.append(len(enis))
        sid = next((s for s in sorted(enis) if s in asg.subnet_ids), None)
        sid = sid or next((s for s in sorted(asg.subnet_ids) if az_of.get(s) == az), None)
        if sid:
            placed[sid] += 1
    per_instance = math.ceil(sum(eni_counts) / len(eni_counts)) if eni_counts else 1
    eni_note = (
        f"{_plural(per_instance, 'ENI')} per instance"
        if eni_counts
        else "1 ENI per instance assumed (no instance ENI in the snapshot)"
    )
    share = spread(more, asg.subnet_ids, placed)
    n = len(set(asg.subnet_ids))
    return {
        sid: Contributor(
            "asg",
            asg.name,
            k * per_instance,
            f"max {asg.max_size}, now {current}: {_plural(k, 'instance')} here of {more} more "
            f"over {_plural(n, 'subnet')}, {eni_note}",
        )
        for sid, k in share.items()
    }


def _ecs_subnets(svc: EcsService, inputs: Inputs) -> tuple[str, ...]:
    """The service's awsvpc subnets, else those of its task ENIs; () when neither."""
    return svc.subnet_ids or tuple(sorted(inputs.task_subnets.get((svc.cluster, svc.service), {})))


def _ecs_max(svc: EcsService, inputs: Inputs) -> tuple[int, str]:
    """The service's maximum task count and how it was found."""
    key = (svc.cluster, svc.service)
    if key in inputs.ecs_max:
        return inputs.ecs_max[key], f"max {inputs.ecs_max[key]}"
    if SCALING_SOURCE in inputs.missing:
        return svc.desired, f"scaling unknown, max = desired {svc.desired}"
    return svc.desired, f"no auto scaling, max = desired {svc.desired}"


def ecs_demand(svc: EcsService, inputs: Inputs) -> tuple[dict[str, Contributor], str]:
    """ECS awsvpc service: (max - running) tasks over its subnets, 1 IP each. Returns the
    contributors and a note when the service's subnets are unknown."""
    tasks = inputs.task_subnets.get((svc.cluster, svc.service), {})
    subnets = _ecs_subnets(svc, inputs)
    name = f"{svc.cluster}/{svc.service}"
    if not subnets:
        if svc.subnet_ids is None:  # older snapshot without the service's subnets
            return {}, f"ECS service {name}: subnets unknown, not counted"
        return {}, ""  # not awsvpc: its tasks take no IPs of their own
    top, how = _ecs_max(svc, inputs)
    more = max(top - svc.running, 0)
    share = spread(more, subnets, tasks)
    n = len(set(subnets))
    return {
        sid: Contributor(
            "ecs",
            name,
            k,
            f"{how}, running {svc.running}: {_plural(k, 'task')} here of {more} more over "
            f"{_plural(n, 'subnet')}, 1 IP each",
        )
        for sid, k in share.items()
    }, ""


def ecs_surge(svc: EcsService, inputs: Inputs) -> dict[str, Contributor]:
    """ECS rolling deployment at max scale: ceil(max * (maximumPercent - 100) / 100)
    extra tasks over the service's subnets, 1 IP each (its own contributor)."""
    if (svc.controller or ROLLING_CONTROLLER) != ROLLING_CONTROLLER:
        return {}  # blue/green (CODE_DEPLOY) or EXTERNAL: no rolling surge
    pct = svc.max_percent if svc.max_percent is not None else DEFAULT_MAX_PERCENT
    if pct <= 100:
        return {}  # old tasks stop before new ones start
    subnets = _ecs_subnets(svc, inputs)
    top, _how = _ecs_max(svc, inputs)
    extra = math.ceil(top * (pct - 100) / 100)
    share = spread(extra, subnets, inputs.task_subnets.get((svc.cluster, svc.service), {}))
    pct_note = f"maxPercent {pct}" + ("" if svc.max_percent is not None else ", the ECS default")
    n = len(set(subnets))
    return {
        sid: Contributor(
            "surge",
            f"{svc.cluster}/{svc.service}",
            k,
            f"{pct_note}: {_plural(k, 'task')} here of {extra} extra at max {top} over "
            f"{_plural(n, 'subnet')} during a rolling deployment, 1 IP each",
        )
        for sid, k in share.items()
    }


def alb_demand(lb: LoadBalancer, inputs: Inputs) -> dict[str, Contributor]:
    """ALB: ALB_RESERVE free IPs reserved in each of its subnets."""
    if lb.lb_type != "application":
        return {}
    subnets = lb.subnet_ids if lb.subnet_ids is not None else inputs.lb_eni_subnets.get(lb.name)
    return {
        sid: Contributor(
            "alb", lb.name, ALB_RESERVE, f"AWS needs ≥ {ALB_RESERVE} free IPs per subnet to scale"
        )
        for sid in sorted(set(subnets or ()))
    }


def lambda_demand(fns: Iterable[LambdaFn], inputs: Inputs) -> dict[str, list[Contributor]]:
    """Lambda: 1 IP per subnet / security-group combination without an ENI yet (the
    functions sharing a combination share its ENI)."""
    combos: dict[tuple[str, tuple[str, ...]], list[str]] = defaultdict(list)
    for fn in fns:
        sgs = tuple(sorted(fn.security_groups))
        for sid in sorted(set(fn.subnet_ids)):
            if (sid, sgs) not in inputs.lambda_combos:
                combos[(sid, sgs)].append(fn.name)
    out: dict[str, list[Contributor]] = defaultdict(list)
    for (sid, sgs), names in sorted(combos.items()):
        groups = ", ".join(sgs) or "no security group"
        out[sid].append(
            Contributor(
                "lambda",
                ", ".join(sorted(names)),
                1,
                f"new subnet / security group combination ({groups}) needs a Hyperplane ENI",
            )
        )
    return out


def analyze(inputs: Inputs, include_surge: bool = True) -> Headroom:
    """Every subnet's projected demand at max scale, worst first; ``include_surge`` adds
    the ECS rolling-deployment surge (:func:`ecs_surge`)."""
    rows = {s.subnet_id: SubnetHeadroom(s) for s in inputs.subnets}
    notes = [
        f"{what} was skipped in this snapshot: {_MISSING_EFFECT[what]}."
        for what in SOURCES
        if what in inputs.missing
    ]

    def add(sid: str, c: Contributor) -> None:
        if sid in rows and c.ips:
            rows[sid].contributors.append(c)

    for asg in sorted(inputs.asgs, key=lambda a: a.name):
        for sid, c in asg_demand(asg, inputs).items():
            add(sid, c)
    for svc in sorted(inputs.ecs, key=lambda s: (s.cluster, s.service)):
        found, note = ecs_demand(svc, inputs)
        for sid, c in found.items():
            add(sid, c)
        if note:
            notes.append(note)
        if include_surge:
            for sid, c in ecs_surge(svc, inputs).items():
                add(sid, c)
    for lb in sorted(inputs.lbs, key=lambda b: b.name):
        for sid, c in alb_demand(lb, inputs).items():
            add(sid, c)
    for sid, found in lambda_demand(inputs.lambdas, inputs).items():
        for c in found:
            add(sid, c)
    for r in rows.values():
        r.contributors.sort(key=lambda c: (-c.ips, c.kind, c.name))
    ranked = sorted(
        rows.values(),
        key=lambda r: (_STATUS_RANK[r.status], r.left_pct, r.left, r.subnet.subnet_id),
    )
    return Headroom(ranked, notes)


# -- snapshot inputs ------------------------------------------------------------------------


def _ids(text: str | None) -> tuple[str, ...] | None:
    return None if text is None else tuple(json.loads(text or "[]"))


def skipped_sources(warnings: str | None) -> frozenset[str]:
    """The SOURCES a snapshot's warnings (JSON list) report as skipped."""
    found = json.loads(warnings or "[]")
    return frozenset(
        what
        for what in SOURCES
        if any(w.startswith(f"{what} skipped") for w in found)
        or (what == ECS_SOURCE and any(w.startswith("ECS enrichment skipped") for w in found))
    )


def load(conn: sqlite3.Connection, snap_id: int, scope: ResolvedScope = UNSCOPED) -> Inputs:
    """The inputs of :func:`analyze` from snapshot ``snap_id``; subnets limited to
    ``scope`` (the demand is still computed over every subnet of a resource)."""
    subnets = [
        Subnet(
            subnet_id=s.subnet_id,
            vpc_id=s.vpc_id,
            az=s.az,
            cidr=s.cidr,
            name=s.name,
            # AWS's own count when known (it sees every address); else IPLens's.
            free=s.aws_available if s.aws_available is not None else s.free,
            usable=s.usable,
            consumed=s.consumed,
        )
        for s in queries.subnet_stats(conn, snap_id)
        if scope.subnet_ok(s.subnet_id) and scope.vpc_ok(s.vpc_id)
    ]
    snap = conn.execute("SELECT warnings FROM snapshots WHERE id=?", (snap_id,)).fetchone()
    asgs = [
        Asg(
            name=r["name"],
            min_size=r["min_size"] or 0,
            desired=r["desired"] or 0,
            max_size=r["max_size"] or 0,
            subnet_ids=_ids(r["subnet_ids"]) or (),
            instances=tuple(tuple(i) for i in json.loads(r["instances"] or "[]")),
        )
        for r in conn.execute("SELECT * FROM asgs WHERE snapshot_id=? ORDER BY name", (snap_id,))
    ]
    ecs = [
        EcsService(
            cluster=r["cluster"],
            service=r["service"],
            desired=r["desired_count"] or 0,
            running=r["running_count"] or 0,
            subnet_ids=_ids(r["subnet_ids"]),
            max_percent=r["max_percent"],
            controller=r["deployment_controller"],
        )
        for r in conn.execute("SELECT * FROM ecs_services WHERE snapshot_id=?", (snap_id,))
    ]
    ecs_max = {
        (r["cluster"], r["service"]): r["max_capacity"]
        for r in conn.execute(
            "SELECT cluster, service, max_capacity FROM ecs_scalable_targets WHERE snapshot_id=?",
            (snap_id,),
        )
    }
    lbs = [
        LoadBalancer(r["name"], r["lb_type"] or "", _ids(r["subnet_ids"]))
        for r in conn.execute("SELECT * FROM load_balancers WHERE snapshot_id=?", (snap_id,))
    ]
    lambdas = [
        LambdaFn(
            r["name"],
            tuple(json.loads(r["subnet_ids"] or "[]")),
            tuple(json.loads(r["security_groups"] or "[]")),
        )
        for r in conn.execute("SELECT * FROM lambdas WHERE snapshot_id=?", (snap_id,))
    ]
    instance_enis: dict[str, list[str]] = defaultdict(list)
    lb_eni_subnets: dict[str, set[str]] = defaultdict(set)
    lambda_combos: set[tuple[str, tuple[str, ...]]] = set()
    for e in conn.execute(
        "SELECT instance_id, subnet_id, owner_type, owner_ref, security_groups FROM enis "
        "WHERE snapshot_id=?",
        (snap_id,),
    ):
        if e["instance_id"]:
            instance_enis[e["instance_id"]].append(e["subnet_id"] or "")
        if e["owner_type"] == "elb" and e["owner_ref"]:
            lb_eni_subnets[e["owner_ref"]].add(e["subnet_id"])
        if e["owner_type"] == "lambda":
            sgs = tuple(sorted(json.loads(e["security_groups"] or "[]")))
            lambda_combos.add((e["subnet_id"], sgs))
    task_subnets: dict[tuple[str, str], dict[str, int]] = defaultdict(dict)
    for r in conn.execute(
        "SELECT t.cluster, t.service, e.subnet_id, COUNT(*) AS n FROM ecs_task_enis t "
        "JOIN enis e ON e.snapshot_id = t.snapshot_id AND e.eni_id = t.eni_id "
        "WHERE t.snapshot_id=? AND t.service != '' GROUP BY t.cluster, t.service, e.subnet_id",
        (snap_id,),
    ):
        task_subnets[(r["cluster"], r["service"])][r["subnet_id"]] = r["n"]
    return Inputs(
        subnets=subnets,
        asgs=asgs,
        ecs=ecs,
        ecs_max=ecs_max,
        lbs=lbs,
        lambdas=lambdas,
        instance_enis=dict(instance_enis),
        task_subnets=dict(task_subnets),
        lb_eni_subnets=dict(lb_eni_subnets),
        lambda_combos=lambda_combos,
        missing=skipped_sources(snap["warnings"] if snap else None),
    )


def for_snapshot(
    conn: sqlite3.Connection,
    snap_id: int,
    scope: ResolvedScope = UNSCOPED,
    include_surge: bool = True,
) -> Headroom:
    return analyze(load(conn, snap_id, scope), include_surge)
