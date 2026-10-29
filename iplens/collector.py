"""Read-only collection of VPC/subnet/ENI (and optional ECS) data into an SQLite snapshot.

Each resource type (one AWS API family, e.g. ``ec2:DescribeInstances``) runs in a helper
thread bounded by the per-resource timeout and by what is left of the overall limit
(Settings → Discovery). A resource past its timeout is abandoned: it is reported as
skipped, its pagination loop stops at the next page, and the botocore connect / read
timeouts (:func:`iplens.aws.call_timeouts`) end a call stuck on the network. The other
resource types still run. VPCs, subnets and ENIs are the snapshot itself: they get at
least REQUIRED_RESOURCE_TIMEOUT seconds, and when one of them times out the Refresh fails
instead of saving an empty snapshot. Once abandoned, a resource's thread no longer writes
to the job's log or progress.

The clusters / domains of RDS, Redshift, ElastiCache, OpenSearch and MSK (each optional)
give their ENIs an owner name such as "Aurora cluster db-a" (see :mod:`iplens.managed`).

Auto Scaling groups and the Application Auto Scaling targets of ECS services (both
optional) give the scale headroom its maximum sizes (see :mod:`iplens.headroom`).

"Retry skipped" runs a Collector with ``only``: just the skipped resource types (plus what
they need, see :func:`retry_plan`), the account identity and VPCs/subnets/ENIs, and a
``source_snapshot``: the latest successful snapshot it derives from. In the snapshot's
transaction the rows of every other resource type are copied from the source, the retried
ones are written fresh and the ENIs are attributed on the merged data, so the new snapshot
is complete. Without the source snapshot (deleted meanwhile) it is a full Refresh.

The snapshot is written in one transaction with a savepoint per resource type, so a
failed write never leaves a resource half-saved.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from botocore.exceptions import BotoCoreError, ClientError

from . import managed, ownership
from .attribution import Attribution, attribute_eni, lambda_eni_index, lambda_owners
from .aws import AwsGateway, call_timeouts
from .db import closing
from .jobs import RES_DONE, RES_RUNNING, SKIPPED, JobCancelled, NullProgress, Progress
from .settings import (
    DEFAULT_DISCOVERY_TIMEOUT_MIN,
    DEFAULT_RESOURCE_TIMEOUT,
    REQUIRED_RESOURCE_TIMEOUT,
)

log = logging.getLogger(__name__)

T = TypeVar("T")

# Progress steps of one collection (see Collector._step).
COLLECT_STEPS = 24
# tag:GetResources page size (the API maximum).
_TAG_PAGE = 100
# CloudTrail events read per looked-up resource.
_CLOUDTRAIL_EVENTS = 50
# Seconds between checks of a running resource for its timeout and for Cancel.
_POLL = 0.1

# The resource types of a Refresh, in collection order (rows of the progress box).
CORE_RESOURCES = ("ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeNetworkInterfaces")
# Owner names of managed-service ENIs (iplens.managed): the resource types of each service.
MANAGED_SOURCES: dict[str, tuple[str, ...]] = {
    "rds": ("rds:DescribeDBInstances", "rds:DescribeDBClusters"),
    "redshift": ("redshift:DescribeClusters",),
    "elasticache": (
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeReplicationGroups",
    ),
    "opensearch": ("es:DescribeDomains",),  # es:ListDomainNames + es:DescribeDomains
    "msk": ("kafka:ListClustersV2",),
}
# Scale headroom (iplens.headroom): Auto Scaling groups and ECS service maximums.
ASG_RESOURCE = "autoscaling:DescribeAutoScalingGroups"
SCALABLE_TARGETS_RESOURCE = "application-autoscaling:DescribeScalableTargets"
# Transit Gateway links of the Visual page's IP view (iplens.extgraph.tgw_links).
TGW_ATTACHMENTS_RESOURCE = "ec2:DescribeTransitGatewayAttachments"
ROUTE_TABLES_RESOURCE = "ec2:DescribeRouteTables"
TGW_RESOURCES = (TGW_ATTACHMENTS_RESOURCE, ROUTE_TABLES_RESOURCE)
RESOURCES = (
    "sts:GetCallerIdentity",
    "iam:ListAccountAliases",
    *CORE_RESOURCES,
    "ec2:DescribeInstances",
    "ec2:DescribeVpcEndpoints",
    "lambda:ListFunctions",
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    "ec2:DescribeSecurityGroups",
    *TGW_RESOURCES,
    "ECS services and tasks",
    ASG_RESOURCE,
    SCALABLE_TARGETS_RESOURCE,
    *(what for sources in MANAGED_SOURCES.values() for what in sources),
    "elasticloadbalancing:DescribeTags",
    "lambda:ListTags",
    "tag:GetResources",
    "cloudformation:ListStacks",
)
CLOUDTRAIL_RESOURCE = "cloudtrail:LookupEvents"
# Who the snapshot belongs to: collected by every Refresh, a retry included.
IDENTITY_RESOURCES = ("sts:GetCallerIdentity", "iam:ListAccountAliases")
# Snapshot write of the ownership sources (a resource row of the progress box).
OWNERSHIP_WRITE = "ownership (tag:GetResources, CloudFormation)"
# Retry skipped: what a resource type needs collected with it.
_NEEDS: dict[str, tuple[str, ...]] = {
    "elasticloadbalancing:DescribeTargetGroups": ("elasticloadbalancing:DescribeLoadBalancers",),
    "elasticloadbalancing:DescribeTargetHealth": (
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
    ),
    "elasticloadbalancing:DescribeTags": ("elasticloadbalancing:DescribeLoadBalancers",),
    "lambda:ListTags": ("lambda:ListFunctions",),
    # Creators are only looked up for resources the other ownership sources left unowned.
    CLOUDTRAIL_RESOURCE: ("tag:GetResources", "cloudformation:ListStacks"),
    OWNERSHIP_WRITE: ("tag:GetResources", "cloudformation:ListStacks"),
    # The ownership rows merge both sources (stacks first), so they are collected together.
    "tag:GetResources": ("cloudformation:ListStacks",),
    "cloudformation:ListStacks": ("tag:GetResources",),
    # A service's rows are derived from both of its calls (e.g. Aurora instances are named
    # after their cluster), so they are collected together.
    "rds:DescribeDBInstances": ("rds:DescribeDBClusters",),
    "rds:DescribeDBClusters": ("rds:DescribeDBInstances",),
    "elasticache:DescribeCacheClusters": ("elasticache:DescribeReplicationGroups",),
    "elasticache:DescribeReplicationGroups": ("elasticache:DescribeCacheClusters",),
}
# Retry skipped: the snapshot rows of each optional write, by the resource types they come
# from: (resource types, tables, resource_tags types). A write whose resource types the
# retry does not collect is copied from the source snapshot instead.
_MERGED: tuple[tuple[frozenset[str], tuple[str, ...], tuple[str, ...]], ...] = (
    (frozenset({"ec2:DescribeVpcEndpoints"}), ("endpoints",), ("endpoint",)),
    (frozenset({"lambda:ListFunctions"}), ("lambdas",), ()),
    (frozenset({"lambda:ListTags"}), (), ("lambda",)),
    (frozenset({"elasticloadbalancing:DescribeLoadBalancers"}), ("load_balancers",), ()),
    (frozenset({"elasticloadbalancing:DescribeTags"}), (), ("lb",)),
    (
        frozenset(
            {
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth",
            }
        ),
        ("lb_targets",),
        (),
    ),
    (
        frozenset({"ECS services and tasks"}),
        ("ecs_services", "ecs_task_enis", "ecs_service_lbs"),
        ("ecs_service",),
    ),
    (
        frozenset({"ec2:DescribeSecurityGroups"}),
        ("sg_refs", "sg_cidr_rules", "security_groups"),
        ("sg",),
    ),
    (
        frozenset({"tag:GetResources", "cloudformation:ListStacks"}),
        ("own_resources", "own_tags"),
        (),
    ),
    (frozenset({TGW_ATTACHMENTS_RESOURCE}), ("tgw_attachments",), ()),
    (frozenset({ROUTE_TABLES_RESOURCE}), ("route_tables", "tgw_routes"), ()),
    (frozenset({ASG_RESOURCE}), ("asgs",), ()),
    (frozenset({SCALABLE_TARGETS_RESOURCE}), ("ecs_scalable_targets",), ()),
    *(
        (frozenset(sources), (managed.TABLES[service],), ())
        for service, sources in MANAGED_SOURCES.items()
    ),
)


def retry_plan(names: Iterable[str]) -> frozenset[str] | None:
    """The resource types a "Retry skipped" collects for the skipped ``names``: those,
    what they need (:data:`_NEEDS`), the identity calls and VPCs/subnets/ENIs. None (a
    full Refresh) when a name is not one resource type (e.g. the "resource tags" write)."""
    known = {*RESOURCES, CLOUDTRAIL_RESOURCE}
    out = {*IDENTITY_RESOURCES, *CORE_RESOURCES}
    todo = list(names)
    if not todo:
        return None
    while todo:
        name = todo.pop()
        if name not in known and name not in _NEEDS:
            return None
        if name in known:
            out.add(name)
        todo += [n for n in _NEEDS.get(name, ()) if n not in out]
    return frozenset(out)


class ResourceTimeout(Exception):  # noqa: N818 - named like JobCancelled
    """A resource type ran past its timeout (or past the Refresh's overall limit)."""

    def __init__(self, resource: str, reason: str):
        self.resource, self.reason = resource, reason
        super().__init__(f"{resource} skipped ({reason})")


class SourceSnapshotGone(Exception):  # noqa: N818 - named like JobCancelled
    """The snapshot a "Retry skipped" copies the other resource types from is gone."""


# The abandon flag of the resource running in this helper thread and its job context,
# muted once the flag is set (see Collector._timed).
_abandon = threading.local()


def _check_abandoned() -> None:
    """Stop an abandoned resource at its next page / call instead of finishing it."""
    event = getattr(_abandon, "event", None)
    if event is not None and event.is_set():
        raise ResourceTimeout("resource", "abandoned")


@dataclass
class CollectResult:
    snapshot_id: int
    account_id: str = ""
    account_alias: str = ""
    vpcs: int = 0
    subnets: int = 0
    enis: int = 0
    ips: int = 0
    warnings: list[str] = field(default_factory=list)
    # (resource type, reason) of every resource type that was skipped.
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _name_tag(tags: Iterable[dict[str, str]] | None) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def tag_pairs(tags: Iterable[dict[str, str]] | None) -> list[tuple[str, str]]:
    """``(key, value)`` pairs of an AWS tag list (``Key``/``Value`` or ECS ``key``/``value``)."""
    out: dict[str, str] = {}
    for t in tags or []:
        key = t.get("Key", t.get("key"))
        if key:
            out[str(key)[:128]] = str(t.get("Value", t.get("value")) or "")[:256]
    return sorted(out.items())


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[Any]:
    out: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        _check_abandoned()
        out.extend(page.get(key, []))
    return out


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


@dataclass(frozen=True)
class InstanceEni:
    """An ENI as attached to an EC2 instance (``ec2:DescribeInstances``)."""

    instance_id: str
    name: str  # the instance's Name tag
    ips: tuple[dict[str, Any], ...]  # the attachment's PrivateIpAddresses (primary + secondary)


def instance_eni_index(reservations: Iterable[dict[str, Any]]) -> dict[str, InstanceEni]:
    """``eni id -> InstanceEni`` for every network interface of every instance."""
    out: dict[str, InstanceEni] = {}
    for res in reservations:
        for inst in res.get("Instances", []) or []:
            instance_id = inst.get("InstanceId") or ""
            name = _name_tag(inst.get("Tags"))
            for ni in inst.get("NetworkInterfaces", []) or []:
                eni_id = ni.get("NetworkInterfaceId")
                if eni_id and instance_id:
                    ips = tuple(ni.get("PrivateIpAddresses") or [])
                    out[eni_id] = InstanceEni(instance_id, name, ips)
    return out


def eni_private_ips(eni: dict[str, Any], inst: InstanceEni | None = None) -> list[dict[str, Any]]:
    """Every private IPv4 of an ENI, primary and secondary, once each.

    Merges the ENI's ``PrivateIpAddresses``, the instance attachment's list (when the
    ENI belongs to an instance) and the ENI's primary ``PrivateIpAddress``; an address
    is primary, and keeps its public association, if any source says so.
    """
    sources = [*(eni.get("PrivateIpAddresses") or []), *(inst.ips if inst else ())]
    if eni.get("PrivateIpAddress"):
        sources.append({"PrivateIpAddress": eni["PrivateIpAddress"], "Primary": True})
    merged: dict[str, dict[str, Any]] = {}
    for p in sources:
        ip = p.get("PrivateIpAddress")
        if not ip:
            continue
        seen = merged.setdefault(ip, {"PrivateIpAddress": ip, "Primary": False})
        seen["Primary"] = bool(seen["Primary"] or p.get("Primary"))
        if p.get("Association") and not seen.get("Association"):
            seen["Association"] = p["Association"]
    return list(merged.values())


def _arn_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


@dataclass
class EcsTaskEni:
    cluster: str
    service: str  # "" for standalone tasks
    task_id: str

    @property
    def owner_ref(self) -> str:
        """``cluster/service/task`` (``cluster/task`` for a standalone task)."""
        if self.service:
            return f"{self.cluster}/{self.service}/{self.task_id}"
        return f"{self.cluster}/{self.task_id}"


@dataclass
class EcsData:
    services: list[dict[str, Any]] = field(default_factory=list)
    task_enis: dict[str, EcsTaskEni] = field(default_factory=dict)


# DescribeServices / DescribeTasks batch limits.
_ECS_SERVICE_BATCH = 10
_ECS_TASK_BATCH = 100
# elbv2 DescribeTags limit.
_LB_TAG_BATCH = 20
# OpenSearch DescribeDomains limit.
_OPENSEARCH_BATCH = 5


@dataclass
class TargetGroupInfo:
    name: str
    target_type: str
    lb_names: list[str]


@dataclass
class LbTargetData:
    groups: dict[str, TargetGroupInfo] = field(default_factory=dict)  # by target group ARN
    # (lb_name, target_group, target_type, target_id, port)
    targets: list[tuple[str, str, str, str, int]] = field(default_factory=list)


def target_ref(target_type: str, target_id: str) -> str:
    """Short, ARN-free reference for a registered target.

    Lambda targets are function ARNs and ALB targets are load balancer ARNs; only
    the function / load balancer name is kept.
    """
    if target_type == "lambda" and ":function:" in target_id:
        return target_id.split(":function:", 1)[1].split(":", 1)[0]
    if target_type == "alb" and target_id.count("/") >= 2:
        return target_id.rsplit("/", 2)[-2]
    return target_id


def _sg_ports(perm: dict[str, Any]) -> str:
    proto = str(perm.get("IpProtocol", "-1"))
    if proto in ("-1", "all"):
        return "all"
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if lo is None or lo == -1:
        return proto
    return f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}"


def sg_ref_rows(groups: Iterable[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    """``(group_id, direction, ref_group_id, ports)`` for every rule naming another SG."""
    out: set[tuple[str, str, str, str]] = set()
    for g in groups:
        for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
            for perm in g.get(key, []):
                ports = _sg_ports(perm)
                for pair in perm.get("UserIdGroupPairs", []):
                    if pair.get("GroupId"):
                        out.add((g["GroupId"], direction, pair["GroupId"], ports))
    return sorted(out)


def sg_cidr_rows(
    groups: Iterable[dict[str, Any]],
) -> list[tuple[str, str, str, int | None, int | None]]:
    """``(group_id, cidr, ip_protocol, from_port, to_port)`` for every IPv4 CIDR ingress rule."""
    out: set[tuple[str, str, str, int | None, int | None]] = set()
    for g in groups:
        for perm in g.get("IpPermissions", []):
            proto = str(perm.get("IpProtocol", "-1"))
            lo, hi = perm.get("FromPort"), perm.get("ToPort")
            if lo == -1:
                lo = hi = None
            for rng in perm.get("IpRanges", []):
                if rng.get("CidrIp"):
                    out.add((g["GroupId"], rng["CidrIp"], proto, lo, hi))
    return sorted(out, key=lambda r: (r[0], r[1], r[2], r[3] or 0, r[4] or 0))


def _ecs_service_row(cluster: str, svc: dict[str, Any]) -> dict[str, Any]:
    stamps = [
        d.get("updatedAt") or d.get("createdAt")
        for d in svc.get("deployments", [])
        if d.get("updatedAt") or d.get("createdAt")
    ]
    last = max(stamps) if stamps else None
    if isinstance(last, datetime):
        last = last.astimezone(UTC).isoformat(timespec="seconds")
    return {
        "cluster": cluster,
        "service": svc.get("serviceName") or _arn_name(svc.get("serviceArn", "")),
        "desired_count": svc.get("desiredCount"),
        "running_count": svc.get("runningCount"),
        "last_deployment": last,
        "tags": tag_pairs(svc.get("tags")),
        # (target group ARN, classic load balancer name); either may be "".
        "load_balancers": [
            (lb.get("targetGroupArn") or "", lb.get("loadBalancerName") or "")
            for lb in svc.get("loadBalancers", [])
        ],
        "subnet_ids": _ecs_service_subnets(svc),
        "max_percent": (svc.get("deploymentConfiguration") or {}).get("maximumPercent"),
        "deployment_controller": (svc.get("deploymentController") or {}).get("type"),
    }


def _ecs_service_subnets(svc: dict[str, Any]) -> list[str]:
    """The awsvpc subnets of a service (its own network configuration, else the primary
    deployment's); [] for a service whose tasks have no ENI of their own."""
    configs = [svc.get("networkConfiguration")]
    configs += [d.get("networkConfiguration") for d in svc.get("deployments", [])]
    for cfg in configs:
        subnets = ((cfg or {}).get("awsvpcConfiguration") or {}).get("subnets")
        if subnets:
            return sorted(set(subnets))
    return []


def asg_rows(groups: Iterable[dict[str, Any]]) -> list[tuple[str, int, int, int, str, str]]:
    """``(name, min, desired, max, subnet ids JSON, [[instance id, AZ], ...] JSON)`` of
    every Auto Scaling group (``VPCZoneIdentifier`` is a comma-separated subnet list)."""
    out = []
    for g in groups:
        subnets = sorted({s.strip() for s in (g.get("VPCZoneIdentifier") or "").split(",")} - {""})
        instances = sorted(
            [i["InstanceId"], i.get("AvailabilityZone") or ""]
            for i in g.get("Instances", []) or []
            if i.get("InstanceId")
        )
        out.append(
            (
                g["AutoScalingGroupName"],
                int(g.get("MinSize") or 0),
                int(g.get("DesiredCapacity") or 0),
                int(g.get("MaxSize") or 0),
                json.dumps(subnets),
                json.dumps(instances),
            )
        )
    return sorted(out)


RouteTableRow = tuple[str, str, int, str]


def route_table_rows(
    tables: Iterable[dict[str, Any]],
) -> list[tuple[RouteTableRow, list[tuple[str, str, str]]]]:
    """``((route table id, VPC id, is main, subnet ids JSON), [(destination, TGW id,
    state), ...])`` of every route table: its explicitly associated subnets and its
    routes to a Transit Gateway (destination: a CIDR, or a prefix list id)."""
    out = []
    for rt in tables:
        assoc = rt.get("Associations", []) or []
        subnets = sorted({a["SubnetId"] for a in assoc if a.get("SubnetId")})
        routes = sorted(
            {
                (dest, r["TransitGatewayId"], r.get("State") or "")
                for r in rt.get("Routes", []) or []
                if r.get("TransitGatewayId")
                and (
                    dest := r.get("DestinationCidrBlock")
                    or r.get("DestinationIpv6CidrBlock")
                    or r.get("DestinationPrefixListId")
                    or ""
                )
            }
        )
        row = (
            rt["RouteTableId"],
            rt.get("VpcId") or "",
            int(any(a.get("Main") for a in assoc)),
            json.dumps(subnets),
        )
        out.append((row, routes))
    return sorted(out)


def ecs_scalable_target_rows(targets: Iterable[dict[str, Any]]) -> list[tuple[str, str, int, int]]:
    """``(cluster, service, min, max)`` of every ECS service desired-count target
    (``ResourceId`` ``service/<cluster>/<service>``)."""
    out = {}
    for t in targets:
        if t.get("ScalableDimension") != "ecs:service:DesiredCount":
            continue
        parts = (t.get("ResourceId") or "").split("/")
        if len(parts) == 3 and parts[0] == "service":
            out[(parts[1], parts[2])] = (
                int(t.get("MinCapacity") or 0),
                int(t.get("MaxCapacity") or 0),
            )
    return sorted((*key, *sizes) for key, sizes in out.items())


def _task_service(task: dict[str, Any]) -> str:
    """Tasks launched by a service carry ``group = "service:<name>"``."""
    group = task.get("group") or ""
    return group.removeprefix("service:") if group.startswith("service:") else ""


def _task_eni_ids(task: dict[str, Any]) -> list[str]:
    """ENI ids from the task's ElasticNetworkInterface attachments (``networkInterfaceId``).

    This is the only source of ECS task attribution: an ENI is mapped to the task
    whose attachment names exactly its id, never to a service by subnet or SG.
    """
    out = []
    for att in task.get("attachments", []):
        if att.get("type") != "ElasticNetworkInterface":
            continue
        for d in att.get("details", []):
            if d.get("name") == "networkInterfaceId" and d.get("value"):
                out.append(d["value"])
    return out


def _creator(cloudtrail: Any, resource_id: str) -> ownership.Principal | None:
    """Principal of the oldest ``Create*`` / ``RunInstances`` event naming ``resource_id``
    (CloudTrail keeps 90 days of management events; events come newest first)."""
    found = None
    pages = cloudtrail.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_id}],
        PaginationConfig={"MaxItems": _CLOUDTRAIL_EVENTS},
    )
    for page in pages:
        for event in page.get("Events", []):
            if ownership.is_create_event(event.get("EventName", "")):
                found = ownership.principal_from_event(event) or found
    return found


class Collector:
    def __init__(
        self,
        gateway: AwsGateway,
        db_path: Path,
        account_ref: int | None = None,
        account_name: str = "",
        progress: Progress | None = None,
        ownership_config: ownership.OwnershipConfig | None = None,
        resource_timeout: float = DEFAULT_RESOURCE_TIMEOUT,
        overall_timeout: float = DEFAULT_DISCOVERY_TIMEOUT_MIN * 60,
        only: Iterable[str] | None = None,
        source_snapshot: int | None = None,
    ):
        self.gw = gateway
        # Which tag values are kept, the CI role patterns and the optional sources.
        self.own = ownership_config or ownership.OwnershipConfig()
        self.db_path = db_path
        self.account_ref = account_ref  # IPLens account record the snapshot belongs to
        # The record's display name, frozen on the snapshot (later renames do not apply).
        self.account_name = account_name
        # Background job reporting; cancellation is checked between API calls.
        self._progress: Progress = progress or NullProgress()
        self._done = 0
        # Seconds one optional resource type may run, a required one (never less than
        # REQUIRED_RESOURCE_TIMEOUT) and the whole collection.
        self.resource_timeout = float(resource_timeout)
        self.required_timeout = max(self.resource_timeout, float(REQUIRED_RESOURCE_TIMEOUT))
        self.overall_timeout = float(overall_timeout)
        self._deadline = math.inf
        self._touched: set[str] = set()
        self._planned: list[str] = []
        # Warnings of the run itself (a retry that fell back to a full Refresh).
        self._notes: list[str] = []
        # Retry skipped: the resource types to collect (see retry_plan); None = all.
        self.only = retry_plan(only) if only is not None else None
        # Retry skipped: the snapshot the other resource types are copied from (none: the
        # retry is a full Refresh).
        self.source_snapshot = source_snapshot if self.only is not None else None
        if self.source_snapshot is None:
            self.only = None
        if isinstance(gateway, AwsGateway):
            gateway.call_config = call_timeouts(self.resource_timeout)

    @property
    def progress(self) -> Progress:
        """The job context; in a resource's helper thread, the one muted on abandon."""
        return getattr(_abandon, "progress", None) or self._progress

    def _wants(self, what: str) -> bool:
        return self.only is None or what in self.only

    def _step(self, text: str) -> None:
        self.progress.check()
        self.progress.step(f"collect · {text}", done=self._done, total=COLLECT_STEPS)
        self._done += 1

    def _tick(self) -> None:
        """Between AWS calls of a resource: honour Cancel and the resource's timeout."""
        self.progress.check()
        _check_abandoned()

    def _mark(self, what: str, status: str, reason: str = "", timeout: int | None = None) -> None:
        self._touched.add(what)
        self.progress.resource(what, status, reason, timeout=timeout)

    def _skip(self, result: CollectResult, what: str, reason: str) -> None:
        self._mark(what, SKIPPED, reason)
        result.skipped.append((what, reason))

    def _limit(self, what: str) -> float:
        """Seconds resource type ``what`` may run: VPCs, subnets and ENIs get the longer
        required timeout, every other type the per-resource one."""
        return self.required_timeout if what in CORE_RESOURCES else self.resource_timeout

    def _client(self, service: str, timeout: float) -> Any:
        """A client whose botocore timeouts fit ``timeout`` instead of the per-resource
        timeout every other client is configured for (see call_timeouts)."""
        if not isinstance(self.gw, AwsGateway):
            return self.gw.client(service)
        return self.gw.client(service, config=call_timeouts(timeout))

    def _timed(self, result: CollectResult, what: str, fn: Callable[[], T]) -> T:
        """Run one resource type in a helper thread, bounded by its timeout (see _limit)
        and what is left of the overall limit. Past it the resource is abandoned (its
        thread stops at the next page; botocore timeouts end a stuck call), recorded as
        skipped and :class:`ResourceTimeout` is raised. Errors of ``fn`` are re-raised."""
        limit = self._limit(what)
        left = self._deadline - time.monotonic()
        overall = left < limit  # the overall limit is the tighter one
        budget = min(limit, left)
        if budget <= 0:
            return self._timed_out(result, what, overall=True)
        self._mark(what, RES_RUNNING, timeout=math.ceil(budget))
        abandon = threading.Event()
        box: dict[str, Any] = {}

        # Once abandoned, the thread's log lines and progress updates are dropped.
        muted = self._progress.muted_when(abandon)

        def target() -> None:
            _abandon.event, _abandon.progress = abandon, muted
            with muted.bind():
                try:
                    box["value"] = fn()
                except BaseException as exc:  # noqa: BLE001 - handed to the caller
                    box["error"] = exc

        worker = threading.Thread(target=target, name="iplens-collect-resource", daemon=True)
        worker.start()
        end = time.monotonic() + budget
        while worker.is_alive():
            worker.join(max(min(_POLL, end - time.monotonic()), 0.0))
            if worker.is_alive() and self.progress.cancelled:
                abandon.set()
                self.progress.check()  # raises JobCancelled
            if time.monotonic() >= end:
                break
        if worker.is_alive():
            abandon.set()
            return self._timed_out(result, what, overall=overall)
        if "error" in box:
            raise box["error"]
        self._mark(what, RES_DONE)
        return box["value"]

    def _timed_out(self, result: CollectResult, what: str, *, overall: bool) -> Any:
        if overall:
            minutes = math.ceil(self.overall_timeout / 60)
            reason = f"overall time limit of {minutes} min reached"
        else:
            reason = f"timeout after {math.ceil(self._limit(what))}s"
        msg = f"{what} skipped ({reason})"
        log.warning(msg)
        result.warnings.append(msg)
        self._skip(result, what, reason)
        raise ResourceTimeout(what, reason)

    def _required(self, result: CollectResult, what: str, fn: Callable[[], list[Any]]) -> list[Any]:
        """VPCs, subnets and ENIs: any error, a timeout included, fails the collection."""
        try:
            return self._timed(result, what, fn)
        except ResourceTimeout:
            raise
        except (BotoCoreError, ClientError) as exc:
            code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else ""
            self._skip(result, what, code or type(exc).__name__)
            raise

    def _source_ok(self, conn: sqlite3.Connection) -> bool:
        """The retry's source snapshot still exists (a successful one of this account)."""
        return bool(
            conn.execute(
                "SELECT 1 FROM snapshots WHERE id=? AND status='ok' AND account_ref IS ?",
                (self.source_snapshot, self.account_ref),
            ).fetchone()
        )

    def _full_refresh_instead(self) -> None:
        """Retry skipped without its source snapshot: collect every resource type."""
        msg = (
            f"Retry of skipped resources: snapshot {self.source_snapshot} (the source of the "
            "other resource types) no longer exists; ran a full Refresh instead"
        )
        log.warning(msg)
        self._notes.append(msg)
        self.only = self.source_snapshot = None

    def _plan(self) -> None:
        self._deadline = time.monotonic() + self.overall_timeout
        self._done = 0
        self._touched = set()
        planned = [*RESOURCES, *([CLOUDTRAIL_RESOURCE] if self.own.cloudtrail else [])]
        self._planned = [what for what in planned if self._wants(what)]
        self.progress.plan_resources(
            self._planned,
            math.ceil(self.resource_timeout),
            math.ceil(self.overall_timeout),
            timeouts={what: math.ceil(self.required_timeout) for what in CORE_RESOURCES},
        )

    def run(self) -> CollectResult:
        if self.only is not None:
            with closing(self.db_path) as conn:
                if not self._source_ok(conn):
                    self._full_refresh_instead()
        self._plan()
        region = self.gw.region or ""
        started = datetime.now(UTC).isoformat(timespec="seconds")
        with closing(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO snapshots(taken_at, region, status, account_ref, account_name) "
                "VALUES(?, ?, 'running', ?, ?)",
                (started, region, self.account_ref, self.account_name),
            )
            snap_id = int(cur.lastrowid or 0)
        log.info(
            "collection started snapshot=%s account=%s region=%s", snap_id, self.account_ref, region
        )
        if self.only is not None:
            log.info(
                "retry of skipped resources: collecting only %s, the rest from snapshot %s",
                ", ".join(self._planned),
                self.source_snapshot,
            )
        try:
            try:
                result = self._collect(snap_id)
            except SourceSnapshotGone:
                # Deleted while the retry collected: nothing was written, start over in full.
                self._full_refresh_instead()
                self._plan()
                result = self._collect(snap_id)
        except Exception as exc:
            if isinstance(exc, JobCancelled):
                log.info("collection cancelled snapshot=%s", snap_id)
                error = "cancelled"
            elif isinstance(exc, ResourceTimeout):
                log.warning("collection failed snapshot=%s: %s", snap_id, exc)
                error = str(exc)
            else:
                log.exception("collection failed snapshot=%s", snap_id)
                error = f"{type(exc).__name__}: {exc}"
            with closing(self.db_path) as conn:
                conn.execute(
                    "UPDATE snapshots SET status='failed', error=? WHERE id=?", (error, snap_id)
                )
            raise
        log.info(
            "collection finished snapshot=%s vpcs=%d subnets=%d enis=%d ips=%d warnings=%d",
            snap_id,
            result.vpcs,
            result.subnets,
            result.enis,
            result.ips,
            len(result.warnings),
        )
        if result.skipped:
            log.warning(
                "collection snapshot=%s skipped %d resource type(s): %s",
                snap_id,
                len(result.skipped),
                "; ".join(f"{what} ({reason})" for what, reason in result.skipped),
            )
        return result

    def _collect(self, snap_id: int) -> CollectResult:
        ec2 = self.gw.client("ec2")
        result = CollectResult(snapshot_id=snap_id, warnings=list(self._notes))
        if self.only is not None:
            retried = [w for w in self._planned if w not in (*IDENTITY_RESOURCES, *CORE_RESOURCES)]
            result.warnings.append(
                "Retry of skipped resources: collected VPCs, subnets, ENIs and "
                + (", ".join(retried) or "no other resource types")
                + f"; the other resource types are copied from snapshot {self.source_snapshot}"
            )

        account_id = ""
        self._step("sts:GetCallerIdentity")
        try:
            account_id = self._timed(result, "sts:GetCallerIdentity", self.gw.caller_identity)[
                "account"
            ]
        except ResourceTimeout:
            pass  # recorded as a warning by _timed
        except (BotoCoreError, ClientError) as exc:
            result.warnings.append(f"sts:GetCallerIdentity unavailable ({type(exc).__name__})")
            self._skip(result, "sts:GetCallerIdentity", type(exc).__name__)
        # Display-only: without the permission the UI falls back to the account id.
        aliases = self._optional(result, "iam:ListAccountAliases", self.gw.account_aliases)
        account_alias = aliases[0] if aliases else ""

        # VPCs, subnets and ENIs: botocore timeouts of their longer timeout (see _limit).
        core = self._client("ec2", self.required_timeout)
        self._step("ec2:DescribeVpcs")
        vpcs = self._required(
            result, "ec2:DescribeVpcs", lambda: _paginate(core, "describe_vpcs", "Vpcs")
        )
        self._step("ec2:DescribeSubnets")
        subnets = self._required(
            result, "ec2:DescribeSubnets", lambda: _paginate(core, "describe_subnets", "Subnets")
        )
        self._step("ec2:DescribeNetworkInterfaces")
        enis = self._required(
            result,
            "ec2:DescribeNetworkInterfaces",
            lambda: _paginate(core, "describe_network_interfaces", "NetworkInterfaces"),
        )
        self._step("ec2:DescribeInstances")
        instances = instance_eni_index(
            self._optional(
                result,
                "ec2:DescribeInstances",
                lambda: _paginate(ec2, "describe_instances", "Reservations"),
            )
        )
        self._step("ec2:DescribeVpcEndpoints")
        endpoints = self._optional(
            result,
            "ec2:DescribeVpcEndpoints",
            lambda: _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"),
        )
        self._step("lambda:ListFunctions")
        lambdas = self._optional(
            result,
            "lambda:ListFunctions",
            lambda: _paginate(self.gw.client("lambda"), "list_functions", "Functions"),
        )
        self._step("elasticloadbalancing:DescribeLoadBalancers")
        lbs = self._optional(
            result,
            "elasticloadbalancing:DescribeLoadBalancers",
            lambda: _paginate(self.gw.client("elbv2"), "describe_load_balancers", "LoadBalancers"),
        )
        lb_targets = self._collect_lb_targets(result, lbs)
        self._step("ec2:DescribeSecurityGroups")
        security_groups = self._optional(
            result,
            "ec2:DescribeSecurityGroups",
            lambda: _paginate(ec2, "describe_security_groups", "SecurityGroups"),
        )
        self._step(TGW_ATTACHMENTS_RESOURCE)
        tgw_attachments = self._optional(
            result,
            TGW_ATTACHMENTS_RESOURCE,
            lambda: _paginate(
                ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments"
            ),
        )
        self._step(ROUTE_TABLES_RESOURCE)
        route_tables = self._optional(
            result,
            ROUTE_TABLES_RESOURCE,
            lambda: _paginate(ec2, "describe_route_tables", "RouteTables"),
        )
        self._step("ECS services and tasks")
        ecs = self._collect_ecs(result)
        self._step(ASG_RESOURCE)
        asgs = asg_rows(
            self._optional(
                result,
                ASG_RESOURCE,
                lambda: _paginate(
                    self.gw.client("autoscaling"),
                    "describe_auto_scaling_groups",
                    "AutoScalingGroups",
                ),
            )
        )
        self._step(SCALABLE_TARGETS_RESOURCE)
        scalable_targets = ecs_scalable_target_rows(
            self._optional(
                result,
                SCALABLE_TARGETS_RESOURCE,
                lambda: _paginate(
                    self.gw.client("application-autoscaling"),
                    "describe_scalable_targets",
                    "ScalableTargets",
                    ServiceNamespace="ecs",
                ),
            )
        )
        managed_rows = self._collect_managed(result)
        self._step("tags")
        lb_tags = self._collect_lb_tags(result, lbs)
        lambda_tags = self._collect_lambda_tags(result, lambdas)
        self._step("tag:GetResources")
        tagged = self._optional(result, "tag:GetResources", self._fetch_tagged_resources)
        self._step("cloudformation:ListStacks")
        stacks = self._optional(result, "cloudformation:ListStacks", self._fetch_stack_resources)
        own_resources, own_tags = self._ownership_rows(tagged, stacks)
        self._step("writing the snapshot")

        lambda_index = lambda_eni_index(lambdas)
        # ENI attribution inputs; a retry replaces those it did not collect (see _merge).
        task_enis = ecs.task_enis
        managed_index = managed.ManagedIndex(r for rows in managed_rows.values() for r in rows)
        # (resource_type, resource_id, key, value) for every tagged ENI-owning resource,
        # plus VPC and subnet tags (environment fallback, "managed elsewhere" tag markers).
        tag_rows: list[tuple[str, str, str, str]] = []
        for v in vpcs:
            tag_rows += [("vpc", v["VpcId"], *kv) for kv in tag_pairs(v.get("Tags"))]
        for s in subnets:
            tag_rows += [("subnet", s["SubnetId"], *kv) for kv in tag_pairs(s.get("Tags"))]
        for e in enis:
            tag_rows += [("eni", e["NetworkInterfaceId"], *kv) for kv in tag_pairs(e.get("TagSet"))]
        for ep in endpoints:
            tag_rows += [("endpoint", ep["VpcEndpointId"], *kv) for kv in tag_pairs(ep.get("Tags"))]
        for g in security_groups:
            tag_rows += [("sg", g["GroupId"], *kv) for kv in tag_pairs(g.get("Tags"))]
        for svc in ecs.services:
            ref = f"{svc['cluster']}/{svc['service']}"
            tag_rows += [("ecs_service", ref, *kv) for kv in svc["tags"]]
        tag_rows += [("lb", name, *kv) for name, pairs in lb_tags.items() for kv in pairs]
        tag_rows += [("lambda", name, *kv) for name, pairs in lambda_tags.items() for kv in pairs]

        ip_count = 0

        # One writer per resource type; each runs in its own savepoint (see _saving).
        def write_vpcs(conn: sqlite3.Connection) -> None:
            for v in vpcs:
                cidrs = [
                    a["CidrBlock"]
                    for a in v.get("CidrBlockAssociationSet", [])
                    if a.get("CidrBlockState", {}).get("State", "associated") == "associated"
                ] or [v["CidrBlock"]]
                conn.execute(
                    "INSERT INTO vpcs(snapshot_id, vpc_id, name, cidrs, is_default) "
                    "VALUES(?,?,?,?,?)",
                    (
                        snap_id,
                        v["VpcId"],
                        _name_tag(v.get("Tags")),
                        json.dumps(cidrs),
                        int(bool(v.get("IsDefault"))),
                    ),
                )

        def write_subnets(conn: sqlite3.Connection) -> None:
            for s in subnets:
                conn.execute(
                    "INSERT INTO subnets(snapshot_id, subnet_id, vpc_id, name, cidr, az, "
                    "available_ip_count) VALUES(?,?,?,?,?,?,?)",
                    (
                        snap_id,
                        s["SubnetId"],
                        s["VpcId"],
                        _name_tag(s.get("Tags")),
                        s["CidrBlock"],
                        s.get("AvailabilityZone"),
                        s.get("AvailableIpAddressCount"),
                    ),
                )

        def write_enis(conn: sqlite3.Connection) -> None:
            nonlocal ip_count
            for e in enis:
                inst = instances.get(e["NetworkInterfaceId"])
                attachment = e.get("Attachment") or {}
                if inst and not attachment.get("InstanceId"):
                    # Map the ENI to its instance even when the ENI view lacks the attachment.
                    e = {**e, "Attachment": {**attachment, "InstanceId": inst.instance_id}}
                attr = attribute_eni(e)
                task = task_enis.get(e["NetworkInterfaceId"])
                if task:
                    attr = Attribution("ecs", task.owner_ref)
                private_ips = eni_private_ips(e, inst)
                owner_name = ""
                found = managed_index.match(e, attr, [p["PrivateIpAddress"] for p in private_ips])
                if found:  # e.g. "Aurora cluster db-a" instead of the generic "RDS"
                    owner_name = found.name
                    attr = Attribution(attr.owner_type, found.ref or attr.owner_ref)
                groups = [g["GroupId"] for g in e.get("Groups", [])]
                owner_names = [attr.owner_ref] if attr.owner_ref else []
                if attr.owner_type == "lambda":
                    shared = lambda_owners(lambda_index, e.get("SubnetId"), groups)
                    if shared:
                        owner_names = shared
                        attr = Attribution("lambda", shared[0])
                conn.execute(
                    "INSERT INTO enis(snapshot_id, eni_id, subnet_id, vpc_id, az, status, "
                    "interface_type, requester_id, requester_managed, description, instance_id, "
                    "security_groups, owner_type, owner_ref, name, owner_names, instance_name, "
                    "owner_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        snap_id,
                        e["NetworkInterfaceId"],
                        e.get("SubnetId"),
                        e.get("VpcId"),
                        e.get("AvailabilityZone"),
                        e.get("Status"),
                        e.get("InterfaceType"),
                        e.get("RequesterId"),
                        int(bool(e.get("RequesterManaged"))),
                        e.get("Description") or "",
                        (e.get("Attachment") or {}).get("InstanceId"),
                        json.dumps(sorted(groups)),
                        attr.owner_type,
                        attr.owner_ref,
                        _name_tag(e.get("TagSet")),
                        json.dumps(owner_names),
                        inst.name if inst else "",
                        owner_name,
                    ),
                )
                for p in private_ips:
                    ip = p.get("PrivateIpAddress")
                    if not ip:
                        continue
                    conn.execute(
                        "INSERT OR IGNORE INTO ips(snapshot_id, ip, ip_int, eni_id, subnet_id, "
                        "vpc_id, is_primary, public_ip, owner_type) VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            snap_id,
                            ip,
                            int(ipaddress.IPv4Address(ip)),
                            e["NetworkInterfaceId"],
                            e.get("SubnetId"),
                            e.get("VpcId"),
                            int(bool(p.get("Primary"))),
                            (p.get("Association") or {}).get("PublicIp"),
                            attr.owner_type,
                        ),
                    )
                    ip_count += 1
                # IPv4 prefix delegation: each /28 prefix consumes 16 addresses.
                for pref in e.get("Ipv4Prefixes", []) or []:
                    net = ipaddress.IPv4Network(pref["Ipv4Prefix"], strict=False)
                    for addr in net:
                        conn.execute(
                            "INSERT OR IGNORE INTO ips(snapshot_id, ip, ip_int, eni_id, "
                            "subnet_id, vpc_id, is_primary, public_ip, owner_type) "
                            "VALUES(?,?,?,?,?,?,0,NULL,?)",
                            (
                                snap_id,
                                str(addr),
                                int(addr),
                                e["NetworkInterfaceId"],
                                e.get("SubnetId"),
                                e.get("VpcId"),
                                attr.owner_type,
                            ),
                        )
                        ip_count += 1

        def write_endpoints(conn: sqlite3.Connection) -> None:
            for ep in endpoints:
                conn.execute(
                    "INSERT INTO endpoints(snapshot_id, endpoint_id, vpc_id, service_name, "
                    "endpoint_type, subnet_ids, eni_ids) VALUES(?,?,?,?,?,?,?)",
                    (
                        snap_id,
                        ep["VpcEndpointId"],
                        ep.get("VpcId"),
                        ep.get("ServiceName"),
                        ep.get("VpcEndpointType"),
                        json.dumps(ep.get("SubnetIds", [])),
                        json.dumps(ep.get("NetworkInterfaceIds", [])),
                    ),
                )

        def write_lambdas(conn: sqlite3.Connection) -> None:
            subnet_vpc = {s["SubnetId"]: s["VpcId"] for s in subnets}
            for fn in lambdas:
                vpc_cfg = fn.get("VpcConfig") or {}
                # Prefer the VPC of the function's subnets from this same snapshot so the
                # row is consistent with subnets/enis; fall back to the reported VpcId.
                vpc_id = (
                    next(
                        (subnet_vpc[s] for s in vpc_cfg.get("SubnetIds", []) if s in subnet_vpc),
                        None,
                    )
                    or vpc_cfg.get("VpcId")
                    or None
                )
                conn.execute(
                    "INSERT INTO lambdas(snapshot_id, name, vpc_id, subnet_ids, security_groups) "
                    "VALUES(?,?,?,?,?)",
                    (
                        snap_id,
                        fn["FunctionName"],
                        vpc_id,
                        json.dumps(sorted(vpc_cfg.get("SubnetIds", []))),
                        json.dumps(sorted(vpc_cfg.get("SecurityGroupIds", []))),
                    ),
                )

        def write_load_balancers(conn: sqlite3.Connection) -> None:
            for lb in lbs:
                subnet_ids = {
                    az["SubnetId"] for az in lb.get("AvailabilityZones", []) if az.get("SubnetId")
                }
                conn.execute(
                    "INSERT INTO load_balancers(snapshot_id, name, lb_type, scheme, vpc_id, "
                    "subnet_ids) VALUES(?,?,?,?,?,?)",
                    (
                        snap_id,
                        lb["LoadBalancerName"],
                        lb.get("Type"),
                        lb.get("Scheme"),
                        lb.get("VpcId"),
                        json.dumps(sorted(subnet_ids)),
                    ),
                )

        def write_lb_targets(conn: sqlite3.Connection) -> None:
            for row in lb_targets.targets:
                conn.execute(
                    "INSERT OR IGNORE INTO lb_targets(snapshot_id, lb_name, target_group, "
                    "target_type, target_id, port) VALUES(?,?,?,?,?,?)",
                    (snap_id, *row),
                )

        def write_ecs(conn: sqlite3.Connection) -> None:
            for svc in ecs.services:
                conn.execute(
                    "INSERT OR IGNORE INTO ecs_services(snapshot_id, cluster, service, "
                    "desired_count, running_count, last_deployment, subnet_ids, max_percent, "
                    "deployment_controller) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        snap_id,
                        svc["cluster"],
                        svc["service"],
                        svc["desired_count"],
                        svc["running_count"],
                        svc["last_deployment"],
                        json.dumps(svc["subnet_ids"]),
                        svc["max_percent"],
                        svc["deployment_controller"],
                    ),
                )
            for eni_id, task in ecs.task_enis.items():
                conn.execute(
                    "INSERT OR IGNORE INTO ecs_task_enis(snapshot_id, eni_id, cluster, service, "
                    "task_id) VALUES(?,?,?,?,?)",
                    (snap_id, eni_id, task.cluster, task.service, task.task_id),
                )
            for svc in ecs.services:
                for tg_arn, classic_name in svc["load_balancers"]:
                    tg = lb_targets.groups.get(tg_arn)
                    pairs = [(n, tg.name) for n in tg.lb_names] if tg else []
                    if not pairs and classic_name:
                        pairs = [(classic_name, "")]
                    for lb_name, tg_name in pairs:
                        conn.execute(
                            "INSERT OR IGNORE INTO ecs_service_lbs(snapshot_id, cluster, "
                            "service, lb_name, target_group) VALUES(?,?,?,?,?)",
                            (snap_id, svc["cluster"], svc["service"], lb_name, tg_name),
                        )

        def write_security_groups(conn: sqlite3.Connection) -> None:
            for row in sg_ref_rows(security_groups):
                conn.execute(
                    "INSERT OR IGNORE INTO sg_refs(snapshot_id, group_id, direction, "
                    "ref_group_id, ports) VALUES(?,?,?,?,?)",
                    (snap_id, *row),
                )
            for row in sg_cidr_rows(security_groups):
                conn.execute(
                    "INSERT OR IGNORE INTO sg_cidr_rules(snapshot_id, group_id, cidr, "
                    "ip_protocol, from_port, to_port) VALUES(?,?,?,?,?,?)",
                    (snap_id, *row),
                )
            for g in security_groups:
                conn.execute(
                    "INSERT OR IGNORE INTO security_groups(snapshot_id, group_id, name, "
                    "group_name, vpc_id) VALUES(?,?,?,?,?)",
                    (
                        snap_id,
                        g["GroupId"],
                        _name_tag(g.get("Tags")),
                        g.get("GroupName") or "",
                        g.get("VpcId"),
                    ),
                )

        def write_tgw_attachments(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "INSERT OR IGNORE INTO tgw_attachments(snapshot_id, attachment_id, tgw_id, "
                "resource_type, resource_id, state) VALUES(?,?,?,?,?,?)",
                [
                    (
                        snap_id,
                        a["TransitGatewayAttachmentId"],
                        a["TransitGatewayId"],
                        a.get("ResourceType"),
                        a.get("ResourceId"),
                        a.get("State"),
                    )
                    for a in tgw_attachments
                ],
            )

        def write_route_tables(conn: sqlite3.Connection) -> None:
            for row, routes in route_table_rows(route_tables):
                conn.execute(
                    "INSERT OR IGNORE INTO route_tables(snapshot_id, route_table_id, vpc_id, "
                    "is_main, subnet_ids) VALUES(?,?,?,?,?)",
                    (snap_id, *row),
                )
                conn.executemany(
                    "INSERT OR IGNORE INTO tgw_routes(snapshot_id, route_table_id, "
                    "destination, tgw_id, state) VALUES(?,?,?,?,?)",
                    [(snap_id, row[0], *r) for r in routes],
                )

        def write_tags(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "INSERT OR IGNORE INTO resource_tags(snapshot_id, resource_type, resource_id, "
                "key, value) VALUES(?,?,?,?,?)",
                [(snap_id, *row) for row in tag_rows],
            )

        def write_ownership(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "INSERT OR IGNORE INTO own_resources(snapshot_id, kind, resource_id, cfn_stack) "
                "VALUES(?,?,?,?)",
                [(snap_id, kind, rid, stack) for (kind, rid), stack in own_resources.items()],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO own_tags(snapshot_id, kind, resource_id, key, value) "
                "VALUES(?,?,?,?,?)",
                [(snap_id, *row) for row in own_tags],
            )

        def write_asgs(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "INSERT OR IGNORE INTO asgs(snapshot_id, name, min_size, desired, max_size, "
                "subnet_ids, instances) VALUES(?,?,?,?,?,?,?)",
                [(snap_id, *row) for row in asgs],
            )

        def write_scalable_targets(conn: sqlite3.Connection) -> None:
            conn.executemany(
                "INSERT OR IGNORE INTO ecs_scalable_targets(snapshot_id, cluster, service, "
                "min_capacity, max_capacity) VALUES(?,?,?,?,?)",
                [(snap_id, *row) for row in scalable_targets],
            )

        def write_managed(service: str) -> Callable[[sqlite3.Connection], None]:
            return lambda conn: managed.write(conn, snap_id, managed_rows[service])

        writers = (
            ("ec2:DescribeVpcs", True, write_vpcs),
            ("ec2:DescribeSubnets", True, write_subnets),
            ("ec2:DescribeNetworkInterfaces", True, write_enis),
            ("ec2:DescribeVpcEndpoints", False, write_endpoints),
            ("lambda:ListFunctions", False, write_lambdas),
            ("elasticloadbalancing:DescribeLoadBalancers", False, write_load_balancers),
            ("elasticloadbalancing:DescribeTargetHealth", False, write_lb_targets),
            ("ECS services and tasks", False, write_ecs),
            ("ec2:DescribeSecurityGroups", False, write_security_groups),
            (TGW_ATTACHMENTS_RESOURCE, False, write_tgw_attachments),
            (ROUTE_TABLES_RESOURCE, False, write_route_tables),
            (ASG_RESOURCE, False, write_asgs),
            (SCALABLE_TARGETS_RESOURCE, False, write_scalable_targets),
            *((MANAGED_SOURCES[s][0], False, write_managed(s)) for s in MANAGED_SOURCES),
            ("resource tags", False, write_tags),
            (OWNERSHIP_WRITE, False, write_ownership),
        )
        with closing(self.db_path) as conn:
            # The savepoints below nest inside this one transaction. A retry takes the
            # write lock first, so its source snapshot cannot go away before the copy.
            conn.execute("BEGIN" if self.only is None else "BEGIN IMMEDIATE")
            if self.only is not None:
                # Copy what the retry did not collect, then attribute the fresh ENIs on
                # the merged rows (ECS tasks, Lambda functions, instance names and the
                # managed-service resources).
                ecs_enis, lambda_rows, instance_names, copied_managed = self._merge(conn, snap_id)
                task_enis = ecs_enis if ecs_enis is not None else task_enis
                if lambda_rows is not None:
                    lambda_index = lambda_eni_index(lambda_rows)
                if copied_managed:
                    managed_index = managed.ManagedIndex(
                        r
                        for service, rows in managed_rows.items()
                        for r in copied_managed.get(service, rows)
                    )
                if instance_names is not None:
                    instances = {
                        e["NetworkInterfaceId"]: InstanceEni(
                            iid, instance_names[(e["NetworkInterfaceId"], iid)], ()
                        )
                        for e in enis
                        if (iid := (e.get("Attachment") or {}).get("InstanceId"))
                        and (e["NetworkInterfaceId"], iid) in instance_names
                    }
            for what, required, write in writers:
                with self._saving(conn, result, what, required=required):
                    write(conn)
            if self.only is not None and not self._wants(CLOUDTRAIL_RESOURCE):
                self._copy_creators(conn, snap_id)

        self._step("cloudtrail:LookupEvents")
        if self.own.cloudtrail and self._wants(CLOUDTRAIL_RESOURCE):
            self._collect_creators(result, snap_id)
        # Planned resource types that had nothing to collect (e.g. no load balancers).
        for what in self._planned:
            if what not in self._touched:
                self.progress.resource(what, RES_DONE, "nothing to collect")
        with closing(self.db_path) as conn:
            conn.execute(
                "UPDATE snapshots SET status='ok', account_id=?, account_alias=?, warnings=? "
                "WHERE id=?",
                (account_id, account_alias, json.dumps(result.warnings), snap_id),
            )

        result.account_id, result.account_alias = account_id, account_alias
        result.vpcs, result.subnets, result.enis, result.ips = (
            len(vpcs),
            len(subnets),
            len(enis),
            ip_count,
        )
        return result

    # -- Retry skipped: the merge with the source snapshot -------------------------------

    def _merge(
        self, conn: sqlite3.Connection, snap_id: int
    ) -> tuple[
        dict[str, EcsTaskEni] | None,
        list[dict[str, Any]] | None,
        dict[tuple[str, str], str] | None,
        dict[str, list[managed.ManagedResource]],
    ]:
        """Copy the rows of every write the retry does not collect (:data:`_MERGED`) from
        the source snapshot into ``snap_id``. Returns what ENI attribution takes from the
        copied data instead: ECS task ENIs, Lambda functions and ``(eni, instance) ->
        instance name`` (None for what the retry collected), and the managed-service
        resources of each service it did not collect. Raises
        :class:`SourceSnapshotGone` when the source snapshot no longer exists."""
        src = self.source_snapshot
        if not self._source_ok(conn):
            raise SourceSnapshotGone(src)
        tag_types: list[str] = []
        copied: list[str] = []
        for sources, tables, tags in _MERGED:
            if any(self._wants(what) for what in sources):
                continue
            for table in tables:
                cols = ", ".join(
                    r["name"]
                    for r in conn.execute(f"PRAGMA table_info({table})")
                    if r["name"] != "snapshot_id"
                )
                conn.execute(
                    f"INSERT INTO {table}(snapshot_id, {cols}) "  # noqa: S608 - constants
                    f"SELECT ?, {cols} FROM {table} WHERE snapshot_id=?",
                    (snap_id, src),
                )
            tag_types += tags
            copied += tables
        if tag_types:
            marks = ",".join("?" * len(tag_types))
            conn.execute(
                "INSERT INTO resource_tags(snapshot_id, resource_type, resource_id, key, "  # noqa: S608
                "value) SELECT ?, resource_type, resource_id, key, value FROM resource_tags "
                f"WHERE snapshot_id=? AND resource_type IN ({marks})",
                (snap_id, src, *tag_types),
            )
        log.info(
            "retry of skipped resources: copied %s and tags of %s from snapshot %s",
            ", ".join(copied) or "no tables",
            ", ".join(tag_types) or "no resource types",
            src,
        )
        task_enis = None
        if not self._wants("ECS services and tasks"):
            task_enis = {
                r["eni_id"]: EcsTaskEni(r["cluster"], r["service"], r["task_id"])
                for r in conn.execute(
                    "SELECT eni_id, cluster, service, task_id FROM ecs_task_enis "
                    "WHERE snapshot_id=?",
                    (snap_id,),
                )
            }
        functions = None
        if not self._wants("lambda:ListFunctions"):
            functions = [
                {
                    "FunctionName": r["name"],
                    "VpcConfig": {
                        "SubnetIds": json.loads(r["subnet_ids"] or "[]"),
                        "SecurityGroupIds": json.loads(r["security_groups"] or "[]"),
                    },
                }
                for r in conn.execute(
                    "SELECT name, subnet_ids, security_groups FROM lambdas WHERE snapshot_id=?",
                    (snap_id,),
                )
            ]
        instance_names = None
        if not self._wants("ec2:DescribeInstances"):
            instance_names = {
                (r["eni_id"], r["instance_id"]): r["instance_name"] or ""
                for r in conn.execute(
                    "SELECT eni_id, instance_id, instance_name FROM enis "
                    "WHERE snapshot_id=? AND COALESCE(instance_id, '') != ''",
                    (src,),
                )
            }
        copied_managed = {
            service: managed.load(conn, snap_id, service)
            for service, sources in MANAGED_SOURCES.items()
            if not any(self._wants(what) for what in sources)
        }
        return task_enis, functions, instance_names, copied_managed

    def _copy_creators(self, conn: sqlite3.Connection, snap_id: int) -> None:
        """A retry that collected the ownership sources again but not CloudTrail keeps
        the source snapshot's creators (when not collected, own_resources is copied whole)."""
        if not any(self._wants(w) for w in ("tag:GetResources", "cloudformation:ListStacks")):
            return
        conn.execute(
            "INSERT INTO own_resources(snapshot_id, kind, resource_id, creator, creator_kind) "
            "SELECT ?, kind, resource_id, creator, creator_kind FROM own_resources "
            "WHERE snapshot_id=? AND creator != '' "
            "ON CONFLICT(snapshot_id, kind, resource_id) DO UPDATE SET "
            "creator=excluded.creator, creator_kind=excluded.creator_kind",
            (snap_id, self.source_snapshot),
        )

    # -- ownership sources (see iplens.ownership) ---------------------------------------

    def _fetch_tagged_resources(self) -> list[tuple[ownership.ResourceKey, list[tuple[str, str]]]]:
        """Every tagged resource of the region with its tags (tag:GetResources, paginated)."""
        client = self.gw.client("resourcegroupstaggingapi")
        out = []
        for page in client.get_paginator("get_resources").paginate(ResourcesPerPage=_TAG_PAGE):
            self._tick()
            for item in page.get("ResourceTagMappingList", []):
                key = ownership.arn_key(item.get("ResourceARN", ""))
                if key:
                    out.append((key, tag_pairs(item.get("Tags"))))
        log.info("tag:GetResources: %d resource(s)", len(out))
        return out

    def _fetch_stack_resources(self) -> list[tuple[ownership.ResourceKey, str]]:
        """``(resource key, stack name)`` of every physical resource of a live stack."""
        cfn = self.gw.client("cloudformation")
        out = []
        stacks = _paginate(cfn, "list_stacks", "StackSummaries")
        live = [s for s in stacks if s.get("StackStatus") != "DELETE_COMPLETE"]
        for stack in live:
            self._tick()
            name = stack.get("StackName", "")
            for r in _paginate(
                cfn, "list_stack_resources", "StackResourceSummaries", StackName=name
            ):
                key = ownership.cfn_key(r.get("ResourceType", ""), r.get("PhysicalResourceId", ""))
                if key:
                    out.append((key, name))
        log.info("CloudFormation: %d stack(s), %d resource(s)", len(live), len(out))
        return out

    def _ownership_rows(
        self,
        tagged: list[tuple[ownership.ResourceKey, list[tuple[str, str]]]],
        stacks: list[tuple[ownership.ResourceKey, str]],
    ) -> tuple[dict[ownership.ResourceKey, str], list[tuple[str, str, str, str]]]:
        """``own_resources`` (key -> stack name) and ``own_tags`` rows.

        Only the values of the ownership tag keys are kept; ``aws:`` tags are dropped
        (``aws:cloudformation:stack-name`` only maps a resource to its stack when
        ListStackResources did not).
        """
        value_keys = self.own.value_keys()
        resources: dict[ownership.ResourceKey, str] = {}
        tags: list[tuple[str, str, str, str]] = []
        for key, stack in stacks:
            resources.setdefault(key, stack)
        for key, pairs in tagged:
            resources.setdefault(key, "")
            for k, v in pairs:
                if k == ownership.CFN_STACK_TAG and not resources[key]:
                    resources[key] = v[:128]
                if k.lower().startswith("aws:"):
                    continue
                tags.append((key[0], key[1], k, v if k.lower() in value_keys else ""))
        return resources, tags

    def _collect_creators(self, result: CollectResult, snap_id: int) -> None:
        """Opt-in: the creator of every resource still unowned after the other sources
        (cloudtrail:LookupEvents, at most MAX_CLOUDTRAIL_LOOKUPS resources per Refresh)."""
        with closing(self.db_path) as conn:
            idx = ownership.load_index(conn, snap_id, self.own)
            unowned = sorted(
                k for k in ownership.inventory(conn, snap_id) if not idx.resolve([k]).source
            )
        if not unowned:
            return
        limit = ownership.MAX_CLOUDTRAIL_LOOKUPS
        if len(unowned) > limit:
            result.warnings.append(
                f"cloudtrail:LookupEvents limited to {limit} of {len(unowned)} unowned resources"
            )
        ct = self.gw.client("cloudtrail")

        def lookup() -> list[tuple[ownership.ResourceKey, ownership.Principal]]:
            found = []
            for key in unowned[:limit]:
                self._tick()
                principal = _creator(ct, key[1])
                if principal:
                    found.append((key, principal))
            return found

        creators = self._optional(result, "cloudtrail:LookupEvents", lookup)
        with closing(self.db_path) as conn:
            conn.executemany(
                "INSERT INTO own_resources(snapshot_id, kind, resource_id, creator, creator_kind) "
                "VALUES(?,?,?,?,?) ON CONFLICT(snapshot_id, kind, resource_id) DO UPDATE SET "
                "creator=excluded.creator, creator_kind=excluded.creator_kind",
                [(snap_id, k[0], k[1], p.name, p.kind) for k, p in creators],
            )
        log.info("CloudTrail: creator found for %d of %d resource(s)", len(creators), len(unowned))

    def _collect_lb_targets(self, result: CollectResult, lbs: list[Any]) -> LbTargetData:
        """Optional enrichment: target groups of each load balancer and their targets.

        Uses only DescribeTargetGroups and DescribeTargetHealth; a missing
        permission records a warning and leaves the diagram without LB edges.
        """
        data = LbTargetData()
        lb_names = {lb["LoadBalancerArn"]: lb["LoadBalancerName"] for lb in lbs}
        if not lb_names:
            return data
        elbv2 = self.gw.client("elbv2")
        groups = self._optional(
            result,
            "elasticloadbalancing:DescribeTargetGroups",
            lambda: _paginate(elbv2, "describe_target_groups", "TargetGroups"),
        )
        for tg in groups:
            names = sorted({lb_names[a] for a in tg.get("LoadBalancerArns", []) if a in lb_names})
            if names:
                data.groups[tg["TargetGroupArn"]] = TargetGroupInfo(
                    name=tg.get("TargetGroupName", ""),
                    target_type=tg.get("TargetType", "instance"),
                    lb_names=names,
                )

        def targets() -> list[tuple[str, str, str, str, int]]:
            rows = []
            for arn, tg in data.groups.items():
                self._tick()
                resp = elbv2.describe_target_health(TargetGroupArn=arn)
                for desc in resp.get("TargetHealthDescriptions", []):
                    target = desc.get("Target") or {}
                    if not target.get("Id"):
                        continue
                    ref = target_ref(tg.target_type, target["Id"])
                    port = int(target.get("Port") or 0)
                    rows.extend((lb, tg.name, tg.target_type, ref, port) for lb in tg.lb_names)
            return rows

        data.targets = self._optional(result, "elasticloadbalancing:DescribeTargetHealth", targets)
        log.info(
            "LB enrichment: %d target group(s), %d target(s)", len(data.groups), len(data.targets)
        )
        return data

    def _collect_lb_tags(
        self, result: CollectResult, lbs: list[Any]
    ) -> dict[str, list[tuple[str, str]]]:
        """Optional: load balancer name -> tags (DescribeTags, 20 ARNs per call)."""
        names = {lb["LoadBalancerArn"]: lb["LoadBalancerName"] for lb in lbs}
        if not names:
            return {}
        elbv2 = self.gw.client("elbv2")

        def fetch() -> list[tuple[str, list[tuple[str, str]]]]:
            out = []
            for batch in _chunks(sorted(names), _LB_TAG_BATCH):
                self._tick()
                for d in elbv2.describe_tags(ResourceArns=batch).get("TagDescriptions", []):
                    if d.get("ResourceArn") in names:
                        out.append((names[d["ResourceArn"]], tag_pairs(d.get("Tags"))))
            return out

        return dict(self._optional(result, "elasticloadbalancing:DescribeTags", fetch))

    def _collect_lambda_tags(
        self, result: CollectResult, functions: list[Any]
    ) -> dict[str, list[tuple[str, str]]]:
        """Optional: function name -> tags (ListTags) for VPC-attached functions only."""
        in_vpc = [
            f
            for f in functions
            if f.get("FunctionArn") and (f.get("VpcConfig") or {}).get("SubnetIds")
        ]
        if not in_vpc:
            return {}
        lam = self.gw.client("lambda")

        def fetch() -> list[tuple[str, list[tuple[str, str]]]]:
            out = []
            for fn in in_vpc:
                self._tick()
                tags = lam.list_tags(Resource=fn["FunctionArn"]).get("Tags") or {}
                pairs = tag_pairs({"Key": k, "Value": v} for k, v in tags.items())
                out.append((fn["FunctionName"], pairs))
            return out

        return dict(self._optional(result, "lambda:ListTags", fetch))

    def _collect_ecs(self, result: CollectResult) -> EcsData:
        """Optional ECS enrichment: map awsvpc task ENIs to cluster + service.

        Uses only ListClusters, ListServices, DescribeServices, ListTasks and
        DescribeTasks. Any AWS error (typically a missing ``ecs:*`` permission)
        discards the partial ECS data, records a warning and lets the snapshot
        continue without the mapping.
        """
        what = "ECS services and tasks"
        if not self._wants(what):
            return EcsData()
        try:
            data = self._timed(result, what, self._fetch_ecs)
        except ResourceTimeout:
            return EcsData()
        except (BotoCoreError, ClientError) as exc:
            if isinstance(exc, ClientError):
                op = exc.operation_name
                code = exc.response.get("Error", {}).get("Code", "")
                cause = f"ecs:{op} ({code or 'ClientError'})"
            else:
                cause = type(exc).__name__
            msg = f"ECS enrichment skipped: {cause}; ECS task ENIs are attributed heuristically"
            log.warning(msg)
            result.warnings.append(msg)
            self._skip(result, what, cause)
            return EcsData()
        log.info(
            "ECS enrichment: %d service(s), %d task ENI(s)",
            len(data.services),
            len(data.task_enis),
        )
        return data

    def _fetch_ecs(self) -> EcsData:
        """ListClusters / ListServices / DescribeServices / ListTasks / DescribeTasks."""
        data = EcsData()
        ecs = self.gw.client("ecs")
        for cluster_arn in _paginate(ecs, "list_clusters", "clusterArns"):
            cluster = _arn_name(cluster_arn)
            svc_arns = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
            for batch in _chunks(svc_arns, _ECS_SERVICE_BATCH):
                self._tick()
                resp = ecs.describe_services(cluster=cluster_arn, services=batch, include=["TAGS"])
                for svc in resp.get("services", []):
                    data.services.append(_ecs_service_row(cluster, svc))
            task_arns = _paginate(ecs, "list_tasks", "taskArns", cluster=cluster_arn)
            for batch in _chunks(task_arns, _ECS_TASK_BATCH):
                self._tick()
                resp = ecs.describe_tasks(cluster=cluster_arn, tasks=batch)
                for task in resp.get("tasks", []):
                    for eni_id in _task_eni_ids(task):
                        data.task_enis[eni_id] = EcsTaskEni(
                            cluster=cluster,
                            service=_task_service(task),
                            task_id=_arn_name(task.get("taskArn", "")),
                        )
        return data

    def _collect_managed(self, result: CollectResult) -> dict[str, list[managed.ManagedResource]]:
        """Optional: the clusters / domains of managed services whose names their ENIs get
        (see iplens.managed), by service. Each call is a resource type of its own: a
        missing permission or a timeout is a warning and leaves those ENIs generic."""

        def pages(service: str, op: str, key: str) -> Callable[[], list[Any]]:
            return lambda: _paginate(self.gw.client(service), op, key)

        self._step("RDS / Aurora")
        rds = managed.rds_resources(
            self._optional(
                result,
                "rds:DescribeDBInstances",
                pages("rds", "describe_db_instances", "DBInstances"),
            ),
            self._optional(
                result,
                "rds:DescribeDBClusters",
                pages("rds", "describe_db_clusters", "DBClusters"),
            ),
        )
        self._step("Redshift")
        redshift = managed.redshift_resources(
            self._optional(
                result,
                "redshift:DescribeClusters",
                pages("redshift", "describe_clusters", "Clusters"),
            )
        )
        self._step("ElastiCache")
        elasticache = managed.elasticache_resources(
            self._optional(
                result,
                "elasticache:DescribeCacheClusters",
                pages("elasticache", "describe_cache_clusters", "CacheClusters"),
            ),
            self._optional(
                result,
                "elasticache:DescribeReplicationGroups",
                pages("elasticache", "describe_replication_groups", "ReplicationGroups"),
            ),
        )
        self._step("OpenSearch")
        opensearch = managed.opensearch_resources(
            self._optional(result, "es:DescribeDomains", self._fetch_opensearch_domains)
        )
        self._step("MSK")
        msk = managed.msk_resources(
            self._optional(
                result,
                "kafka:ListClustersV2",
                pages("kafka", "list_clusters_v2", "ClusterInfoList"),
            )
        )
        out = {
            "rds": rds,
            "redshift": redshift,
            "elasticache": elasticache,
            "opensearch": opensearch,
            "msk": msk,
        }
        log.info(
            "managed services: %s",
            ", ".join(f"{len(rows)} {service}" for service, rows in out.items()),
        )
        return out

    def _fetch_opensearch_domains(self) -> list[dict[str, Any]]:
        """es:ListDomainNames, then es:DescribeDomains (at most 5 domains per call)."""
        client = self.gw.client("opensearch")
        names = [d["DomainName"] for d in client.list_domain_names().get("DomainNames", [])]
        out = []
        for batch in _chunks(names, _OPENSEARCH_BATCH):
            self._tick()
            out += client.describe_domains(DomainNames=batch).get("DomainStatusList", [])
        return out

    def _optional(self, result: CollectResult, what: str, fn: Any) -> list[Any]:
        """Optional enrichment calls: missing permissions and timeouts downgrade to a
        warning, and the collection continues without this resource type. A type a
        retry does not collect (see retry_plan) is left out without a call."""
        if not self._wants(what):
            return []
        try:
            return self._timed(result, what, fn)
        except ResourceTimeout:
            return []
        except (BotoCoreError, ClientError) as exc:
            code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else ""
            msg = f"{what} skipped ({code or type(exc).__name__})"
            log.warning(msg)
            result.warnings.append(msg)
            self._skip(result, what, code or type(exc).__name__)
            return []

    @contextmanager
    def _saving(
        self, conn: sqlite3.Connection, result: CollectResult, what: str, *, required: bool = False
    ) -> Iterator[None]:
        """One resource type's rows, all or nothing (a savepoint of the snapshot's
        transaction). A failed optional write is a warning; a required one re-raises."""
        conn.execute("SAVEPOINT resource_write")
        try:
            yield
        except Exception as exc:
            conn.execute("ROLLBACK TO resource_write")
            conn.execute("RELEASE resource_write")
            if required:
                raise
            msg = f"{what} not saved ({type(exc).__name__})"
            log.exception(msg)
            result.warnings.append(msg)
            self._skip(result, what, f"write failed ({type(exc).__name__})")
        else:
            conn.execute("RELEASE resource_write")
