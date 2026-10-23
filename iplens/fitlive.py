"""Live data for ``iplens check``: the headroom inputs of just the subnets involved, read
straight from AWS.

Only these read-only calls are made, all through :class:`iplens.aws.AwsGateway` (its
read-only guard) with the Refresh timeouts of :func:`iplens.aws.call_timeouts`:

- ``ec2:DescribeSubnets`` and ``ec2:DescribeNetworkInterfaces``, filtered to the subnets
  (required: an error ends the check). The ENIs give each instance's ENIs, the ALBs
  (their ``ELB app/...`` ENIs) and the existing Lambda subnet / security-group
  combinations.
- ``autoscaling:DescribeAutoScalingGroups`` and ``ecs:ListClusters`` /
  ``ecs:ListServices`` / ``ecs:DescribeServices``, kept for the groups and services in
  those subnets (optional: an error is a note and that demand is not counted).
- ``application-autoscaling:DescribeScalableTargets`` for those ECS services (only when
  there are any): their ``MaxCapacity``, as in the headroom model of a snapshot (optional:
  an error is a note and the services count up to their desired count).

Not called: ``lambda:ListFunctions`` (existing functions' combinations without an ENI are
not counted); named in the notes.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import headroom
from .attribution import attribute_eni
from .aws import AwsGateway, ReadOnlyViolation, call_timeouts
from .cidrplan import SUBNET_RESERVED
from .collector import (
    _arn_name,
    _chunks,
    _ecs_service_row,
    _paginate,
    asg_rows,
    ecs_scalable_target_rows,
)
from .fitcheck import CheckError, Source
from .headroom import Asg, EcsService, Inputs, LoadBalancer, Subnet
from .settings import DEFAULT_RESOURCE_TIMEOUT, REQUIRED_RESOURCE_TIMEOUT

log = logging.getLogger(__name__)

# EC2 filters take at most 200 values.
_FILTER_VALUES = 200
_ECS_SERVICE_BATCH = 10
# DescribeScalableTargets takes at most 50 ResourceIds.
_SCALABLE_TARGET_BATCH = 50
_ALB_DESCRIPTION = re.compile(r"^ELB app/(?P<name>[^/]+)/")


def gateway(profile: str | None = None, region: str | None = None) -> AwsGateway:
    """A gateway on the named profile, else the default credential chain (env vars, ...)."""
    try:
        session = boto3.session.Session(profile_name=profile or None, region_name=region or None)
    except BotoCoreError as exc:  # e.g. ProfileNotFound
        raise CheckError(f"AWS session: {exc}") from exc
    if not session.region_name:
        raise CheckError("no AWS region: pass --region or set AWS_REGION / AWS_DEFAULT_REGION")
    return AwsGateway(session)


def _filtered(client: Any, op: str, key: str, subnet_ids: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for batch in _chunks(subnet_ids, _FILTER_VALUES):
        out += _paginate(client, op, key, Filters=[{"Name": "subnet-id", "Values": batch}])
    return out


def _subnet(s: dict[str, Any]) -> Subnet:
    size = ipaddress.ip_network(s["CidrBlock"], strict=False).num_addresses
    usable = max(size - SUBNET_RESERVED, 0)
    free = int(s.get("AvailableIpAddressCount") or 0)
    name = next((t["Value"] for t in s.get("Tags") or [] if t.get("Key") == "Name"), "")
    return Subnet(
        subnet_id=s["SubnetId"],
        vpc_id=s.get("VpcId") or "",
        az=s.get("AvailabilityZone") or "",
        cidr=s["CidrBlock"],
        name=name,
        free=free,
        usable=usable,
        consumed=max(usable - free, 0),
    )


def _skipped(what: str, exc: Exception) -> str:
    if isinstance(exc, ClientError):
        cause = exc.response.get("Error", {}).get("Code", "") or "ClientError"
    else:
        cause = type(exc).__name__
    log.warning("%s skipped: %s", what, cause)
    return cause


def _asgs(gw: AwsGateway, timeout: float, wanted: set[str]) -> list[Asg]:
    client = gw.client("autoscaling", config=call_timeouts(timeout))
    groups = _paginate(client, "describe_auto_scaling_groups", "AutoScalingGroups")
    out = []
    for name, lo, desired, top, subnets, instances in asg_rows(groups):
        ids = tuple(_json_list(subnets))
        if wanted & set(ids):
            out.append(
                Asg(name, lo, desired, top, ids, tuple(tuple(i) for i in _json_list(instances)))
            )
    return out


def _json_list(text: str) -> list[Any]:
    return list(json.loads(text or "[]"))


def _ecs(gw: AwsGateway, timeout: float, wanted: set[str]) -> list[EcsService]:
    ecs = gw.client("ecs", config=call_timeouts(timeout))
    out = []
    for cluster_arn in _paginate(ecs, "list_clusters", "clusterArns"):
        arns = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
        for batch in _chunks(arns, _ECS_SERVICE_BATCH):
            for svc in ecs.describe_services(cluster=cluster_arn, services=batch).get(
                "services", []
            ):
                row = _ecs_service_row(_arn_name(cluster_arn), svc)
                if not wanted & set(row["subnet_ids"]):
                    continue
                out.append(
                    EcsService(
                        cluster=row["cluster"],
                        service=row["service"],
                        desired=int(row["desired_count"] or 0),
                        running=int(row["running_count"] or 0),
                        subnet_ids=tuple(row["subnet_ids"]),
                        max_percent=row["max_percent"],
                        controller=row["deployment_controller"],
                    )
                )
    return out


def _ecs_max(
    gw: AwsGateway, timeout: float, services: list[EcsService]
) -> dict[tuple[str, str], int]:
    """(cluster, service) -> MaxCapacity of the services' ecs:service:DesiredCount targets."""
    client = gw.client("application-autoscaling", config=call_timeouts(timeout))
    ids = sorted({f"service/{s.cluster}/{s.service}" for s in services})
    targets: list[dict[str, Any]] = []
    for batch in _chunks(ids, _SCALABLE_TARGET_BATCH):
        targets += _paginate(
            client,
            "describe_scalable_targets",
            "ScalableTargets",
            ServiceNamespace="ecs",
            ResourceIds=batch,
            ScalableDimension="ecs:service:DesiredCount",
        )
    return {(c, s): top for c, s, _lo, top in ecs_scalable_target_rows(targets)}


def _from_enis(enis: Iterable[dict[str, Any]]) -> dict[str, Any]:
    instance_enis: dict[str, list[str]] = defaultdict(list)
    lb_eni_subnets: dict[str, set[str]] = defaultdict(set)
    lambda_combos: set[tuple[str, tuple[str, ...]]] = set()
    for e in enis:
        sid = e.get("SubnetId") or ""
        instance_id = (e.get("Attachment") or {}).get("InstanceId")
        if instance_id:
            instance_enis[instance_id].append(sid)
        m = _ALB_DESCRIPTION.match(e.get("Description") or "")
        if m:
            lb_eni_subnets[m["name"]].add(sid)
        if attribute_eni(e).owner_type == "lambda":
            sgs = tuple(sorted(g["GroupId"] for g in e.get("Groups") or [] if g.get("GroupId")))
            lambda_combos.add((sid, sgs))
    return {
        "instance_enis": dict(instance_enis),
        "lb_eni_subnets": dict(lb_eni_subnets),
        "lambda_combos": lambda_combos,
        # Subnets of an ALB come from its ENIs (no elasticloadbalancing call).
        "lbs": [LoadBalancer(name, "application", None) for name in sorted(lb_eni_subnets)],
    }


def load(
    gw: AwsGateway, subnet_ids: Iterable[str], timeout: float = DEFAULT_RESOURCE_TIMEOUT
) -> tuple[Inputs, Source, list[str]]:
    """The headroom inputs of ``subnet_ids`` from AWS, a :class:`Source` and notes.
    ``timeout``: the per-resource Refresh timeout (subnets / ENIs get at least the
    required-resource one). CheckError when the required calls fail."""
    ids = sorted(set(subnet_ids))
    notes: list[str] = []
    missing: set[str] = {headroom.LAMBDA_SOURCE}
    if not ids:
        return Inputs(subnets=[], missing=frozenset(missing)), _source(gw), notes
    core = gw.client("ec2", config=call_timeouts(max(timeout, REQUIRED_RESOURCE_TIMEOUT)))
    try:
        subnets = [_subnet(s) for s in _filtered(core, "describe_subnets", "Subnets", ids)]
        enis = _filtered(core, "describe_network_interfaces", "NetworkInterfaces", ids)
    except ReadOnlyViolation as exc:  # pragma: no cover - only Describe calls are made
        raise CheckError(str(exc)) from exc
    except (BotoCoreError, ClientError) as exc:
        raise CheckError(f"AWS: {_aws_error(exc)}") from exc
    wanted = set(ids)
    asgs: list[Asg] = []
    ecs: list[EcsService] = []
    try:
        asgs = _asgs(gw, timeout, wanted)
    except (BotoCoreError, ClientError) as exc:
        missing.add(headroom.ASG_SOURCE)
        notes.append(f"autoscaling:DescribeAutoScalingGroups failed ({_skipped('ASG', exc)}).")
    try:
        ecs = _ecs(gw, timeout, wanted)
    except (BotoCoreError, ClientError) as exc:
        missing.add(headroom.ECS_SOURCE)
        notes.append(f"ECS services could not be read ({_skipped('ECS', exc)}).")
    ecs_max: dict[tuple[str, str], int] = {}
    if ecs:
        try:
            ecs_max = _ecs_max(gw, timeout, ecs)
        except (BotoCoreError, ClientError) as exc:
            missing.add(headroom.SCALING_SOURCE)
            notes.append(
                "application-autoscaling:DescribeScalableTargets failed "
                f"({_skipped('Application Auto Scaling', exc)})."
            )
    inputs = Inputs(
        subnets=subnets,
        asgs=asgs,
        ecs=ecs,
        ecs_max=ecs_max,
        missing=frozenset(missing),
        **_from_enis(enis),
    )
    return inputs, _source(gw), notes


def _source(gw: AwsGateway) -> Source:
    return Source(kind="live", label=f"live AWS ({gw.region})")


def _aws_error(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"
