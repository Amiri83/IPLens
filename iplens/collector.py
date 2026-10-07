"""Read-only collection of VPC/subnet/ENI (and optional ECS) data into an SQLite snapshot."""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .attribution import Attribution, attribute_eni
from .aws import AwsGateway
from .db import closing

log = logging.getLogger(__name__)


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


def _name_tag(tags: Iterable[dict[str, str]] | None) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[Any]:
    out: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _arn_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


@dataclass
class EcsTaskEni:
    cluster: str
    service: str  # "" for standalone tasks
    task_id: str

    @property
    def owner_ref(self) -> str:
        return f"{self.cluster}/{self.service or self.task_id}"


@dataclass
class EcsData:
    services: list[dict[str, Any]] = field(default_factory=list)
    task_enis: dict[str, EcsTaskEni] = field(default_factory=dict)


# DescribeServices / DescribeTasks batch limits.
_ECS_SERVICE_BATCH = 10
_ECS_TASK_BATCH = 100


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
    }


def _task_service(task: dict[str, Any]) -> str:
    """Tasks launched by a service carry ``group = "service:<name>"``."""
    group = task.get("group") or ""
    return group.removeprefix("service:") if group.startswith("service:") else ""


def _task_eni_ids(task: dict[str, Any]) -> list[str]:
    out = []
    for att in task.get("attachments", []):
        if att.get("type") != "ElasticNetworkInterface":
            continue
        for d in att.get("details", []):
            if d.get("name") == "networkInterfaceId" and d.get("value"):
                out.append(d["value"])
    return out


class Collector:
    def __init__(self, gateway: AwsGateway, db_path: Path):
        self.gw = gateway
        self.db_path = db_path

    def run(self) -> CollectResult:
        region = self.gw.region or ""
        started = datetime.now(UTC).isoformat(timespec="seconds")
        with closing(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO snapshots(taken_at, region, status) VALUES(?, ?, 'running')",
                (started, region),
            )
            snap_id = int(cur.lastrowid or 0)
        log.info("collection started snapshot=%s region=%s", snap_id, region)
        try:
            result = self._collect(snap_id)
        except Exception as exc:
            log.exception("collection failed snapshot=%s", snap_id)
            with closing(self.db_path) as conn:
                conn.execute(
                    "UPDATE snapshots SET status='failed', error=? WHERE id=?",
                    (f"{type(exc).__name__}: {exc}", snap_id),
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
        return result

    def _collect(self, snap_id: int) -> CollectResult:
        ec2 = self.gw.client("ec2")
        result = CollectResult(snapshot_id=snap_id)

        account_id = ""
        try:
            account_id = self.gw.caller_identity()["account"]
        except (BotoCoreError, ClientError) as exc:
            result.warnings.append(f"sts:GetCallerIdentity unavailable ({type(exc).__name__})")
        # Display-only: without the permission the UI falls back to the account id.
        aliases = self._optional(result, "iam:ListAccountAliases", self.gw.account_aliases)
        account_alias = aliases[0] if aliases else ""

        vpcs = _paginate(ec2, "describe_vpcs", "Vpcs")
        subnets = _paginate(ec2, "describe_subnets", "Subnets")
        enis = _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces")
        endpoints = self._optional(
            result,
            "ec2:DescribeVpcEndpoints",
            lambda: _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"),
        )
        lambdas = self._optional(
            result,
            "lambda:ListFunctions",
            lambda: _paginate(self.gw.client("lambda"), "list_functions", "Functions"),
        )
        lbs = self._optional(
            result,
            "elasticloadbalancing:DescribeLoadBalancers",
            lambda: _paginate(self.gw.client("elbv2"), "describe_load_balancers", "LoadBalancers"),
        )
        ecs = self._collect_ecs(result)

        with closing(self.db_path) as conn:
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
            ip_count = 0
            for e in enis:
                attr = attribute_eni(e)
                task = ecs.task_enis.get(e["NetworkInterfaceId"])
                if task:
                    attr = Attribution("ecs", task.owner_ref)
                groups = [g["GroupId"] for g in e.get("Groups", [])]
                conn.execute(
                    "INSERT INTO enis(snapshot_id, eni_id, subnet_id, vpc_id, az, status, "
                    "interface_type, requester_id, requester_managed, description, instance_id, "
                    "security_groups, owner_type, owner_ref, name) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    ),
                )
                for p in e.get("PrivateIpAddresses", []) or [
                    {"PrivateIpAddress": e.get("PrivateIpAddress"), "Primary": True}
                ]:
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
            for lb in lbs:
                conn.execute(
                    "INSERT INTO load_balancers(snapshot_id, name, lb_type, scheme, vpc_id) "
                    "VALUES(?,?,?,?,?)",
                    (
                        snap_id,
                        lb["LoadBalancerName"],
                        lb.get("Type"),
                        lb.get("Scheme"),
                        lb.get("VpcId"),
                    ),
                )
            for svc in ecs.services:
                conn.execute(
                    "INSERT OR IGNORE INTO ecs_services(snapshot_id, cluster, service, "
                    "desired_count, running_count, last_deployment) VALUES(?,?,?,?,?,?)",
                    (
                        snap_id,
                        svc["cluster"],
                        svc["service"],
                        svc["desired_count"],
                        svc["running_count"],
                        svc["last_deployment"],
                    ),
                )
            for eni_id, task in ecs.task_enis.items():
                conn.execute(
                    "INSERT OR IGNORE INTO ecs_task_enis(snapshot_id, eni_id, cluster, service, "
                    "task_id) VALUES(?,?,?,?,?)",
                    (snap_id, eni_id, task.cluster, task.service, task.task_id),
                )
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

    def _collect_ecs(self, result: CollectResult) -> EcsData:
        """Optional ECS enrichment: map awsvpc task ENIs to cluster + service.

        Uses only ListClusters, ListServices, DescribeServices, ListTasks and
        DescribeTasks. Any AWS error (typically a missing ``ecs:*`` permission)
        discards the partial ECS data, records a warning and lets the snapshot
        continue without the mapping.
        """
        data = EcsData()
        try:
            ecs = self.gw.client("ecs")
            for cluster_arn in _paginate(ecs, "list_clusters", "clusterArns"):
                cluster = _arn_name(cluster_arn)
                svc_arns = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
                for batch in _chunks(svc_arns, _ECS_SERVICE_BATCH):
                    resp = ecs.describe_services(cluster=cluster_arn, services=batch)
                    for svc in resp.get("services", []):
                        data.services.append(_ecs_service_row(cluster, svc))
                task_arns = _paginate(ecs, "list_tasks", "taskArns", cluster=cluster_arn)
                for batch in _chunks(task_arns, _ECS_TASK_BATCH):
                    resp = ecs.describe_tasks(cluster=cluster_arn, tasks=batch)
                    for task in resp.get("tasks", []):
                        for eni_id in _task_eni_ids(task):
                            data.task_enis[eni_id] = EcsTaskEni(
                                cluster=cluster,
                                service=_task_service(task),
                                task_id=_arn_name(task.get("taskArn", "")),
                            )
        except (BotoCoreError, ClientError) as exc:
            if isinstance(exc, ClientError):
                op = exc.operation_name
                code = exc.response.get("Error", {}).get("Code", "")
                what = f"ecs:{op} ({code or 'ClientError'})"
            else:
                what = type(exc).__name__
            msg = f"ECS enrichment skipped: {what}; ECS task ENIs are attributed heuristically"
            log.warning(msg)
            result.warnings.append(msg)
            return EcsData()
        log.info(
            "ECS enrichment: %d service(s), %d task ENI(s)",
            len(data.services),
            len(data.task_enis),
        )
        return data

    @staticmethod
    def _optional(result: CollectResult, what: str, fn: Any) -> list[Any]:
        """Optional enrichment calls: missing permissions downgrade to a warning."""
        try:
            return fn()
        except (BotoCoreError, ClientError) as exc:
            code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else ""
            msg = f"{what} skipped ({code or type(exc).__name__})"
            log.warning(msg)
            result.warnings.append(msg)
            return []
