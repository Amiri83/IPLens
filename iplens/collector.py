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

from .attribution import Attribution, attribute_eni, lambda_eni_index, lambda_owners
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
    }


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


class Collector:
    def __init__(
        self,
        gateway: AwsGateway,
        db_path: Path,
        account_ref: int | None = None,
        account_name: str = "",
    ):
        self.gw = gateway
        self.db_path = db_path
        self.account_ref = account_ref  # IPLens account record the snapshot belongs to
        # The record's display name, frozen on the snapshot (later renames do not apply).
        self.account_name = account_name

    def run(self) -> CollectResult:
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
        lb_targets = self._collect_lb_targets(result, lbs)
        security_groups = self._optional(
            result,
            "ec2:DescribeSecurityGroups",
            lambda: _paginate(ec2, "describe_security_groups", "SecurityGroups"),
        )
        ecs = self._collect_ecs(result)
        lb_tags = self._collect_lb_tags(result, lbs)
        lambda_tags = self._collect_lambda_tags(result, lambdas)

        lambda_index = lambda_eni_index(lambdas)
        # (resource_type, resource_id, key, value) for every tagged ENI-owning resource.
        tag_rows: list[tuple[str, str, str, str]] = []
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
                owner_names = [attr.owner_ref] if attr.owner_ref else []
                if attr.owner_type == "lambda":
                    shared = lambda_owners(lambda_index, e.get("SubnetId"), groups)
                    if shared:
                        owner_names = shared
                        attr = Attribution("lambda", shared[0])
                conn.execute(
                    "INSERT INTO enis(snapshot_id, eni_id, subnet_id, vpc_id, az, status, "
                    "interface_type, requester_id, requester_managed, description, instance_id, "
                    "security_groups, owner_type, owner_ref, name, owner_names) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
            for row in lb_targets.targets:
                conn.execute(
                    "INSERT OR IGNORE INTO lb_targets(snapshot_id, lb_name, target_group, "
                    "target_type, target_id, port) VALUES(?,?,?,?,?,?)",
                    (snap_id, *row),
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
            conn.executemany(
                "INSERT OR IGNORE INTO resource_tags(snapshot_id, resource_type, resource_id, "
                "key, value) VALUES(?,?,?,?,?)",
                [(snap_id, *row) for row in tag_rows],
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
        data = EcsData()
        try:
            ecs = self.gw.client("ecs")
            for cluster_arn in _paginate(ecs, "list_clusters", "clusterArns"):
                cluster = _arn_name(cluster_arn)
                svc_arns = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
                for batch in _chunks(svc_arns, _ECS_SERVICE_BATCH):
                    resp = ecs.describe_services(
                        cluster=cluster_arn, services=batch, include=["TAGS"]
                    )
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
