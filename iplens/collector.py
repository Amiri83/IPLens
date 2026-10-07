"""Read-only collection of VPC/subnet/ENI data into an SQLite snapshot."""

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

from .attribution import attribute_eni
from .aws import AwsGateway
from .db import closing

log = logging.getLogger(__name__)


@dataclass
class CollectResult:
    snapshot_id: int
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


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
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
            snap_id, result.vpcs, result.subnets, result.enis, result.ips, len(result.warnings),
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

        vpcs = _paginate(ec2, "describe_vpcs", "Vpcs")
        subnets = _paginate(ec2, "describe_subnets", "Subnets")
        enis = _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces")
        endpoints = self._optional(
            result, "ec2:DescribeVpcEndpoints",
            lambda: _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"),
        )
        lambdas = self._optional(
            result, "lambda:ListFunctions",
            lambda: _paginate(self.gw.client("lambda"), "list_functions", "Functions"),
        )
        lbs = self._optional(
            result, "elasticloadbalancing:DescribeLoadBalancers",
            lambda: _paginate(
                self.gw.client("elbv2"), "describe_load_balancers", "LoadBalancers"
            ),
        )

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
                    (snap_id, v["VpcId"], _name_tag(v.get("Tags")), json.dumps(cidrs),
                     int(bool(v.get("IsDefault")))),
                )
            for s in subnets:
                conn.execute(
                    "INSERT INTO subnets(snapshot_id, subnet_id, vpc_id, name, cidr, az, "
                    "available_ip_count) VALUES(?,?,?,?,?,?,?)",
                    (snap_id, s["SubnetId"], s["VpcId"], _name_tag(s.get("Tags")),
                     s["CidrBlock"], s.get("AvailabilityZone"), s.get("AvailableIpAddressCount")),
                )
            ip_count = 0
            for e in enis:
                attr = attribute_eni(e)
                groups = [g["GroupId"] for g in e.get("Groups", [])]
                conn.execute(
                    "INSERT INTO enis(snapshot_id, eni_id, subnet_id, vpc_id, az, status, "
                    "interface_type, requester_id, requester_managed, description, instance_id, "
                    "security_groups, owner_type, owner_ref, name) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (snap_id, e["NetworkInterfaceId"], e.get("SubnetId"), e.get("VpcId"),
                     e.get("AvailabilityZone"), e.get("Status"), e.get("InterfaceType"),
                     e.get("RequesterId"), int(bool(e.get("RequesterManaged"))),
                     e.get("Description") or "", (e.get("Attachment") or {}).get("InstanceId"),
                     json.dumps(sorted(groups)), attr.owner_type, attr.owner_ref,
                     _name_tag(e.get("TagSet"))),
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
                        (snap_id, ip, int(ipaddress.IPv4Address(ip)), e["NetworkInterfaceId"],
                         e.get("SubnetId"), e.get("VpcId"), int(bool(p.get("Primary"))),
                         (p.get("Association") or {}).get("PublicIp"), attr.owner_type),
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
                            (snap_id, str(addr), int(addr), e["NetworkInterfaceId"],
                             e.get("SubnetId"), e.get("VpcId"), attr.owner_type),
                        )
                        ip_count += 1
            for ep in endpoints:
                conn.execute(
                    "INSERT INTO endpoints(snapshot_id, endpoint_id, vpc_id, service_name, "
                    "endpoint_type, subnet_ids, eni_ids) VALUES(?,?,?,?,?,?,?)",
                    (snap_id, ep["VpcEndpointId"], ep.get("VpcId"), ep.get("ServiceName"),
                     ep.get("VpcEndpointType"), json.dumps(ep.get("SubnetIds", [])),
                     json.dumps(ep.get("NetworkInterfaceIds", []))),
                )
            subnet_vpc = {s["SubnetId"]: s["VpcId"] for s in subnets}
            for fn in lambdas:
                vpc_cfg = fn.get("VpcConfig") or {}
                # Prefer the VPC of the function's subnets from this same snapshot so the
                # row is consistent with subnets/enis; fall back to the reported VpcId.
                vpc_id = next(
                    (subnet_vpc[s] for s in vpc_cfg.get("SubnetIds", []) if s in subnet_vpc), None
                ) or vpc_cfg.get("VpcId") or None
                conn.execute(
                    "INSERT INTO lambdas(snapshot_id, name, vpc_id, subnet_ids, security_groups) "
                    "VALUES(?,?,?,?,?)",
                    (snap_id, fn["FunctionName"], vpc_id,
                     json.dumps(sorted(vpc_cfg.get("SubnetIds", []))),
                     json.dumps(sorted(vpc_cfg.get("SecurityGroupIds", [])))),
                )
            for lb in lbs:
                conn.execute(
                    "INSERT INTO load_balancers(snapshot_id, name, lb_type, scheme, vpc_id) "
                    "VALUES(?,?,?,?,?)",
                    (snap_id, lb["LoadBalancerName"], lb.get("Type"), lb.get("Scheme"),
                     lb.get("VpcId")),
                )
            conn.execute(
                "UPDATE snapshots SET status='ok', account_id=?, warnings=? WHERE id=?",
                (account_id, json.dumps(result.warnings), snap_id),
            )

        result.vpcs, result.subnets, result.enis, result.ips = (
            len(vpcs), len(subnets), len(enis), ip_count,
        )
        return result

    @staticmethod
    def _optional(result: CollectResult, what: str, fn: Any) -> list[dict[str, Any]]:
        """Optional enrichment calls: missing permissions downgrade to a warning."""
        try:
            return fn()
        except (BotoCoreError, ClientError) as exc:
            code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else ""
            msg = f"{what} skipped ({code or type(exc).__name__})"
            log.warning(msg)
            result.warnings.append(msg)
            return []
