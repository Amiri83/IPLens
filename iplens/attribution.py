"""Attribute an ENI (and therefore its private IPs) to an owning service.

Signals, in priority order:
1. ``InterfaceType`` (authoritative for NAT, endpoints, Lambda, NLB/GWLB, ...)
2. ``RequesterId`` for AWS-managed interfaces (``amazon-elb``, ``amazon-rds``, ...)
3. ``Description`` conventions used by AWS services
4. An EC2 instance attachment
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

OWNER_TYPES = ("ec2", "lambda", "vpc_endpoint", "elb", "nat", "rds", "other")

OWNER_LABELS = {
    "ec2": "EC2",
    "lambda": "Lambda",
    "vpc_endpoint": "VPC endpoint",
    "elb": "Load balancer",
    "nat": "NAT gateway",
    "rds": "RDS",
    "other": "Other",
}

_INTERFACE_TYPE_MAP = {
    "nat_gateway": "nat",
    "vpc_endpoint": "vpc_endpoint",
    "gateway_load_balancer_endpoint": "vpc_endpoint",
    "lambda": "lambda",
    "network_load_balancer": "elb",
    "gateway_load_balancer": "elb",
    "load_balancer": "elb",
    "efa": "ec2",
    "efa-only": "ec2",
    "trunk": "ec2",
    "branch": "ec2",
}

_REQUESTER_MAP = {
    "amazon-elb": "elb",
    "amazon-rds": "rds",
}

_DESC_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^AWS Lambda VPC ENI-(?P<ref>.+?)(?:-[0-9a-f]{8}-[0-9a-f-]{27})?$"), "lambda"),
    (re.compile(r"^ELB (?:app|net|gwy)/(?P<ref>[^/]+)/"), "elb"),
    (re.compile(r"^ELB (?P<ref>\S+)$"), "elb"),
    (re.compile(r"^Interface for NAT Gateway (?P<ref>nat-[0-9a-f]+)"), "nat"),
    (re.compile(r"^VPC Endpoint Interface (?P<ref>vpce-[0-9a-f]+)"), "vpc_endpoint"),
    (re.compile(r"^RDSNetworkInterface"), "rds"),
]

_OTHER_DESC_HINTS = (
    ("Amazon EKS", "EKS"),
    ("EFS mount target", "EFS"),
    ("Network Interface for Transit Gateway", "Transit Gateway"),
    ("AWS created network interface for directory", "Directory Service"),
    ("ElastiCache", "ElastiCache"),
    ("Route 53 Resolver", "Route 53 Resolver"),
)


@dataclass(frozen=True)
class Attribution:
    owner_type: str
    owner_ref: str


def attribute_eni(eni: dict[str, Any]) -> Attribution:
    """Classify a raw ``describe_network_interfaces`` item."""
    itype = (eni.get("InterfaceType") or "").lower()
    requester = (eni.get("RequesterId") or "").lower()
    desc = eni.get("Description") or ""
    attachment = eni.get("Attachment") or {}
    instance_id = attachment.get("InstanceId") or ""

    desc_owner, desc_ref = _from_description(desc)

    owner = _INTERFACE_TYPE_MAP.get(itype)
    if owner:
        return Attribution(owner, desc_ref if desc_owner == owner else (instance_id or desc_ref))

    owner = _REQUESTER_MAP.get(requester)
    if owner:
        return Attribution(owner, desc_ref if desc_owner == owner else "")
    if requester.endswith(":awslambda") or "awslambda" in requester:
        return Attribution("lambda", desc_ref if desc_owner == "lambda" else "")

    if desc_owner:
        return Attribution(desc_owner, desc_ref)

    if instance_id and not eni.get("RequesterManaged"):
        return Attribution("ec2", instance_id)

    for hint, label in _OTHER_DESC_HINTS:
        if hint in desc:
            return Attribution("other", label)
    if instance_id:
        return Attribution("ec2", instance_id)
    return Attribution("other", itype if itype not in ("", "interface") else "")


def _from_description(desc: str) -> tuple[str, str]:
    for pattern, owner in _DESC_PATTERNS:
        m = pattern.match(desc)
        if m:
            return owner, (m.groupdict().get("ref") or "")
    return "", ""
