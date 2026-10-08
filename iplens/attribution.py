"""Attribute an ENI (and therefore its private IPs) to an owning service.

Signals, in priority order:
1. ``InterfaceType`` (authoritative for NAT, endpoints, Lambda, NLB/GWLB, ...)
2. ``RequesterId`` for AWS-managed interfaces (``amazon-elb``, ``amazon-rds``, ...)
3. ``Description`` conventions used by AWS services
4. An EC2 instance attachment

ECS task ENIs are only recognised heuristically here (their description is the
ECS attachment ARN); the collector's ECS enrichment step resolves them to a
cluster/service authoritatively when permissions allow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

OWNER_TYPES = (
    "ec2",
    "lambda",
    "ecs",
    "vpc_endpoint",
    "elb",
    "nat",
    "rds",
    "elasticache",
    "opensearch",
    "other",
)

OWNER_LABELS = {
    "ec2": "EC2",
    "lambda": "Lambda",
    "ecs": "ECS task",
    "vpc_endpoint": "VPC endpoint",
    "elb": "ALB/NLB",
    "nat": "NAT gateway",
    "rds": "RDS",
    "elasticache": "ElastiCache",
    "opensearch": "OpenSearch",
    "other": "ENI/other",
}

# Keys are lower-cased InterfaceType values. AWS has used both NAT spellings
# (``nat_gateway`` and ``natGateway``), so both map to "nat".
_INTERFACE_TYPE_MAP = {
    "nat_gateway": "nat",
    "natgateway": "nat",
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
    "amazon-elasticache": "elasticache",
    "amazon-elasticsearch": "opensearch",
    "amazon-opensearch": "opensearch",
}

_DESC_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^AWS Lambda VPC ENI-(?P<ref>.+?)(?:-[0-9a-f]{8}-[0-9a-f-]{27})?$"), "lambda"),
    (re.compile(r"^ELB (?:app|net|gwy)/(?P<ref>[^/]+)/"), "elb"),
    (re.compile(r"^ELB (?P<ref>\S+)$"), "elb"),
    (re.compile(r"^Interface for NAT Gateway (?P<ref>nat-[0-9a-f]+)"), "nat"),
    (re.compile(r"^VPC Endpoint Interface (?P<ref>vpce-[0-9a-f]+)"), "vpc_endpoint"),
    (re.compile(r"^RDSNetworkInterface"), "rds"),
    # Fargate / awsvpc task ENIs: "arn:aws:ecs:<region>:<account>:attachment/<uuid>"
    (re.compile(r"^arn:aws[\w-]*:ecs:[^:]*:[^:]*:attachment/(?P<ref>[0-9a-f-]+)"), "ecs"),
    (re.compile(r"^ElastiCache (?:Serverless )?(?P<ref>\S+)"), "elasticache"),
    (re.compile(r"^(?:ES|OpenSearch(?: Service)?) (?P<ref>\S+)$"), "opensearch"),
]

_OTHER_DESC_HINTS = (
    ("Amazon EKS", "EKS"),
    ("EFS mount target", "EFS"),
    ("Network Interface for Transit Gateway", "Transit Gateway"),
    ("AWS created network interface for directory", "Directory Service"),
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
    if owner == "ec2" and desc_owner == "ecs":
        # ENI trunking: awsvpc tasks on EC2 get "branch" ENIs described as ECS attachments.
        return Attribution("ecs", desc_ref)
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


LambdaKey = tuple[str, frozenset[str]]


def lambda_eni_index(functions: list[dict[str, Any]]) -> dict[LambdaKey, list[str]]:
    """``(subnet id, security group set) -> sorted function names`` from ListFunctions.

    Lambda creates one Hyperplane ENI per unique subnet + security-group combination
    and shares it between every function with that combination, so an ENI belongs to
    all functions whose VpcConfig uses its subnet and exactly its security groups.
    """
    index: dict[LambdaKey, set[str]] = {}
    for fn in functions:
        cfg = fn.get("VpcConfig") or {}
        sgs = frozenset(cfg.get("SecurityGroupIds") or [])
        for subnet_id in cfg.get("SubnetIds") or []:
            index.setdefault((subnet_id, sgs), set()).add(fn["FunctionName"])
    return {key: sorted(names) for key, names in index.items()}


def lambda_owners(
    index: dict[LambdaKey, list[str]], subnet_id: str | None, security_groups: list[str]
) -> list[str]:
    """Every function sharing a Lambda ENI in ``subnet_id`` with ``security_groups``."""
    return list(index.get((subnet_id or "", frozenset(security_groups)), []))


def _from_description(desc: str) -> tuple[str, str]:
    for pattern, owner in _DESC_PATTERNS:
        m = pattern.match(desc)
        if m:
            return owner, (m.groupdict().get("ref") or "")
    return "", ""
