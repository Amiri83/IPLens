"""AWS-first ownership of a resource: who / what manages it.

Sources, first match wins:

1. **CloudFormation**: the resource is a physical resource of a stack
   (``cloudformation:ListStackResources``; the ``aws:cloudformation:stack-name`` tag
   AWS adds to stack resources is the fallback when ListStacks is not permitted).
2. **IaC tag**: the configured project / repo tag key (Settings → Ownership).
3. **Terraform**: a loaded / synced Terraform root manages it, only when the optional
   Terraform enrichment is enabled (off by default).
4. **CloudTrail**: the principal of the resource's ``Create*`` / ``RunInstances`` event
   (opt-in, ``cloudtrail:LookupEvents``; CloudTrail only looks back 90 days). A role or
   user matching a CI role name pattern means "IaC (unknown repo)", anyone else "manual".
5. **unmanaged**.

Only identifiers are stored by the collector: resource ids, stack names, the creating
role / user *name* (never its ARN, account id or session name) and tag values of the
ownership tag keys (every other tag key is kept without its value).
"""

from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import terraform

# -- configuration --------------------------------------------------------------------

DEFAULT_PROJECT_KEY = "Project"
DEFAULT_ENV_KEY = "Environment"
DEFAULT_TEAM_KEY = "Team"
DEFAULT_OWNER_KEY = "Owner"
DEFAULT_CI_PATTERNS = (
    "*github*",
    "*gitlab*",
    "*jenkins*",
    "*atlantis*",
    "*terraform*",
    "*codebuild*",
    "*codepipeline*",
    "*deploy*",
    "ci-*",
    "*-ci",
    "*-ci-*",
)
MAX_CI_PATTERNS = 20
MAX_PATTERN = 128
MAX_TAG_KEY = 128
# Unowned resources looked up in CloudTrail per Refresh (LookupEvents allows 2 calls/s).
MAX_CLOUDTRAIL_LOOKUPS = 50
CLOUDTRAIL_DAYS = 90
# CloudFormation's own tags; only the stack name is used, nothing else is kept.
CFN_STACK_TAG = "aws:cloudformation:stack-name"

# Ownership fields configurable in Settings: name -> label.
TAG_FIELDS = {
    "project": "IaC project / repo",
    "env": "Environment",
    "team": "Team",
    "owner": "Owner",
}


def parse_patterns(text: str | Iterable[str] | None) -> tuple[str, ...]:
    """CI role name patterns from a comma / whitespace / newline separated string."""
    if text is None:
        return DEFAULT_CI_PATTERNS
    parts = re.split(r"[,\s]+", text) if isinstance(text, str) else list(text)
    out: list[str] = []
    for p in parts:
        p = str(p).strip()[:MAX_PATTERN]
        if p and p.lower() not in out:
            out.append(p.lower())
    return tuple(out[:MAX_CI_PATTERNS])


def clean_tag_key(value: str | None) -> str:
    """A configured tag key ('' = not used). ``aws:`` keys are reserved by AWS."""
    key = (value or "").strip()[:MAX_TAG_KEY]
    return "" if key.lower().startswith("aws:") else key


@dataclass(frozen=True)
class OwnershipConfig:
    project_key: str = DEFAULT_PROJECT_KEY
    env_key: str = DEFAULT_ENV_KEY
    team_key: str = DEFAULT_TEAM_KEY
    owner_key: str = DEFAULT_OWNER_KEY
    ci_patterns: tuple[str, ...] = DEFAULT_CI_PATTERNS
    tf_enabled: bool = False  # optional Terraform state enrichment
    cloudtrail: bool = False  # optional CloudTrail creator lookup
    # Further keys whose values are kept (the environment tag keys of Settings).
    extra_value_keys: tuple[str, ...] = ()

    def key(self, name: str) -> str:
        return {
            "project": self.project_key,
            "env": self.env_key,
            "team": self.team_key,
            "owner": self.owner_key,
        }.get(name, "")

    def value_keys(self) -> frozenset[str]:
        """Lower-cased tag keys whose *values* the collector keeps."""
        keys = (self.project_key, self.env_key, self.team_key, self.owner_key)
        return frozenset(k.lower() for k in (*keys, *self.extra_value_keys) if k)

    @property
    def ci_patterns_text(self) -> str:
        return ", ".join(self.ci_patterns)


def tag_value(tags: dict[str, str] | None, key: str) -> str:
    """Value of ``key`` in ``tags`` (case-insensitive key match), '' when absent."""
    if not tags or not key:
        return ""
    wanted = key.lower()
    for k, v in tags.items():
        if k.lower() == wanted and (v or "").strip():
            return v.strip()[:256]
    return ""


# -- resource keys: ARNs and CloudFormation physical ids -> (kind, id) -------------------
#
# Kinds are those of :data:`iplens.terraform.MANAGED_TYPES` (vpc, subnet, eni, sg, vpce,
# nat, instance, lb, lambda, ecs_service) so that one key matches the snapshot, the tag
# index, CloudFormation and Terraform; other resources get "<service>:<type>".

ResourceKey = tuple[str, str]

_EC2_TYPES = {
    "vpc": "vpc",
    "subnet": "subnet",
    "network-interface": "eni",
    "security-group": "sg",
    "vpc-endpoint": "vpce",
    "natgateway": "nat",
    "instance": "instance",
}

_CFN_TYPES = {
    "AWS::EC2::VPC": "vpc",
    "AWS::EC2::Subnet": "subnet",
    "AWS::EC2::NetworkInterface": "eni",
    "AWS::EC2::SecurityGroup": "sg",
    "AWS::EC2::VPCEndpoint": "vpce",
    "AWS::EC2::NatGateway": "nat",
    "AWS::EC2::Instance": "instance",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "lb",
    "AWS::ElasticLoadBalancing::LoadBalancer": "lb",
    "AWS::Lambda::Function": "lambda",
    "AWS::ECS::Service": "ecs_service",
}

KIND_LABELS = {
    **terraform.KIND_LABELS,
    "rds:db": "RDS instance",
    "s3:bucket": "S3 bucket",
}


def arn_key(arn: str) -> ResourceKey | None:
    """``(kind, id)`` of a resource ARN from tag:GetResources, None if not parseable."""
    parts = (arn or "").split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    service, resource = parts[2], parts[5]
    if service == "ec2":
        rtype, _, rid = resource.partition("/")
        kind = _EC2_TYPES.get(rtype)
        return (kind, rid) if kind and rid else (f"ec2:{rtype}", rid) if rid else None
    if service == "elasticloadbalancing":
        if resource.startswith("loadbalancer/"):
            # loadbalancer/app/<name>/<hash> (ALB / NLB) or loadbalancer/<name> (classic)
            bits = resource.split("/")
            name = bits[2] if len(bits) >= 4 else bits[-1]
            return ("lb", name) if name else None
        rtype = resource.split("/", 1)[0]
        return (f"elasticloadbalancing:{rtype}", resource.split("/")[1] if "/" in resource else "")
    if service == "lambda" and resource.startswith("function:"):
        return ("lambda", resource.split(":")[1])
    if service == "ecs" and resource.startswith("service/"):
        rid = terraform._ecs_service(arn)
        return ("ecs_service", rid) if rid else None
    if service == "s3":
        return ("s3:bucket", resource)
    sep = "/" if "/" in resource else ":"
    rtype, _, rid = resource.partition(sep)
    if not rid:
        return (service, rtype) if rtype else None
    return (f"{service}:{rtype}", rid)


def cfn_key(resource_type: str, physical_id: str) -> ResourceKey | None:
    """``(kind, id)`` of a CloudFormation stack resource, None without a physical id."""
    if not physical_id:
        return None
    kind = _CFN_TYPES.get(resource_type)
    if kind == "lb":
        return ("lb", terraform._lb_name(physical_id))
    if kind == "lambda":
        return ("lambda", terraform._lambda_name(physical_id))
    if kind == "ecs_service":
        rid = terraform._ecs_service(physical_id)
        return ("ecs_service", rid) if rid else None
    if kind:
        return (kind, physical_id)
    if physical_id.startswith("arn:"):
        return arn_key(physical_id)
    service = resource_type.removeprefix("AWS::").split("::")
    return (":".join(s.lower() for s in service), physical_id)


# Snapshot resource_tags types -> kinds.
TAG_TYPE_KINDS = {
    "vpc": "vpc",
    "subnet": "subnet",
    "eni": "eni",
    "sg": "sg",
    "endpoint": "vpce",
    "lb": "lb",
    "lambda": "lambda",
    "ecs_service": "ecs_service",
}


# -- CloudTrail creator ---------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    name: str  # role or user name ("root" for the root user); never an ARN
    kind: str  # role | user | root


def principal_from_event(event: dict[str, Any]) -> Principal | None:
    """The creating role / user of a LookupEvents event, None for AWS services.

    Only the role / IAM user name is returned: session names (often e-mail addresses),
    ARNs and account ids are dropped with the parsed event.
    """
    try:
        detail = json.loads(event.get("CloudTrailEvent") or "{}")
    except ValueError:
        return None
    ident = detail.get("userIdentity") if isinstance(detail, dict) else None
    if not isinstance(ident, dict):
        return None
    itype = ident.get("type", "")
    if itype == "AssumedRole":
        issuer = (ident.get("sessionContext") or {}).get("sessionIssuer") or {}
        name = issuer.get("userName") or ""
        if not name and ":assumed-role/" in (ident.get("arn") or ""):
            name = ident["arn"].split(":assumed-role/", 1)[1].split("/", 1)[0]
        return Principal(name[:128], "role") if name else None
    if itype == "IAMUser":
        name = ident.get("userName") or ""
        return Principal(name[:128], "user") if name else None
    if itype == "Root":
        return Principal("root", "root")
    if itype in ("FederatedUser", "IdentityCenterUser", "WebIdentityUser", "SAMLUser"):
        return Principal("federated user", "user")
    return None  # AWSService, AWSAccount, unknown


def is_create_event(name: str) -> bool:
    return name.startswith("Create") or name == "RunInstances"


def is_ci(principal_name: str, patterns: Sequence[str]) -> bool:
    name = principal_name.lower()
    return any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns)


# -- resolution -----------------------------------------------------------------------

SOURCES = ("cloudformation", "iac_tag", "terraform", "cloudtrail_ci", "cloudtrail_human", "")
SOURCE_LABELS = {
    "cloudformation": "CloudFormation",
    "iac_tag": "IaC tag",
    "terraform": "Terraform",
    "cloudtrail_ci": "CloudTrail (CI)",
    "cloudtrail_human": "CloudTrail (manual)",
    "": "unmanaged",
}
UNMANAGED = ""
# IP list filter value for "unmanaged".
FILTER_UNMANAGED = "unmanaged"
CI_VALUE = "IaC (unknown repo)"
HUMAN_VALUE = "manual"


@dataclass(frozen=True)
class Owner:
    source: str = UNMANAGED
    value: str = ""  # stack / project tag value / Terraform root / CI or "manual"
    detail: str = ""  # CloudTrail: the creating role / user name

    @property
    def label(self) -> str:
        return SOURCE_LABELS.get(self.source, self.source)

    @property
    def text(self) -> str:
        """``"CloudFormation: stack-a"`` / ``"unmanaged"``."""
        return f"{self.label}: {self.value}" if self.value else self.label

    def as_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "label": self.label,
            "value": self.value,
            "detail": self.detail,
            "text": self.text,
        }


@dataclass
class OwnershipIndex:
    """Ownership inputs of one snapshot (see :func:`load_index`)."""

    config: OwnershipConfig = field(default_factory=OwnershipConfig)
    cfn: dict[ResourceKey, str] = field(default_factory=dict)
    tags: dict[ResourceKey, dict[str, str]] = field(default_factory=dict)
    creators: dict[ResourceKey, Principal] = field(default_factory=dict)
    tf: terraform.TfIndex = field(default_factory=dict)
    resources: set[ResourceKey] = field(default_factory=set)  # tag:GetResources inventory

    def tags_of(self, keys: Iterable[ResourceKey], extra: dict[str, str] | None = None) -> dict:
        """Tags of the first key that has any, overridden by ``extra`` (row tags)."""
        out: dict[str, str] = {}
        for key in reversed(list(keys)):  # the most specific key wins
            out.update(self.tags.get(key, {}))
        out.update(extra or {})
        return out

    def resolve(self, keys: Sequence[ResourceKey], tags: dict[str, str] | None = None) -> Owner:
        """Owner of a resource known by ``keys`` (most specific first), first match wins."""
        for key in keys:
            stack = self.cfn.get(key)
            if stack:
                return Owner("cloudformation", stack)
        all_tags = self.tags_of(keys, tags)
        project = tag_value(all_tags, self.config.project_key)
        if project:
            return Owner("iac_tag", project)
        if self.config.tf_enabled and self.tf:
            for m in terraform.ownership(self.tf, keys):
                return Owner("terraform", m["root"], m["address"])
        for key in keys:
            p = self.creators.get(key)
            if p:
                if is_ci(p.name, self.config.ci_patterns):
                    return Owner("cloudtrail_ci", CI_VALUE, p.name)
                return Owner("cloudtrail_human", HUMAN_VALUE, p.name)
        return Owner()

    def labels(self, keys: Sequence[ResourceKey], tags: dict[str, str] | None = None) -> dict:
        """``{"env", "team", "owner", "project"}`` tag values of the configured keys."""
        all_tags = self.tags_of(keys, tags)
        return {name: tag_value(all_tags, self.config.key(name)) for name in TAG_FIELDS}


def load_index(
    conn: sqlite3.Connection,
    snap_id: int,
    config: OwnershipConfig | None = None,
    tf_index: terraform.TfIndex | None = None,
) -> OwnershipIndex:
    """Ownership inputs of a snapshot. The Terraform index (``tf_index`` when the caller
    already has it) is only used when the Terraform enrichment is enabled."""
    config = config or OwnershipConfig()
    idx = OwnershipIndex(config=config)
    for r in conn.execute(
        "SELECT kind, resource_id, cfn_stack, creator, creator_kind FROM own_resources "
        "WHERE snapshot_id=?",
        (snap_id,),
    ):
        key = (r["kind"], r["resource_id"])
        idx.resources.add(key)
        if r["cfn_stack"]:
            idx.cfn[key] = r["cfn_stack"]
        if r["creator"]:
            idx.creators[key] = Principal(r["creator"], r["creator_kind"])
    for r in conn.execute(
        "SELECT kind, resource_id, key, value FROM own_tags WHERE snapshot_id=?", (snap_id,)
    ):
        idx.tags.setdefault((r["kind"], r["resource_id"]), {})[r["key"]] = r["value"]
    # Tags of the snapshot's own resources (ENI owners, VPCs, subnets, SGs) as well.
    for r in conn.execute(
        "SELECT resource_type, resource_id, key, value FROM resource_tags WHERE snapshot_id=?",
        (snap_id,),
    ):
        kind = TAG_TYPE_KINDS.get(r["resource_type"])
        if kind:
            idx.tags.setdefault((kind, r["resource_id"]), {}).setdefault(r["key"], r["value"])
    if config.tf_enabled:
        idx.tf = terraform.load_index(conn) if tf_index is None else tf_index
    return idx


def tag_keys_seen(conn: sqlite3.Connection, snap_id: int | None) -> list[str]:
    """Every tag key of a snapshot (tag:GetResources and the collected resources), for the
    Settings dropdowns. ``aws:`` keys and ``Name`` are left out."""
    if snap_id is None:
        return []
    rows = conn.execute(
        "SELECT key FROM own_tags WHERE snapshot_id=? UNION "
        "SELECT key FROM resource_tags WHERE snapshot_id=?",
        (snap_id, snap_id),
    )
    keys = {r["key"] for r in rows if not r["key"].lower().startswith("aws:")}
    keys.discard("Name")
    return sorted(keys, key=str.lower)


# -- Ownership page -------------------------------------------------------------------

_INVENTORY_SQL = (
    ("vpc", "SELECT vpc_id AS id FROM vpcs WHERE snapshot_id=? AND is_default=0"),
    (
        "subnet",
        "SELECT s.subnet_id AS id FROM subnets s JOIN vpcs v ON v.snapshot_id = s.snapshot_id "
        "AND v.vpc_id = s.vpc_id WHERE s.snapshot_id=? AND v.is_default=0",
    ),
    (
        "sg",
        "SELECT group_id AS id FROM security_groups WHERE snapshot_id=? "
        "AND group_name != 'default'",
    ),
    ("lb", "SELECT name AS id FROM load_balancers WHERE snapshot_id=?"),
    ("lambda", "SELECT name AS id FROM lambdas WHERE snapshot_id=?"),
    ("vpce", "SELECT endpoint_id AS id FROM endpoints WHERE snapshot_id=?"),
    ("ecs_service", "SELECT cluster || '/' || service AS id FROM ecs_services WHERE snapshot_id=?"),
    (
        "instance",
        "SELECT DISTINCT instance_id AS id FROM enis WHERE snapshot_id=? "
        "AND COALESCE(instance_id, '') LIKE 'i-%'",
    ),
    (
        "nat",
        "SELECT DISTINCT owner_ref AS id FROM enis WHERE snapshot_id=? AND owner_type='nat' "
        "AND COALESCE(owner_ref, '') != ''",
    ),
    (
        # Stand-alone interfaces: not requester-managed and not part of another resource.
        "eni",
        "SELECT eni_id AS id FROM enis WHERE snapshot_id=? AND requester_managed=0 "
        "AND owner_type='other'",
    ),
)


def inventory(conn: sqlite3.Connection, snap_id: int) -> set[ResourceKey]:
    """Resources of a snapshot: the collected ones plus every tag:GetResources resource."""
    keys: set[ResourceKey] = set()
    for kind, sql in _INVENTORY_SQL:
        keys.update((kind, r["id"]) for r in conn.execute(sql, (snap_id,)) if r["id"])
    keys.update(
        (r["kind"], r["resource_id"])
        for r in conn.execute(
            "SELECT kind, resource_id FROM own_resources WHERE snapshot_id=?", (snap_id,)
        )
    )
    return keys


def kind_label(kind: str) -> str:
    return KIND_LABELS.get(kind, kind)


@dataclass
class OwnershipReport:
    counts: list[dict[str, Any]]  # [{"source", "label", "count"}] in precedence order
    total: int
    unmanaged: list[dict[str, str]]
    tag_gaps: list[dict[str, Any]]
    gap_keys: list[str]  # the configured keys checked for gaps


def report(conn: sqlite3.Connection, snap_id: int, config: OwnershipConfig) -> OwnershipReport:
    idx = load_index(conn, snap_id, config)
    counts = dict.fromkeys(SOURCES, 0)
    unmanaged: list[dict[str, str]] = []
    gaps: list[dict[str, Any]] = []
    gap_keys = [k for k in (config.env_key, config.project_key) if k]
    resources = sorted(inventory(conn, snap_id), key=lambda k: (kind_label(k[0]).lower(), k[1]))
    for key in resources:
        owner = idx.resolve([key])
        counts[owner.source] += 1
        row = {"kind": key[0], "label": kind_label(key[0]), "resource_id": key[1]}
        if owner.source == UNMANAGED:
            unmanaged.append(row)
        tags = idx.tags.get(key, {})
        missing = [k for k in gap_keys if not tag_value(tags, k)]
        if missing:
            gaps.append({**row, "missing": missing, "owner": owner.text})
    return OwnershipReport(
        counts=[{"source": s, "label": SOURCE_LABELS[s], "count": counts[s]} for s in SOURCES],
        total=len(resources),
        unmanaged=unmanaged,
        tag_gaps=gaps,
        gap_keys=gap_keys,
    )


def matches(owner: dict[str, str], wanted: str) -> bool:
    """IP list filter: ``wanted`` is a source, or :data:`FILTER_UNMANAGED`."""
    if not wanted:
        return True
    if wanted == FILTER_UNMANAGED:
        return owner["source"] == UNMANAGED
    return owner["source"] == wanted
