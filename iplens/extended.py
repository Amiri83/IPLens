"""Extended view crawl: regional services and the evidence that links them.

The crawl is opt-in ("Crawl services" on the Visual page's Extended view) and is
attached to the account's latest snapshot. Every source is optional: a missing
permission, a disabled feature (AWS Config recorder, Resource Explorer index, no
X-Ray traces) or an unsupported API records a warning and the crawl continues.
All AWS calls go through :class:`iplens.aws.AwsGateway` and so are read-only.

Every link is an *evidence line* with one of four levels, strongest first:

- ``observed``: traffic was seen (VPC flow logs, X-Ray service graph)
- ``configured``: a resource's configuration wires the two together (SNS
  subscription, event source mapping, EventBridge target, route table, ...)
- ``permitted``: an IAM policy of a Lambda / ECS role allows actions on the resource
- ``referenced``: an environment variable names the resource

Secrets stay secret: environment variable values, IAM policy documents, Step
Functions definitions and secret values are inspected in memory only and matched
against the ARNs / names of resources found by the crawl (:class:`Catalog`). Only the
match is stored ("env var QUEUE_URL of fn-a names queue-a"), never the value. A
statement allowing ``Resource: "*"`` is counted as *broad access* on its holder and
never expanded into edges. Secrets Manager is read for secret *names* only, and the
read-only guard refuses ``GetSecretValue`` outright.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import ClientError

from . import access
from .aws import AwsGateway, ReadOnlyViolation
from .db import closing
from .jobs import NullProgress, Progress

log = logging.getLogger(__name__)

EVIDENCE_LEVELS = ("observed", "configured", "permitted", "referenced")  # strongest first
EVIDENCE_LABELS = {
    "observed": "Observed",
    "configured": "Configured",
    "permitted": "Permitted (IAM)",
    "referenced": "Referenced (env var)",
}
EVIDENCE_HELP = {
    "observed": "traffic seen in VPC flow logs or the X-Ray service graph",
    "configured": "a resource's configuration wires them together",
    "permitted": "an IAM policy of the role allows actions on the resource",
    "referenced": "an environment variable names the resource",
}
EVIDENCE_RANK = {level: i for i, level in enumerate(EVIDENCE_LEVELS)}

SERVICE_LABELS = {
    "lambda": "Lambda function",
    "ecs": "ECS service",
    "sns": "SNS topic",
    "sqs": "SQS queue",
    "dynamodb": "DynamoDB table",
    "events": "EventBridge rule",
    "s3": "S3 bucket",
    "apigateway": "API Gateway",
    "states": "Step Functions",
    "secretsmanager": "Secret (name only)",
    "kinesis": "Kinesis stream",
    "kafka": "Kafka (MSK / self-managed)",
    "tgw": "Transit Gateway",
    "tgw-attachment": "TGW attachment",
    "pcx": "VPC peering",
    "internet": "Internet",
    "route53": "Route 53 private zone",
    "resolver": "Resolver rule",
    "other": "Other resource",
}
EXTERNAL_SERVICES = frozenset({"tgw", "tgw-attachment", "pcx", "internet"})

# Upper bounds on per-item calls, so one huge account cannot stall the crawl.
MAX_PER_SOURCE = 300
MAX_CONFIG_ITEMS = 100
MAX_REX_RESOURCES = 2000
# Ends every snapshot-level "a source hit its cap" warning (see ExtendedCrawler._cap).
CAPPED_SUFFIX = " of more"
# A pattern matching more resources than this counts as broad access, like "*".
MAX_PATTERN_MATCHES = 25
# Names shorter than this are never matched as references (too many false hits).
MIN_NAME_MATCH = 3
XRAY_WINDOW = timedelta(hours=1)

ARN_RE = re.compile(r"^arn:aws[\w-]*:[\w-]+:[\w-]*:\d*:.+$")
LAMBDA_URI_RE = re.compile(r"functions/(arn:aws[\w-]*:lambda:[^/]+)/invocations")
FN_PREFIX = "function:"


def node_id(service: str, name: str) -> str:
    return f"{service}:{name}"


def arn_parts(arn: str) -> tuple[str, str]:
    """``(service, resource)`` of an ARN (``("", "")`` if not an ARN)."""
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return "", ""
    return parts[2], parts[5]


def _last(text: str, seps: str = "/:") -> str:
    for sep in seps:
        text = text.rsplit(sep, 1)[-1]
    return text


def node_for_arn(arn: str) -> tuple[str, str] | None:
    """``(service, name)`` of a resource ARN for services the Extended view draws."""
    service, res = arn_parts(arn)
    if not service:
        return None
    if service == "lambda" and res.startswith(FN_PREFIX):
        return "lambda", res[len(FN_PREFIX) :].split(":", 1)[0]
    if service in ("sqs", "sns"):
        return service, res
    if service == "dynamodb" and res.startswith("table/"):
        return "dynamodb", res.split("/", 2)[1]
    if service == "s3" and res and "/" not in res:
        return "s3", res
    if service == "kinesis" and res.startswith("stream/"):
        return "kinesis", res.split("/", 2)[1]
    if service == "kafka" and res.startswith("cluster/"):
        return "kafka", res.split("/", 2)[1]  # cluster/<name>/<uuid>
    if service == "states" and res.startswith("stateMachine:"):
        return "states", res.split(":", 2)[1]
    if service == "secretsmanager" and res.startswith("secret:"):
        return "secretsmanager", res[len("secret:") :]
    if service == "events" and res.startswith("rule/"):
        return "events", res[len("rule/") :]
    if service == "ecs" and res.startswith("service/"):
        return "ecs", res[len("service/") :]
    return None


def kafka_bootstrap_host(mapping: dict[str, Any]) -> str:
    """First bootstrap host (port dropped) of a self-managed Kafka event source mapping."""
    endpoints = (mapping.get("SelfManagedEventSource") or {}).get("Endpoints") or {}
    for server in endpoints.get("KAFKA_BOOTSTRAP_SERVERS") or []:
        host, sep, port = str(server).strip().rpartition(":")
        host = host if sep and port.isdigit() else str(server).strip()
        if host and len(host) <= 253:
            return host
    return ""


@dataclass
class NodeRec:
    node_id: str
    service: str
    name: str
    arn: str = ""
    area: str = "regional"
    broad_access: int = 0


@dataclass
class Catalog:
    """ARNs, URLs and names of crawled resources -> node id, for reference matching.

    Values are matched, never kept: :meth:`match` returns node ids only.
    """

    exact: dict[str, set[str]] = field(default_factory=dict)  # ARN / URL / name -> ids
    arns: dict[str, str] = field(default_factory=dict)  # ARN -> id (prefix + IAM matching)
    pending: dict[str, NodeRec] = field(default_factory=dict)  # lazily drawn (Resource Explorer)

    def add(self, nid: str, *keys: str, arn: str = "") -> None:
        for key in (arn, *keys):
            if key and len(key) >= MIN_NAME_MATCH:
                self.exact.setdefault(key, set()).add(nid)
        if arn:
            self.arns[arn] = nid

    def match(self, value: Any) -> set[str]:
        """Node ids a configuration value names (exact ARN / URL / name, a qualified
        ARN of a known resource, or an ``s3://bucket/...`` URL)."""
        if not isinstance(value, str) or len(value) < MIN_NAME_MATCH or len(value) > 2048:
            return set()
        value = value.strip()
        if value in self.exact:
            return set(self.exact[value])
        if value.startswith("s3://"):
            bucket = value[5:].split("/", 1)[0]
            return set(self.exact.get(bucket, ()))
        if value.startswith("arn:"):
            # A stream / alias / version / partial ARN of a known resource.
            for arn, nid in self.arns.items():
                if value.startswith(arn) and value[len(arn) : len(arn) + 1] in (":", "/"):
                    return {nid}
                if arn.startswith(value) and arn[len(value) : len(value) + 1] == "-":
                    return {nid}  # secret ARN without its random suffix
        return set()

    def match_pattern(self, pattern: str) -> set[str] | None:
        """Node ids an IAM ``Resource`` pattern covers; None if the pattern is broad."""
        if pattern == "*":
            return None
        service, res = arn_parts(pattern)
        if not service or res in ("*", "") or service == "*":
            return None
        out = set()
        for arn, nid in self.arns.items():
            if (
                fnmatchcase(arn, pattern)
                or pattern.startswith(arn + "/")
                or fnmatchcase(arn + "/*", pattern)
            ):
                out.add(nid)
        if len(out) > MAX_PATTERN_MATCHES:
            return None
        return out


@dataclass
class ExtGraph:
    nodes: dict[str, NodeRec] = field(default_factory=dict)
    edges: set[tuple[str, str, str, str, str]] = field(default_factory=set)
    facts: set[tuple[str, str]] = field(default_factory=set)
    catalog: Catalog = field(default_factory=Catalog)

    def node(self, service: str, name: str, arn: str = "", *keys: str, area: str = "") -> str:
        nid = node_id(service, name)
        if nid not in self.nodes:
            area = area or ("external" if service in EXTERNAL_SERVICES else "regional")
            self.nodes[nid] = NodeRec(nid, service, name, arn, area)
        elif arn and not self.nodes[nid].arn:
            self.nodes[nid].arn = arn
        self.catalog.add(nid, name, *keys, arn=arn)
        return nid

    def node_from_arn(self, arn: str) -> str | None:
        """Node id for a known ARN, else a new node when the ARN's service is drawn."""
        hits = self.catalog.match(arn)
        if hits:
            return sorted(hits)[0]
        parsed = node_for_arn(arn)
        return self.node(parsed[0], parsed[1], arn) if parsed else None

    def edge(self, source: str, target: str, evidence: str, label: str, detail: str) -> None:
        if not source or not target or source == target:
            return
        for nid in (source, target):
            if nid not in self.nodes and nid in self.catalog.pending:
                self.nodes[nid] = self.catalog.pending.pop(nid)
        self.edges.add((source, target, evidence, label[:60], detail[:400]))

    def fact(self, subject: str, detail: str) -> None:
        self.facts.add((subject, detail[:400]))


@dataclass
class CrawlResult:
    snapshot_id: int
    nodes: int = 0
    edges: int = 0
    warnings: list[str] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)


def _pages(client: Any, op: str, key: str, limit: int = 0, **kwargs: Any) -> list[Any]:
    out: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
        if limit and len(out) >= limit:
            return out[:limit]
    return out


def _policy_doc(doc: Any) -> dict[str, Any]:
    if isinstance(doc, str):
        try:
            doc = json.loads(unquote(doc))
        except ValueError:
            return {}
    return doc if isinstance(doc, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def walk_strings(doc: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """``(path, value)`` for every string in a JSON document (Step Functions definitions).

    Keys ending in ``.$`` hold JSONPath expressions, not resource names, and are skipped.
    """
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(k, str) and k.endswith(".$"):
                continue
            yield from walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(doc, list):
        for v in doc:
            yield from walk_strings(v, path)
    elif isinstance(doc, str):
        yield path, doc


def state_resources(definition: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """``(state name, string)`` for every string inside each state of a state machine,
    including the states of Parallel branches and Map iterators."""
    for name, state in (definition.get("States") or {}).items():
        if not isinstance(state, dict):
            continue
        for key, value in state.items():
            if key in ("Branches",):
                for branch in _as_list(value):
                    if isinstance(branch, dict):
                        yield from state_resources(branch)
            elif key in ("Iterator", "ItemProcessor") and isinstance(value, dict):
                yield from state_resources(value)
            elif key not in ("Comment", "Next", "Type", "End"):
                for _, s in walk_strings(value):
                    yield str(name), s


def policy_statements(doc: Any) -> Iterator[dict[str, Any]]:
    for st in _as_list(_policy_doc(doc).get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow":
            yield st


def action_services(statement: dict[str, Any]) -> set[str]:
    """IAM service prefixes of a statement's actions ("*" for any)."""
    out = set()
    for action in _as_list(statement.get("Action")):
        if isinstance(action, str):
            out.add("*" if action == "*" else action.split(":", 1)[0].lower())
    return out


class ExtendedCrawler:
    """Crawl regional services into the ``ext_*`` tables of snapshot ``snapshot_id``."""

    def __init__(
        self,
        gateway: AwsGateway,
        db_path: Path,
        snapshot_id: int,
        progress: Progress | None = None,
    ):
        self.gw = gateway
        self.db_path = db_path
        self.snapshot_id = snapshot_id
        # Background job reporting; cancellation is checked between sources.
        self.progress: Progress = progress or NullProgress()
        self.graph = ExtGraph()
        self.result = CrawlResult(snapshot_id)
        # In-memory only, dropped when the crawl ends (env values are never stored).
        self._functions: list[dict[str, Any]] = []
        self._role_holders: dict[str, set[str]] = {}  # role ARN -> holder node ids
        self._task_defs: dict[str, set[str]] = {}  # task definition ARN -> ECS service ids
        self._vpcs: set[str] = set()
        self._nat_enis: dict[str, str] = {}  # NAT gateway id -> ENI id
        self._prefix_lists: dict[str, str] = {}
        # Effective access (iplens.access): (holder node id, purpose) -> role ARN, the
        # simulations already cached for this snapshot, new results and the verdicts of
        # resource policies (the policies themselves stay in memory, in _policies).
        self._principals: dict[tuple[str, str], str] = {}
        self._cached_sims: set[access.SimRequest] = set()
        self._sims: dict[access.SimRequest, tuple[str, str]] = {}
        self._resource_checks: dict[access.SimRequest, tuple[str, str]] = {}
        self._policies: dict[str, str | None] = {}
        self._ecr_actions: list[str] = []  # the snapshot has ECR interface endpoints
        self._vpc_holders: set[str] = set()  # Lambda functions / ECS services with VPC ENIs
        # Full path: the simulated requests (-> resource node id), KMS key references of
        # encrypted queues / topics, ECR repositories each ECS service's images come from,
        # the KMS and SCP results (new ones; cached ones are not asked again) and the
        # subnets' NACL / route rows (None: the source did not run).
        self._requests: dict[access.SimRequest, str] = {}
        self._key_refs: dict[str, str] = {}
        self._images: dict[str, set[str]] = {}
        self._kms_targets: dict[tuple[str, str], str] = {}
        self._kms_requests: list[access.SimRequest] = []
        self._cached_kms: set[access.SimRequest] = set()
        self._kms_sims: dict[access.SimRequest, tuple[str, str, str, str]] = {}
        self._cached_scps: set[tuple[str, str, str]] = set()
        self._scp_rows: dict[tuple[str, str, str], tuple[str, str]] = {}
        self._acl_rows: tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]] | None = None
        self._route_rows: tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]] | None = None
        # Condition context: DescribeOrganization (the organization, or the error code),
        # the organization id (also cached for the snapshot), each holder's VPC (None: not
        # in a VPC) and the interface endpoints (VPC, service name, endpoint id).
        self._org: dict[str, Any] | str | None = None
        self._org_id = ""
        self._holder_vpcs: dict[str, str | None] = {}
        self._interface_eps: list[tuple[str, str, str]] = []

    # -- plumbing ---------------------------------------------------------------------

    def _source(self, name: str, fn: Callable[[], int | None]) -> None:
        """Run one optional source; any failure becomes a warning and the crawl goes on."""
        try:
            count = fn()
        except ReadOnlyViolation:
            raise
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "") or "ClientError"
            self._warn(f"{name} skipped ({code})")
            return
        except Exception as exc:  # noqa: BLE001 - optional source: degrade to a warning
            self._warn(f"{name} skipped ({type(exc).__name__})")
            return
        self.result.sources[name] = int(count or 0)

    def _warn(self, msg: str) -> None:
        log.warning("extended crawl: %s", msg)
        self.result.warnings.append(msg)

    def _cap(self, what: str, items: list[Any], limit: int) -> list[Any]:
        """The first ``limit`` items, with a warning if ``items`` holds more than that.

        Callers fetch ``limit + 1`` items where they can, so "more" is known, not guessed.
        """
        if len(items) <= limit:
            return items
        self._warn(f"{what}: showing first {limit}{CAPPED_SUFFIX}")
        return items[:limit]

    def _client(self, service: str) -> Any:
        return self.gw.client(service)

    # -- run --------------------------------------------------------------------------

    def run(self) -> CrawlResult:
        with closing(self.db_path) as conn:
            self._load_snapshot(conn)
        log.info("extended crawl started snapshot=%s", self.snapshot_id)
        # Inventory first: later sources match references against the catalog.
        sources = (
            ("lambda:ListFunctions", self._lambdas),
            ("sns:ListTopics", self._sns_topics),
            ("sqs:ListQueues", self._sqs),
            ("dynamodb:ListTables", self._dynamodb),
            ("s3:ListBuckets", self._s3_buckets),
            ("secretsmanager:ListSecrets", self._secrets),
            ("states:ListStateMachines", self._state_machine_inventory),
            ("events:ListRules", self._event_rules),
            ("apigateway:GetRestApis", self._apigw_rest),
            ("apigatewayv2:GetApis", self._apigw_http),
            ("ecs:DescribeServices", self._ecs_services),
            ("kafka:ListClustersV2", self._msk_clusters),
            ("resource-explorer-2:ListResources", self._resource_explorer),
            # Relationships.
            ("sns:ListSubscriptions", self._sns_subscriptions),
            ("lambda:ListEventSourceMappings", self._event_source_mappings),
            ("lambda:GetFunctionConfiguration", self._lambda_config),
            ("s3:GetBucketNotificationConfiguration", self._s3_notifications),
            ("states:DescribeStateMachine", self._state_machines),
            ("ecs:DescribeTaskDefinition", self._task_definitions),
            ("iam:GetRolePolicy", self._iam),
            ("iam:SimulatePrincipalPolicy", self._simulate),
            ("kms:DescribeKey", self._kms),
            ("organizations:ListPoliciesForTarget", self._scps),
            ("ec2:DescribeManagedPrefixLists", self._prefix_list_names),
            ("ec2:DescribeRouteTables", self._route_tables),
            ("ec2:DescribeNetworkAcls", self._nacls),
            ("ec2:DescribeTransitGatewayAttachments", self._tgw),
            ("ec2:DescribeVpcPeeringConnections", self._peering),
            ("route53:ListHostedZones", self._route53),
            ("route53resolver:ListResolverRules", self._resolver),
            ("config:GetResourceConfigHistory", self._config),
            ("xray:GetServiceGraph", self._xray),
        )
        for i, (name, fn) in enumerate(sources):
            self.progress.check()
            self.progress.step(f"crawl · {name}", done=i, total=len(sources) + 1)
            self._source(name, fn)
        self._functions.clear()
        self._policies.clear()
        self.progress.check()
        self.progress.step("crawl · saving", done=len(sources), total=len(sources) + 1)
        self._save()
        log.info(
            "extended crawl finished snapshot=%s nodes=%d edges=%d warnings=%d",
            self.snapshot_id,
            self.result.nodes,
            self.result.edges,
            len(self.result.warnings),
        )
        return self.result

    def _load_snapshot(self, conn: sqlite3.Connection) -> None:
        sid = self.snapshot_id
        self._vpcs = {
            r[0] for r in conn.execute("SELECT vpc_id FROM vpcs WHERE snapshot_id=?", (sid,))
        }
        for r in conn.execute(
            "SELECT eni_id, owner_ref FROM enis WHERE snapshot_id=? AND owner_type='nat'", (sid,)
        ):
            if r["owner_ref"]:
                self._nat_enis.setdefault(r["owner_ref"], r["eni_id"])
        self._cached_sims = {
            access.SimRequest(r["role_arn"], r["action"], r["resource"])
            for r in conn.execute(
                "SELECT role_arn, action, resource FROM iam_sims WHERE snapshot_id=?", (sid,)
            )
        }
        self._cached_kms = {
            access.SimRequest(r["role_arn"], r["action"], r["key_arn"])
            for r in conn.execute(
                "SELECT role_arn, action, key_arn FROM kms_sims WHERE snapshot_id=?", (sid,)
            )
        }
        self._cached_scps = {
            (r["account"], r["action"], r["resource"])
            for r in conn.execute(
                "SELECT account, action, resource FROM scp_checks WHERE snapshot_id=?", (sid,)
            )
        }
        services = {
            r[0]
            for r in conn.execute("SELECT service_name FROM endpoints WHERE snapshot_id=?", (sid,))
        }
        self._ecr_actions = sorted({a for s in services if (a := access.ecr_action(s))})
        self._holder_vpcs = {
            node_id("lambda", r[0]): r[1]
            for r in conn.execute("SELECT name, vpc_id FROM lambdas WHERE snapshot_id=?", (sid,))
        }
        ecs_vpcs: dict[str, set[str | None]] = {}
        for r in conn.execute(
            "SELECT DISTINCT t.cluster, t.service, e.vpc_id FROM ecs_task_enis t "
            "LEFT JOIN enis e ON e.snapshot_id=t.snapshot_id AND e.eni_id=t.eni_id "
            "WHERE t.snapshot_id=? AND t.service != ''",
            (sid,),
        ):
            ecs_vpcs.setdefault(node_id("ecs", f"{r[0]}/{r[1]}"), set()).add(r[2])
        # A service's tasks are in one VPC; otherwise its context is unknown (left out).
        self._holder_vpcs.update(
            {h: next(iter(v)) for h, v in ecs_vpcs.items() if len(v) == 1 and None not in v}
        )
        self._vpc_holders = {h for h, vpc in self._holder_vpcs.items() if vpc} | set(ecs_vpcs)
        self._interface_eps = [
            (r[0], r[1] or "", r[2])
            for r in conn.execute(
                "SELECT vpc_id, service_name, endpoint_id FROM endpoints "
                "WHERE snapshot_id=? AND endpoint_type='Interface' ORDER BY endpoint_id",
                (sid,),
            )
        ]
        row = conn.execute("SELECT org_id FROM iam_context WHERE snapshot_id=?", (sid,)).fetchone()
        self._org_id = row[0] if row else ""

    def _save(self) -> None:
        g, sid = self.graph, self.snapshot_id
        with closing(self.db_path) as conn:
            for table in ("ext_nodes", "ext_edges", "ext_facts", "ext_crawls"):
                conn.execute(f"DELETE FROM {table} WHERE snapshot_id=?", (sid,))  # noqa: S608
            conn.executemany(
                "INSERT INTO ext_nodes(snapshot_id, node_id, service, name, arn, area, "
                "broad_access) VALUES(?,?,?,?,?,?,?)",
                [
                    (sid, n.node_id, n.service, n.name, n.arn, n.area, n.broad_access)
                    for n in g.nodes.values()
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO ext_edges(snapshot_id, source, target, evidence, label, "
                "detail) VALUES(?,?,?,?,?,?)",
                [(sid, *e) for e in sorted(g.edges)],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO ext_facts(snapshot_id, subject, detail) VALUES(?,?,?)",
                [(sid, *f) for f in sorted(g.facts)],
            )
            # Effective access: simulations stay cached; the roles are the crawl's.
            conn.execute("DELETE FROM iam_principals WHERE snapshot_id=?", (sid,))
            conn.executemany(
                "INSERT INTO iam_principals(snapshot_id, holder, purpose, role_arn) "
                "VALUES(?,?,?,?)",
                [(sid, h, p, role) for (h, p), role in sorted(self._principals.items())],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO iam_sims(snapshot_id, role_arn, action, resource, "
                "decision, detail) VALUES(?,?,?,?,?,?)",
                [
                    (sid, r.role_arn, r.action, r.resource, d, detail)
                    for r, (d, detail) in sorted(self._sims.items())
                ],
            )
            conn.executemany(
                "UPDATE iam_sims SET resource_decision=?, resource_detail=? WHERE snapshot_id=? "
                "AND role_arn=? AND action=? AND resource=?",
                [
                    (d, detail[:400], sid, r.role_arn, r.action, r.resource)
                    for r, (d, detail) in sorted(self._resource_checks.items())
                ],
            )
            # Full path: NACLs and routes as this crawl read them (kept when unreadable),
            # the keys of encrypted targets, and the cached KMS / SCP verdicts.
            for rows, tables in (
                (self._acl_rows, ("nacl_subnets", "nacl_entries")),
                (self._route_rows, ("route_subnets", "route_entries")),
            ):
                if rows is None:
                    continue
                for table, table_rows in zip(tables, rows, strict=True):
                    conn.execute(f"DELETE FROM {table} WHERE snapshot_id=?", (sid,))  # noqa: S608
                    if table_rows:
                        marks = ",".join("?" * (len(table_rows[0]) + 1))
                        conn.executemany(
                            f"INSERT OR IGNORE INTO {table} VALUES({marks})",  # noqa: S608
                            [(sid, *row) for row in table_rows],
                        )
            conn.execute("DELETE FROM kms_targets WHERE snapshot_id=?", (sid,))
            conn.executemany(
                "INSERT INTO kms_targets(snapshot_id, resource, holder, key_arn) VALUES(?,?,?,?)",
                [
                    (sid, res, holder, key)
                    for (res, holder), key in sorted(self._kms_targets.items())
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO kms_sims(snapshot_id, role_arn, key_arn, action, decision, "
                "detail, policy_decision, policy_detail) VALUES(?,?,?,?,?,?,?,?)",
                [
                    (sid, r.role_arn, r.resource, r.action, *(v[:400] for v in result))
                    for r, result in sorted(self._kms_sims.items())
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO scp_checks(snapshot_id, account, action, resource, "
                "decision, detail) VALUES(?,?,?,?,?,?)",
                [(sid, *key, *result) for key, result in sorted(self._scp_rows.items())],
            )
            if self._org_id:
                conn.execute(
                    "INSERT OR REPLACE INTO iam_context(snapshot_id, org_id) VALUES(?,?)",
                    (sid, self._org_id),
                )
            conn.execute(
                "INSERT INTO ext_crawls(snapshot_id, crawled_at, warnings, sources) "
                "VALUES(?,?,?,?)",
                (
                    sid,
                    datetime.now(UTC).isoformat(timespec="seconds"),
                    json.dumps(self.result.warnings),
                    json.dumps(self.result.sources),
                ),
            )
        self.result.nodes, self.result.edges = len(g.nodes), len(g.edges)

    def _label(self, nid: str) -> str:
        rec = self.graph.nodes.get(nid)
        return rec.name if rec else nid.split(":", 1)[-1]

    def _match_refs(
        self, holder: str, env: dict[str, Any] | Iterable[tuple[str, Any]], where: str
    ) -> None:
        """``referenced`` edges for environment variables naming a known resource.

        Only the variable *name* and the matched resource go into the detail text.
        """
        items = env.items() if isinstance(env, dict) else env
        for key, value in items:
            for target in sorted(self.graph.catalog.match(value)):
                if target == holder:
                    continue
                self.graph.edge(
                    holder,
                    target,
                    "referenced",
                    "env",
                    f"environment variable {str(key)[:64]} of {where} names "
                    f"{SERVICE_LABELS.get(target.split(':', 1)[0], 'resource')} "
                    f"{self._label(target)}",
                )

    # -- inventory --------------------------------------------------------------------

    def _lambdas(self) -> int:
        self._functions = _pages(self._client("lambda"), "list_functions", "Functions")
        for fn in self._functions:
            nid = self.graph.node("lambda", fn["FunctionName"], fn.get("FunctionArn", ""))
            if fn.get("Role"):
                self._role_holders.setdefault(fn["Role"], set()).add(nid)
                self._principals[(nid, "lambda")] = fn["Role"]
        return len(self._functions)

    def _sns_topics(self) -> int:
        topics = _pages(self._client("sns"), "list_topics", "Topics")
        for t in topics:
            arn = t.get("TopicArn", "")
            self.graph.node("sns", _last(arn, ":"), arn)
        return len(topics)

    def _sqs(self) -> int:
        sqs = self._client("sqs")
        urls = self._cap(
            "SQS queues",
            _pages(sqs, "list_queues", "QueueUrls", MAX_PER_SOURCE + 1),
            MAX_PER_SOURCE,
        )
        attrs: dict[str, dict[str, str]] = {}
        for url in urls:
            try:
                attrs[url] = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=["QueueArn", "RedrivePolicy", "Policy", "KmsMasterKeyId"],
                ).get("Attributes", {})
            except ClientError:
                attrs[url] = {}
            name = _last(url, "/")
            nid = self.graph.node("sqs", name, attrs[url].get("QueueArn", ""), url)
            # The queue policy: evaluated by _simulate, never stored.
            self._policies[nid] = attrs[url].pop("Policy", None)
            if attrs[url].get("KmsMasterKeyId"):
                self._key_refs[nid] = attrs[url]["KmsMasterKeyId"]
        for url, a in attrs.items():
            policy = _policy_doc(a.get("RedrivePolicy") or "{}")
            dlq = policy.get("deadLetterTargetArn")
            target = self.graph.node_from_arn(dlq) if isinstance(dlq, str) else None
            if target:
                self.graph.edge(
                    node_id("sqs", _last(url, "/")),
                    target,
                    "configured",
                    "DLQ",
                    f"redrive policy sends failed messages to dead-letter queue "
                    f"{self._label(target)}",
                )
        return len(urls)

    def _dynamodb(self) -> int:
        ddb = self._client("dynamodb")
        names = self._cap(
            "DynamoDB tables",
            _pages(ddb, "list_tables", "TableNames", MAX_PER_SOURCE + 1),
            MAX_PER_SOURCE,
        )
        for name in names:
            arn, stream = "", ""
            try:
                table = ddb.describe_table(TableName=name).get("Table", {})
                arn, stream = table.get("TableArn", ""), table.get("LatestStreamArn", "")
            except ClientError:
                pass
            nid = self.graph.node("dynamodb", name, arn)
            if stream:
                self.graph.catalog.add(nid, arn=stream)
                self.graph.catalog.arns[stream] = nid
        return len(names)

    def _s3_buckets(self) -> int:
        buckets = self._client("s3").list_buckets().get("Buckets", [])
        for b in buckets:
            self.graph.node("s3", b["Name"], f"arn:aws:s3:::{b['Name']}")
        return len(buckets)

    def _secrets(self) -> int:
        """Secret names and ARNs only (ListSecrets never returns secret values)."""
        secrets = _pages(self._client("secretsmanager"), "list_secrets", "SecretList")
        for s in secrets:
            self.graph.node("secretsmanager", s.get("Name", ""), s.get("ARN", ""))
        return len(secrets)

    def _state_machine_inventory(self) -> int:
        machines = _pages(self._client("stepfunctions"), "list_state_machines", "stateMachines")
        for m in machines:
            self.graph.node("states", m["name"], m.get("stateMachineArn", ""))
        return len(machines)

    def _event_rules(self) -> int:
        events = self._client("events")
        buses = ["default"]
        with suppress(ClientError):
            buses += [
                b["Name"]
                for b in events.list_event_buses().get("EventBuses", [])
                if b.get("Name") and b["Name"] != "default"
            ]
        count = 0
        for bus in buses:
            rules = self._cap(
                f"EventBridge rules ({bus} bus)",
                events.list_rules(EventBusName=bus).get("Rules", []),
                MAX_PER_SOURCE,
            )
            for rule in rules:
                name = rule["Name"] if bus == "default" else f"{bus}/{rule['Name']}"
                nid = self.graph.node("events", name, rule.get("Arn", ""))
                count += 1
                targets = events.list_targets_by_rule(Rule=rule["Name"], EventBusName=bus)
                for t in targets.get("Targets", []):
                    # Only the target ARN is read; Input / InputTransformer never are.
                    target = self.graph.node_from_arn(t.get("Arn", ""))
                    if target:
                        self.graph.edge(
                            nid,
                            target,
                            "configured",
                            "rule target",
                            f"EventBridge rule {name} ({bus} bus) targets {self._label(target)}",
                        )
                if rule.get("RoleArn"):
                    self._role_holders.setdefault(rule["RoleArn"], set()).add(nid)
        return count

    def _apigw_rest(self) -> int:
        apigw = self._client("apigateway")
        apis = self._cap(
            "API Gateway REST APIs",
            _pages(apigw, "get_rest_apis", "items", MAX_PER_SOURCE + 1),
            MAX_PER_SOURCE,
        )
        for api in apis:
            nid = self.graph.node("apigateway", api.get("name") or api["id"])
            for res in _pages(
                apigw, "get_resources", "items", restApiId=api["id"], embed=["methods"]
            ):
                for method, spec in (res.get("resourceMethods") or {}).items():
                    integ = (spec or {}).get("methodIntegration") or {}
                    self._apigw_link(nid, integ.get("uri", ""), f"{method} {res.get('path', '')}")
        return len(apis)

    def _apigw_http(self) -> int:
        apigw = self._client("apigatewayv2")
        apis = self._cap(
            "API Gateway HTTP/WebSocket APIs", apigw.get_apis().get("Items", []), MAX_PER_SOURCE
        )
        for api in apis:
            nid = self.graph.node("apigateway", api.get("Name") or api["ApiId"])
            for integ in apigw.get_integrations(ApiId=api["ApiId"]).get("Items", []):
                self._apigw_link(nid, integ.get("IntegrationUri", ""), "integration")
        return len(apis)

    def _apigw_link(self, api: str, uri: str, where: str) -> None:
        """Integration URI -> Lambda function (or any known ARN); HTTP URLs are ignored."""
        m = LAMBDA_URI_RE.search(uri or "")
        target = self.graph.node_from_arn(m.group(1)) if m else None
        if target is None and uri.startswith("arn:"):
            hits = self.graph.catalog.match(uri)
            target = sorted(hits)[0] if hits else None
        if target:
            self.graph.edge(
                api,
                target,
                "configured",
                "integration",
                f"API Gateway {self._label(api)} {where} integrates {self._label(target)}",
            )

    def _ecs_services(self) -> int:
        ecs = self._client("ecs")
        count = 0
        for cluster_arn in _pages(ecs, "list_clusters", "clusterArns"):
            cluster = _last(cluster_arn, "/")
            arns = _pages(ecs, "list_services", "serviceArns", cluster=cluster_arn)
            for i in range(0, len(arns), 10):
                resp = ecs.describe_services(cluster=cluster_arn, services=arns[i : i + 10])
                for svc in resp.get("services", []):
                    name = svc.get("serviceName") or _last(svc.get("serviceArn", ""), "/")
                    nid = self.graph.node("ecs", f"{cluster}/{name}", svc.get("serviceArn", ""))
                    if svc.get("taskDefinition"):
                        self._task_defs.setdefault(svc["taskDefinition"], set()).add(nid)
                    count += 1
        return count

    def _resource_explorer(self) -> int:
        """If an index is on, resources it lists can be named by references (drawn lazily)."""
        rex = self._client("resource-explorer-2")
        try:
            rex.get_index()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("ResourceNotFoundException", "404"):
                self._warn("Resource Explorer: no index in this region; skipped")
                return 0
            raise
        count = 0
        resources = self._cap(
            "Resource Explorer resources",
            _pages(rex, "list_resources", "Resources", MAX_REX_RESOURCES + 1),
            MAX_REX_RESOURCES,
        )
        for r in resources:
            arn = r.get("Arn", "")
            parsed = node_for_arn(arn)
            service, res = arn_parts(arn)
            if not service:
                continue
            svc, name = parsed or ("other", f"{service}/{_last(res)}")
            nid = node_id(svc, name)
            if nid in self.graph.nodes:
                continue
            self.graph.catalog.pending[nid] = NodeRec(nid, svc, name, arn)
            self.graph.catalog.add(nid, arn=arn)
            count += 1
        return count

    # -- relationships ----------------------------------------------------------------

    def _sns_subscriptions(self) -> int:
        subs = _pages(self._client("sns"), "list_subscriptions", "Subscriptions")
        count = 0
        for s in subs:
            topic = self.graph.node_from_arn(s.get("TopicArn", ""))
            # Only AWS resource endpoints; e-mail / SMS / HTTP endpoints are never read.
            endpoint = s.get("Endpoint", "")
            target = self.graph.node_from_arn(endpoint) if endpoint.startswith("arn:") else None
            if topic and target:
                self.graph.edge(
                    topic,
                    target,
                    "configured",
                    "subscription",
                    f"SNS subscription ({s.get('Protocol', '?')}) delivers to "
                    f"{self._label(target)}",
                )
                count += 1
        return count

    def _msk_clusters(self) -> int:
        """Amazon MSK clusters (provisioned and serverless) by name and ARN.

        ``ListClustersV2`` is the MSK list call that covers both cluster types (the old
        ``ListClusters`` only returns provisioned ones); it needs the read-only
        ``kafka:ListClustersV2`` permission. Broker, authentication and configuration
        details are not read.
        """
        kafka = self._client("kafka")
        clusters = self._cap(
            "MSK (Kafka) clusters",
            _pages(kafka, "list_clusters_v2", "ClusterInfoList", MAX_PER_SOURCE + 1),
            MAX_PER_SOURCE,
        )
        for c in clusters:
            arn = c.get("ClusterArn", "")
            name = c.get("ClusterName") or (node_for_arn(arn) or ("", ""))[1]
            if name:
                self.graph.node("kafka", name, arn)
        return len(clusters)

    def _kafka_source(self, mapping: dict[str, Any]) -> str | None:
        """Node of a mapping's MSK cluster (by ARN) or self-managed Kafka bootstrap host."""
        arn = mapping.get("EventSourceArn", "")
        if arn:
            return self.graph.node_from_arn(arn)
        host = kafka_bootstrap_host(mapping)
        return self.graph.node("kafka", host, area="external") if host else None

    def _event_source_mappings(self) -> int:
        maps = _pages(self._client("lambda"), "list_event_source_mappings", "EventSourceMappings")
        for m in maps:
            fn = self.graph.node_from_arn(m.get("FunctionArn", ""))
            src = self._kafka_source(m)
            if fn and src and src.startswith("kafka:"):
                topics = [str(t)[:64] for t in (m.get("Topics") or [])[:3]]
                kind = "MSK cluster" if m.get("EventSourceArn") else "self-managed Kafka"
                self.graph.edge(
                    src,
                    fn,
                    "configured",
                    "event source",
                    f"event source mapping ({m.get('State', 'unknown')}): {kind} "
                    f"{self._label(src)}"
                    + (f" topic(s) {', '.join(topics)}" if topics else "")
                    + f" triggers {self._label(fn)}",
                )
            elif fn and src:
                what = "DynamoDB stream" if ":table/" in m.get("EventSourceArn", "") else "source"
                self.graph.edge(
                    src,
                    fn,
                    "configured",
                    "event source",
                    f"event source mapping ({m.get('State', 'unknown')}): {what} "
                    f"{self._label(src)} triggers {self._label(fn)}",
                )
        return len(maps)

    def _lambda_config(self) -> int:
        """DLQ targets and environment variable references (values matched, never kept).

        ListFunctions already returned each function's configuration, so no extra
        calls are made here.
        """
        for fn in self._functions:
            nid = node_id("lambda", fn["FunctionName"])
            dlq = (fn.get("DeadLetterConfig") or {}).get("TargetArn")
            target = self.graph.node_from_arn(dlq) if dlq else None
            if target:
                self.graph.edge(
                    nid,
                    target,
                    "configured",
                    "DLQ",
                    f"dead-letter target of {fn['FunctionName']} is {self._label(target)}",
                )
            env = (fn.get("Environment") or {}).get("Variables") or {}
            self._match_refs(nid, env, f"function {fn['FunctionName']}")
        return len(self._functions)

    def _s3_notifications(self) -> int:
        s3 = self._client("s3")
        buckets = self._cap(
            "S3 bucket notifications",
            [n for n in self.graph.nodes.values() if n.service == "s3"],
            MAX_PER_SOURCE,
        )
        unreadable = 0
        for b in buckets:
            # One bucket in another region or behind a bucket policy must not end the source.
            try:
                conf = s3.get_bucket_notification_configuration(Bucket=b.name)
            except ClientError:
                unreadable += 1
                continue
            for key, arn_key in (
                ("LambdaFunctionConfigurations", "LambdaFunctionArn"),
                ("QueueConfigurations", "QueueArn"),
                ("TopicConfigurations", "TopicArn"),
            ):
                for item in conf.get(key, []):
                    target = self.graph.node_from_arn(item.get(arn_key, ""))
                    if target:
                        events = ", ".join(item.get("Events", [])[:3])
                        self.graph.edge(
                            b.node_id,
                            target,
                            "configured",
                            "notification",
                            f"bucket notification ({events}) sends to {self._label(target)}",
                        )
        if unreadable:
            self._warn(f"s3:GetBucketNotificationConfiguration: {unreadable} bucket(s) unreadable")
        return len(buckets) - unreadable

    def _state_machines(self) -> int:
        sfn = self._client("stepfunctions")
        machines = self._cap(
            "Step Functions state machine definitions",
            [n for n in self.graph.nodes.values() if n.service == "states" and n.arn],
            MAX_PER_SOURCE,
        )
        for m in machines:
            desc = sfn.describe_state_machine(stateMachineArn=m.arn)
            if desc.get("roleArn"):
                self._role_holders.setdefault(desc["roleArn"], set()).add(m.node_id)
            try:
                definition = json.loads(desc.get("definition") or "{}")
            except ValueError:
                continue
            # The definition is only matched against the catalog, never stored.
            for state, value in state_resources(definition):
                for target in sorted(self.graph.catalog.match(value)):
                    self.graph.edge(
                        m.node_id,
                        target,
                        "configured",
                        "task",
                        f"state {state[:64]} of {m.name} uses {self._label(target)}",
                    )
        return len(machines)

    def _task_definitions(self) -> int:
        ecs = self._client("ecs")
        for td_arn, services in self._task_defs.items():
            td = ecs.describe_task_definition(taskDefinition=td_arn).get("taskDefinition", {})
            family = td.get("family", _last(td_arn, "/"))
            for purpose, role in (
                ("task", td.get("taskRoleArn")),
                ("execution", td.get("executionRoleArn")),
            ):
                if role:
                    self._role_holders.setdefault(role, set()).update(services)
                    self._principals.update({(svc, purpose): role for svc in services})
            for c in td.get("containerDefinitions", []):
                where = f"task definition {family} container {c.get('name', '?')}"
                # <account>.dkr.ecr.<region>.amazonaws.com/<repository>[:tag|@digest]
                image = str(c.get("image", ""))
                if ".dkr.ecr." in image and "/" in image:
                    repo = re.split(r"[:@]", image.split("/", 1)[1], maxsplit=1)[0]
                    for svc in services:
                        self._images.setdefault(svc, set()).add(repo)
                env = [(e.get("name", ""), e.get("value")) for e in c.get("environment", [])]
                for svc in services:
                    self._match_refs(svc, env, where)
                # ECS injects these secrets at start: valueFrom is an ARN, not the value.
                for s in c.get("secrets", []):
                    for target in sorted(self.graph.catalog.match(s.get("valueFrom"))):
                        for svc in services:
                            self.graph.edge(
                                svc,
                                target,
                                "configured",
                                "secret",
                                f"{where} injects secret {self._label(target)} as "
                                f"{str(s.get('name', ''))[:64]}",
                            )
        return len(self._task_defs)

    def _iam(self) -> int:
        """``permitted`` edges from the roles of Lambda functions, ECS services, state
        machines and rules. Policy documents are parsed in memory; only matched
        resources and a broad-access count are kept."""
        iam = self._client("iam")
        cache: dict[str, Any] = {}
        for role_arn, holders in sorted(self._role_holders.items()):
            role = _last(role_arn, "/")
            docs: list[tuple[str, Any]] = []
            for p in _pages(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role):
                arn = p["PolicyArn"]
                if arn not in cache:
                    ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                    cache[arn] = iam.get_policy_version(PolicyArn=arn, VersionId=ver)[
                        "PolicyVersion"
                    ]["Document"]
                docs.append((p.get("PolicyName", _last(arn, "/")), cache[arn]))
            for name in _pages(iam, "list_role_policies", "PolicyNames", RoleName=role):
                docs.append(
                    (name, iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"])
                )
            broad = 0
            for policy, doc in docs:
                for st in policy_statements(doc):
                    services = action_services(st)
                    if "NotResource" in st or "NotAction" in st:
                        broad += 1
                        continue
                    covered: set[str] = set()
                    for pattern in _as_list(st.get("Resource")):
                        hits = self.graph.catalog.match_pattern(str(pattern))
                        if hits is None:
                            broad += 1
                            covered = set()
                            break
                        covered |= hits
                    for target in sorted(covered):
                        rec = self.graph.nodes.get(target) or self.graph.catalog.pending.get(target)
                        target_svc, _ = arn_parts(rec.arn if rec else "")
                        if "*" not in services and target_svc not in services:
                            continue
                        for holder in sorted(holders):
                            self.graph.edge(
                                holder,
                                target,
                                "permitted",
                                "IAM",
                                f"role {role} policy {policy[:64]} allows {target_svc} actions "
                                f"on {self._label(target)}",
                            )
            if broad:
                for holder in holders:
                    if holder in self.graph.nodes:
                        self.graph.nodes[holder].broad_access += broad
                        self.graph.fact(
                            holder,
                            f"broad access: role {role} has {broad} statement(s) allowing "
                            f'Resource "*" (not expanded)',
                        )
        return len(self._role_holders)

    def _role_for(self, holder: str, action: str) -> str | None:
        return next(
            (
                self._principals[(holder, p)]
                for p in access.purposes(holder, action)
                if (holder, p) in self._principals
            ),
            None,
        )

    def _organization(self) -> dict[str, Any] | str:
        """``DescribeOrganization``, once per crawl: the organization, or the error code."""
        if self._org is None:
            try:
                self._org = self._client("organizations").describe_organization()["Organization"]
                self._org_id = self._org.get("Id", "")
            except ClientError as exc:
                self._org = exc.response.get("Error", {}).get("Code", "") or "ClientError"
        return self._org

    def _context(self, req: access.SimRequest) -> dict[str, str | None]:
        """The condition keys of ``req`` known here: the principal's and, when every holder
        of the role sits in the same VPC (or none in a VPC), the network path: through
        the VPC's interface endpoint for the service (private DNS assumed), else none."""
        ctx = access.principal_context(req.role_arn, self._org_id)
        holders = {h for (h, _), role in self._principals.items() if role == req.role_arn}
        vpcs = {self._holder_vpcs.get(h, "?") for h in holders}
        if len(vpcs) != 1 or "?" in vpcs:
            return ctx
        vpc = vpcs.pop()
        suffix = access.endpoint_suffix(req.action)
        ep = next(
            (e for v, name, e in self._interface_eps if vpc and v == vpc and name.endswith(suffix)),
            None,
        )
        return {**ctx, **access.network_context(ep, vpc)}

    def _need_org(self, todo: Iterable[access.SimRequest], cached: set[access.SimRequest]) -> None:
        """Read the organization id (aws:PrincipalOrgID) before simulating anything new."""
        if not self._org_id and any(r not in cached for r in todo):
            self._organization()

    def _resource_policy(self, nid: str) -> str | None:
        """An SQS queue's policy (read with its attributes) or an SNS topic's (read here)."""
        if nid not in self._policies and nid.startswith("sns:"):
            arn = self.graph.nodes[nid].arn
            try:
                attrs = self._client("sns").get_topic_attributes(TopicArn=arn)["Attributes"]
                self._policies[nid] = attrs.get("Policy")
                if attrs.get("KmsMasterKeyId"):
                    self._key_refs[nid] = attrs["KmsMasterKeyId"]
            except ClientError:
                self._policies[nid] = None
        return self._policies.get(nid)

    def _simulate(self) -> int:
        """Effective access: ``iam:SimulatePrincipalPolicy`` for the actions the crawled
        connections need (a function / service sending to a queue or topic, a queue feeding
        a function) and, when the snapshot has ECR interface endpoints, the image pull of
        every function / service with VPC ENIs. Results cached for the snapshot are not
        simulated again; resource policies are evaluated here (see iplens.access)."""
        requests: dict[access.SimRequest, str] = {}  # -> resource node id ("" for "*")
        for source, target, *_ in sorted(self.graph.edges):
            req = access.ext_request(source, target)
            if req is None:
                continue
            holder, action, res_node = req
            rec, role = self.graph.nodes.get(res_node), self._role_for(holder, action)
            if rec is not None and rec.arn and role:
                requests[access.SimRequest(role, action, rec.arn)] = res_node
        for holder in sorted(self._vpc_holders):
            for action in self._ecr_actions:
                role = self._role_for(holder, action)
                if role:
                    requests[access.SimRequest(role, action, "*")] = ""
        wanted = self._cap("IAM simulations", sorted(requests), MAX_PER_SOURCE)
        self._requests = {req: requests[req] for req in wanted}
        self._need_org(wanted, self._cached_sims)
        for req in wanted:
            policy = self._resource_policy(requests[req]) if requests[req] else None
            if policy:
                self._resource_checks[req] = access.policy_decision(
                    policy, req.role_arn, req.action, req.resource, context=self._context(req)
                )
        for req, decision, detail in access.simulate(
            self._client("iam"), wanted, self._cached_sims, self._context
        ):
            self._sims[req] = (decision, detail)
        return len(wanted)

    def _kms(self) -> int:
        """Effective access, KMS: the keys of the encrypted queues / topics the simulated
        connections reach and of the ECR repositories (``ecr:DescribeRepositories``) the ECS
        services' images come from, resolved with ``kms:DescribeKey``; then
        ``kms:GenerateDataKey`` / ``kms:Decrypt`` simulated for each role on each key, and
        the key policy (``kms:GetKeyPolicy``) evaluated when it is readable."""
        refs: dict[tuple[str, str], str] = {}  # (resource ARN, holder) -> key id / alias / ARN
        kms_requests: set[tuple[str, str, str]] = set()  # (role, action, key reference)
        for req, nid in self._requests.items():
            if nid in self._key_refs:
                refs[(req.resource, "")] = self._key_refs[nid]
                for action in access.KMS_ACTIONS.get(req.action, ()):
                    kms_requests.add((req.role_arn, action, self._key_refs[nid]))
        pull = "ecr:BatchGetImage"
        if pull in self._ecr_actions:
            ecr = self._client("ecr")
            for holder in sorted(self._vpc_holders):
                role = self._role_for(holder, pull)
                for repo in sorted(self._images.get(holder, ()))[:MAX_PER_SOURCE]:
                    try:
                        found = ecr.describe_repositories(repositoryNames=[repo])["repositories"]
                    except ClientError:
                        continue  # another account's repository, or not readable
                    enc = (found[0] if found else {}).get("encryptionConfiguration") or {}
                    if enc.get("encryptionType") == "KMS" and enc.get("kmsKey") and role:
                        refs[(found[0]["repositoryArn"], holder)] = enc["kmsKey"]
                        kms_requests.add((role, "kms:Decrypt", enc["kmsKey"]))
        if not refs:
            return 0
        kms = self._client("kms")
        keys: dict[str, tuple[str, str | None]] = {}  # reference -> (key ARN, key policy)
        for ref in sorted(set(refs.values())):
            try:
                arn = kms.describe_key(KeyId=ref)["KeyMetadata"]["Arn"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "") or "ClientError"
                self._warn(f"kms:DescribeKey {ref}: {code}; its targets are not KMS-checked")
                continue
            try:
                policy = kms.get_key_policy(KeyId=arn, PolicyName="default")["Policy"]
            except ClientError:
                policy = None  # the IAM simulation alone decides
            keys[ref] = (arn, policy)
        self._kms_targets = {k: keys[ref][0] for k, ref in refs.items() if ref in keys}
        wanted: dict[access.SimRequest, str | None] = {}
        for role, action, ref in sorted(kms_requests):
            if ref in keys:
                arn, policy = keys[ref]
                wanted[access.SimRequest(role, action, arn)] = policy
        self._kms_requests = sorted(wanted)
        self._need_org(wanted, self._cached_kms)

        # KMS is called by the queue / topic / ECR on the role's behalf: principal keys only.
        def context(req: access.SimRequest) -> dict[str, str | None]:
            return access.principal_context(req.role_arn, self._org_id)

        policies = {
            req: (
                access.key_policy_decision(
                    policy, req.role_arn, req.action, req.resource, context(req)
                )
                if policy
                else ("", "")
            )
            for req, policy in wanted.items()
        }
        for req, decision, detail in access.simulate(
            self._client("iam"), sorted(wanted), self._cached_kms, context
        ):
            self._kms_sims[req] = (decision, detail, *policies[req])
        return len(wanted)

    def _scps(self) -> int:
        """Effective access, SCPs: when Organizations is readable (``DescribeOrganization``,
        ``ListParents``, ``ListPoliciesForTarget``, ``DescribePolicy``), the SCPs from the
        root down to each role's account for every simulated action. Without access the
        connections stay "SCP not evaluated" (a warning, never a block)."""
        todo = sorted(
            {
                (access.account_of(r.role_arn), r.action, r.resource)
                for r in (*self._requests, *self._kms_requests)
            }
            - self._cached_scps
        )
        if not todo:
            return 0
        org = self._client("organizations")
        found = self._organization()
        if isinstance(found, str):
            self._warn(f"SCP not evaluated: Organizations not readable ({found})")
            return 0
        master = found.get("MasterAccountId", "")
        levels: dict[str, list[tuple[str, list[tuple[str, Any]]]]] = {}
        contents: dict[str, Any] = {}
        for account, action, resource in todo:
            if account == master:
                self._scp_rows[(account, action, resource)] = (
                    access.ALLOWED,
                    "the management account: SCPs do not apply",
                )
                continue
            if account not in levels:
                levels[account] = self._scp_levels(org, account, contents)
            # SCP rows are per account: the principal ARN stays unknown.
            context = {"aws:principalaccount": account}
            if self._org_id:
                context["aws:principalorgid"] = self._org_id
            self._scp_rows[(account, action, resource)] = access.scp_decision(
                levels[account], action, resource, context
            )
        return len(todo)

    def _scp_levels(
        self, org: Any, account: str, contents: dict[str, Any]
    ) -> list[tuple[str, list[tuple[str, Any]]]]:
        """``[(target id, [(SCP name, document), ...]), ...]`` from the root down to the
        account."""
        chain, child = [account], account
        for _ in range(8):  # an organization nests OUs at most five levels deep
            parents = org.list_parents(ChildId=child).get("Parents", [])
            if not parents:
                break
            chain.append(parents[0]["Id"])
            if parents[0].get("Type") == "ROOT":
                break
            child = parents[0]["Id"]
        out = []
        for target in reversed(chain):
            policies = []
            for p in _pages(
                org,
                "list_policies_for_target",
                "Policies",
                TargetId=target,
                Filter="SERVICE_CONTROL_POLICY",
            ):
                if p["Id"] not in contents:
                    contents[p["Id"]] = org.describe_policy(PolicyId=p["Id"])["Policy"]["Content"]
                policies.append((p.get("Name") or p["Id"], contents[p["Id"]]))
            out.append((target, policies))
        return out

    def _prefix_list_names(self) -> int:
        lists = _pages(self._client("ec2"), "describe_managed_prefix_lists", "PrefixLists")
        for pl in lists:
            self._prefix_lists[pl["PrefixListId"]] = pl.get("PrefixListName") or pl["PrefixListId"]
        return len(lists)

    def _route_tables(self) -> int:
        tables = _pages(self._client("ec2"), "describe_route_tables", "RouteTables")
        count = 0
        assoc_rows: list[tuple[Any, ...]] = []
        route_rows: list[tuple[Any, ...]] = []
        self._route_rows = (assoc_rows, route_rows)
        for rt in tables:
            vpc = rt.get("VpcId", "")
            if vpc not in self._vpcs:
                continue
            count += 1
            rtb = rt["RouteTableId"]
            assoc = rt.get("Associations", [])
            subnets = sorted(a["SubnetId"] for a in assoc if a.get("SubnetId"))
            scope = "main route table" if any(a.get("Main") for a in assoc) else ""
            # Effective access (route layer): '' is the VPC's main route table.
            assoc_rows += [(rtb, vpc, s) for s in [*subnets, *([""] if scope else [])]]
            for r in rt.get("Routes", []):
                dest = r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId")
                target = next(
                    (
                        str(r[k])
                        for k in (
                            "GatewayId",
                            "NatGatewayId",
                            "TransitGatewayId",
                            "VpcPeeringConnectionId",
                            "NetworkInterfaceId",
                            "InstanceId",
                            "LocalGatewayId",
                            "CarrierGatewayId",
                        )
                        if r.get(k)
                    ),
                    "",
                )
                if dest and target:
                    route_rows.append((rtb, dest, target, r.get("State") or "active"))
            where = f"route table {rtb} ({', '.join(filter(None, [scope, *subnets])) or 'unused'})"
            for s in subnets:
                self.graph.fact(f"subnet:{s}", f"{where}: {len(rt.get('Routes', []))} route(s)")
            for r in rt.get("Routes", []):
                dest = (
                    r.get("DestinationCidrBlock")
                    or r.get("DestinationIpv6CidrBlock")
                    or self._prefix_lists.get(r.get("DestinationPrefixListId", ""), "")
                    or r.get("DestinationPrefixListId", "")
                )
                line = f"{where}: {dest} →"
                if r.get("TransitGatewayId"):
                    t = self.graph.node("tgw", r["TransitGatewayId"])
                    self.graph.edge(
                        f"vpc:{vpc}", t, "configured", "route", f"{line} {r['TransitGatewayId']}"
                    )
                elif r.get("VpcPeeringConnectionId"):
                    p = self.graph.node("pcx", r["VpcPeeringConnectionId"])
                    self.graph.edge(
                        f"vpc:{vpc}",
                        p,
                        "configured",
                        "route",
                        f"{line} {r['VpcPeeringConnectionId']}",
                    )
                elif r.get("NatGatewayId"):
                    nat = r["NatGatewayId"]
                    t = self.graph.node("internet", "nat", area="external")
                    src = f"eni:{self._nat_enis[nat]}" if nat in self._nat_enis else f"vpc:{vpc}"
                    self.graph.edge(src, t, "configured", "route", f"{line} {nat}")
                elif str(r.get("GatewayId", "")).startswith("igw-"):
                    t = self.graph.node("internet", "igw", area="external")
                    self.graph.edge(
                        f"vpc:{vpc}", t, "configured", "route", f"{line} {r['GatewayId']}"
                    )
        return count

    def _nacls(self) -> int:
        acls = _pages(self._client("ec2"), "describe_network_acls", "NetworkAcls")
        count = 0
        subnet_rows: list[tuple[Any, ...]] = []
        entry_rows: list[tuple[Any, ...]] = []
        self._acl_rows = (subnet_rows, entry_rows)
        for acl in acls:
            if acl.get("VpcId") not in self._vpcs:
                continue
            count += 1
            entries = [e for e in acl.get("Entries", []) if e.get("RuleNumber") != 32767]
            # Effective access (NACL layer): IPv4 entries; the default rule * is implicit.
            nacl = acl["NetworkAclId"]
            subnet_rows += [
                (a["SubnetId"], nacl) for a in acl.get("Associations", []) if a.get("SubnetId")
            ]
            for e in entries:
                if not e.get("CidrBlock"):
                    continue
                ports = e.get("PortRange") or {}
                entry_rows.append(
                    (
                        nacl,
                        int(bool(e.get("Egress"))),
                        e["RuleNumber"],
                        str(e.get("Protocol", "-1")),
                        e["CidrBlock"],
                        ports.get("From"),
                        ports.get("To"),
                        e.get("RuleAction", "deny"),
                    )
                )
            inbound = sum(1 for e in entries if not e.get("Egress"))
            deny = sum(1 for e in entries if e.get("RuleAction") == "deny")
            text = (
                f"network ACL {acl['NetworkAclId']}{' (default)' if acl.get('IsDefault') else ''}: "
                f"{inbound} inbound / {len(entries) - inbound} outbound rule(s), {deny} deny"
            )
            for a in acl.get("Associations", []):
                if a.get("SubnetId"):
                    self.graph.fact(f"subnet:{a['SubnetId']}", text)
        return count

    def _tgw(self) -> int:
        ec2 = self._client("ec2")
        atts = _pages(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
        for a in atts:
            tgw = self.graph.node("tgw", a["TransitGatewayId"])
            rtype, rid = a.get("ResourceType", ""), a.get("ResourceId", "")
            line = (
                f"TGW attachment {a.get('TransitGatewayAttachmentId', '?')} "
                f"({rtype} {rid}, {a.get('State', '?')})"
            )
            assoc = (a.get("Association") or {}).get("TransitGatewayRouteTableId")
            if assoc:
                line += f", route table {assoc}"
            if rtype == "vpc" and rid in self._vpcs:
                self.graph.edge(f"vpc:{rid}", tgw, "configured", "attachment", line)
            elif rid:
                other = self.graph.node("tgw-attachment", f"{rtype} {rid}")
                self.graph.edge(tgw, other, "configured", "attachment", line)
        # Route tables and their propagations (SearchTransitGatewayRoutes is not a
        # read-only-prefixed call and stays blocked by the guard).
        for rt in _pages(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"):
            tgw = node_id("tgw", rt["TransitGatewayId"])
            props = ec2.get_transit_gateway_route_table_propagations(
                TransitGatewayRouteTableId=rt["TransitGatewayRouteTableId"]
            ).get("TransitGatewayRouteTablePropagations", [])
            for p in props:
                if p.get("ResourceType") == "vpc" and p.get("ResourceId") in self._vpcs:
                    self.graph.edge(
                        f"vpc:{p['ResourceId']}",
                        tgw,
                        "configured",
                        "propagation",
                        f"TGW route table {rt['TransitGatewayRouteTableId']} learns routes "
                        f"propagated from {p['ResourceId']} ({p.get('State', '?')})",
                    )
        return len(atts)

    def _peering(self) -> int:
        conns = _pages(
            self._client("ec2"), "describe_vpc_peering_connections", "VpcPeeringConnections"
        )
        count = 0
        for p in conns:
            req = (p.get("RequesterVpcInfo") or {}).get("VpcId", "")
            acc = (p.get("AccepterVpcInfo") or {}).get("VpcId", "")
            status = (p.get("Status") or {}).get("Code", "?")
            for mine, peer in ((req, acc), (acc, req)):
                if mine in self._vpcs:
                    nid = self.graph.node("pcx", p["VpcPeeringConnectionId"])
                    self.graph.edge(
                        f"vpc:{mine}",
                        nid,
                        "configured",
                        "peering",
                        f"VPC peering {p['VpcPeeringConnectionId']} with {peer} ({status})",
                    )
                    count += 1
        return count

    def _route53(self) -> int:
        r53 = self._client("route53")
        zones = self._cap(
            "Route 53 private hosted zones",
            [
                z
                for z in _pages(r53, "list_hosted_zones", "HostedZones")
                if (z.get("Config") or {}).get("PrivateZone")
            ],
            MAX_PER_SOURCE,
        )
        for z in zones:
            vpcs = r53.get_hosted_zone(Id=z["Id"]).get("VPCs", [])
            for v in vpcs:
                if v.get("VPCId") in self._vpcs:
                    nid = self.graph.node("route53", z["Name"].rstrip("."))
                    self.graph.edge(
                        f"vpc:{v['VPCId']}",
                        nid,
                        "configured",
                        "DNS",
                        f"private hosted zone {z['Name'].rstrip('.')} is associated with "
                        f"{v['VPCId']}",
                    )
        return len(zones)

    def _resolver(self) -> int:
        res = self._client("route53resolver")
        rules = {r["Id"]: r for r in _pages(res, "list_resolver_rules", "ResolverRules")}
        assocs = _pages(res, "list_resolver_rule_associations", "ResolverRuleAssociations")
        for a in assocs:
            rule = rules.get(a.get("ResolverRuleId", ""))
            if not rule or a.get("VPCId") not in self._vpcs:
                continue
            domain = str(rule.get("DomainName", "")).rstrip(".")
            nid = self.graph.node("resolver", rule.get("Name") or domain or rule["Id"])
            self.graph.edge(
                f"vpc:{a['VPCId']}",
                nid,
                "configured",
                "DNS",
                f"Resolver rule {rule.get('RuleType', '?')} for {domain or '.'} is associated "
                f"with {a['VPCId']}",
            )
        return len(assocs)

    # Config resource types (and how the crawl names them) worth asking about.
    _CONFIG_TYPES = {
        "lambda": "AWS::Lambda::Function",
        "sqs": "AWS::SQS::Queue",
        "sns": "AWS::SNS::Topic",
        "dynamodb": "AWS::DynamoDB::Table",
        "s3": "AWS::S3::Bucket",
        "states": "AWS::StepFunctions::StateMachine",
    }

    def _config(self) -> int:
        """Relationships recorded by AWS Config (only if a recorder is recording).

        Only each item's ``relationships`` are read; its ``configuration`` is not."""
        cfg = self._client("config")
        status = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
        if not any(s.get("recording") for s in status):
            self._warn("AWS Config: no configuration recorder is recording; skipped")
            return 0
        items = self._cap(
            "AWS Config resource histories",
            [n for n in self.graph.nodes.values() if n.service in self._CONFIG_TYPES],
            MAX_CONFIG_ITEMS,
        )
        count = 0
        for n in items:
            rtype = self._CONFIG_TYPES[n.service]
            rid = n.arn if n.service == "sns" else n.name
            try:
                hist = cfg.get_resource_config_history(resourceType=rtype, resourceId=rid, limit=1)
            except ClientError:
                continue
            for item in hist.get("configurationItems", [])[:1]:
                for rel in item.get("relationships", []):
                    hits = self.graph.catalog.match(rel.get("resourceName")) or (
                        self.graph.catalog.match(rel.get("resourceId"))
                    )
                    for target in sorted(hits):
                        self.graph.edge(
                            n.node_id,
                            target,
                            "configured",
                            "AWS Config",
                            f"AWS Config: {n.name} {rel.get('relationshipName', 'is related to')} "
                            f"{self._label(target)}",
                        )
                        count += 1
        return count

    # X-Ray service types -> Extended view service.
    _XRAY_TYPES = {
        "AWS::Lambda::Function": "lambda",
        "AWS::Lambda": "lambda",
        "AWS::DynamoDB::Table": "dynamodb",
        "AWS::SQS::Queue": "sqs",
        "AWS::SNS": "sns",
        "AWS::SNS::Topic": "sns",
        "AWS::S3::Bucket": "s3",
        "AWS::StepFunctions::StateMachine": "states",
        "AWS::ECS::Container": "ecs",
    }

    def _xray(self) -> int:
        xray = self._client("xray")
        end = datetime.now(UTC)
        services = _pages(
            xray, "get_service_graph", "Services", StartTime=end - XRAY_WINDOW, EndTime=end
        )
        if not services:
            self._warn("X-Ray: no traces in the last hour; skipped")
            return 0
        by_ref: dict[int, str] = {}
        for s in services:
            svc = self._XRAY_TYPES.get(s.get("Type", ""))
            name = s.get("Name", "")
            if not svc:
                continue
            nid = node_id(svc, name)
            if nid not in self.graph.nodes:
                hits = [h for h in self.graph.catalog.match(name) if h.startswith(svc + ":")]
                nid = sorted(hits)[0] if hits else ""
            if nid:
                by_ref[s.get("ReferenceId", -1)] = nid
        count = 0
        for s in services:
            src = by_ref.get(s.get("ReferenceId", -1))
            for e in s.get("Edges", []):
                dst = by_ref.get(e.get("ReferenceId", -2))
                if src and dst:
                    total = (e.get("SummaryStatistics") or {}).get("TotalCount", 0)
                    self.graph.edge(
                        src,
                        dst,
                        "observed",
                        "X-Ray",
                        f"X-Ray service graph: {total} request(s) in the last hour",
                    )
                    count += 1
        return count


def latest_crawl(conn: sqlite3.Connection, snapshot_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT crawled_at, warnings, sources FROM ext_crawls WHERE snapshot_id=?", (snapshot_id,)
    ).fetchone()
    if row is None:
        return None
    warnings = json.loads(row["warnings"] or "[]")
    return {
        "crawled_at": row["crawled_at"],
        "warnings": warnings,
        "capped": [w for w in warnings if str(w).endswith(CAPPED_SUFFIX)],
        "sources": json.loads(row["sources"] or "{}"),
    }
