"""Effective access (iplens.access): security group checks on both sides of a flow, the
VPC endpoint case, IAM simulation (moto) and its per-snapshot cache. Placeholders only:
192.0.2.N addresses, 123456789012, example names."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any, NamedTuple

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from moto import mock_aws
from moto.iam.access_control import IAMPolicy, PermissionResult
from moto.iam.models import iam_backends

from iplens import access, extgraph, queries
from iplens.access import Ports, SgRules
from iplens.attribution import OWNER_LABELS
from iplens.aws import AwsGateway, _guard_read_only, is_read_only_operation
from iplens.db import closing
from iplens.extended import ExtendedCrawler

REGION = "us-east-1"
ACCOUNT = "123456789012"
VPC = "vpc-0example0000001"
SUB_A, SUB_B = "subnet-0000000a", "subnet-0000000b"
HTTPS = Ports("tcp", 443, 443)


class Peer(NamedTuple):
    name: str
    sgs: tuple[str, ...]
    ips: tuple[str, ...]


A = Peer("test-server-a", ("sg-000000a1", "sg-000000a2"), ("192.0.2.10",))
B = Peer("test-server-b", ("sg-000000b1", "sg-000000b2"), ("192.0.2.20",))


def _rules(db_path, snapshot_builder, rules, egress_collected=True) -> SgRules:
    """A snapshot holding A's and B's groups and ``rules``: (kind, group, peer, ports)."""
    b = snapshot_builder(db_path)
    for g in (*A.sgs, *B.sgs):
        b.security_group(g, vpc_id=VPC, egress_collected=egress_collected)
    for kind, group, peer, ports in rules:
        if kind in ("ingress", "egress"):
            b.sg_ref(group, kind, peer, ports)
        else:
            proto, lo, hi = ports
            if kind == "in_cidr":
                b.sg_cidr(group, peer, proto, lo, hi)
            else:
                b.sg_egress_cidr(group, peer, proto, lo, hi)
    with closing(db_path) as conn:
        return SgRules(conn, b.id, {"sg-000000b1": "example-b"})


# kind: ingress / egress (SG reference), in_cidr / out_cidr (CIDR rule).
EGRESS_ALL = ("out_cidr", "sg-000000a1", "0.0.0.0/0", ("-1", None, None))
MATRIX = [
    # Both sides by SG reference.
    (
        "sg-ref both sides",
        [
            ("egress", "sg-000000a1", "sg-000000b1", "tcp/443"),
            ("ingress", "sg-000000b1", "sg-000000a1", "tcp/443"),
        ],
        True,
    ),
    # Both sides by CIDR (egress to everything, ingress from A's /32).
    (
        "cidr both sides",
        [EGRESS_ALL, ("in_cidr", "sg-000000b1", "192.0.2.10/32", ("tcp", 443, 443))],
        True,
    ),
    # Ingress names B's peer by CIDR, egress by SG reference.
    (
        "mixed sg-ref and cidr",
        [
            ("egress", "sg-000000a2", "sg-000000b2", "all"),
            ("in_cidr", "sg-000000b2", "192.0.2.0/28", ("tcp", 400, 500)),
        ],
        True,
    ),
    # Union: only A's second group sends, only B's second group admits.
    (
        "union of groups",
        [
            ("egress", "sg-000000a2", "sg-000000b1", "tcp/443"),
            ("ingress", "sg-000000b2", "sg-000000a1", "tcp/443"),
        ],
        True,
    ),
    ("egress only", [EGRESS_ALL], False),
    ("ingress only", [("ingress", "sg-000000b1", "sg-000000a1", "tcp/443")], False),
    (
        "ingress CIDR misses A",
        [EGRESS_ALL, ("in_cidr", "sg-000000b1", "192.0.2.128/25", ("tcp", 443, 443))],
        False,
    ),
    (
        "wrong port",
        [EGRESS_ALL, ("ingress", "sg-000000b1", "sg-000000a1", "tcp/80")],
        False,
    ),
    (
        "egress to another group",
        [
            ("egress", "sg-000000a1", "sg-0000other", "all"),
            ("ingress", "sg-000000b1", "sg-000000a1", "all"),
        ],
        False,
    ),
    ("nothing", [], False),
]


@pytest.mark.parametrize(("case", "rules", "allowed"), MATRIX, ids=[m[0] for m in MATRIX])
def test_sg_matrix(db_path, snapshot_builder, case, rules, allowed):
    verdict = _rules(db_path, snapshot_builder, rules).check(A, B, HTTPS)
    assert verdict.allowed is allowed, (case, verdict.lines)
    if not allowed:
        assert any(ln.startswith("blocked") for ln in verdict.lines)


def test_blocked_reason_names_the_side_and_the_groups(db_path, snapshot_builder):
    rules = _rules(db_path, snapshot_builder, [EGRESS_ALL])
    verdict = rules.check(A, B, HTTPS)
    assert verdict.lines == [
        "blocked by ingress: no rule of sg-000000b1 (example-b), sg-000000b2 on "
        "test-server-b allows tcp/443 from test-server-a (192.0.2.10)"
    ]
    allowed = _rules(
        db_path,
        snapshot_builder,
        [EGRESS_ALL, ("ingress", "sg-000000b1", "sg-000000a1", "tcp/443")],
    ).check(A, B, HTTPS)
    assert (
        "ingress: sg-000000b1 (example-b) on test-server-b allows tcp/443 from "
        "sg-000000a1 (test-server-a)" in allowed.lines
    )


def test_no_common_port(db_path, snapshot_builder):
    rules = _rules(
        db_path,
        snapshot_builder,
        [
            ("egress", "sg-000000a1", "sg-000000b1", "tcp/80"),
            ("ingress", "sg-000000b1", "sg-000000a1", "tcp/443"),
        ],
    )
    verdict = rules.check(A, B, Ports("all"))
    assert not verdict.allowed
    assert "no port in common" in verdict.lines[0]


def test_unknown_rules_are_not_checked(db_path, snapshot_builder):
    # A snapshot from before 1.6.0: no egress CIDR rules collected, so only ingress decides.
    ingress = [("ingress", "sg-000000b1", "sg-000000a1", "tcp/443")]
    verdict = _rules(db_path, snapshot_builder, ingress, egress_collected=False).check(A, B, HTTPS)
    assert verdict.allowed
    assert any("egress of test-server-a not checked" in ln for ln in verdict.lines)
    # An ENI without security groups is not filtered on its side.
    open_peer = Peer("test-server-c", (), ("192.0.2.30",))
    assert _rules(db_path, snapshot_builder, [EGRESS_ALL]).check(A, open_peer, HTTPS).allowed


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("all", Ports("all")),
        ("tcp", Ports("tcp")),
        ("tcp/443", Ports("tcp", 443, 443)),
        ("udp/53-54", Ports("udp", 53, 54)),
        ("6/22", Ports("tcp", 22, 22)),
    ],
)
def test_parse_ports(text, expected):
    assert access.parse_ports(text) == expected


ROLE_A = f"arn:aws:iam::{ACCOUNT}:role/role-fn-a"
ROLE_B = f"arn:aws:iam::{ACCOUNT}:role/role-fn-b"


@pytest.mark.parametrize(
    ("statements", "principal", "expected"),
    [
        ([], ROLE_A, "implicitDeny"),
        (
            [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
            ROLE_A,
            "allowed",
        ),
        (
            [
                {"Effect": "Allow", "Principal": "*", "Action": "sqs:*", "Resource": "*"},
                {
                    "Sid": "deny-b",
                    "Effect": "Deny",
                    "Principal": {"AWS": ROLE_B},
                    "Action": "sqs:SendMessage",
                    "Resource": "*",
                },
            ],
            ROLE_B,
            "explicitDeny",
        ),
        (
            [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                    "Action": "SQS:sendmessage",
                    "Resource": "arn:aws:sqs:*:*:sqs-a",
                }
            ],
            ROLE_A,
            "allowed",
        ),
        (
            [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ROLE_B},
                    "Action": "sqs:SendMessage",
                    "Resource": "*",
                }
            ],
            ROLE_A,
            "implicitDeny",
        ),
    ],
)
def test_policy_decision(statements, principal, expected):
    doc = json.dumps({"Version": "2012-10-17", "Statement": statements})
    resource = f"arn:aws:sqs:{REGION}:{ACCOUNT}:sqs-a"
    assert access.policy_decision(doc, principal, "sqs:SendMessage", resource)[0] == expected


# -- the Visual page: VPC endpoint case, IAM on ECR, the Logical view -------------------

FN, TASK, ECR_API = "eni-00000000fn", "eni-000000task", "eni-0000ecrapi"
ROLE_TASK = f"arn:aws:iam::{ACCOUNT}:role/role-task-a"


def _endpoint_snapshot(db_path, builder, policy: str | None = None):
    """fn-a (Lambda) and service-a (ECS) both send tcp/443 towards an ECR api endpoint
    whose security group admits only the ECS tasks' group."""
    b = builder(db_path)
    b.vpc(VPC, "192.0.2.0/24").subnet(SUB_A, VPC, "192.0.2.0/25").subnet(
        SUB_B, VPC, "192.0.2.128/25", az="us-east-1b"
    )
    b.eni(FN, SUB_A, ["192.0.2.10"], owner_type="lambda", owner_ref="fn-a", sgs=("sg-0000fna",))
    b.eni(
        TASK,
        SUB_A,
        ["192.0.2.11"],
        owner_type="ecs",
        owner_ref="cluster-a/service-a/0task",
        sgs=("sg-000task",),
    )
    b.ecs_service("cluster-a", "service-a", None, eni_ids=(TASK,))
    b.eni(
        ECR_API,
        SUB_A,
        ["192.0.2.20"],
        owner_type="vpc_endpoint",
        owner_ref="vpce-0example0001",
        sgs=("sg-00ecrapi",),
    )
    b.eni(
        "eni-0000ecrapb",
        SUB_B,
        ["192.0.2.140"],
        owner_type="vpc_endpoint",
        owner_ref="vpce-0example0001",
        sgs=("sg-00ecrapi",),
    )
    b.endpoint(
        "vpce-0example0001",
        VPC,
        f"com.amazonaws.{REGION}.ecr.api",
        [SUB_A, SUB_B],
        [ECR_API, "eni-0000ecrapb"],
        policy=policy,
    )
    for g in ("sg-0000fna", "sg-000task", "sg-00ecrapi"):
        b.security_group(g, vpc_id=VPC, egress_collected=True)
        b.sg_egress_cidr(g, "0.0.0.0/0")
    b.sg_ref("sg-0000fna", "egress", "sg-00ecrapi", "tcp/443")
    b.sg_ref("sg-00ecrapi", "ingress", "sg-000task", "tcp/443")
    return b


def _data(db_path, snap_id):
    with closing(db_path) as conn:
        return queries.visual_data(conn, snap_id, VPC, OWNER_LABELS)


def _reach(data) -> dict[str, dict[str, Any]]:
    return {e["source"]: e for e in data["edges"] if e["type"] == "reach"}


def test_lambda_not_linked_to_an_endpoint_admitting_only_ecs_tasks(db_path, snapshot_builder):
    b = _endpoint_snapshot(db_path, snapshot_builder)
    data = _data(db_path, b.id)
    reach = _reach(data)
    assert reach[TASK]["blocked"] is False
    assert reach[FN]["blocked"] is True
    assert any(
        ln.startswith("blocked by ingress: no rule of sg-00ecrapi") and "fn-a" in ln
        for ln in reach[FN]["access"]
    )
    counts = {t["type"]: (t["count"], t["blocked"]) for t in data["edge_types"]}
    assert counts["reach"] == (1, 1)
    # IAM was not simulated (no crawl yet): noted, not blocking.
    assert (
        "IAM: ecr:GetAuthorizationToken not checked (run the Extended crawl)"
        in (reach[TASK]["access"])
    )


@pytest.mark.parametrize(
    ("decision", "policy", "blocked", "reason"),
    [
        ("allowed", None, False, "IAM: role role-task-a of cluster-a/service-a allows"),
        ("implicitDeny", None, True, "IAM: blocked: no policy of role role-task-a"),
        ("explicitDeny", None, True, "explicitly denied by deny-ecr"),
        (
            "allowed",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Sid": "only-fn",
                            "Effect": "Allow",
                            "Principal": {"AWS": ROLE_A},
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            ),
            True,
            "IAM: blocked by the endpoint policy of vpce-0example0001 (no statement allows it)",
        ),
    ],
)
def test_iam_and_endpoint_policy_on_ecr_edges(
    db_path, snapshot_builder, decision, policy, blocked, reason
):
    b = _endpoint_snapshot(db_path, snapshot_builder, policy)
    b.iam_principal("ecs:cluster-a/service-a", "execution", ROLE_TASK)
    b.iam_sim(ROLE_TASK, "ecr:GetAuthorizationToken", "*", decision, "deny-ecr")
    edge = _reach(_data(db_path, b.id))[TASK]
    assert edge["blocked"] is blocked
    assert any(reason in ln for ln in edge["access"]), edge["access"]


def test_logical_view_keeps_blocked_edges_apart(db_path, snapshot_builder):
    from iplens.logical import annotate_zones, logical_view

    b = _endpoint_snapshot(db_path, snapshot_builder)
    data = _data(db_path, b.id)
    view = logical_view(data)
    reach = [e for e in view["edges"] if e["type"] == "reach"]
    assert {(e["source"], e["blocked"]) for e in reach} == {
        ("lambda:fn-a", True),
        ("ecs:cluster-a/service-a", False),
    }
    assert next(e for e in reach if e["blocked"])["id"].endswith("!blocked")
    # The IP view's "3 AZ" badge: every ENI carries its logical resource's AZs.
    annotate_zones(data)
    zones = {r["eni_id"]: r["zones_all"] for s in data["vpc"]["subnets"] for r in s["items"]}
    assert zones[ECR_API] == ["us-east-1a", "us-east-1b"]
    assert zones[FN] == ["us-east-1a"]


# -- IAM simulation in the Extended crawl (moto) ------------------------------------------


def _moto_simulator(session: boto3.session.Session) -> list[dict[str, Any]]:
    """Answer iam:SimulatePrincipalPolicy from moto's stored role policies.

    moto 5 does not implement the call; this evaluates the role's inline and attached
    policies with moto's own policy evaluator. The read-only guard runs first, as it
    would for a real call. Returns the list of calls made."""
    calls: list[dict[str, Any]] = []

    def handler(model=None, params=None, **_: Any):
        _guard_read_only(model=model)
        body = params["body"]
        role = iam_backends[ACCOUNT]["global"].get_role(body["PolicySourceArn"].rsplit("/", 1)[1])
        actions = [v for k, v in sorted(body.items()) if k.startswith("ActionNames.member.")]
        resource = body.get("ResourceArns.member.1", "*")
        calls.append({"role": body["PolicySourceArn"], "actions": actions, "resource": resource})
        docs = [*role.policies.items()] + [
            (p.name, next(v.document for v in p.versions if v.is_default))
            for p in role.managed_policies.values()
        ]
        results = []
        for action in actions:
            decision, matched = "implicitDeny", []
            for name, doc in docs:
                verdict = IAMPolicy(doc).is_action_permitted(action, resource)
                if verdict == PermissionResult.DENIED:
                    decision, matched = "explicitDeny", [name]
                    break
                if verdict == PermissionResult.PERMITTED:
                    decision = "allowed"
                    matched.append(name)
            results.append(
                {
                    "EvalActionName": action,
                    "EvalResourceName": resource,
                    "EvalDecision": decision,
                    "MatchedStatements": [{"SourcePolicyId": m} for m in matched],
                }
            )
        parsed = {
            "EvaluationResults": results,
            "IsTruncated": False,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }
        return AWSResponse("https://iam.amazonaws.com/", 200, {}, None), parsed

    session.events.register("before-call.iam.SimulatePrincipalPolicy", handler)
    return calls


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("handler.py", "def handler(event, context):\n    return None\n")
    return buf.getvalue()


def _seed_iam() -> dict[str, str]:
    """fn-a (may send to any queue) and fn-b (no policy) both name sqs-a and sqs-b in an
    environment variable; sqs-b's queue policy denies fn-a's role."""
    iam = boto3.client("iam", region_name=REGION)
    assume = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    roles = {
        n: iam.create_role(RoleName=f"role-{n}", AssumeRolePolicyDocument=assume)["Role"]["Arn"]
        for n in ("fn-a", "fn-b")
    }
    iam.put_role_policy(
        RoleName="role-fn-a",
        PolicyName="policy-fn-a",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
            }
        ),
    )
    sqs = boto3.client("sqs", region_name=REGION)
    url_a = sqs.create_queue(QueueName="sqs-a")["QueueUrl"]
    url_b = sqs.create_queue(
        QueueName="sqs-b",
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "deny-fn-a",
                            "Effect": "Deny",
                            "Principal": {"AWS": roles["fn-a"]},
                            "Action": "sqs:SendMessage",
                            "Resource": f"arn:aws:sqs:{REGION}:{ACCOUNT}:sqs-b",
                        }
                    ],
                }
            )
        },
    )["QueueUrl"]
    lam = boto3.client("lambda", region_name=REGION)
    for name in ("fn-a", "fn-b"):
        lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=roles[name],
            Handler="handler.handler",
            Code={"ZipFile": _zip()},
            Environment={"Variables": {"QUEUE_A": url_a, "QUEUE_B": url_b}},
        )
    return roles


def _sims(db_path, snap_id) -> dict[tuple[str, str], tuple[str, str]]:
    with closing(db_path) as conn:
        return {
            (r["role_arn"].rsplit("/", 1)[1], r["resource"].rsplit(":", 1)[1]): (
                r["decision"],
                r["resource_decision"],
            )
            for r in conn.execute(
                "SELECT * FROM iam_sims WHERE snapshot_id=? AND action='sqs:SendMessage'",
                (snap_id,),
            )
        }


def _crawl_snapshot(db_path, snapshot_builder):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "192.0.2.0/24").subnet(SUB_A, VPC, "192.0.2.0/25")
    b.eni(FN, SUB_A, ["192.0.2.10"], owner_type="lambda", owner_ref="fn-a", sgs=("sg-0000fna",))
    return b


@mock_aws
def test_crawl_simulates_allowed_and_denied_principals(db_path, snapshot_builder):
    _seed_iam()
    b = _crawl_snapshot(db_path, snapshot_builder)
    session = boto3.session.Session(region_name=REGION)
    calls = _moto_simulator(session)
    result = ExtendedCrawler(AwsGateway(session), db_path, b.id).run()

    assert result.sources["iam:SimulatePrincipalPolicy"] == 4
    assert {c["role"].rsplit("/", 1)[1] for c in calls} == {"role-fn-a", "role-fn-b"}
    assert _sims(db_path, b.id) == {
        ("role-fn-a", "sqs-a"): ("allowed", ""),
        ("role-fn-a", "sqs-b"): ("allowed", "explicitDeny"),  # the queue policy denies
        ("role-fn-b", "sqs-a"): ("implicitDeny", ""),
        ("role-fn-b", "sqs-b"): ("implicitDeny", "implicitDeny"),
    }
    with closing(db_path) as conn:
        principals = {
            (r["holder"], r["purpose"])
            for r in conn.execute("SELECT * FROM iam_principals WHERE snapshot_id=?", (b.id,))
        }
        # Only ids and decisions are stored, never a policy document.
        stored = json.dumps([tuple(r) for r in conn.execute("SELECT * FROM iam_sims")])
    assert {("lambda:fn-a", "lambda"), ("lambda:fn-b", "lambda")} <= principals
    assert "Statement" not in stored and "deny-fn-a" in stored

    # The Extended view: fn-a -> sqs-a effective; fn-a -> sqs-b and fn-b -> both blocked.
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC, OWNER_LABELS)
        ext = extgraph.extended_data(conn, b.id, data)
    blocked = {
        (e["source"], e["target"]): e["blocked"]
        for e in ext["edges"]
        if e["target"].startswith("x:sqs:")
    }
    assert blocked == {
        (FN, "x:sqs:sqs-a"): False,
        (FN, "x:sqs:sqs-b"): True,
        ("x:lambda:fn-b", "x:sqs:sqs-a"): True,
        ("x:lambda:fn-b", "x:sqs:sqs-b"): True,
    }
    line = next(e for e in ext["edges"] if e["target"] == "x:sqs:sqs-b" and e["source"] == FN)
    assert "the resource policy of sqs-b denies role role-fn-a" in line["lines"][0]["text"]


@mock_aws
def test_simulations_are_cached_per_snapshot(db_path, snapshot_builder):
    _seed_iam()
    b = _crawl_snapshot(db_path, snapshot_builder)
    session = boto3.session.Session(region_name=REGION)
    calls = _moto_simulator(session)
    ExtendedCrawler(AwsGateway(session), db_path, b.id).run()
    first = len(calls)
    before = _sims(db_path, b.id)
    assert first == 4 and len(before) == 4

    # A second crawl of the same snapshot reuses every cached result.
    ExtendedCrawler(AwsGateway(session), db_path, b.id).run()
    assert len(calls) == first
    assert _sims(db_path, b.id) == before

    # A new snapshot has its own cache.
    c = _crawl_snapshot(db_path, snapshot_builder)
    ExtendedCrawler(AwsGateway(session), db_path, c.id).run()
    assert len(calls) == 2 * first


def test_simulate_principal_policy_is_allowlisted():
    assert is_read_only_operation("iam", "SimulatePrincipalPolicy")
    assert not is_read_only_operation("iam", "SimulateCustomPolicy")
    assert not is_read_only_operation("iam", "PutRolePolicy")
