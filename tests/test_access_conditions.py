"""Effective access, conditions and edge states (1.6.2): aws:SourceVpce / SourceVpc /
PrincipalArn / PrincipalAccount / PrincipalOrgID evaluated locally, ContextEntries for the
simulation, an unknown key or operator => unverified, and the "IAM not checked" banner.
Placeholders only: 192.0.2.N, 123456789012, vpce-a, vpc-a, fn-a, sqs-a, key-a, org-a."""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest
from moto import mock_aws

from iplens import access, queries
from iplens.access import CONDITIONAL, EXPLICIT_DENY, IMPLICIT_DENY
from iplens.attribution import OWNER_LABELS
from iplens.aws import AwsGateway
from iplens.db import closing
from iplens.extended import ExtendedCrawler
from iplens.web import create_app
from tests.test_access import (
    ACCOUNT,
    REGION,
    ROLE_TASK,
    SUB_A,
    TASK,
    VPC,
    _endpoint_snapshot,
    _moto_simulator,
    _seed_iam,
)
from tests.test_access_path import _FakeOrganizations

QUEUE = f"arn:aws:sqs:{REGION}:{ACCOUNT}:sqs-a"
ROLE_FN = f"arn:aws:iam::{ACCOUNT}:role/role-fn-a"
ENDPOINT = "vpce-0example0001"  # the ECR api endpoint of tests.test_access
PULL = "ecr:GetAuthorizationToken"


def _doc(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _st(effect: str, condition: dict[str, Any] | None = None, sid: str = "") -> dict[str, Any]:
    st: dict[str, Any] = {"Sid": sid or effect.lower(), "Effect": effect, "Principal": "*"}
    st |= {"Action": "*", "Resource": "*"}
    return st | ({"Condition": condition} if condition else {})


ALLOW_ALL = _st("Allow", sid="allow-all")


# -- the condition evaluator ----------------------------------------------------------------


def _decide(condition: dict[str, Any], context: dict[str, str | None], effect: str = "Allow"):
    statements = [_st(effect, condition, "cond")]
    if effect == "Deny":
        statements.insert(0, ALLOW_ALL)
    return access.policy_decision(
        _doc(*statements), ROLE_FN, "sqs:SendMessage", QUEUE, context=context
    )[0]


NOT_IN_VPC = {**access.principal_context(ROLE_FN, "o-orga"), **access.network_context(None, None)}
VIA_VPCE_A = {
    **access.principal_context(ROLE_FN, "o-orga"),
    **access.network_context("vpce-a", "vpc-a"),
}


@pytest.mark.parametrize(
    ("condition", "context", "effect", "expected"),
    [
        # aws:SourceVpce: a Deny unless through vpce-a.
        ({"StringNotEquals": {"aws:SourceVpce": "vpce-a"}}, NOT_IN_VPC, "Deny", EXPLICIT_DENY),
        ({"StringNotEquals": {"aws:SourceVpce": "vpce-a"}}, VIA_VPCE_A, "Deny", "allowed"),
        (
            {"StringNotEqualsIfExists": {"aws:SourceVpce": "vpce-a"}},
            NOT_IN_VPC,
            "Deny",
            EXPLICIT_DENY,
        ),
        ({"StringEquals": {"aws:SourceVpce": "vpce-a"}}, NOT_IN_VPC, "Allow", IMPLICIT_DENY),
        ({"StringEqualsIfExists": {"aws:SourceVpce": "vpce-a"}}, NOT_IN_VPC, "Allow", "allowed"),
        ({"StringEquals": {"aws:SourceVpc": "vpc-a"}}, VIA_VPCE_A, "Allow", "allowed"),
        ({"StringLike": {"aws:SourceVpc": "vpc-*"}}, VIA_VPCE_A, "Allow", "allowed"),
        ({"StringNotLike": {"aws:SourceVpc": "vpc-*"}}, VIA_VPCE_A, "Allow", IMPLICIT_DENY),
        # aws:PrincipalArn / PrincipalAccount / PrincipalOrgID.
        ({"ArnEquals": {"aws:PrincipalArn": ROLE_FN}}, NOT_IN_VPC, "Allow", "allowed"),
        (
            {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/role-*"}},
            NOT_IN_VPC,
            "Allow",
            "allowed",
        ),
        # Arn wildcards stay within one colon-separated part.
        ({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*"}}, NOT_IN_VPC, "Allow", IMPLICIT_DENY),
        (
            {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/admin-*"}},
            NOT_IN_VPC,
            "Deny",
            EXPLICIT_DENY,
        ),
        ({"StringEquals": {"aws:PrincipalAccount": ACCOUNT}}, NOT_IN_VPC, "Allow", "allowed"),
        (
            {"StringEquals": {"aws:PrincipalOrgID": ["o-other", "o-orga"]}},
            NOT_IN_VPC,
            "Allow",
            "allowed",
        ),
        # Every operator and key must hold.
        (
            {
                "StringEquals": {"aws:PrincipalAccount": ACCOUNT},
                "StringNotEquals": {"aws:PrincipalOrgID": "o-orga"},
            },
            NOT_IN_VPC,
            "Allow",
            IMPLICIT_DENY,
        ),
        # Not evaluated locally: an unknown key or operator, or a key the context lacks.
        ({"StringEquals": {"aws:SourceIp": "192.0.2.10"}}, NOT_IN_VPC, "Allow", CONDITIONAL),
        ({"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}, NOT_IN_VPC, "Allow", CONDITIONAL),
        ({"Bool": {"aws:SecureTransport": "false"}}, NOT_IN_VPC, "Deny", CONDITIONAL),
        ({"StringEquals": {"aws:SourceVpce": "vpce-a"}}, {}, "Allow", CONDITIONAL),
        # A false part decides even next to an unknown one.
        (
            {
                "StringEquals": {"aws:PrincipalAccount": "000000000000"},
                "IpAddress": {"aws:SourceIp": "192.0.2.0/24"},
            },
            NOT_IN_VPC,
            "Allow",
            IMPLICIT_DENY,
        ),
    ],
)
def test_conditions(condition, context, effect, expected):
    assert _decide(condition, context, effect) == expected


def test_source_vpce_deny_blocks_a_sender_outside_the_vpc():
    """A queue policy that denies anything not coming through vpce-a: fn-a (not in a VPC,
    so aws:SourceVpce is absent) is denied, the same role through vpce-a is not."""
    doc = _doc(
        ALLOW_ALL,
        _st("Deny", {"StringNotEquals": {"aws:SourceVpce": "vpce-a"}}, "only-vpce-a"),
    )
    out = access.policy_decision(doc, ROLE_FN, "sqs:SendMessage", QUEUE, context=NOT_IN_VPC)
    assert out == (EXPLICIT_DENY, "only-vpce-a")
    out = access.policy_decision(doc, ROLE_FN, "sqs:SendMessage", QUEUE, context=VIA_VPCE_A)
    assert out == ("allowed", "allow-all")


ROLE_ECS = f"arn:aws:iam::{ACCOUNT}:role/ecs-task-role"
ROLE_LAMBDA = f"arn:aws:iam::{ACCOUNT}:role/lambda-a"
ASSUMED_ECS = f"arn:aws:sts::{ACCOUNT}:assumed-role/ecs-task-role/i-0abc1234"


def _not_principal_deny(*names: str) -> str:
    deny = {"Sid": "only-ecs", "Effect": "Deny", "NotPrincipal": {"AWS": list(names)}}
    return _doc(ALLOW_ALL, deny | {"Action": "*", "Resource": "*"})


@pytest.mark.parametrize(
    ("not_principal", "principal", "expected"),
    [
        # A queue policy denying everyone but the ECS task role.
        (ROLE_ECS, ROLE_LAMBDA, EXPLICIT_DENY),
        (ROLE_ECS, ROLE_ECS, "allowed"),
        # An assumed-role principal matches the role form, and the reverse.
        (ROLE_ECS, ASSUMED_ECS, "allowed"),
        (ROLE_ECS, f"arn:aws:sts::{ACCOUNT}:assumed-role/lambda-a/fn-a", EXPLICIT_DENY),
        (ASSUMED_ECS, ROLE_ECS, "allowed"),
        (ASSUMED_ECS, ROLE_LAMBDA, EXPLICIT_DENY),
        # The account (id or root) names every role in it.
        (f"arn:aws:iam::{ACCOUNT}:root", ROLE_LAMBDA, "allowed"),
        (ACCOUNT, ROLE_LAMBDA, "allowed"),
        ("arn:aws:iam::000000000000:root", ROLE_LAMBDA, EXPLICIT_DENY),
        # Same role name in another account is another role.
        ("arn:aws:iam::000000000000:role/lambda-a", ROLE_LAMBDA, EXPLICIT_DENY),
    ],
)
def test_not_principal_deny_applies_to_every_principal_it_does_not_name(
    not_principal, principal, expected
):
    doc = _not_principal_deny(not_principal)
    out = access.policy_decision(doc, principal, "sqs:SendMessage", QUEUE, context=NOT_IN_VPC)
    assert out[0] == expected
    assert out[1] == ("only-ecs" if expected == EXPLICIT_DENY else "allow-all")


def test_scp_with_an_unevaluated_condition_is_conditional():
    deny = _doc(ALLOW_ALL, _st("Deny", {"ArnNotLike": {"aws:PrincipalArn": "arn:*:role/x"}}))
    levels = [("r-a", [("scp-full", _doc(ALLOW_ALL)), ("scp-guard", deny)])]
    context = {"aws:principalaccount": ACCOUNT}  # SCP rows are per account: no principal ARN
    decision, detail = access.scp_decision(levels, "sqs:SendMessage", QUEUE, context)
    assert decision == CONDITIONAL and "scp-guard" in detail and "aws:PrincipalArn" in detail


# -- iam:SimulatePrincipalPolicy: ContextEntries ---------------------------------------------


class _FakeIam:
    def __init__(self, missing: list[str]):
        self.missing = missing
        self.calls: list[dict[str, Any]] = []

    def get_paginator(self, op):
        assert op == "simulate_principal_policy"
        return self

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        return [
            {
                "EvaluationResults": [
                    {
                        "EvalActionName": a,
                        "EvalDecision": "allowed",
                        "MatchedStatements": [{"SourcePolicyId": "policy-a"}],
                        "ResourceSpecificResults": [{"MissingContextValues": self.missing}],
                    }
                    for a in kwargs["ActionNames"]
                ]
            }
        ]


def test_simulation_gets_context_entries_and_unknown_keys_make_it_conditional():
    req = access.SimRequest(ROLE_FN, "sqs:SendMessage", QUEUE)
    iam = _FakeIam(missing=["aws:SourceVpce"])
    out = list(access.simulate(iam, [req], set(), lambda _r: NOT_IN_VPC))
    entries = {e["ContextKeyName"]: e["ContextKeyValues"] for e in iam.calls[0]["ContextEntries"]}
    assert entries == {
        "aws:PrincipalArn": [ROLE_FN],
        "aws:PrincipalAccount": [ACCOUNT],
        "aws:PrincipalOrgID": ["o-orga"],
    }
    # aws:SourceVpce is known to be absent: the simulator's answer stands.
    assert out == [(req, "allowed", "policy-a")]

    iam = _FakeIam(missing=["aws:SourceIp"])
    ((_, decision, detail),) = access.simulate(iam, [req], set(), lambda _r: NOT_IN_VPC)
    assert decision == CONDITIONAL and "aws:SourceIp not evaluated" in detail


@mock_aws
def test_crawl_evaluates_queue_policy_conditions_with_the_request_context(
    db_path, snapshot_builder
):
    """fn-a is not in a VPC (aws:SourceVpce absent): sqs-a's "only through vpce-a" Deny
    applies. The organization id is read once and cached for the snapshot."""
    roles = _seed_iam()
    sqs = boto3.client("sqs", region_name=REGION)
    deny = _st("Deny", {"StringNotEquals": {"aws:SourceVpce": "vpce-a"}}, "only-vpce-a")
    sqs.set_queue_attributes(
        QueueUrl=sqs.get_queue_url(QueueName="sqs-a")["QueueUrl"],
        Attributes={"Policy": _doc(ALLOW_ALL, deny)},
    )
    b = snapshot_builder(db_path)
    b.vpc(VPC, "192.0.2.0/24").subnet(SUB_A, VPC, "192.0.2.0/25")
    b.lambda_fn("fn-a", None).lambda_fn("fn-b", None)
    session = boto3.session.Session(region_name=REGION)
    _moto_simulator(session)
    org = _FakeOrganizations()

    class Crawler(ExtendedCrawler):
        def _client(self, service):
            return org if service == "organizations" else super()._client(service)

    Crawler(AwsGateway(session), db_path, b.id).run()
    with closing(db_path) as conn:
        row = conn.execute(
            "SELECT resource_decision, resource_detail FROM iam_sims WHERE snapshot_id=? "
            "AND role_arn=? AND resource=?",
            (b.id, roles["fn-a"], QUEUE),
        ).fetchone()
        org_id = conn.execute(
            "SELECT org_id FROM iam_context WHERE snapshot_id=?", (b.id,)
        ).fetchone()[0]
    assert tuple(row) == (EXPLICIT_DENY, "only-vpce-a")
    assert org_id == "o-example"
    assert org.calls.count("DescribeOrganization") == 1


# -- edge states on the Visual page ------------------------------------------------------------


def _verified_path(b) -> None:
    """Every layer of service-a -> the ECR endpoint checked: route, IAM, SCP (one subnet,
    so the NACLs do not filter)."""
    b.route_table("rtb-0000000a", VPC, [SUB_A], [("192.0.2.0/24", "local")])
    b.iam_principal("ecs:cluster-a/service-a", "execution", ROLE_TASK)
    b.iam_sim(ROLE_TASK, PULL, "*", "allowed", "policy-ecr")
    b.scp_check(ACCOUNT, PULL, "*", "allowed", "allowed by scp-full on r-a")


def _task_edge(db_path, snap_id) -> dict[str, Any]:
    with closing(db_path) as conn:
        data = queries.visual_data(conn, snap_id, VPC, OWNER_LABELS)
    return next(e for e in data["edges"] if e["type"] == "reach" and e["source"] == TASK)


def test_principal_arn_allow_passes_and_is_verified(db_path, snapshot_builder):
    policy = _doc(
        _st("Allow", {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/role-task-*"}})
    )
    b = _endpoint_snapshot(db_path, snapshot_builder, policy)
    _verified_path(b)
    edge = _task_edge(db_path, b.id)
    assert edge["state"] == "allowed" and edge["unverified"] == []
    assert any(
        f"the endpoint policy of {ENDPOINT} allows it (allow (condition met))" in ln
        for ln in edge["access"]
    ), edge["access"]


def test_principal_arn_mismatch_blocks_at_the_endpoint_policy(db_path, snapshot_builder):
    policy = _doc(_st("Allow", {"ArnEquals": {"aws:PrincipalArn": ROLE_FN}}))
    b = _endpoint_snapshot(db_path, snapshot_builder, policy)
    _verified_path(b)
    edge = _task_edge(db_path, b.id)
    assert edge["state"] == "blocked" and edge["blocked_by"] == ["endpoint policy"]


def test_source_vpce_deny_in_an_endpoint_policy_blocks(db_path, snapshot_builder):
    # The request goes through vpce-0example0001, not vpce-a: the Deny applies.
    policy = _doc(ALLOW_ALL, _st("Deny", {"StringNotEquals": {"aws:SourceVpce": "vpce-a"}}))
    b = _endpoint_snapshot(db_path, snapshot_builder, policy)
    _verified_path(b)
    edge = _task_edge(db_path, b.id)
    assert edge["blocked"] is True and edge["state"] == "blocked"
    assert edge["access"][0] == "Blocked at layer: endpoint policy"
    # Through the right endpoint (and its VPC) the same Deny does not apply.
    policy = _doc(
        ALLOW_ALL,
        _st("Deny", {"StringNotEquals": {"aws:SourceVpce": ENDPOINT, "aws:SourceVpc": VPC}}),
    )
    c = _endpoint_snapshot(db_path, snapshot_builder, policy)
    _verified_path(c)
    assert _task_edge(db_path, c.id)["state"] == "allowed"


def test_not_principal_deny_in_an_endpoint_policy(db_path, snapshot_builder):
    # Deny everyone but the lambda role: the ECS task's role is denied.
    b = _endpoint_snapshot(db_path, snapshot_builder, _not_principal_deny(ROLE_LAMBDA))
    _verified_path(b)
    edge = _task_edge(db_path, b.id)
    assert edge["state"] == "blocked" and edge["blocked_by"] == ["endpoint policy"]
    # Deny everyone but the ECS task's role: it passes.
    c = _endpoint_snapshot(db_path, snapshot_builder, _not_principal_deny(ROLE_TASK))
    _verified_path(c)
    assert _task_edge(db_path, c.id)["state"] == "allowed"


def test_unknown_condition_key_makes_the_edge_unverified(db_path, snapshot_builder):
    policy = _doc(_st("Allow", {"StringEquals": {"aws:SourceIp": "192.0.2.11"}}))
    b = _endpoint_snapshot(db_path, snapshot_builder, policy)
    _verified_path(b)
    edge = _task_edge(db_path, b.id)
    assert edge["blocked"] is False and edge["state"] == "unverified"
    assert edge["unverified"] == ["endpoint policy conditional"]
    assert edge["access"][0] == "Unverified: endpoint policy conditional"
    assert any("condition aws:SourceIp not evaluated" in ln for ln in edge["access"])


def test_a_layer_not_checked_makes_the_edge_unverified(db_path, snapshot_builder):
    # No Extended crawl data at all: SG checked (and no NACL inside one subnet), the rest not.
    b = _endpoint_snapshot(db_path, snapshot_builder)
    edge = _task_edge(db_path, b.id)
    assert edge["state"] == "unverified"
    assert edge["unverified"] == ["route not checked", "IAM not checked"]
    assert edge["access"][0] == "Unverified: route not checked, IAM not checked"


def test_conditional_kms_and_scp_rows_are_unverified(db_path, snapshot_builder):
    b = _endpoint_snapshot(db_path, snapshot_builder)
    b.route_table("rtb-0000000a", VPC, [SUB_A], [("192.0.2.0/24", "local")])
    b.iam_principal("ecs:cluster-a/service-a", "execution", ROLE_TASK)
    b.iam_sim(ROLE_TASK, PULL, "*", CONDITIONAL, "policy-ecr; condition aws:SourceIp")
    b.scp_check(ACCOUNT, PULL, "*", CONDITIONAL, "conditional: SCP scp-guard")
    edge = _task_edge(db_path, b.id)
    assert edge["state"] == "unverified"
    assert edge["unverified"] == ["IAM conditional", "SCP conditional"]


# -- "IAM not checked" banner --------------------------------------------------------------------


def test_banner_when_the_snapshot_has_no_extended_crawl(home, snapshot_builder):
    app = create_app(home, testing=True)
    db_path = app.extensions["iplens"]["paths"].db_path
    b = _endpoint_snapshot(db_path, snapshot_builder)
    client = app.test_client()
    page = client.get(f"/visual?vpc={VPC}").data.decode()
    assert 'id="iam-banner"' in page and "IAM not checked – run Extended crawl" in page
    assert 'id="verified-only"' in page

    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO ext_crawls(snapshot_id, crawled_at) VALUES(?, '2026-01-01T00:00:00')",
            (b.id,),
        )
    page = client.get(f"/visual?vpc={VPC}").data.decode()
    assert 'id="iam-banner"' not in page
