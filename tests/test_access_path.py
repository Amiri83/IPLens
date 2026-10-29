"""Effective access, full path (iplens.access, 1.6.1): network ACLs (rule order, deny
rules, both directions with the ephemeral return ports), routes, KMS (simulation and key
policy), SCPs (allow / deny / not evaluated) and the blocked reason naming its layer.
Synthetic fixtures with placeholders only: 192.0.2.N, 123456789012, sqs-a, fn-a, key-a,
scp-a."""

from __future__ import annotations

import json
from typing import Any, NamedTuple

import boto3
import pytest
from moto import mock_aws

from iplens import access, extgraph, queries
from iplens.access import Nacls, Ports, Routes
from iplens.attribution import OWNER_LABELS
from iplens.aws import AwsGateway, is_read_only_operation
from iplens.db import closing
from iplens.extended import ExtendedCrawler
from tests.test_access import _moto_simulator, _seed_iam

REGION = "us-east-1"
ACCOUNT = "123456789012"
VPC = "vpc-0example0000001"
SUB_A, SUB_B, SUB_C = "subnet-0000000a", "subnet-0000000b", "subnet-0000000c"
NACL_A, NACL_B = "acl-0000000a", "acl-0000000b"
RTB = "rtb-0000000a"
HTTPS = Ports("tcp", 443, 443)
OPEN = [
    (True, 100, "-1", "0.0.0.0/0", None, None, "allow"),
    (False, 100, "-1", "0.0.0.0/0", None, None, "allow"),
]


class Peer(NamedTuple):
    name: str
    sgs: tuple[str, ...]
    ips: tuple[str, ...]


A = Peer("test-server-a", (), ("192.0.2.10",))
B = Peer("test-server-b", (), ("192.0.2.140",))


def _base(db_path, builder):
    b = builder(db_path)
    b.vpc(VPC, "192.0.2.0/24")
    b.subnet(SUB_A, VPC, "192.0.2.0/26").subnet(SUB_B, VPC, "192.0.2.128/26")
    b.subnet(SUB_C, VPC, "192.0.2.64/26")
    return b


def _nacls(db_path, builder, a_entries, b_entries) -> Nacls:
    b = _base(db_path, builder)
    b.nacl(NACL_A, [SUB_A], a_entries).nacl(NACL_B, [SUB_B], b_entries)
    with closing(db_path) as conn:
        return Nacls(conn, b.id)


def _check(nacls: Nacls, flow: Ports = HTTPS) -> access.Verdict | None:
    return nacls.check(A, SUB_A, B, SUB_B, flow)


# -- NACL --------------------------------------------------------------------------------


def test_nacl_open_both_ways(db_path, snapshot_builder):
    verdict = _check(_nacls(db_path, snapshot_builder, OPEN, OPEN))
    assert verdict.allowed
    assert verdict.lines == [
        f"NACL: {NACL_A} ({SUB_A}) outbound and {NACL_B} ({SUB_B}) inbound allow tcp/443; "
        "return traffic allowed on tcp/1024-65535"
    ]


@pytest.mark.parametrize(
    ("entries", "allowed"),
    [
        # The lower rule number wins: deny 90 before allow 100.
        ([(True, 90, "6", "192.0.2.128/26", 443, 443, "deny"), *OPEN], False),
        # The same deny after the allow never applies.
        ([*OPEN, (True, 200, "6", "192.0.2.128/26", 443, 443, "deny")], True),
        # A deny for another CIDR / port does not match the flow.
        ([(True, 90, "6", "192.0.2.0/26", 443, 443, "deny"), *OPEN], True),
        ([(True, 90, "6", "192.0.2.128/26", 80, 80, "deny"), *OPEN], True),
    ],
    ids=["deny-first", "deny-after-allow", "deny-other-cidr", "deny-other-port"],
)
def test_nacl_rule_order(db_path, snapshot_builder, entries, allowed):
    verdict = _check(_nacls(db_path, snapshot_builder, entries, OPEN))
    assert verdict.allowed is allowed, verdict.lines
    if not allowed:
        assert verdict.layers == ["NACL"]
        assert verdict.lines == [
            f"NACL: blocked: outbound of {NACL_A} ({SUB_A}): rule 90 denies tcp/443 – tcp/443 "
            "to test-server-b (192.0.2.140)"
        ]


def test_nacl_inbound_default_rule_denies(db_path, snapshot_builder):
    b_entries = [(True, 100, "-1", "0.0.0.0/0", None, None, "allow")]  # no inbound rule
    verdict = _check(_nacls(db_path, snapshot_builder, OPEN, b_entries))
    assert not verdict.allowed
    assert "inbound of acl-0000000b" in verdict.lines[0]
    assert "no rule allows it (rule * denies)" in verdict.lines[0]


def test_nacl_return_traffic_needs_the_ephemeral_ports(db_path, snapshot_builder):
    # B's outbound only allows tcp/443: the response to A's ephemeral port is refused.
    b_entries = [
        (True, 100, "6", "0.0.0.0/0", 443, 443, "allow"),
        (False, 100, "-1", "0.0.0.0/0", None, None, "allow"),
    ]
    verdict = _check(_nacls(db_path, snapshot_builder, OPEN, b_entries))
    assert not verdict.allowed
    assert verdict.lines[0].startswith(
        f"NACL: blocked: return traffic: outbound of {NACL_B} ({SUB_B}): no rule allows it"
    )
    assert "tcp/1024-65535 to test-server-a" in verdict.lines[0]


def test_nacl_ephemeral_deny_rule_on_the_way_back(db_path, snapshot_builder):
    # A's inbound denies the ephemeral range from B before allowing everything.
    a_entries = [(False, 50, "6", "192.0.2.128/26", 1024, 65535, "deny"), *OPEN]
    verdict = _check(_nacls(db_path, snapshot_builder, a_entries, OPEN))
    assert not verdict.allowed
    assert verdict.lines == [
        f"NACL: blocked: return traffic: inbound of {NACL_A} ({SUB_A}): rule 50 denies "
        "tcp/1024-65535 – tcp/1024-65535 from test-server-b (192.0.2.140)"
    ]


def test_nacl_partial_ephemeral_range_is_noted(db_path, snapshot_builder):
    a_entries = [
        (True, 100, "-1", "0.0.0.0/0", None, None, "allow"),
        (False, 100, "6", "192.0.2.128/26", 32768, 65535, "allow"),
    ]
    verdict = _check(_nacls(db_path, snapshot_builder, a_entries, OPEN))
    assert verdict.allowed
    assert (
        "return traffic allowed on tcp/32768-65535 (not all ephemeral ports" in (verdict.lines[0])
    )


def test_nacl_no_port_in_common(db_path, snapshot_builder):
    a_entries = [(True, 100, "6", "0.0.0.0/0", 80, 80, "allow"), OPEN[1]]
    b_entries = [OPEN[0], (False, 100, "6", "0.0.0.0/0", 443, 443, "allow")]
    verdict = _check(_nacls(db_path, snapshot_builder, a_entries, b_entries), Ports("tcp"))
    assert not verdict.allowed
    assert verdict.lines == [f"NACL: blocked: {NACL_A} and {NACL_B} allow no tcp port in common"]


def test_nacl_same_subnet_and_not_collected(db_path, snapshot_builder):
    nacls = _nacls(db_path, snapshot_builder, [], [])  # deny everything
    assert nacls.check(A, SUB_A, A, SUB_A, HTTPS).allowed  # not filtered inside a subnet
    assert nacls.check(A, SUB_A, B, SUB_C, HTTPS) is None  # SUB_C: no ACL in the snapshot


# -- routes ------------------------------------------------------------------------------


def _routes(db_path, builder, routes, subnets=(SUB_A,), main=False, endpoint=False) -> Routes:
    b = _base(db_path, builder)
    b.route_table(RTB, VPC, subnets, routes, main=main)
    if endpoint:
        b.endpoint("vpce-0example0001", VPC, f"com.amazonaws.{REGION}.sqs", [SUB_B], [])
    with closing(db_path) as conn:
        return Routes(conn, b.id)


@pytest.mark.parametrize(
    ("routes", "expected"),
    [
        ([("192.0.2.0/24", "local")], "via 192.0.2.0/24 → local (local)"),
        # The longest prefix wins over local.
        (
            [("192.0.2.0/24", "local"), ("192.0.2.128/26", "tgw-0example0001")],
            "via 192.0.2.128/26 → tgw-0example0001 (transit gateway)",
        ),
        ([("192.0.2.128/25", "pcx-0example0001")], "(VPC peering)"),
        ([("0.0.0.0/0", "nat-0example0001")], "(NAT gateway)"),
    ],
)
def test_route_found(db_path, snapshot_builder, routes, expected):
    verdict = _routes(db_path, snapshot_builder, routes).to_ip(SUB_A, B)
    assert verdict.allowed and expected in verdict.lines[0], verdict.lines


def test_missing_route_blocks(db_path, snapshot_builder):
    routes = _routes(db_path, snapshot_builder, [("192.0.2.0/26", "local")])
    verdict = routes.to_ip(SUB_A, B)
    assert not verdict.allowed and verdict.layers == ["route"]
    assert verdict.lines == [
        f"route: blocked: no route in {RTB} of {SUB_A} to test-server-b (192.0.2.140)"
    ]
    blackhole = _routes(
        db_path,
        snapshot_builder,
        [("192.0.2.0/24", "local"), ("192.0.2.128/26", "pcx-0example0001", "blackhole")],
    ).to_ip(SUB_A, B)
    assert not blackhole.allowed and "is a blackhole" in blackhole.lines[0]


def test_main_route_table_and_not_collected(db_path, snapshot_builder):
    routes = _routes(db_path, snapshot_builder, [("192.0.2.0/24", "local")], (), main=True)
    assert routes.to_ip(SUB_B, A).allowed  # no explicit association: the main table
    empty = _base(db_path, snapshot_builder)
    with closing(db_path) as conn:
        assert Routes(conn, empty.id).to_ip(SUB_A, B) is None


@pytest.mark.parametrize(
    ("routes", "endpoint", "public", "allowed", "text"),
    [
        ([], True, False, True, "through VPC endpoint vpce-0example0001"),
        ([("0.0.0.0/0", "nat-0example0001")], False, False, True, "(NAT gateway)"),
        ([("0.0.0.0/0", "igw-0example0001")], False, True, True, "(internet gateway)"),
        ([("0.0.0.0/0", "igw-0example0001")], False, False, False, "has no public IP"),
        ([("0.0.0.0/0", "tgw-0example0001")], False, False, True, "beyond the transit"),
        ([("0.0.0.0/0", "pcx-0example0001")], False, False, False, "does not reach sqs"),
        ([], False, False, False, "no VPC endpoint for sqs"),
    ],
)
def test_route_to_a_regional_service(
    db_path, snapshot_builder, routes, endpoint, public, allowed, text
):
    rts = _routes(
        db_path, snapshot_builder, [("192.0.2.0/24", "local"), *routes], endpoint=endpoint
    )
    verdict = rts.to_service(SUB_A, "sqs", "fn-a", public)
    assert verdict.allowed is allowed and text in verdict.lines[0], verdict.lines


# -- KMS / SCP policy evaluation -----------------------------------------------------------

ROLE = f"arn:aws:iam::{ACCOUNT}:role/role-task-a"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/key-a"


def _doc(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


ROOT = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        (
            _doc({"Effect": "Allow", "Principal": ROOT, "Action": "kms:*", "Resource": "*"}),
            "delegated",
        ),
        (
            _doc(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ROLE},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ),
            "allowed",
        ),
        (
            _doc(
                {"Effect": "Allow", "Principal": ROOT, "Action": "kms:*", "Resource": "*"},
                {
                    "Sid": "deny-a",
                    "Effect": "Deny",
                    "Principal": {"AWS": ROLE},
                    "Action": "kms:*",
                    "Resource": "*",
                },
            ),
            "explicitDeny",
        ),
        (
            _doc(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"{ROLE}-other"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ),
            "implicitDeny",
        ),
    ],
    ids=["root-delegates", "role-direct", "deny", "other-principal"],
)
def test_key_policy_decision(doc, expected):
    assert access.key_policy_decision(doc, ROLE, "kms:Decrypt", KEY)[0] == expected


FULL = ("scp-full", _doc({"Effect": "Allow", "Action": "*", "Resource": "*"}))
DENY_SQS = (
    "scp-a",
    _doc({"Sid": "no-sqs", "Effect": "Deny", "Action": "sqs:SendMessage", "Resource": "*"}),
)
ONLY_SNS = ("scp-a", _doc({"Effect": "Allow", "Action": "sns:*", "Resource": "*"}))


@pytest.mark.parametrize(
    ("levels", "decision", "detail"),
    [
        ([("r-a", [FULL]), (ACCOUNT, [FULL])], "allowed", "allowed by scp-full on r-a"),
        (
            [("r-a", [FULL]), ("ou-a", [FULL, DENY_SQS]), (ACCOUNT, [FULL])],
            "explicitDeny",
            "SCP scp-a (no-sqs) attached to ou-a denies it",
        ),
        # Every level must allow: the OU only allows SNS.
        (
            [("r-a", [FULL]), ("ou-a", [ONLY_SNS]), (ACCOUNT, [FULL])],
            "implicitDeny",
            "no SCP attached to ou-a allows it",
        ),
    ],
)
def test_scp_decision(levels, decision, detail):
    resource = f"arn:aws:sqs:{REGION}:{ACCOUNT}:sqs-a"
    got = access.scp_decision(levels, "sqs:SendMessage", resource)
    assert got[0] == decision and detail in got[1]


# -- the Visual page: every layer named in the blocked reason ------------------------------

TASK, ECR = "eni-000000task", "eni-0000ecrdkr"
HOLDER = "ecs:cluster-a/service-a"
REPO = f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/repo-a"
PULL = "ecr:BatchGetImage"


def _pull_snapshot(db_path, builder, *, sg_ok=True, nacls=True, routes=True):
    """service-a's task (SUB_C) pulls images through an ECR dkr endpoint ENI (SUB_A);
    the endpoint's group admits the task's group on tcp/443."""
    b = _base(db_path, builder)
    b.eni(
        TASK,
        SUB_C,
        ["192.0.2.70"],
        owner_type="ecs",
        owner_ref="cluster-a/service-a/0task",
        sgs=("sg-000task",),
    )
    b.ecs_service("cluster-a", "service-a", None, eni_ids=(TASK,))
    b.eni(
        ECR,
        SUB_A,
        ["192.0.2.20"],
        owner_type="vpc_endpoint",
        owner_ref="vpce-0example0001",
        sgs=("sg-00ecrdkr",),
    )
    b.endpoint("vpce-0example0001", VPC, f"com.amazonaws.{REGION}.ecr.dkr", [SUB_A], [ECR])
    for g in ("sg-000task", "sg-00ecrdkr"):
        b.security_group(g, vpc_id=VPC, egress_collected=True)
        b.sg_egress_cidr(g, "0.0.0.0/0")
    if sg_ok:
        b.sg_ref("sg-00ecrdkr", "ingress", "sg-000task", "tcp/443")
    else:  # only the task's egress names the endpoint: a (blocked) candidate
        b.sg_ref("sg-000task", "egress", "sg-00ecrdkr", "tcp/443")
    if nacls:
        b.nacl(NACL_A, [SUB_A], OPEN).nacl(NACL_B, [SUB_C], OPEN)
    if routes:
        b.route_table(RTB, VPC, (), [("192.0.2.0/24", "local")], main=True)
    return b


def _pull_edge(db_path, snap_id) -> dict[str, Any]:
    with closing(db_path) as conn:
        data = queries.visual_data(conn, snap_id, VPC, OWNER_LABELS)
    return next(e for e in data["edges"] if e["type"] == "reach" and e["source"] == TASK)


def _identity(b, pull="allowed", kms=None, scp=None):
    b.iam_principal(HOLDER, "execution", ROLE)
    b.iam_sim(ROLE, PULL, "*", pull, "policy-a")
    if kms is not None:
        b.kms_target(REPO, KEY, holder=HOLDER)
        b.kms_sim(ROLE, KEY, "kms:Decrypt", *kms)
    for action, resource, decision, detail in scp or []:
        b.scp_check(ACCOUNT, action, resource, decision, detail)
    return b


def test_all_layers_allow(db_path, snapshot_builder):
    b = _identity(
        _pull_snapshot(db_path, snapshot_builder),
        kms=("allowed", "policy-a", "delegated", "statement 1"),
        scp=[
            (PULL, "*", "allowed", "allowed by scp-full on r-a"),
            ("kms:Decrypt", KEY, "allowed", "allowed by scp-full on r-a"),
        ],
    )
    edge = _pull_edge(db_path, b.id)
    assert edge["blocked"] is False and edge["blocked_by"] == []
    text = "\n".join(edge["access"])
    for expected in (
        "ingress: sg-00ecrdkr",
        f"NACL: {NACL_B} ({SUB_C}) outbound and {NACL_A} ({SUB_A}) inbound allow tcp/443; "
        "return traffic allowed on tcp/1024-65535",
        f"(192.0.2.20) via 192.0.2.0/24 → local (local) in {RTB}",
        "IAM: role role-task-a of cluster-a/service-a allows ecr:BatchGetImage",
        "KMS: role role-task-a allows kms:Decrypt on key key-a (policy-a; the key policy "
        "delegates to IAM (statement 1))",
        f"SCP: account {ACCOUNT}: allowed by scp-full on r-a",
    ):
        assert expected in text, (expected, text)
    assert f"route: {SUB_C} to " in text


def test_not_collected_layers_are_noted_not_blocking(db_path, snapshot_builder):
    b = _pull_snapshot(db_path, snapshot_builder, nacls=False, routes=False)
    _identity(b)
    edge = _pull_edge(db_path, b.id)
    assert edge["blocked"] is False
    assert "NACL and route not checked (run the Extended crawl)" in edge["access"]
    # No Organizations data: marked, never failed.
    assert (
        "SCP not evaluated (no Organizations read access in the Extended crawl)" in (edge["access"])
    )


@pytest.mark.parametrize(
    ("layer", "setup", "detail"),
    [
        ("SG", {"sg_ok": False}, "blocked by ingress: no rule of sg-00ecrdkr"),
        (
            "NACL",
            {"nacl": [(False, 50, "6", "192.0.2.0/26", 1024, 65535, "deny"), *OPEN]},
            f"NACL: blocked: return traffic: inbound of {NACL_B} ({SUB_C}): rule 50 denies",
        ),
        ("route", {"route": [("192.0.2.64/26", "local")]}, "route: blocked: no route in"),
        ("IAM", {"pull": "implicitDeny"}, "IAM: blocked: no policy of role role-task-a"),
        (
            "endpoint policy",
            {
                "policy": _doc(
                    {"Effect": "Deny", "Principal": "*", "Action": "ecr:*", "Resource": "*"}
                )
            },
            "IAM: blocked by the endpoint policy of vpce-0example0001",
        ),
        (
            "KMS",
            {"kms": ("explicitDeny", "deny-kms", "delegated", "statement 1")},
            "KMS: blocked: role role-task-a: kms:Decrypt on key key-a explicitly denied by "
            "deny-kms",
        ),
        (
            "KMS",
            {"kms": ("allowed", "policy-a", "implicitDeny", "no statement allows it")},
            "KMS: blocked: the key policy of key-a allows kms:Decrypt to neither role "
            "role-task-a nor its account",
        ),
        (
            "KMS",
            {"kms": ("allowed", "policy-a", "explicitDeny", "deny-a")},
            "KMS: blocked: the key policy of key-a denies role role-task-a kms:Decrypt (deny-a)",
        ),
        (
            "SCP",
            {"scp": [(PULL, "*", "explicitDeny", "SCP scp-a (no-ecr) attached to ou-a denies it")]},
            f"SCP: blocked: ecr:BatchGetImage for account {ACCOUNT}: SCP scp-a (no-ecr)",
        ),
        (
            "SCP",
            {"pull": "implicitDeny", "detail": "no matching statement; not allowed by an SCP"},
            "IAM: blocked: no policy of role role-task-a",
        ),
    ],
    ids=[
        "sg",
        "nacl-ephemeral",
        "route",
        "iam",
        "endpoint-policy",
        "kms-simulate",
        "kms-key-policy-implicit",
        "kms-key-policy-deny",
        "scp",
        "scp-in-simulation",
    ],
)
def test_blocked_reason_names_the_layer(db_path, snapshot_builder, layer, setup, detail):
    b = _pull_snapshot(
        db_path, snapshot_builder, sg_ok=setup.get("sg_ok", True), nacls=False, routes=False
    )
    b.nacl(NACL_A, [SUB_A], OPEN).nacl(NACL_B, [SUB_C], setup.get("nacl", OPEN))
    b.route_table(RTB, VPC, (), setup.get("route", [("192.0.2.0/24", "local")]), main=True)
    if "policy" in setup:
        with closing(db_path) as conn:
            conn.execute(
                "UPDATE endpoints SET policy=? WHERE snapshot_id=?", (setup["policy"], b.id)
            )
    scp = setup.get("scp")
    if scp is None and "pull" not in setup:
        scp = [(PULL, "*", "allowed", "ok"), ("kms:Decrypt", KEY, "allowed", "ok")]
    b.iam_principal(HOLDER, "execution", ROLE)
    b.iam_sim(ROLE, PULL, "*", setup.get("pull", "allowed"), setup.get("detail", "policy-a"))
    b.kms_target(REPO, KEY, holder=HOLDER)
    b.kms_sim(ROLE, KEY, "kms:Decrypt", *setup.get("kms", ("allowed", "policy-a", "allowed", "s1")))
    for action, resource, decision, why in scp or []:
        b.scp_check(ACCOUNT, action, resource, decision, why)

    edge = _pull_edge(db_path, b.id)
    assert edge["blocked"] is True
    assert edge["blocked_by"] == [layer]
    assert edge["access"][0] == f"Blocked at layer: {layer}"
    assert any(ln.startswith(detail) for ln in edge["access"][1:]), edge["access"]


def test_resource_policy_and_kms_on_a_queue(db_path, snapshot_builder):
    queue = f"arn:aws:sqs:{REGION}:{ACCOUNT}:sqs-a"
    b = _base(db_path, snapshot_builder)
    b.iam_principal("lambda:fn-a", "lambda", ROLE)
    b.iam_sim(ROLE, "sqs:SendMessage", queue, "allowed", "policy-a", "explicitDeny")
    with closing(db_path) as conn:
        verdict = access.IamIndex(conn, b.id).check("lambda:fn-a", "sqs:SendMessage", queue)
    assert verdict.layers == ["resource policy"]
    assert access.reasons(verdict)[:2] == [
        "Blocked at layer: resource policy",
        "IAM: blocked: the resource policy of sqs-a denies role role-task-a of fn-a "
        "sqs:SendMessage ()",
    ]
    # An encrypted queue: sending needs kms:GenerateDataKey and kms:Decrypt on its key.
    c = _base(db_path, snapshot_builder)
    c.iam_principal("lambda:fn-a", "lambda", ROLE)
    c.iam_sim(ROLE, "sqs:SendMessage", queue, "allowed", "policy-a")
    c.kms_target(queue, KEY)
    c.kms_sim(ROLE, KEY, "kms:Decrypt", "allowed", "policy-a", "allowed", "s1")
    c.kms_sim(ROLE, KEY, "kms:GenerateDataKey", "implicitDeny", "", "delegated", "s1")
    with closing(db_path) as conn:
        verdict = access.IamIndex(conn, c.id).check("lambda:fn-a", "sqs:SendMessage", queue)
    assert verdict.layers == ["KMS"]
    assert (
        "KMS: blocked: no policy of role role-task-a allows kms:GenerateDataKey on key key-a"
        in (verdict.lines)
    )


# -- the Extended crawl (moto): NACLs, routes, KMS and SCPs stored and cached ---------------


def _moto_vpc(db_path, builder):
    """A moto VPC (default NACL and main route table) mirrored in a snapshot, fn-a's ENI in
    its subnet."""
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="192.0.2.0/25")["Subnet"]["SubnetId"]
    b = builder(db_path)
    b.vpc(vpc, "192.0.2.0/24").subnet(subnet, vpc, "192.0.2.0/25")
    b.eni(
        "eni-00000000fn",
        subnet,
        ["192.0.2.10"],
        owner_type="lambda",
        owner_ref="fn-a",
        sgs=("sg-0000fna",),
    )
    return b, vpc, subnet


def _rows(db_path, snap_id, table) -> list[tuple[Any, ...]]:
    with closing(db_path) as conn:
        return [
            tuple(r)[1:]
            for r in conn.execute(f"SELECT * FROM {table} WHERE snapshot_id=?", (snap_id,))  # noqa: S608
        ]


def _encrypted_queues() -> None:
    """fn-a may send to sqs-a and use KMS (its key key-a delegates to IAM); sqs-b's key's
    policy denies fn-a's role."""
    iam = boto3.client("iam", region_name=REGION)
    iam.put_role_policy(
        RoleName="role-fn-a",
        PolicyName="policy-kms-a",
        PolicyDocument=_doc({"Effect": "Allow", "Action": "kms:*", "Resource": "*"}),
    )
    kms = boto3.client("kms", region_name=REGION)
    root = {"Effect": "Allow", "Principal": ROOT, "Action": "kms:*", "Resource": "*"}
    role = f"arn:aws:iam::{ACCOUNT}:role/role-fn-a"
    deny = {
        "Sid": "deny-fn-a",
        "Effect": "Deny",
        "Principal": {"AWS": role},
        "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
        "Resource": "*",
    }
    key_a = kms.create_key(Description="key-a", Policy=_doc(root))["KeyMetadata"]["KeyId"]
    key_b = kms.create_key(Description="key-b", Policy=_doc(root, deny))["KeyMetadata"]["KeyId"]
    sqs = boto3.client("sqs", region_name=REGION)
    for name, key in (("sqs-a", key_a), ("sqs-b", key_b)):
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsMasterKeyId": key, "Policy": ""})


@mock_aws
def test_crawl_stores_nacls_routes_and_kms(db_path, snapshot_builder):
    _seed_iam()
    _encrypted_queues()
    b, vpc, subnet = _moto_vpc(db_path, snapshot_builder)
    session = boto3.session.Session(region_name=REGION)
    calls = _moto_simulator(session)
    result = ExtendedCrawler(AwsGateway(session), db_path, b.id).run()

    # The subnet's default NACL (rule 100 allows all both ways) and the main route table.
    (acl,) = {n for s, n in _rows(db_path, b.id, "nacl_subnets") if s == subnet}
    entries = _rows(db_path, b.id, "nacl_entries")
    assert (acl, 0, 100, "-1", "0.0.0.0/0", None, None, "allow") in entries
    assert (acl, 1, 100, "-1", "0.0.0.0/0", None, None, "allow") in entries
    assert not any(e[2] == 32767 for e in entries)  # the default rule * stays implicit
    (main,) = [rtb for rtb, v, s in _rows(db_path, b.id, "route_subnets") if v == vpc and s == ""]
    assert (main, "192.0.2.0/24", "local", "active") in _rows(db_path, b.id, "route_entries")

    # KMS: both queues' keys, both actions simulated per key; key policies evaluated.
    targets = {r[0].rsplit(":", 1)[1]: r[2] for r in _rows(db_path, b.id, "kms_targets")}
    assert set(targets) == {"sqs-a", "sqs-b"}
    sims = {
        (r[0].rsplit("/", 1)[1], r[1] == targets["sqs-a"], r[2]): (r[3], r[5])
        for r in _rows(db_path, b.id, "kms_sims")
    }
    assert sims[("role-fn-a", True, "kms:GenerateDataKey")] == ("allowed", "delegated")
    assert sims[("role-fn-a", False, "kms:Decrypt")] == ("allowed", "explicitDeny")
    assert sims[("role-fn-b", True, "kms:Decrypt")] == ("implicitDeny", "delegated")
    assert result.sources["kms:DescribeKey"] == len(sims)
    # Organizations is not in use: SCPs not evaluated, a warning, no rows.
    assert any(
        w.startswith("SCP not evaluated: Organizations not readable") for w in result.warnings
    )
    assert _rows(db_path, b.id, "scp_checks") == []

    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, vpc, OWNER_LABELS)
        ext = extgraph.extended_data(conn, b.id, data)
    lines = {
        (e["source"], e["target"]): e["lines"][0]["text"]
        for e in ext["edges"]
        if e["target"].startswith("x:sqs:")
    }
    a = lines[("eni-00000000fn", "x:sqs:sqs-a")]
    assert "KMS: role role-fn-a allows kms:GenerateDataKey on key" in a
    assert "SCP not evaluated" in a
    # No VPC endpoint for SQS and no default route: blocked at the route layer, and sqs-b's
    # key policy denies the role.
    assert "Blocked at layer: KMS, route" in lines[("eni-00000000fn", "x:sqs:sqs-b")]
    assert "the key policy of" in lines[("eni-00000000fn", "x:sqs:sqs-b")]

    # A second crawl asks nothing again (the KMS simulations are cached too).
    before = len(calls)
    ExtendedCrawler(AwsGateway(session), db_path, b.id).run()
    assert len(calls) == before


class _Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return [{"Policies": self.pages(kwargs["TargetId"])}]


class _FakeOrganizations:
    """An organization root r-a > OU ou-a > the account; scp-a on ou-a denies sending to
    queues. No management account id is reported, so SCPs apply to the account."""

    attached = {"r-a": ["p-full"], "ou-a": ["p-full", "p-a"], ACCOUNT: ["p-full"]}
    names = {"p-full": "scp-full", "p-a": "scp-a"}
    docs = {"p-full": FULL[1], "p-a": DENY_SQS[1]}

    def __init__(self):
        self.calls: list[str] = []

    def describe_organization(self):
        self.calls.append("DescribeOrganization")
        return {"Organization": {"Id": "o-example"}}

    def list_parents(self, ChildId):  # noqa: N803 - boto3 parameter name
        self.calls.append("ListParents")
        parent = {ACCOUNT: ("ou-a", "ORGANIZATIONAL_UNIT"), "ou-a": ("r-a", "ROOT")}.get(ChildId)
        return {"Parents": [{"Id": parent[0], "Type": parent[1]}] if parent else []}

    def get_paginator(self, op):
        assert op == "list_policies_for_target"
        self.calls.append("ListPoliciesForTarget")
        return _Pages(lambda t: [{"Id": p, "Name": self.names[p]} for p in self.attached[t]])

    def describe_policy(self, PolicyId):  # noqa: N803 - boto3 parameter name
        self.calls.append("DescribePolicy")
        return {"Policy": {"Content": self.docs[PolicyId]}}


@mock_aws
def test_crawl_evaluates_scps_when_organizations_is_readable(db_path, snapshot_builder):
    _seed_iam()
    b, vpc, _subnet = _moto_vpc(db_path, snapshot_builder)
    session = boto3.session.Session(region_name=REGION)
    _moto_simulator(session)
    org = _FakeOrganizations()

    class Crawler(ExtendedCrawler):
        def _client(self, service):
            return org if service == "organizations" else super()._client(service)

    Crawler(AwsGateway(session), db_path, b.id).run()
    rows = {
        (r[1], r[2].rsplit(":", 1)[1]): (r[3], r[4]) for r in _rows(db_path, b.id, "scp_checks")
    }
    assert rows[("sqs:SendMessage", "sqs-a")] == (
        "explicitDeny",
        "SCP scp-a (no-sqs) attached to ou-a denies it",
    )
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, vpc, OWNER_LABELS)
        ext = extgraph.extended_data(conn, b.id, data)
    edge = next(
        e for e in ext["edges"] if e["target"] == "x:sqs:sqs-a" and e["source"] == "eni-00000000fn"
    )
    assert edge["blocked"] and "SCP" in edge["blocked_by"]
    assert (
        f"SCP: blocked: sqs:SendMessage for account {ACCOUNT}: SCP scp-a"
        in edge["lines"][0]["text"]
    )
    # Cached: a second crawl does not read Organizations again.
    seen = len(org.calls)
    Crawler(AwsGateway(session), db_path, b.id).run()
    assert len(org.calls) == seen


@pytest.mark.parametrize(
    ("service", "op"),
    [
        ("kms", "DescribeKey"),
        ("kms", "GetKeyPolicy"),
        ("ecr", "DescribeRepositories"),
        ("organizations", "DescribeOrganization"),
        ("organizations", "ListParents"),
        ("organizations", "ListPoliciesForTarget"),
        ("organizations", "ListPolicies"),
        ("organizations", "ListTargetsForPolicy"),
        ("organizations", "DescribePolicy"),
        ("ec2", "DescribeNetworkAcls"),
    ],
)
def test_full_path_calls_are_read_only(service, op):
    assert is_read_only_operation(service, op)


@pytest.mark.parametrize(
    ("service", "op"),
    [("kms", "Decrypt"), ("kms", "GenerateDataKey"), ("organizations", "AttachPolicy")],
)
def test_kms_and_organizations_writes_stay_blocked(service, op):
    assert not is_read_only_operation(service, op)
