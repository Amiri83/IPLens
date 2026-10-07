from datetime import UTC, datetime, timedelta

import pytest

from iplens import suggestions as sg
from iplens.db import closing
from iplens.rules import Rule, normalize_params

VPC = "vpc-0example0000001"
SA, SA2, SB, SC = "subnet-0000000a", "subnet-000000a2", "subnet-0000000b", "subnet-0000000c"
SQS = "com.amazonaws.us-east-1.sqs"
S3 = "com.amazonaws.us-east-1.s3"


@pytest.fixture
def ctx(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/22")
    b.subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    b.subnet(SA2, VPC, "10.0.1.0/24", az="us-east-1a")
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    b.subnet(SC, VPC, "10.0.3.0/24", az="us-east-1b")
    b.eni("eni-0000000ec2", SA, ips("10.0.0.0", 10, 200), owner_ref="i-0example0001")
    b.eni(
        "eni-00000000d1",
        SA,
        ["10.0.0.220", "10.0.0.221"],
        status="available",
        owner_type="other",
        description="example keep detached",
    )
    b.eni(
        "eni-00000000d2",
        SA,
        ["10.0.0.222"],
        status="available",
        owner_type="other",
        requester_managed=True,
    )
    b.eni("eni-00000000l1", SA, ["10.0.0.230"], owner_type="lambda", sgs=("sg-000a",))
    b.eni("eni-00000000l2", SA, ["10.0.0.231"], owner_type="lambda", sgs=("sg-000b",))
    b.eni("eni-00000000l3", SA2, ["10.0.1.10"], owner_type="lambda", sgs=("sg-000a",))
    b.eni("eni-00000000e1", SA, ["10.0.0.240"], owner_type="vpc_endpoint")
    b.eni("eni-00000000e2", SB, ["10.0.2.10"], owner_type="vpc_endpoint")
    b.eni("eni-00000000e3", SB, ["10.0.2.11"], owner_type="vpc_endpoint")
    b.eni("eni-00000000e4", SB, ["10.0.2.12"], owner_type="vpc_endpoint")
    b.eni("eni-0000000nat", SB, ["10.0.2.20"], owner_type="nat")
    b.endpoint("vpce-000000001", VPC, SQS, [SA, SB], ["eni-00000000e1", "eni-00000000e2"])
    b.endpoint("vpce-000000002", VPC, SQS, [SB], ["eni-00000000e3"])
    b.endpoint("vpce-000000003", VPC, S3, [SB], ["eni-00000000e4"])
    b.endpoint(
        "vpce-000000004", VPC, "com.amazonaws.us-east-1.dynamodb", [], [], endpoint_type="Gateway"
    )
    with closing(db_path) as conn:
        return sg.build_context(conn, b.id)


def _by_key(items):
    return {s.key: s for s in items}


def test_generates_expected_suggestions(ctx):
    items = _by_key(sg.generate(ctx, []))

    d = items["detached:eni-00000000d1"]
    assert d.ips_saved == 2 and d.eni_ids == ["eni-00000000d1"]
    assert "detached:eni-00000000d2" not in items  # AWS-managed ENIs are left alone

    combo = items[f"lambda-sg:{VPC}"]
    assert combo.ips_saved == 1 and combo.subnet_ids == [SA]

    spread = items[f"lambda-spread:{VPC}:us-east-1a"]
    assert spread.ips_saved == 1
    assert spread.target_subnets == {SA2: 1}
    assert spread.subnet_ids == [SA]

    novpc = items[f"lambda-novpc:{VPC}"]
    assert novpc.ips_saved == 3 and "lambda_detach_vpc" in novpc.flags

    dup = items[f"dup-endpoint:{VPC}:{SQS}"]
    assert dup.ips_saved == 1 and dup.eni_ids == ["eni-00000000e3"]
    assert "vpce-000000001" in dup.detail
    assert f"dup-endpoint:{VPC}:{S3}" not in items

    gw = items[f"gw-endpoint:{VPC}:{S3}"]
    assert gw.ips_saved == 1 and not gw.flags

    nat = items[f"endpoint-nat:{VPC}"]
    assert nat.ips_saved == 4 and "public_path:vpc_endpoint" in nat.flags

    az = items[f"az:{VPC}"]
    # us-east-1a: 200 ec2 + 3 idle + 3 lambda + 1 endpoint = 207; us-east-1b: 4
    assert az.target_subnets == {SC: (207 - 4) // 2}
    assert az.ips_saved == 0 and "headroom" in az.impact

    assert f"cidr:{VPC}" not in items  # only ~22% of subnet IPs consumed

    assert not any(s.blocked for s in items.values())


def test_rules_block_and_sort(ctx):
    rules = [
        Rule(name="lambda-in-vpc", kind="lambda_vpc_required"),
        Rule(name="internal", kind="internal_only", params={"scope": "both"}),
        Rule(name="reserved-c", kind="subnet_reserved", params={"subnet_ids": [SC]}),
        Rule(name="keep", kind="protected_eni", params={"pattern": "keep"}),
        Rule(name="free-99", kind="min_free_pct", params={"percent": 99.7, "subnet_ids": [SA2]}),
        Rule(name="disabled", kind="subnet_reserved", params={"subnet_ids": [SA]}, enabled=False),
    ]
    items = sg.generate(ctx, rules)
    by_key = _by_key(items)

    def blockers(key):
        return [name for name, _ in by_key[key].blocked_by]

    assert blockers(f"lambda-novpc:{VPC}") == ["lambda-in-vpc"]
    assert blockers(f"endpoint-nat:{VPC}") == ["internal"]
    assert blockers(f"az:{VPC}") == ["reserved-c"]
    assert blockers("detached:eni-00000000d1") == ["keep"]
    assert blockers(f"lambda-spread:{VPC}:us-east-1a") == ["free-99"]
    assert not by_key[f"gw-endpoint:{VPC}:{S3}"].blocked

    flags = [s.blocked for s in items]
    assert flags == sorted(flags)  # allowed first, blocked last
    totals = sg.totals(items)
    assert totals["blocked"] == 3 + 4 + 0 + 2 + 1
    assert totals["allowed"] == 1 + 1 + 1


def test_secondary_cidr(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc("vpc-0example0000002", "10.1.0.0/24")
    b.subnet("subnet-000000f1", "vpc-0example0000002", "10.1.0.0/24")
    b.eni("eni-00000000f1", "subnet-000000f1", ips("10.1.0.0", 4, 200))
    with closing(db_path) as conn:
        items = _by_key(sg.generate(sg.build_context(conn, b.id), []))
    s = items["cidr:vpc-0example0000002"]
    assert s.ips_saved == 0 and s.impact == "adds capacity"
    assert "100.64.0.0/10" in s.detail


@pytest.fixture
def ecs_ctx(db_path, snapshot_builder, ips):
    now = datetime.now(UTC)
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    # single-IP task ENIs, alternating between the two AZs
    free = {SA: iter(ips("10.0.0.0", 10, 20)), SB: iter(ips("10.0.2.0", 10, 20))}
    eni_ids: dict[str, list[str]] = {}
    for svc, n in (("idle-env", 10), ("busy-env", 10), ("small-env", 2)):
        eni_ids[svc] = [f"eni-{svc}-{i:02d}" for i in range(n)]
        for i, eni_id in enumerate(eni_ids[svc]):
            subnet = SA if i % 2 == 0 else SB
            b.eni(
                eni_id,
                subnet,
                [next(free[subnet])],
                owner_type="ecs",
                owner_ref=f"example-cluster/{svc}",
            )
    b.ecs_service("example-cluster", "idle-env", now - timedelta(days=90), eni_ids["idle-env"])
    b.ecs_service("example-cluster", "busy-env", now - timedelta(days=2), eni_ids["busy-env"])
    b.ecs_service("example-cluster", "small-env", now - timedelta(days=90), eni_ids["small-env"])
    b.ecs_service("example-cluster", "never-deployed", None)
    with closing(db_path) as conn:
        return sg.build_context(conn, b.id)


def test_ecs_idle_environment_suggestion(ecs_ctx):
    items = _by_key(sg.generate(ecs_ctx, []))
    ecs_items = {k: v for k, v in items.items() if v.kind == "ecs_idle_service"}
    # busy-env was deployed recently, small-env holds too few IPs
    assert list(ecs_items) == ["ecs-idle:example-cluster/idle-env"]
    s = ecs_items["ecs-idle:example-cluster/idle-env"]
    assert s.ips_saved == 10 and len(s.eni_ids) == 10
    assert s.subnet_ids == [SA, SB] and s.vpc_id == VPC
    assert "Scale down / delete idle environment" in s.title and "90 days" in s.detail
    assert s.flags == {"ecs_scale_down:example-cluster/idle-env"}
    assert s.kind_label == "Idle ECS environment"


@pytest.mark.parametrize(
    "params, blocked",
    [
        ({"mode": "deny", "pattern": ""}, True),  # deny all scale-downs
        ({"mode": "deny", "pattern": "/idle-"}, True),  # deny matching service
        ({"mode": "deny", "pattern": "^prod-"}, False),  # deny others only
        ({"mode": "allow", "pattern": "/idle-env$"}, False),  # on the allow-list
        ({"mode": "allow", "pattern": "^sandbox/"}, True),  # not on the allow-list
    ],
)
def test_ecs_scale_down_rule_allow_deny(ecs_ctx, params, blocked):
    rule = Rule(
        name="ecs-policy", kind="ecs_scale_down", params=normalize_params("ecs_scale_down", params)
    )
    items = _by_key(sg.generate(ecs_ctx, [rule]))
    s = items["ecs-idle:example-cluster/idle-env"]
    assert s.blocked is blocked
    assert ([n for n, _ in s.blocked_by] == ["ecs-policy"]) is blocked
    # the rule never touches non-ECS suggestions
    assert not any(v.blocked for v in items.values() if v.kind != "ecs_idle_service")


def test_ecs_scale_down_rule_validation():
    assert normalize_params("ecs_scale_down", {}) == {"mode": "deny", "pattern": ""}
    with pytest.raises(ValueError, match="allow mode needs a pattern"):
        normalize_params("ecs_scale_down", {"mode": "allow"})
    with pytest.raises(ValueError, match="mode must be one of"):
        normalize_params("ecs_scale_down", {"mode": "maybe"})


def test_no_az_suggestion_when_balanced(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    b.eni("eni-00000000a1", SA, ips("10.0.0.0", 10, 20))
    b.eni("eni-00000000b1", SB, ips("10.0.2.0", 10, 12))
    with closing(db_path) as conn:
        items = sg.generate(sg.build_context(conn, b.id), [])
    assert items == []
