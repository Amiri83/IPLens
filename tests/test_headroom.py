"""Scale headroom: free IPs per subnet vs. the demand if everything scales to max.

Pure demand rules (iplens.headroom.analyze), the two optional collectors
(autoscaling:DescribeAutoScalingGroups, application-autoscaling:DescribeScalableTargets)
against moto, Retry skipped copying their tables, and the pages. Placeholders only:
192.0.2.N addresses, i-0abc1234-style ids, example names."""

from __future__ import annotations

import json
import random
import re
from collections import Counter

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from moto.core import DEFAULT_ACCOUNT_ID
from moto.ecs.models import ecs_backends

from iplens import collector as collector_mod
from iplens import headroom as hr
from iplens.aws import AwsGateway
from iplens.collector import (
    ASG_RESOURCE,
    SCALABLE_TARGETS_RESOURCE,
    Collector,
    asg_rows,
    ecs_scalable_target_rows,
    retry_plan,
)
from iplens.db import closing
from iplens.headroom import (
    Asg,
    EcsService,
    Inputs,
    LambdaFn,
    LoadBalancer,
    Subnet,
    analyze,
)
from iplens.web import create_app

REGION = "us-east-1"
SA, SB, SC = "subnet-a", "subnet-b", "subnet-c"
VPC = "vpc-a"


def _subnet(sid: str, az: str, free: int = 50, usable: int = 59, cidr: str = "") -> Subnet:
    return Subnet(sid, VPC, az, cidr or "192.0.2.0/26", free=free, usable=usable)


def _three(free: int = 50) -> list[Subnet]:
    return [
        _subnet(SA, "us-east-1a", free),
        _subnet(SB, "us-east-1b", free),
        _subnet(SC, "us-east-1c", free),
    ]


def _demand(result: hr.Headroom) -> dict[str, int]:
    return {s.subnet.subnet_id: s.demand for s in result.subnets}


# -- ASG ------------------------------------------------------------------------------------


def test_asg_spreads_the_instances_to_max_evenly_over_its_subnets():
    asg = Asg(
        "web",
        2,
        8,
        20,
        (SA, SB),
        tuple((f"i-0abc{n:04d}", "us-east-1a" if n % 2 else "us-east-1b") for n in range(8)),
    )
    inputs = Inputs(subnets=_three()[:2], asgs=[asg])
    result = analyze(inputs)
    assert _demand(result) == {SA: 6, SB: 6}
    (c,) = result.by_id[SA].contributors
    assert (c.kind, c.name, c.ips) == ("asg", "web", 6)
    assert c.text.startswith("ASG web: +6 (max 20, now 8: 6 instances here of 12 more")
    assert "1 ENI per instance assumed" in c.text  # no instance ENI in the snapshot


def test_asg_uneven_az_spread_gives_the_remainder_to_the_emptiest_subnets():
    # 2 instances in subnet-a, none elsewhere; max 9 -> 7 more over 3 subnets: 2 each and
    # the remainder to the subnet with the fewest instances (subnet-b before subnet-c).
    asg = Asg("web", 1, 2, 9, (SC, SA, SB), (("i-0abc0001", ""), ("i-0abc0002", "")))
    inputs = Inputs(
        subnets=_three(),
        asgs=[asg],
        instance_enis={"i-0abc0001": [SA], "i-0abc0002": [SA, SA]},
    )
    # ENIs per instance: ceil((1 + 2) / 2) = 2.
    assert _demand(analyze(inputs)) == {SA: 4, SB: 6, SC: 4}
    assert "2 ENIs per instance" in analyze(inputs).by_id[SB].contributors[0].assumption


def test_asg_places_current_instances_by_az_when_their_enis_are_unknown():
    # 4 instances in us-east-1b (no ENI rows): max 6 -> 2 more, both to the other subnets.
    asg = Asg(
        "web", 1, 4, 6, (SA, SB, SC), tuple((f"i-0abc000{n}", "us-east-1b") for n in range(4))
    )
    assert _demand(analyze(Inputs(subnets=_three(), asgs=[asg]))) == {SA: 1, SB: 0, SC: 1}


def test_asg_at_or_above_max_or_without_subnets_adds_nothing():
    full = Asg("full", 1, 2, 2, (SA,), (("i-0abc0001", ""), ("i-0abc0002", "")))
    nowhere = Asg("ec2-classic", 0, 0, 5, ())
    result = analyze(Inputs(subnets=_three(), asgs=[full, nowhere]))
    assert all(not s.contributors for s in result.subnets)


# -- ECS ------------------------------------------------------------------------------------


def test_ecs_service_scales_to_its_scalable_target_max_one_ip_per_task():
    svc = EcsService("cluster-a", "api", 4, 4, (SA, SB, SC))
    inputs = Inputs(
        subnets=_three(),
        ecs=[svc],
        ecs_max={("cluster-a", "api"): 8},
        task_subnets={("cluster-a", "api"): {SA: 2, SB: 2}},
    )
    result = analyze(inputs, include_surge=False)
    # 4 more tasks: 1 each, the remainder to subnet-c (no task there yet).
    assert _demand(result) == {SA: 1, SB: 1, SC: 2}
    assert result.by_id[SC].contributors[0].text == (
        "ECS service cluster-a/api: +2 (max 8, running 4: 2 tasks here of 4 more over "
        "3 subnets, 1 IP each)"
    )


def test_ecs_service_without_a_scalable_target_counts_up_to_its_desired_count():
    svc = EcsService("cluster-a", "api", 5, 3, (SA,))
    result = analyze(Inputs(subnets=_three(), ecs=[svc]), include_surge=False)
    assert _demand(result)[SA] == 2
    assert "no auto scaling, max = desired 5" in result.by_id[SA].contributors[0].assumption
    assert result.notes == []


def test_ecs_missing_scaling_permission_uses_what_is_known():
    svc = EcsService("cluster-a", "api", 5, 3, (SA,))
    inputs = Inputs(subnets=_three(), ecs=[svc], missing=frozenset({hr.SCALING_SOURCE}))
    result = analyze(inputs, include_surge=False)
    assert _demand(result)[SA] == 2
    assert "scaling unknown, max = desired 5" in result.by_id[SA].contributors[0].assumption
    assert result.notes == [
        "application-autoscaling:DescribeScalableTargets was skipped in this snapshot: ECS "
        "services are assumed not to scale beyond their desired count."
    ]


def test_ecs_subnets_fall_back_to_the_task_enis_and_unknown_subnets_are_a_note():
    old = EcsService("cluster-a", "old", 2, 2, None)  # snapshot before the subnets column
    lost = EcsService("cluster-a", "lost", 1, 1, None)
    bridge = EcsService("cluster-a", "bridge", 1, 1, ())  # not awsvpc: no IPs of its own
    inputs = Inputs(
        subnets=_three(),
        ecs=[old, lost, bridge],
        ecs_max={("cluster-a", "old"): 4, ("cluster-a", "bridge"): 9},
        task_subnets={("cluster-a", "old"): {SB: 2}},
    )
    result = analyze(inputs, include_surge=False)
    assert _demand(result) == {SA: 0, SB: 2, SC: 0}
    assert result.notes == ["ECS service cluster-a/lost: subnets unknown, not counted"]


# -- ECS deploy surge -----------------------------------------------------------------------


def _surge(result: hr.Headroom) -> dict[str, int]:
    return {
        s.subnet.subnet_id: sum(c.ips for c in s.contributors if c.kind == "surge")
        for s in result.subnets
    }


def test_surge_missing_max_percent_defaults_to_200_spread_unevenly():
    # Max 5 at the default 200%: 5 extra tasks over 3 subnets, 1 each and the remainder
    # to the subnets with the fewest tasks now (subnet-c, then subnet-a before subnet-b).
    svc = EcsService("cluster-a", "api", 4, 4, (SA, SB, SC))
    inputs = Inputs(
        subnets=_three(),
        ecs=[svc],
        ecs_max={("cluster-a", "api"): 5},
        task_subnets={("cluster-a", "api"): {SA: 2, SB: 2}},
    )
    result = analyze(inputs)
    assert _surge(result) == {SA: 2, SB: 1, SC: 2}
    surge = next(c for c in result.by_id[SA].contributors if c.kind == "surge")
    assert surge.text == (
        "ECS service cluster-a/api deploy surge: +2, maxPercent 200, the ECS default: 2 tasks "
        "here of 5 extra at max 5 over 3 subnets during a rolling deployment, 1 IP each"
    )
    # Its own contributor, next to the scale-out (1 more task, to subnet-c).
    assert [c.kind for c in result.by_id[SC].contributors] == ["surge", "ecs"]
    assert _demand(result) == {SA: 2, SB: 1, SC: 3}


def test_surge_rounds_up_and_uses_the_desired_count_without_a_scalable_target():
    # maxPercent 150 of desired 5 (no auto scaling): ceil(5 * 50 / 100) = 3 extra tasks.
    svc = EcsService("cluster-a", "api", 5, 5, (SA, SB), max_percent=150, controller="ECS")
    result = analyze(Inputs(subnets=_three(), ecs=[svc]))
    assert _surge(result) == {SA: 2, SB: 1, SC: 0}
    assert (
        result.by_id[SB]
        .contributors[0]
        .text.startswith(
            "ECS service cluster-a/api deploy surge: +1, maxPercent 150: 1 task here of 3 extra at "
            "max 5 over 2 subnets"
        )
    )


@pytest.mark.parametrize("controller", ["CODE_DEPLOY", "EXTERNAL"])
def test_surge_is_not_counted_for_non_rolling_deployment_controllers(controller):
    svc = EcsService("cluster-a", "api", 4, 4, (SA,), max_percent=200, controller=controller)
    assert _surge(analyze(Inputs(subnets=_three(), ecs=[svc]))) == {SA: 0, SB: 0, SC: 0}


@pytest.mark.parametrize("pct", [100, 50, 0])
def test_surge_is_not_counted_at_max_percent_100_or_less(pct):
    svc = EcsService("cluster-a", "api", 4, 4, (SA,), max_percent=pct)
    assert _surge(analyze(Inputs(subnets=_three(), ecs=[svc]))) == {SA: 0, SB: 0, SC: 0}


def test_surge_needs_awsvpc_subnets_and_falls_back_to_the_task_enis():
    bridge = EcsService("cluster-a", "bridge", 3, 3, ())  # not awsvpc: no IPs of its own
    lost = EcsService("cluster-a", "lost", 3, 3, None)  # subnets unknown
    old = EcsService("cluster-a", "old", 2, 2, None)  # subnets from its task ENIs
    inputs = Inputs(
        subnets=_three(),
        ecs=[bridge, lost, old],
        task_subnets={("cluster-a", "old"): {SB: 2}},
    )
    assert _surge(analyze(inputs)) == {SA: 0, SB: 2, SC: 0}


def test_include_surge_defaults_on_and_off_drops_the_surge_contributor():
    svc = EcsService("cluster-a", "api", 2, 2, (SA,), max_percent=200)
    inputs = Inputs(subnets=_three(), ecs=[svc], ecs_max={("cluster-a", "api"): 4})
    on = analyze(inputs)
    assert [(c.kind, c.ips) for c in on.by_id[SA].contributors] == [("surge", 4), ("ecs", 2)]
    off = analyze(inputs, include_surge=False)
    assert [(c.kind, c.ips) for c in off.by_id[SA].contributors] == [("ecs", 2)]
    assert on.by_id[SA].demand - off.by_id[SA].demand == 4


# -- ALB and Lambda -------------------------------------------------------------------------


def test_alb_reserves_eight_ips_per_subnet_and_other_lbs_none():
    inputs = Inputs(
        subnets=_three(),
        lbs=[
            LoadBalancer("alb-a", "application", (SA, SB)),
            LoadBalancer("nlb-a", "network", (SA, SB, SC)),
            # A snapshot from before the subnets column: the subnets of its ENIs.
            LoadBalancer("alb-old", "application", None),
        ],
        lb_eni_subnets={"alb-old": {SC}},
    )
    result = analyze(inputs)
    assert _demand(result) == {SA: 8, SB: 8, SC: 8}
    assert result.by_id[SA].contributors[0].text == (
        "ALB alb-a: +8 (AWS needs ≥ 8 free IPs per subnet to scale)"
    )


def test_lambda_only_needs_an_ip_for_a_new_subnet_security_group_combination():
    inputs = Inputs(
        subnets=_three(),
        lambdas=[
            LambdaFn("fn-a", (SA, SB), ("sg-a",)),
            LambdaFn("fn-b", (SB,), ("sg-a",)),  # shares fn-a's ENI in subnet-b
            LambdaFn("fn-c", (SC,), ("sg-b", "sg-a")),
            LambdaFn("fn-d", (), ()),  # not in a VPC
        ],
        lambda_combos={(SA, ("sg-a",)), (SC, ("sg-a", "sg-b"))},
    )
    result = analyze(inputs)
    assert _demand(result) == {SA: 0, SB: 1, SC: 0}
    (c,) = result.by_id[SB].contributors
    assert c.name == "fn-a, fn-b" and c.ips == 1
    assert "new subnet / security group combination (sg-a)" in c.assumption


# -- result ---------------------------------------------------------------------------------


def test_status_sorting_suggestion_and_az_imbalance():
    subnets = [
        _subnet(SA, "us-east-1a", free=20, usable=27),  # /27
        _subnet(SB, "us-east-1b", free=50, usable=59),
        _subnet(SC, "us-east-1b", free=50, usable=59),
    ]
    asg = Asg("web", 1, 0, 70, (SA, SB, SC))  # 70 more over 3 subnets: 24 / 23 / 23
    lbs = [LoadBalancer("alb-a", "application", (SB, SC))]
    result = analyze(Inputs(subnets=subnets, asgs=[asg], lbs=lbs))
    rows = {s.subnet.subnet_id: s for s in result.subnets}
    assert (rows[SA].demand, rows[SA].left, rows[SA].status) == (24, -4, hr.OVER)
    # 50 - 31 = 19 left of 59 usable (32%): OK; 20% would be tight.
    assert (rows[SB].demand, rows[SB].left, rows[SB].status) == (31, 19, hr.OK)
    assert [s.subnet.subnet_id for s in result.subnets] == [SA, SB, SC]  # worst first
    assert result.counts == {"over": 1, "tight": 0, "ok": 2}
    assert rows[SA].needed_prefix == 27  # 24 IPs fit a /27 (27 usable)
    assert rows[SA].suggestion == (
        "Short by 4 IPs at max scale: move the scaling resources to a /27 or larger subnet "
        "in us-east-1a, or add a secondary CIDR to vpc-a and create one there."
    )
    assert rows[SB].suggestion == "" and rows[SB].needed_prefix is None
    (vpc,) = result.by_az
    assert [(a.az, a.free, a.demand, a.status) for a in vpc.azs] == [
        ("us-east-1a", 20, 24, hr.OVER),
        ("us-east-1b", 100, 62, hr.OK),
    ]
    assert vpc.imbalanced


def test_tight_when_less_than_twenty_percent_of_the_usable_ips_are_left():
    subnets = [_subnet(SA, "us-east-1a", free=50, usable=100)]
    tight = analyze(Inputs(subnets=subnets, asgs=[Asg("web", 0, 0, 31, (SA,))]))
    ok = analyze(Inputs(subnets=subnets, asgs=[Asg("web", 0, 0, 30, (SA,))]))
    assert tight.subnets[0].status == hr.TIGHT  # 19 left
    assert ok.subnets[0].status == hr.OK  # 20 left


def test_missing_data_is_noted_and_nothing_scaling_is_ok():
    missing = frozenset({hr.ASG_SOURCE, hr.LB_SOURCE})
    result = analyze(Inputs(subnets=_three(), missing=missing))
    assert result.counts == {"over": 0, "tight": 0, "ok": 3}
    assert result.notes == [
        "autoscaling:DescribeAutoScalingGroups was skipped in this snapshot: Auto Scaling "
        "groups are not counted.",
        "elasticloadbalancing:DescribeLoadBalancers was skipped in this snapshot: ALB "
        "reserves are not counted.",
    ]
    assert analyze(Inputs(subnets=[])).subnets == []


def test_analyze_is_deterministic_whatever_the_input_order():
    def inputs(shuffle: random.Random | None) -> Inputs:
        asgs = [Asg(f"asg-{n}", 0, 0, 7 + n, (SA, SB, SC)) for n in range(3)]
        ecs = [EcsService("cluster-a", f"svc-{n}", 1, 1, (SC, SA)) for n in range(3)]
        lbs = [LoadBalancer(f"alb-{n}", "application", (SB, SA)) for n in range(2)]
        subnets = _three(free=80)
        if shuffle:
            for items in (asgs, ecs, lbs, subnets):
                shuffle.shuffle(items)
        return Inputs(subnets=subnets, asgs=asgs, ecs=ecs, lbs=lbs)

    first = analyze(inputs(None))
    for seed in range(5):
        again = analyze(inputs(random.Random(seed)))  # noqa: S311 - shuffling test input
        assert [(s.subnet, s.contributors) for s in again.subnets] == [
            (s.subnet, s.contributors) for s in first.subnets
        ]


def test_spread_and_required_prefix():
    assert hr.spread(5, [SB, SA], {}) == {SA: 3, SB: 2}
    assert hr.spread(1, [SA, SB], {SA: 3}) == {SB: 1}
    assert hr.spread(0, [SA], {}) == {} and hr.spread(3, [], {}) == {}
    assert hr.required_prefix(11) == 28 and hr.required_prefix(12) == 27
    assert hr.required_prefix(251) == 24 and hr.required_prefix(70_000) is None


def test_skipped_sources_from_snapshot_warnings():
    warnings = json.dumps(
        [
            "autoscaling:DescribeAutoScalingGroups skipped (AccessDenied)",
            "ECS enrichment skipped: ecs:ListClusters (AccessDenied); ...",
            "lambda:ListTags skipped (AccessDenied)",
        ]
    )
    assert hr.skipped_sources(warnings) == {hr.ASG_SOURCE, hr.ECS_SOURCE}
    assert hr.skipped_sources(None) == frozenset()


def test_row_helpers_parse_the_aws_responses():
    groups = [
        {
            "AutoScalingGroupName": "web",
            "MinSize": 1,
            "DesiredCapacity": 2,
            "MaxSize": 6,
            "VPCZoneIdentifier": "subnet-b, subnet-a,",
            "Instances": [
                {"InstanceId": "i-0abc0002", "AvailabilityZone": "us-east-1b"},
                {"InstanceId": "i-0abc0001", "AvailabilityZone": "us-east-1a"},
            ],
        }
    ]
    assert asg_rows(groups) == [
        (
            "web",
            1,
            2,
            6,
            '["subnet-a", "subnet-b"]',
            '[["i-0abc0001", "us-east-1a"], ["i-0abc0002", "us-east-1b"]]',
        )
    ]
    targets = [
        {
            "ResourceId": "service/cluster-a/api",
            "ScalableDimension": "ecs:service:DesiredCount",
            "MinCapacity": 2,
            "MaxCapacity": 10,
        },
        {"ResourceId": "service/cluster-a", "ScalableDimension": "ecs:service:DesiredCount"},
        {"ResourceId": "table/table-a", "ScalableDimension": "dynamodb:table:ReadCapacityUnits"},
    ]
    assert ecs_scalable_target_rows(targets) == [("cluster-a", "api", 2, 10)]


# -- snapshot inputs ------------------------------------------------------------------------


def _seed_snapshot(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "192.0.2.0/24")
    b.subnet(SA, VPC, "192.0.2.0/27", az="us-east-1a", name="app-a")
    b.subnet(SB, VPC, "192.0.2.64/26", az="us-east-1b", name="app-b")
    b.eni("eni-0abc0001", SA, ips("192.0.2.0", 4, 6), instance_id="i-0abc0001")
    b.eni("eni-0abc0002", SB, ["192.0.2.70"], owner_type="lambda", sgs=("sg-a",))
    b.eni("eni-0abc0003", SA, ["192.0.2.20"], owner_type="ecs")
    b.eni("eni-0abc0004", SB, ["192.0.2.71"], owner_type="elb", owner_ref="alb-old")
    b.lambda_fn("fn-a", VPC, [SA, SB], ["sg-a"])
    b.load_balancer("alb-old", VPC)  # subnet_ids NULL: from its ENIs
    b.ecs_service("cluster-a", "api", None, eni_ids=["eni-0abc0003"], desired=1)
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO asgs(snapshot_id, name, min_size, desired, max_size, subnet_ids, "
            "instances) VALUES(?,?,?,?,?,?,?)",
            (b.id, "web", 1, 1, 15, json.dumps([SA, SB]), '[["i-0abc0001", "us-east-1a"]]'),
        )
        conn.execute(
            "INSERT INTO ecs_scalable_targets(snapshot_id, cluster, service, min_capacity, "
            "max_capacity) VALUES(?,?,?,?,?)",
            (b.id, "cluster-a", "api", 1, 5),
        )
    return b


def test_load_reads_the_inputs_from_a_snapshot(db_path, snapshot_builder, ips):
    b = _seed_snapshot(db_path, snapshot_builder, ips)
    with closing(db_path) as conn:
        result = hr.for_snapshot(conn, b.id)
    rows = result.by_id
    # subnet-a /27: 27 usable, 7 IPs used -> 20 free. ASG: 14 more over 2 subnets, the
    # remainder-free split 7 / 7. ECS: max 5, running 1 -> 4 more in subnet-a (its task's
    # subnet); its deploy surge (maxPercent unset: 200) 5 extra there. Lambda: fn-a has no
    # ENI in subnet-a with sg-a yet -> +1.
    assert [(c.kind, c.ips) for c in rows[SA].contributors] == [
        ("asg", 7),
        ("surge", 5),
        ("ecs", 4),
        ("lambda", 1),
    ]
    assert (rows[SA].free, rows[SA].demand, rows[SA].status) == (20, 17, hr.TIGHT)  # 3 left
    with closing(db_path) as conn:
        off = hr.for_snapshot(conn, b.id, include_surge=False).by_id[SA]
    assert (off.demand, off.status) == (12, hr.OK)  # 8 of 27 left
    # subnet-b: the ASG's 7 and the old ALB's reserve (subnet of its ENI).
    assert [(c.kind, c.name, c.ips) for c in rows[SB].contributors] == [
        ("alb", "alb-old", 8),
        ("asg", "web", 7),
    ]


def test_scope_limits_the_subnets_not_the_spread(db_path, snapshot_builder, ips):
    from iplens.scope import ResolvedScope

    b = _seed_snapshot(db_path, snapshot_builder, ips)
    with closing(db_path) as conn:
        result = hr.for_snapshot(conn, b.id, ResolvedScope(subnet_ids=frozenset({SB})))
    assert [s.subnet.subnet_id for s in result.subnets] == [SB]
    assert result.by_id[SB].demand == 15


# -- pages ----------------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


def test_headroom_page_overview_column_and_report_section(app, snapshot_builder, ips):
    b = _seed_snapshot(_db(app), snapshot_builder, ips)
    with closing(_db(app)) as conn:  # push subnet-a over: a bigger ASG
        conn.execute("UPDATE asgs SET max_size=41 WHERE snapshot_id=?", (b.id,))
    client = app.test_client()

    page = client.get("/headroom").get_data(as_text=True)
    assert page.index(f'id="{SA}"') < page.index(f'id="{SB}"')  # worst first
    assert "ASG web: +20 (max 41, now 1" in page
    assert "ECS service cluster-a/api deploy surge: +5, maxPercent 200" in page
    assert "Short by 10 IPs at max scale" in page
    assert re.search(r'name="surge" value="1" checked', page)  # the toggle defaults on
    # 7 IPs used + 30 at max scale need a /26.
    assert "/cidr-planner?vpc=vpc-a&amp;size=26&amp;az=us-east-1a" in page
    assert "AZ imbalance" in page

    # Toggle off (the form's hidden surge=0 alone): no surge contributor.
    off = client.get("/headroom?surge=0").get_data(as_text=True)
    assert "deploy surge:" not in off and "Short by 5 IPs at max scale" in off
    assert not re.search(r'name="surge" value="1" checked', off)
    on = client.get("/headroom?surge=0&surge=1").get_data(as_text=True)
    assert "deploy surge: +5" in on

    overview = client.get("/").get_data(as_text=True)
    assert "<th title=" in overview and ">Headroom</th>" in overview
    assert f'href="/headroom#{SA}"' in overview and "over · -10 left" in overview

    report = client.get("/report").get_data(as_text=True)
    assert '<section id="scale-headroom">' in report
    section = report.split('<section id="scale-headroom">', 1)[1].split("</section>", 1)[0]
    assert "Short by 10 IPs at max scale" in section
    assert 'CIDR Planner: VPC <span class="mono">vpc-a</span>, a /26 in us-east-1a.' in section


def test_headroom_page_without_a_snapshot(app):
    assert "No data yet" in app.test_client().get("/headroom").get_data(as_text=True)


# -- collectors (moto) ----------------------------------------------------------------------


@pytest.fixture
def aws_env():
    """An ASG over two subnets, an awsvpc ECS service with a scalable target and an
    internal ALB, all in 192.0.2.0/24."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
        sa = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="192.0.2.0/26", AvailabilityZone="us-east-1a"
        )["Subnet"]["SubnetId"]
        sb = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="192.0.2.64/26", AvailabilityZone="us-east-1b"
        )["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="sg-a", Description="example", VpcId=vpc_id)[
            "GroupId"
        ]
        image_id = ec2.describe_images()["Images"][0]["ImageId"]
        ec2.create_launch_template(
            LaunchTemplateName="lt-a",
            LaunchTemplateData={"ImageId": image_id, "InstanceType": "t3.micro"},
        )
        boto3.client("autoscaling", region_name=REGION).create_auto_scaling_group(
            AutoScalingGroupName="web",
            MinSize=1,
            MaxSize=10,
            DesiredCapacity=2,
            LaunchTemplate={"LaunchTemplateName": "lt-a"},
            VPCZoneIdentifier=f"{sa},{sb}",
        )
        ecs = boto3.client("ecs", region_name=REGION)
        ecs.create_cluster(clusterName="cluster-a")
        ecs.register_task_definition(
            family="td-a",
            networkMode="awsvpc",
            containerDefinitions=[{"name": "app", "image": "example", "memory": 128}],
        )
        ecs.create_service(
            cluster="cluster-a",
            serviceName="api",
            taskDefinition="td-a",
            desiredCount=2,
            networkConfiguration={
                "awsvpcConfiguration": {"subnets": [sb, sa], "securityGroups": [sg]}
            },
        )
        boto3.client("application-autoscaling", region_name=REGION).register_scalable_target(
            ServiceNamespace="ecs",
            ResourceId="service/cluster-a/api",
            ScalableDimension="ecs:service:DesiredCount",
            MinCapacity=2,
            MaxCapacity=12,
        )
        boto3.client("elbv2", region_name=REGION).create_load_balancer(
            Name="alb-a", Subnets=[sa, sb], Scheme="internal", Type="application"
        )
        yield {"a": sa, "b": sb}


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _table(db_path, table: str, snap_id: int) -> list[tuple]:
    with closing(db_path) as conn:
        return [
            tuple(r)[1:]
            for r in conn.execute(
                f"SELECT * FROM {table} WHERE snapshot_id=? ORDER BY 2",  # noqa: S608 - constants
                (snap_id,),
            )
        ]


def test_collector_stores_asgs_scalable_targets_and_subnets(aws_env, db_path):
    sa, sb = aws_env["a"], aws_env["b"]
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == [] and result.warnings == []
    ((name, lo, desired, hi, subnets, instances),) = _table(db_path, "asgs", result.snapshot_id)
    assert (name, lo, desired, hi) == ("web", 1, 2, 10)
    assert json.loads(subnets) == sorted([sa, sb])
    assert len(json.loads(instances)) == 2
    assert _table(db_path, "ecs_scalable_targets", result.snapshot_id) == [
        ("cluster-a", "api", 2, 12)
    ]
    with closing(db_path) as conn:
        svc = conn.execute(
            "SELECT subnet_ids FROM ecs_services WHERE snapshot_id=?", (result.snapshot_id,)
        ).fetchone()
        lb = conn.execute(
            "SELECT subnet_ids FROM load_balancers WHERE snapshot_id=?", (result.snapshot_id,)
        ).fetchone()
        scale = hr.for_snapshot(conn, result.snapshot_id)
    assert json.loads(svc[0]) == sorted([sa, sb])
    assert json.loads(lb[0]) == sorted([sa, sb])
    kinds = {(c.kind, c.name) for s in scale.subnets for c in s.contributors}
    assert {("asg", "web"), ("ecs", "cluster-a/api"), ("alb", "alb-a")} <= kinds
    # ASG: 8 more over 2 subnets; ALB: 8 per subnet.
    assert sum(c.ips for s in scale.subnets for c in s.contributors if c.kind == "asg") == 8
    for sid in (sa, sb):  # (moto's default VPC has subnets of its own)
        assert [c.ips for c in scale.by_id[sid].contributors if c.kind == "alb"] == [8]


def test_collector_stores_max_percent_and_deployment_controller(aws_env, db_path):
    sa, sb = aws_env["a"], aws_env["b"]
    ecs = boto3.client("ecs", region_name=REGION)
    net = {"awsvpcConfiguration": {"subnets": [sa, sb], "securityGroups": []}}
    ecs.create_service(
        cluster="cluster-a",
        serviceName="worker",
        taskDefinition="td-a",
        desiredCount=4,
        networkConfiguration=net,
        deploymentConfiguration={"maximumPercent": 150, "minimumHealthyPercent": 100},
    )
    ecs.create_service(
        cluster="cluster-a",
        serviceName="bluegreen",
        taskDefinition="td-a",
        desiredCount=4,
        networkConfiguration=net,
        deploymentController={"type": "CODE_DEPLOY"},
        deploymentConfiguration={"maximumPercent": 200},
    )
    # moto drops deploymentConfiguration: set it on its service models (serialized as is).
    for svc in ecs_backends[DEFAULT_ACCOUNT_ID][REGION].services.values():
        pct = {"worker": 150, "bluegreen": 200}.get(svc.name)
        if pct:
            svc.deployment_configuration = {"maximumPercent": pct, "minimumHealthyPercent": 100}
    result = Collector(_gateway(), db_path).run()
    with closing(db_path) as conn:
        rows = {
            r["service"]: (r["max_percent"], r["deployment_controller"])
            for r in conn.execute(
                "SELECT service, max_percent, deployment_controller FROM ecs_services "
                "WHERE snapshot_id=?",
                (result.snapshot_id,),
            )
        }
        scale = hr.for_snapshot(conn, result.snapshot_id)
    assert rows["worker"] == (150, "ECS")
    assert rows["bluegreen"] == (200, "CODE_DEPLOY")
    surge = Counter()
    for s in scale.subnets:
        for c in s.contributors:
            if c.kind == "surge":
                surge[c.name] += c.ips
    # worker: ceil(4 * 50 / 100) = 2; bluegreen: none (not a rolling deployment).
    assert surge["cluster-a/worker"] == 2 and "cluster-a/bluegreen" not in surge


@pytest.mark.parametrize(
    ("op", "what", "table"),
    [
        ("describe_auto_scaling_groups", ASG_RESOURCE, "asgs"),
        ("describe_scalable_targets", SCALABLE_TARGETS_RESOURCE, "ecs_scalable_targets"),
    ],
)
def test_missing_permission_is_a_warning_and_headroom_uses_what_is_known(
    aws_env, db_path, monkeypatch, op, what, table
):
    real = collector_mod._paginate

    def paginate(client, name, key, **kwargs):
        if name == op:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, name)
        return real(client, name, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == [(what, "AccessDenied")]
    assert f"{what} skipped (AccessDenied)" in result.warnings
    assert _table(db_path, table, result.snapshot_id) == []
    with closing(db_path) as conn:
        scale = hr.for_snapshot(conn, result.snapshot_id)
    assert any(n.startswith(f"{what} was skipped in this snapshot") for n in scale.notes)
    # The rest of the demand is still counted.
    assert any(c.kind == "alb" for s in scale.subnets for c in s.contributors)


# -- Retry skipped --------------------------------------------------------------------------


def test_the_new_tables_are_part_of_the_retry_merge():
    merged = {
        table: sources for sources, tables, _tags in collector_mod._MERGED for table in tables
    }
    assert merged["asgs"] == frozenset({ASG_RESOURCE})
    assert merged["ecs_scalable_targets"] == frozenset({SCALABLE_TARGETS_RESOURCE})
    assert ASG_RESOURCE in retry_plan([ASG_RESOURCE])


def test_retry_copies_the_asg_and_scaling_tables_it_does_not_collect(aws_env, db_path, monkeypatch):
    source = Collector(_gateway(), db_path).run().snapshot_id
    tables = ("asgs", "ecs_scalable_targets", "ecs_services", "load_balancers")
    before = {t: _table(db_path, t, source) for t in tables}
    assert all(before.values())
    calls: list[str] = []
    real = collector_mod._paginate

    def paginate(client, op, key, **kwargs):
        calls.append(op)
        return real(client, op, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    retry = Collector(
        _gateway(), db_path, only=["ec2:DescribeVpcEndpoints"], source_snapshot=source
    ).run()
    assert retry.skipped == []
    assert "describe_auto_scaling_groups" not in calls
    assert "describe_scalable_targets" not in calls
    assert {t: _table(db_path, t, retry.snapshot_id) for t in tables} == before

    # Retrying one of them collects it again and copies the other.
    calls.clear()
    again = Collector(_gateway(), db_path, only=[ASG_RESOURCE], source_snapshot=source).run()
    assert "describe_auto_scaling_groups" in calls and "describe_scalable_targets" not in calls
    assert {t: _table(db_path, t, again.snapshot_id) for t in tables[:2]} == {
        t: before[t] for t in tables[:2]
    }
