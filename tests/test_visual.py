"""Visual page edges and label shortening (synthetic 10.0.x.x data only)."""

import pytest

from iplens import queries, visual
from iplens.db import closing

VPC = "vpc-0example0000001"
PUB_A, PUB_B = "subnet-0000pub0a", "subnet-0000pub0b"
APP_A, APP_B = "subnet-0000app0a", "subnet-0000app0b"

ALB_A, ALB_B = "eni-00000alb0a", "eni-00000alb0b"
WEB_1, WEB_2 = "eni-00000web01", "eni-00000web02"
TASK_1, TASK_2 = "eni-0000task01", "eni-0000task02"
VPCE, FN = "eni-0000vpce01", "eni-00000fn001"


def seed_edge_topology(db_path, builder):
    """A two-AZ ALB in front of two EC2 instances, an ECS service and a Lambda."""
    b = builder(db_path)
    b.vpc(VPC, "10.0.0.0/16", name="example-vpc")
    b.subnet(PUB_A, VPC, "10.0.0.0/24", az="us-east-1a", name="example-public-a")
    b.subnet(PUB_B, VPC, "10.0.10.0/24", az="us-east-1b", name="example-public-b")
    b.subnet(APP_A, VPC, "10.0.1.0/24", az="us-east-1a", name="example-app-a")
    b.subnet(APP_B, VPC, "10.0.2.0/24", az="us-east-1b", name="example-app-b")
    for eni, subnet, ip in ((ALB_A, PUB_A, "10.0.0.10"), (ALB_B, PUB_B, "10.0.10.10")):
        b.eni(eni, subnet, [ip], owner_type="elb", owner_ref="example-alb", sgs=("sg-0000alb",))
    for eni, subnet, ip, instance in (
        (WEB_1, APP_A, "10.0.1.10", "i-0example0001"),
        (WEB_2, APP_B, "10.0.2.10", "i-0example0002"),
    ):
        b.eni(eni, subnet, [ip], owner_ref=instance, instance_id=instance, sgs=("sg-0000web",))
    for eni, subnet, ip in ((TASK_1, APP_A, "10.0.1.20"), (TASK_2, APP_B, "10.0.2.20")):
        b.eni(
            eni,
            subnet,
            [ip],
            owner_type="ecs",
            owner_ref="example-cluster/example-svc",
            sgs=("sg-000task",),
        )
    b.ecs_service("example-cluster", "example-svc", None, eni_ids=(TASK_1, TASK_2), desired=2)
    b.eni(
        VPCE,
        APP_A,
        ["10.0.1.30"],
        owner_type="vpc_endpoint",
        owner_ref="vpce-0example0001",
        sgs=("sg-000vpce",),
    )
    b.eni(FN, APP_B, ["10.0.2.40"], owner_type="lambda", owner_ref="example-fn", sgs=("sg-0000fn",))

    b.lb_target("example-alb", "example-web-tg", "instance", "i-0example0001", 80)
    b.lb_target("example-alb", "example-web-tg", "instance", "i-0example0002", 80)
    b.lb_target("example-alb", "example-svc-tg", "ip", "10.0.1.20", 8080)
    b.lb_target("example-alb", "example-svc-tg", "ip", "10.0.2.20", 8080)
    b.lb_target("example-alb", "example-fn-tg", "lambda", "example-fn")
    b.lb_target("example-alb", "example-svc-tg", "ip", "10.9.9.9", 8080)  # outside the VPC
    b.ecs_service_lb("example-cluster", "example-svc", "example-alb", "example-svc-tg")
    b.sg_ref("sg-0000web", "ingress", "sg-0000alb", "tcp/80")
    b.sg_ref("sg-000task", "egress", "sg-000vpce", "tcp/443")
    b.sg_ref("sg-000task", "ingress", "sg-000task", "all")  # self reference: no edge
    b.sg_ref("sg-0000web", "ingress", "sg-0unknown", "tcp/22")  # held by nothing: no edge
    return b


def _edges(data, etype):
    return {(e["source"], e["target"]): e for e in data["edges"] if e["type"] == etype}


def test_lb_target_edges_pick_same_az_lb_eni(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    targets = _edges(data, "targets")
    assert set(targets) == {
        (ALB_A, WEB_1),
        (ALB_B, WEB_2),
        (ALB_A, TASK_1),
        (ALB_B, TASK_2),
        (ALB_B, FN),
    }
    web = targets[(ALB_A, WEB_1)]
    assert web["label"] == "example-web-tg:80"
    assert web["title"] == "example-alb → i-0example0001 (target group example-web-tg:80)"
    assert web["id"] == f"targets:{ALB_A}>{WEB_1}"
    assert targets[(ALB_B, FN)]["label"] == "example-fn-tg"


def test_ecs_service_to_lb_edges(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    ecs = _edges(data, "ecs_lb")
    assert set(ecs) == {(TASK_1, ALB_A), (TASK_2, ALB_B)}
    edge = ecs[(TASK_1, ALB_A)]
    assert edge["label"] == "ecs→lb example-svc"
    assert edge["title"] == (
        "ECS service example-cluster/example-svc → example-alb via example-svc-tg"
    )


def test_sg_reference_edges(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    sg = _edges(data, "sg")
    # ingress on the web SG from the ALB SG: ALB (same-AZ ENI) -> instance;
    # egress from the task SG to the endpoint SG: task -> endpoint.
    assert set(sg) == {(ALB_A, WEB_1), (ALB_B, WEB_2), (TASK_1, VPCE), (TASK_2, VPCE)}
    assert all(e["type"] == "sg" for e in sg.values())
    # labels are sent in full; the browser shortens them only on request
    assert sg[(ALB_A, WEB_1)]["label"] == "from sg-0000alb of example-alb"
    assert sg[(ALB_A, WEB_1)]["title"] == (
        "sg-0000web on i-0example0001 allows tcp/80 from sg-0000alb on example-alb"
    )
    assert sg[(TASK_1, VPCE)]["label"] == "to vpce-0example0001"
    counts = {t["type"]: t["count"] for t in data["edge_types"]}
    # the task SG's egress to the endpoint SG is not endpoint ingress: no reach edge
    assert counts == {"targets": 5, "ecs_lb": 2, "reach": 0, "sg": 4}
    assert data["edges_truncated"] is False


def test_edge_type_filter(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    with closing(db_path) as conn:
        only_sg = queries.visual_data(conn, b.id, VPC, edge_types=("sg",))
        none = queries.visual_data(conn, b.id, VPC, edge_types=())
    assert {e["type"] for e in only_sg["edges"]} == {"sg"}
    assert [t["selected"] for t in only_sg["edge_types"]] == [False, False, False, True]
    # counts stay unfiltered so the UI can show what a hidden group holds
    assert [t["count"] for t in none["edge_types"]] == [5, 2, 0, 4]
    assert none["edges"] == []


# -- endpoint reach -------------------------------------------------------------------


def test_reach_edge_from_resource_security_group(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    b.sg_ref("sg-000vpce", "ingress", "sg-000task", "tcp/443")
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    reach = _edges(data, "reach")
    assert set(reach) == {(TASK_1, VPCE), (TASK_2, VPCE)}
    edge = reach[(TASK_1, VPCE)]
    assert edge["label"] == "can reach (SG)"
    assert edge["title"] == (
        "example-cluster/example-svc can reach vpce-0example0001: "
        "sg-000vpce allows tcp/443 from sg-000task on example-cluster/example-svc"
    )
    # reach is in addition to the SG reference edges
    assert (TASK_1, VPCE) in _edges(data, "sg")


def test_reach_edge_from_cidr_containing_resource_ip(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    b.sg_cidr("sg-000vpce", "10.0.2.0/24")  # app-b: WEB_2, TASK_2, FN; not ALB_B (10.0.10.10)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    reach = _edges(data, "reach")
    assert set(reach) == {(WEB_2, VPCE), (TASK_2, VPCE), (FN, VPCE)}
    assert reach[(WEB_2, VPCE)]["title"] == (
        "i-0example0002 can reach vpce-0example0001: "
        "sg-000vpce allows tcp/443 from 10.0.2.0/24 (10.0.2.10)"
    )


@pytest.mark.parametrize(
    "protocol, from_port, to_port",
    [("-1", None, None), ("tcp", 0, 65535), ("tcp", 400, 500)],
)
def test_reach_edge_from_wide_cidr_rule(db_path, snapshot_builder, protocol, from_port, to_port):
    b = seed_edge_topology(db_path, snapshot_builder)
    b.sg_cidr("sg-000vpce", "10.0.1.10/32", protocol, from_port, to_port)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    assert set(_edges(data, "reach")) == {(WEB_1, VPCE)}


def test_no_reach_edge_for_other_ports(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    b.sg_ref("sg-000vpce", "ingress", "sg-000task", "tcp/22")
    b.sg_ref("sg-000vpce", "ingress", "sg-0000web", "udp/443")
    b.sg_cidr("sg-000vpce", "10.0.0.0/16", "tcp", 22)
    b.sg_cidr("sg-000vpce", "10.0.0.0/16", "tcp", 8443)
    b.sg_cidr("sg-000vpce", "10.0.0.0/16", "icmp", None)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    assert _edges(data, "reach") == {}
    # the SG references themselves are still drawn as sg edges
    assert (TASK_1, VPCE) in _edges(data, "sg")


def test_no_reach_edge_for_cidr_not_containing_resource(db_path, snapshot_builder):
    b = seed_edge_topology(db_path, snapshot_builder)
    b.sg_cidr("sg-000vpce", "10.0.99.0/24")
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    assert _edges(data, "reach") == {}


def test_reach_edges_are_capped(db_path, snapshot_builder, monkeypatch):
    monkeypatch.setattr(visual, "MAX_REACH_EDGES", 2)
    b = seed_edge_topology(db_path, snapshot_builder)
    b.sg_cidr("sg-000vpce", "10.0.0.0/16")
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    assert len(_edges(data, "reach")) == 2
    assert data["edges_truncated"] is True
    truncated = {t["type"]: t["truncated"] for t in data["edge_types"]}
    assert truncated == {"targets": False, "ecs_lb": False, "reach": True, "sg": False}


@pytest.mark.parametrize(
    "protocol, from_port, to_port, expected",
    [
        ("-1", None, None, True),
        ("all", None, None, True),
        ("tcp", 443, 443, True),
        ("6", 443, 443, True),
        ("tcp", 1, 1024, True),
        ("tcp", 22, 22, False),
        ("tcp", 444, 8443, False),
        ("udp", 443, 443, False),
        ("icmp", None, None, False),
    ],
)
def test_allows_endpoint_port(protocol, from_port, to_port, expected):
    assert visual.allows_endpoint_port(protocol, from_port, to_port) is expected


def test_edges_into_collapsed_groups_keep_member_ids(db_path, snapshot_builder):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(PUB_A, VPC, "10.0.0.0/24").subnet(APP_A, VPC, "10.0.1.0/24")
    b.eni(ALB_A, PUB_A, ["10.0.0.10"], owner_type="elb", owner_ref="example-alb")
    for n in range(12):
        b.eni(f"eni-00000ecs{n:02d}", APP_A, [f"10.0.1.{10 + n}"], owner_type="ecs")
        b.lb_target("example-alb", "example-tg", "ip", f"10.0.1.{10 + n}", 80)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    # the browser re-points edges at the group node; the JSON keeps ENI ids
    assert data["vpc"]["subnets"][1]["items"][0]["kind"] == "group"
    assert {e["target"] for e in data["edges"]} == {f"eni-00000ecs{n:02d}" for n in range(12)}


def test_sg_edges_are_capped(db_path, snapshot_builder, monkeypatch):
    monkeypatch.setattr(visual, "MAX_SG_EDGES", 3)
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(APP_A, VPC, "10.0.1.0/24")
    for n in range(4):
        b.eni(f"eni-0000src{n:03d}", APP_A, [f"10.0.1.{10 + n}"], sgs=("sg-00000src",))
    b.eni("eni-00000dst01", APP_A, ["10.0.1.50"], sgs=("sg-00000dst",))
    b.sg_ref("sg-00000dst", "ingress", "sg-00000src", "tcp/5432")
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    assert len(data["edges"]) == 3 and data["edges_truncated"] is True


def test_visual_data_sends_full_labels(db_path, snapshot_builder):
    long_name = "example-" + "very-long-resource-name-" * 3
    subnet_name = "example-subnet-" + "x" * 40
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", name="example-vpc")
    b.subnet(APP_A, VPC, "10.0.1.0/24", name=subnet_name)
    b.eni(WEB_1, APP_A, ["10.0.1.10"], name=long_name)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    vpc = data["vpc"]
    subnet = vpc["subnets"][0]
    node = subnet["items"][0]
    assert node["name"] == node["label_name"] == long_name
    assert subnet["label_name"] == subnet_name
    assert subnet["label_meta"] == f"{APP_A} · 10.0.1.0/24 · us-east-1a"
    assert vpc["label_cidrs"] == "10.0.0.0/16, 10.1.0.0/16, 10.2.0.0/16, 10.3.0.0/16"
    assert vpc["label_name"] == "example-vpc"
    assert "…" not in str(data)


def test_visual_data_keeps_distinct_lambda_suffixes(db_path, snapshot_builder):
    prefix = "team-app-dev-platform-shared-lambda-worker-"
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16", name="example-vpc")
    b.subnet(APP_A, VPC, "10.0.1.0/24", name="example-app-a")
    for i, eni in enumerate((WEB_1, WEB_2), start=1):
        b.eni(eni, APP_A, [f"10.0.1.{10 + i}"], owner_type="lambda", owner_ref=f"{prefix}{i}")
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    names = sorted(n["label_name"] for n in data["vpc"]["subnets"][0]["items"])
    assert names == [f"{prefix}1", f"{prefix}2"]
    short = [visual.middle_ellipsize(n) for n in names]
    assert short[0] != short[1]
    assert all(len(x) <= visual.SHORT_NAME_MAX for x in short)
    assert short[0].endswith("-worker-1") and short[1].endswith("-worker-2")


@pytest.mark.parametrize(
    "text, limit, expected",
    [
        ("team-app-dev-lambda-worker-1", 32, "team-app-dev-lambda-worker-1"),  # fits: unchanged
        ("datalab-ingest-pipeline-stream-kafka-producer", 32, "datalab-…-kafka-producer"),
        ("team-app-dev-lambda-worker-1", 20, "team-…-worker-1"),
        ("team-app-dev-lambda-worker-2", 20, "team-…-worker-2"),
        ("abcdefghijklmnopqrstuvwxyz", 10, "abc…uvwxyz"),  # no separator: plain middle cut
        ("", 5, ""),
        (None, 5, ""),
        ("abc", 2, "…"),
        ("abc", 0, ""),
    ],
)
def test_middle_ellipsize(text, limit, expected):
    out = visual.middle_ellipsize(text, limit)
    assert out == expected
    assert len(out) <= limit


def test_middle_ellipsize_defaults_to_short_name_max():
    name = "team-app-dev-" + "x" * 40 + "-lambda-worker-1"
    out = visual.middle_ellipsize(name)
    assert len(out) <= visual.SHORT_NAME_MAX == 32
    assert out.startswith("team-app-") and out.endswith("-lambda-worker-1")


@pytest.mark.parametrize(
    "text, limit, expected",
    [
        ("example-alb", 20, "example-alb"),
        ("example-alb", 11, "example-alb"),
        ("example-alb", 10, "example-a…"),
        ("example alb", 9, "example…"),  # no dangling space before the ellipsis
        ("", 5, ""),
        (None, 5, ""),
        ("abc", 1, "…"),
        ("abc", 0, ""),
    ],
)
def test_ellipsize(text, limit, expected):
    assert visual.ellipsize(text, limit) == expected


@pytest.mark.parametrize(
    "values, expected",
    [
        (None, ("targets", "ecs_lb", "reach", "sg")),
        ([""], ()),
        (["sg"], ("sg",)),
        (["", "targets", "sg"], ("targets", "sg")),
        (["sg,targets,reach"], ("targets", "reach", "sg")),
        (["bogus", "ecs_lb"], ("ecs_lb",)),
    ],
)
def test_parse_edge_types(values, expected):
    assert visual.parse_edge_types(values) == expected


def test_parse_edge_types_default():
    assert visual.parse_edge_types(None, visual.DEFAULT_EDGE_TYPES) == (
        "targets",
        "ecs_lb",
        "reach",
    )
    assert visual.parse_edge_types(["sg"], visual.DEFAULT_EDGE_TYPES) == ("sg",)
