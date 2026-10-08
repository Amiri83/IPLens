"""Group member labels, "Expand all groups" exports, security group names / grouping and
tag grouping (synthetic 10.0.x.x data and example names only)."""

import json
import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own generated output

import pytest

from iplens import queries
from iplens.db import closing
from iplens.diagram import expand_groups, parse_view, view_to_drawio, view_to_svg
from iplens.queries import TYPE_ICONS, VPC_ICON
from iplens.web import create_app

SVG_NS = "{http://www.w3.org/2000/svg}"
VPC = "vpc-0example0000001"
SA, SB = "subnet-0000000a", "subnet-0000000b"
SERVICES = (
    "ec2",
    "ecr.api",
    "ecr.dkr",
    "kms",
    "lambda",
    "logs",
    "secretsmanager",
    "sns",
    "sqs",
    "ssm",
    "sts",
    "xray",
)


# -- group labels ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "count, names, expected",
    [
        (14, ["lambda", "sts", "ssm", "kms"], "14 × VPC endpoint: lambda, sts, ssm, …"),
        (3, ["lambda", "sts", "ssm"], "3 × VPC endpoint: lambda, sts, ssm"),
        (12, ["lambda", "lambda", "sts"], "12 × VPC endpoint: lambda, sts"),  # distinct names
        (11, [], "11 × VPC endpoint"),
    ],
)
def test_group_name_lists_members(count, names, expected):
    assert queries.group_name(count, "VPC endpoint", names) == expected


def _seed_endpoints(db_path, builder):
    b = builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(SA, VPC, "10.0.1.0/24", name="example-app-a")
    for i, svc in enumerate(SERVICES):
        eni, vpce = f"eni-000000vpce{i:02d}", f"vpce-0example{i:04d}"
        b.eni(eni, SA, [f"10.0.1.{10 + i}"], owner_type="vpc_endpoint", owner_ref=vpce)
        b.endpoint(vpce, VPC, f"com.amazonaws.us-east-1.{svc}", [SA], [eni])
    return b


def test_collapsed_endpoint_group_label_lists_service_names(db_path, snapshot_builder):
    b = _seed_endpoints(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC, labels={"vpc_endpoint": "VPC endpoint"})
    (group,) = data["vpc"]["subnets"][0]["items"]
    assert group["kind"] == "group" and group["count"] == 12
    assert group["name"] == "12 × VPC endpoint: ec2, ecr.api, ecr.dkr, …"
    assert group["member_names"] == list(SERVICES)


# -- "Expand all groups" export ---------------------------------------------------------


def _member(i: int) -> dict:
    return {
        "id": f"res:eni-000000vpce{i:02d}",
        "label": f"{SERVICES[i]}\nVPC endpoint\n10.0.1.{10 + i}",
        "icon": TYPE_ICONS["vpc_endpoint"],
        "w": 44,
        "h": 44,
    }


def _group_view(expand: bool, n_members: int = 12) -> dict:
    """Subnet A holds an ALB and a collapsed group of endpoints; subnet B sits below."""
    members = [_member(i) for i in range(n_members)]
    return {
        "vpc_id": VPC,
        "expand_groups": expand,
        "nodes": [
            {"id": "vpc", "kind": "vpc", "label": "example-vpc", "icon": VPC_ICON}
            | {"x": 0, "y": 0, "w": 1000, "h": 700},
            {"id": f"subnet:{SA}", "kind": "subnet", "parent": "vpc", "label": "example-app-a"}
            | {"x": 50, "y": 80, "w": 900, "h": 200},
            {"id": f"subnet:{SB}", "kind": "subnet", "parent": "vpc", "label": "example-app-b"}
            | {"x": 50, "y": 400, "w": 900, "h": 200},
            {"id": "res:eni-00000alb0a", "kind": "res", "parent": f"subnet:{SA}"}
            | {"label": "example-alb", "x": 80, "y": 110, "w": 44, "h": 44},
            {"id": "res:eni-00000web01", "kind": "res", "parent": f"subnet:{SB}"}
            | {"label": "example-web", "x": 80, "y": 430, "w": 44, "h": 44},
            {
                "id": f"group:{SA}:vpc_endpoint",
                "kind": "group",
                "parent": f"subnet:{SA}",
                "label": "▸ 12 × VPC endpoint: ec2, ecr.api, ecr.dkr, …\n12 IPs",
                "x": 300,
                "y": 110,
                "w": 44,
                "h": 44,
                "icon": TYPE_ICONS["vpc_endpoint"],
                "members": members,
            },
            {  # a "Group by" box around two endpoints, refitted after expansion
                "id": "ctx:0",
                "kind": "ctx",
                "label": "SG example-vpce-sg",
                "color": "#2457c5",
                "member_ids": [_member(0)["id"], _member(5)["id"]],
                "x": 280,
                "y": 90,
                "w": 90,
                "h": 90,
            },
        ],
        "edges": [
            {
                "source": "res:eni-00000web01",
                "target": m["id"] if expand else f"group:{SA}:vpc_endpoint",
                "type": "reach",
                "label": "example-vpce-sg",
            }
            for m in members[:2]
        ],
    }


def test_expand_all_groups_replaces_group_with_members():
    view = parse_view(json.dumps(_group_view(expand=True)))
    by_id = {n.id: n for n in view.nodes}
    assert not [n for n in view.nodes if n.kind == "group"]
    members = [by_id[_member(i)["id"]] for i in range(12)]
    subnet_a, subnet_b, vpc = by_id[f"subnet:{SA}"], by_id[f"subnet:{SB}"], by_id["vpc"]
    # members sit inside subnet A, below its original content, without overlapping
    for m in members:
        assert m.parent == f"subnet:{SA}" and m.kind == "res"
        assert subnet_a.x <= m.x and m.x + m.w <= subnet_a.x + subnet_a.w
        # below the ALB and its label (110 + 44 + label), inside the grown box
        assert m.y > 200 and m.y + m.h + m.label_height() <= subnet_a.y + subnet_a.h
    assert len({(m.x, m.y) for m in members}) == 12
    rows = len({m.y for m in members})
    assert rows == 3  # 4 per row
    # subnet A, the VPC and everything below grew / moved by the same amount
    delta = subnet_a.h - 200
    assert delta > 0 and vpc.h == 700 + delta
    assert subnet_b.y == 400 + delta and by_id["res:eni-00000web01"].y == 430 + delta
    assert by_id["res:eni-00000alb0a"].y == 110  # above the growth: unchanged
    # edges go to the members; the context box now encloses its two members
    assert [(e.source, e.target) for e in view.edges] == [
        ("res:eni-00000web01", _member(0)["id"]),
        ("res:eni-00000web01", _member(1)["id"]),
    ]
    box = by_id["ctx:0"]
    for m in (members[0], members[5]):
        assert box.x <= m.x and m.x + m.w <= box.x + box.w
        assert box.y <= m.y and m.y + m.h <= box.y + box.h


def test_expand_all_groups_in_svg_and_drawio():
    view = parse_view(json.dumps(_group_view(expand=True)))
    svg = ET.fromstring(view_to_svg(view).split("\n", 1)[1])  # noqa: S314 - own output
    leaves = [g for g in svg.iter(f"{SVG_NS}g") if g.get("class") in ("res", "group")]
    assert len(leaves) == 2 + 12 and not [g for g in leaves if g.get("class") == "group"]
    texts = list(svg.itertext())
    assert all(s in texts for s in SERVICES)
    mx = ET.fromstring(view_to_drawio(view).split("\n", 1)[1])  # noqa: S314
    vertices = [c for c in mx.iter("mxCell") if c.get("vertex") == "1"]
    assert len(vertices) == 3 + 2 + 12 + 1  # boxes, two resources, members, context box
    assert len([c for c in mx.iter("mxCell") if c.get("edge") == "1"]) == 2


def test_without_expand_the_group_box_is_kept():
    view = parse_view(json.dumps(_group_view(expand=False)))
    kinds = [n.kind for n in view.nodes]
    assert kinds.count("group") == 1 and len(view.nodes) == 7  # members ignored
    assert expand_groups(view) == 0
    # member ids are not nodes of a collapsed view
    raw = _group_view(expand=False)
    raw["edges"][0]["target"] = _member(0)["id"]
    with pytest.raises(ValueError, match="connect nodes"):
        parse_view(json.dumps(raw))


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda v: v["nodes"][5]["members"][0].update(icon="../../x.svg"), "unknown icon"),
        (lambda v: v["nodes"][5]["members"][0].update(id="vpc"), "unique"),
        (lambda v: v["nodes"][6].update(parent="vpc"), "context box"),
        (lambda v: v["nodes"][6].update(color="red;x"), "#rrggbb"),
        (lambda v: v["edges"][0].update(target="ctx:0"), "connect nodes"),
    ],
)
def test_expand_and_context_validation(change, message):
    raw = _group_view(expand=True)
    change(raw)
    with pytest.raises(ValueError, match=message):
        parse_view(json.dumps(raw))


# -- security groups ------------------------------------------------------------------

APP, VPCE_ENI, WEB = "eni-0000000app", "eni-000000vpce", "eni-0000000web"


def _seed_sgs(db_path, builder):
    b = builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(SA, VPC, "10.0.1.0/24").subnet(SB, VPC, "10.0.2.0/24")
    b.eni(APP, SA, ["10.0.1.10"], owner_ref="i-0example0001", sgs=("sg-0000app", "sg-00shared"))
    b.eni(WEB, SB, ["10.0.2.10"], owner_ref="i-0example0002", sgs=("sg-0000web", "sg-00shared"))
    b.eni(
        VPCE_ENI,
        SA,
        ["10.0.1.20"],
        owner_type="vpc_endpoint",
        owner_ref="vpce-0example0001",
        sgs=("sg-000vpce",),
    )
    b.security_group("sg-0000app", name="example-app", group_name="team-app-dev-app")
    b.security_group("sg-00shared", name="", group_name="example-shared-sg")
    b.security_group("sg-000vpce", name="example-vpce-sg", group_name="vpce")
    b.security_group("sg-0000web", name="", group_name="")  # no name at all
    b.sg_ref("sg-000vpce", "ingress", "sg-0000app", "tcp/443")
    b.sg_cidr("sg-000vpce", "10.0.2.0/24")
    return b


def test_reach_edges_are_labelled_with_the_endpoint_sg_name(db_path, snapshot_builder):
    b = _seed_sgs(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    reach = {(e["source"], e["target"]): e for e in data["edges"] if e["type"] == "reach"}
    assert set(reach) == {(APP, VPCE_ENI), (WEB, VPCE_ENI)}
    assert reach[(APP, VPCE_ENI)]["label"] == "example-vpce-sg"
    assert reach[(WEB, VPCE_ENI)]["label"] == "example-vpce-sg"


def test_sg_names_and_per_node_groups_for_group_by_sg(db_path, snapshot_builder):
    b = _seed_sgs(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
        assert queries.sg_names(conn, b.id)["sg-0000web"] == "sg-0000web"
    # Name tag, else the group name, else the id
    assert data["sg_names"] == {
        "sg-0000app": "example-app",
        "sg-00shared": "example-shared-sg",
        "sg-000vpce": "example-vpce-sg",
        "sg-0000web": "sg-0000web",
    }
    nodes = {
        n["eni_id"]: n for s in data["vpc"]["subnets"] for n in s["items"] if n["kind"] != "group"
    }
    # one box per SG: the shared SG spans both subnets
    by_sg: dict[str, set[str]] = {}
    for eni, n in nodes.items():
        for sg in n["sgs"]:
            by_sg.setdefault(sg, set()).add(eni)
    assert by_sg == {
        "sg-0000app": {APP},
        "sg-00shared": {APP, WEB},
        "sg-0000web": {WEB},
        "sg-000vpce": {VPCE_ENI},
    }


def _ctx_view(boxes: list[tuple[str, str, list[str]]]) -> dict:
    nodes = [
        {"id": "vpc", "kind": "vpc", "label": "example-vpc", "x": 0, "y": 0, "w": 600, "h": 300},
        {"id": f"subnet:{SA}", "kind": "subnet", "parent": "vpc", "label": "a"}
        | {"x": 20, "y": 40, "w": 560, "h": 240},
    ]
    for i, eni in enumerate((APP, WEB)):
        nodes.append(
            {"id": f"res:{eni}", "kind": "res", "parent": f"subnet:{SA}", "label": eni}
            | {"x": 60 + 200 * i, "y": 80, "w": 44, "h": 44, "color": "#2457c5"}
        )
    for i, (label, color, members) in enumerate(boxes):
        nodes.append(
            {"id": f"ctx:{i}", "kind": "ctx", "label": label, "color": color}
            | {"member_ids": members, "x": 40 + i * 4, "y": 60, "w": 300, "h": 120}
        )
    return {"vpc_id": VPC, "nodes": nodes, "edges": []}


def test_group_by_sg_boxes_are_exported():
    view = parse_view(
        json.dumps(
            _ctx_view(
                [
                    ("SG example-shared-sg", "#2457c5", [f"res:{APP}", f"res:{WEB}"]),
                    ("SG example-app", "#c2410c", [f"res:{APP}"]),
                ]
            )
        )
    )
    svg = ET.fromstring(view_to_svg(view).split("\n", 1)[1])  # noqa: S314
    boxes = [g for g in svg.iter(f"{SVG_NS}g") if g.get("class") == "ctx"]
    assert len(boxes) == 2
    rects = [g.find(f"{SVG_NS}rect") for g in boxes]
    assert all(r.get("stroke-dasharray") == "6 4" for r in rects)
    assert [r.get("stroke") for r in rects] == ["#2457c5", "#c2410c"]
    texts = list(svg.itertext())
    assert "SG example-shared-sg" in texts and "SG example-app" in texts
    # resources are outlined in their box colour
    outlines = [r for r in svg.iter(f"{SVG_NS}rect") if r.get("stroke") == "#2457c5"]
    assert len(outlines) == 1 + 2

    mx = ET.fromstring(view_to_drawio(view).split("\n", 1)[1])  # noqa: S314
    dashed = [c for c in mx.iter("mxCell") if "dashPattern=6 4" in (c.get("style") or "")]
    assert [c.get("value") for c in dashed] == ["SG example-shared-sg", "SG example-app"]
    assert all(c.get("parent") == "1" for c in dashed)


# -- tags -----------------------------------------------------------------------------


def _seed_tags(db_path, builder):
    b = builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(SA, VPC, "10.0.1.0/24")
    b.eni("eni-00000alb0a", SA, ["10.0.1.5"], owner_type="elb", owner_ref="example-alb")
    b.eni("eni-0000000fn1", SA, ["10.0.1.11"], owner_type="lambda", owner_ref="fn-a")
    b.eni(
        "eni-000000task",
        SA,
        ["10.0.1.20"],
        owner_type="ecs",
        owner_ref="example-cluster/example-svc/0example0000",
    )
    b.eni("eni-0000000ep1", SA, ["10.0.1.30"], owner_type="vpc_endpoint", owner_ref="vpce-0ex1")
    b.eni("eni-00000plain", SA, ["10.0.1.40"], owner_ref="i-0example0001")
    b.tag("lb", "example-alb", "team", "app")
    b.tag("lb", "example-alb", "env", "dev")
    b.tag("eni", "eni-00000alb0a", "env", "prod")  # the ENI's own tag wins
    b.tag("lambda", "fn-a", "team", "app")
    b.tag("ecs_service", "example-cluster/example-svc", "team", "data")
    b.tag("endpoint", "vpce-0ex1", "team", "platform")
    b.tag("sg", "sg-0001", "owner", "security")  # SG tags are not resource tags
    return b


def test_resource_tags_merge_owner_and_eni_tags(db_path, snapshot_builder):
    b = _seed_tags(db_path, snapshot_builder)
    with closing(db_path) as conn:
        rows = {r["eni_id"]: r for r in queries.ip_list(conn, b.id)}
        keys = queries.tag_keys(conn, b.id)
        team_app = queries.ip_list(conn, b.id, queries.IpFilter(tag_key="team", tag_value="app"))
        any_team = queries.ip_list(conn, b.id, queries.IpFilter(tag_key="team"))
    assert rows["eni-00000alb0a"]["tags"] == {"env": "prod", "team": "app"}
    assert rows["eni-0000000fn1"]["tags"] == {"team": "app"}
    assert rows["eni-000000task"]["tags"] == {"team": "data"}
    assert rows["eni-0000000ep1"]["tags"] == {"team": "platform"}
    assert rows["eni-00000plain"]["tags"] == {}
    assert keys == ["env", "team"]
    assert [r["ip"] for r in team_app] == ["10.0.1.5", "10.0.1.11"]
    assert [r["ip"] for r in any_team] == ["10.0.1.5", "10.0.1.11", "10.0.1.20", "10.0.1.30"]


def test_group_by_tag_data(db_path, snapshot_builder):
    b = _seed_tags(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    assert data["tag_keys"] == ["env", "team"]
    by_value: dict[str, set[str]] = {}
    for n in data["vpc"]["subnets"][0]["items"]:
        if "team" in n["tags"]:
            by_value.setdefault(n["tags"]["team"], set()).add(n["eni_id"])
    assert by_value == {
        "app": {"eni-00000alb0a", "eni-0000000fn1"},
        "data": {"eni-000000task"},
        "platform": {"eni-0000000ep1"},
    }


def test_ip_list_tag_column_filter_and_visual_options(home, snapshot_builder):
    app = create_app(home, testing=True)
    client = app.test_client()
    client.get("/")
    _seed_tags(app.extensions["iplens"]["paths"].db_path, snapshot_builder)
    page = client.get("/ips").data.decode()
    assert "team=app" in page and "env=prod" in page
    assert '<option value="team" >team</option>' in page
    page = client.get("/ips?tag_key=team&tag_value=data").data.decode()
    assert "10.0.1.20" in page and "10.0.1.5" not in page

    visual = client.get("/visual?group=tag&tag=team").data.decode()
    assert 'id="group-by"' in visual and '<option value="tag" selected>' in visual
    assert 'data-selected="team"' in visual
    assert 'id="export-expand" checked' in visual
    for value in ("sg", "tf"):
        assert f'<option value="{value}" >' in visual
