"""SVG and draw.io export of the Visual page's view (placeholder data only)."""

import json
import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own generated output

import pytest

from iplens.diagram import (
    DRAWIO_HIDDEN_BOX,
    export_filename,
    parse_view,
    view_to_drawio,
    view_to_svg,
)
from iplens.queries import LB_ICONS, TYPE_ICONS, VPC_ICON

SVG_NS = "{http://www.w3.org/2000/svg}"


def _view(**overrides) -> dict:
    """A VPC with two subnets, three resources, one group and three edges."""
    view = {
        "vpc_id": "vpc-0example0000001",
        "show_vpc": True,
        "show_subnets": True,
        "nodes": [
            {
                "id": "vpc",
                "kind": "vpc",
                "parent": None,
                "label": "example-vpc\nvpc-0example0000001 · 10.0.0.0/16",
                "x": 0,
                "y": 0,
                "w": 900,
                "h": 500,
                "icon": VPC_ICON,
            },
            {
                "id": "subnet:subnet-0000000a",
                "kind": "subnet",
                "parent": "vpc",
                "label": "example-private-a\n10.0.1.0/24",
                "x": 50,
                "y": 80,
                "w": 380,
                "h": 300,
            },
            {
                "id": "subnet:subnet-0000000b",
                "kind": "subnet",
                "parent": "vpc",
                "label": "example-private-b\n10.0.2.0/24",
                "x": 470,
                "y": 80,
                "w": 380,
                "h": 300,
            },
            {
                "id": "res:eni-00000alb0a",
                "kind": "res",
                "parent": "subnet:subnet-0000000a",
                "label": "example-alb\nALB\n10.0.1.5",
                "x": 80,
                "y": 110,
                "w": 44,
                "h": 44,
                "icon": LB_ICONS["application"],
            },
            {
                "id": "res:eni-00000web01",
                "kind": "res",
                "parent": "subnet:subnet-0000000a",
                "label": 'example-web <&> "one"\n10.0.1.10',
                "x": 80,
                "y": 260,
                "w": 44,
                "h": 44,
                "icon": TYPE_ICONS["ec2"],
            },
            {
                "id": "res:eni-00000idle1",
                "kind": "res",
                "parent": "subnet:subnet-0000000b",
                "label": "ENI/other\n10.0.2.50",
                "x": 500,
                "y": 110,
                "w": 44,
                "h": 44,
                "icon": TYPE_ICONS["other"],
                "idle": True,
            },
            {
                "id": "group:subnet-0000000b:ecs",
                "kind": "group",
                "parent": "subnet:subnet-0000000b",
                "label": "▸ 12 × ECS task\n12 IPs",
                "x": 650,
                "y": 110,
                "w": 44,
                "h": 44,
                "icon": TYPE_ICONS["ecs"],
            },
        ],
        "edges": [
            {
                "source": "res:eni-00000alb0a",
                "target": "res:eni-00000web01",
                "type": "targets",
                "label": "example-tg :80",
            },
            {
                "source": "group:subnet-0000000b:ecs",
                "target": "res:eni-00000alb0a",
                "type": "ecs_lb",
                "label": "ECS→LB ×12",
            },
            {
                "source": "res:eni-00000web01",
                "target": "res:eni-00000idle1",
                "type": "sg",
                "label": "tcp/443",
            },
        ],
    }
    view.update(overrides)
    return view


def _parse(text: str) -> ET.Element:
    assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    return ET.fromstring(text.split("\n", 1)[1])  # noqa: S314 - our own output


# -- draw.io --------------------------------------------------------------------------


def test_drawio_is_well_formed_with_expected_counts():
    root = _parse(view_to_drawio(parse_view(json.dumps(_view()))))
    assert root.tag == "mxfile"
    (diagram,) = root.findall("diagram")
    assert diagram.get("name") == "vpc-0example0000001"
    cells = diagram.findall("./mxGraphModel/root/mxCell")
    vertices = [c for c in cells if c.get("vertex") == "1"]
    edges = [c for c in cells if c.get("edge") == "1"]
    assert len(vertices) == 7  # 1 VPC + 2 subnets + 3 resources + 1 group
    assert len(edges) == 3
    assert [c.get("id") for c in cells[:2]] == ["0", "1"]  # mxGraph root cells
    assert len({c.get("id") for c in cells}) == len(cells)


def test_drawio_containers_shapes_and_relative_geometry():
    root = _parse(view_to_drawio(parse_view(json.dumps(_view()))))
    cells = {c.get("id"): c for c in root.iter("mxCell")}
    by_value = {c.get("value", "").split("<br>")[0]: c for c in cells.values()}

    vpc = by_value["example-vpc"]
    assert "shape=mxgraph.aws4.group;" in vpc.get("style")
    assert "grIcon=mxgraph.aws4.group_vpc2" in vpc.get("style")
    assert "container=1" in vpc.get("style") and vpc.get("parent") == "1"

    subnet = by_value["example-private-a"]
    assert "container=1" in subnet.get("style")
    assert subnet.get("parent") == vpc.get("id")
    geo = subnet.find("mxGeometry")
    assert (geo.get("x"), geo.get("y"), geo.get("width")) == ("50", "80", "380")

    alb = by_value["example-alb"]
    assert "shape=mxgraph.aws4.application_load_balancer" in alb.get("style")
    assert alb.get("parent") == subnet.get("id")
    # absolute (80, 110) minus the subnet's (50, 80)
    assert (alb.find("mxGeometry").get("x"), alb.find("mxGeometry").get("y")) == ("30", "30")

    ec2 = by_value["example-web &lt;&amp;&gt; &quot;one&quot;"]  # HTML-escaped label
    assert "resIcon=mxgraph.aws4.ec2" in ec2.get("style")
    idle = by_value["ENI/other"]
    assert "mxgraph.aws4.elastic_network_interface" in idle.get("style")
    assert "labelBorderColor=#E8A33A" in idle.get("style")
    group = by_value["▸ 12 × ECS task"]
    assert "resIcon=mxgraph.aws4.ecs" in group.get("style") and "fontStyle=1" in group.get("style")

    edges = [c for c in cells.values() if c.get("edge") == "1"]
    targets = next(e for e in edges if e.get("value") == "example-tg :80")
    assert (targets.get("source"), targets.get("target")) == (alb.get("id"), ec2.get("id"))
    sg = next(e for e in edges if e.get("value") == "tcp/443")
    assert "dashed=1" in sg.get("style")
    assert next(e for e in edges if e.get("source") == group.get("id")).get("target") == alb.get(
        "id"
    )
    for e in edges:
        assert e.find("mxGeometry").get("relative") == "1"


def test_drawio_hidden_borders():
    view = parse_view(json.dumps(_view(show_vpc=False, show_subnets=False)))
    root = _parse(view_to_drawio(view))
    containers = [c for c in root.iter("mxCell") if "container=1" in (c.get("style") or "")]
    assert len(containers) == 3
    assert all(c.get("style").endswith(DRAWIO_HIDDEN_BOX) for c in containers)


# -- SVG ------------------------------------------------------------------------------


def test_svg_is_well_formed_with_expected_counts():
    svg = _parse(view_to_svg(parse_view(json.dumps(_view()))))
    assert svg.tag == f"{SVG_NS}svg"
    groups = {g.get("class"): g for g in svg.iter(f"{SVG_NS}g") if g.get("class")}
    boxes = [g for g in svg.iter(f"{SVG_NS}g") if g.get("class") in ("vpc", "subnet")]
    leaves = [g for g in svg.iter(f"{SVG_NS}g") if g.get("class") in ("res", "group")]
    edges = list(groups["edges"].findall(f"{SVG_NS}g"))
    assert (len(boxes), len(leaves), len(edges)) == (3, 4, 3)
    assert [e.get("class") for e in edges] == [
        "edge edge-targets",
        "edge edge-ecs_lb",
        "edge edge-sg",
    ]
    assert edges[2].find(f"{SVG_NS}line").get("stroke-dasharray") == "6 4"
    # icons are embedded, so the file works offline and outside IPLens
    images = list(svg.iter(f"{SVG_NS}image"))
    assert len(images) == 5  # VPC + 4 leaves
    assert all(i.get("href").startswith("data:image/svg+xml;base64,") for i in images)
    texts = "".join(svg.itertext())
    assert 'example-web <&> "one"' in texts and "example-tg :80" in texts


def test_svg_hidden_borders_keep_labels():
    svg = _parse(view_to_svg(parse_view(json.dumps(_view(show_vpc=False, show_subnets=False)))))
    for g in svg.iter(f"{SVG_NS}g"):
        if g.get("class") in ("vpc", "subnet"):
            assert g.find(f"{SVG_NS}rect") is None
            assert g.find(f"{SVG_NS}text") is not None


def test_exports_keep_full_wrapped_and_shortened_labels():
    # As visual.js sends them: a full name wrapped after "-", and a middle-ellipsized one.
    wrapped = "team-app-dev-platform-shared-\nlambda-worker-1\nLambda\n10.0.1.11"
    short = "team-app-…-lambda-worker-2 +1 more\nLambda\n10.0.1.12"
    view = _view()
    view["nodes"][3]["label"] = wrapped
    view["nodes"][4]["label"] = short
    parsed = parse_view(json.dumps(view))

    svg = _parse(view_to_svg(parsed))
    lines = [t.text for t in svg.iter(f"{SVG_NS}tspan")] or list(svg.itertext())
    for line in (*wrapped.split("\n"), *short.split("\n")):
        assert line in lines

    values = {c.get("value") for c in _parse(view_to_drawio(parsed)).iter("mxCell")}
    assert wrapped.replace("\n", "<br>") in values
    assert short.replace("\n", "<br>") in values


def test_empty_view_exports():
    view = parse_view(json.dumps({"vpc_id": "", "nodes": [], "edges": []}))
    assert _parse(view_to_svg(view)).tag == f"{SVG_NS}svg"
    assert len(list(_parse(view_to_drawio(view)).iter("mxCell"))) == 2
    assert export_filename(view, "svg") == "iplens-diagram.svg"


# -- validation -----------------------------------------------------------------------


def _with_node(**changes) -> str:
    view = _view()
    view["nodes"][3] = {**view["nodes"][3], **changes}
    return json.dumps(view)


@pytest.mark.parametrize(
    "raw, message",
    [
        ("not json", "JSON"),
        ("[]", "object"),
        (_with_node(kind="bogus"), "node kind"),
        (_with_node(icon="../../secret.key"), "unknown icon"),
        (_with_node(x="1"), "finite number"),
        (_with_node(x=1e12), "out of range"),
        (_with_node(parent="res:eni-00000web01"), "parent"),
        (_with_node(id="vpc"), "unique"),
        (
            json.dumps(_view(edges=[{"source": "vpc", "target": "nope", "type": "sg"}])),
            "connect nodes",
        ),
        (
            json.dumps(_view(edges=[{"source": "vpc", "target": "vpc", "type": "bogus"}])),
            "edge type",
        ),
    ],
)
def test_parse_view_rejects_bad_input(raw, message):
    with pytest.raises(ValueError, match=message):
        parse_view(raw)


def test_export_filename_is_sanitised():
    view = parse_view(json.dumps(_view(vpc_id='vpc-0example";\r\nX: y')))
    assert export_filename(view, "drawio") == "iplens-vpc-0exampleXy.drawio"
