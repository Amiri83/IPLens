"""Visual page Logical view (iplens.logical): multi-AZ ENIs of one owner collapse into one
node, edges between collapsed nodes are merged, the comma-separated name filter applies to
logical nodes, and the page / data routes serve the view. The browser path is in
tests/test_visual_browser.py. Placeholders only: 192.0.2.N, fn-a, lb-a, nat-a."""

import json

import pytest

from iplens import logical, queries, viewstate
from iplens.attribution import OWNER_LABELS
from iplens.db import closing
from iplens.logical import identity, logical_edges, logical_view, node_id
from iplens.tagfilter import name_terms, resource_visible
from iplens.web import create_app

VPC = "vpc-0abc1234"
SUBNETS = {"subnet-a": "us-east-1a", "subnet-b": "us-east-1b", "subnet-c": "us-east-1c"}
LB = {"subnet-a": "eni-0abc0001", "subnet-b": "eni-0abc0002", "subnet-c": "eni-0abc0003"}
FN = {"subnet-a": "eni-0abc0011", "subnet-b": "eni-0abc0012", "subnet-c": "eni-0abc0013"}
TASKS = {"subnet-a": "eni-0abc0021", "subnet-b": "eni-0abc0022"}
NAT, WEB = "eni-0abc0031", "eni-0abc0041"
LOOSE = ("eni-0abc0051", "eni-0abc0052")  # no owner reference: one node each


def _ip(subnet: str, n: int) -> str:
    return f"192.0.2.{64 * list(SUBNETS).index(subnet) + n}"


def seed(db, snapshot_builder):
    """lb-a and fn-a in three AZs, an ECS service in two, nat-a and an instance in one,
    two ENIs without owner; lb-a targets fn-a and the instance, the service sits behind lb-a."""
    b = snapshot_builder(db)
    b.vpc(VPC, "192.0.2.0/24")
    for subnet, az in SUBNETS.items():
        b.subnet(subnet, VPC, f"{_ip(subnet, 0)}/26", az=az, name=f"test-{subnet}")
    for subnet, eni in LB.items():
        b.eni(eni, subnet, [_ip(subnet, 10)], owner_type="elb", owner_ref="lb-a")
    for subnet, eni in FN.items():
        b.eni(eni, subnet, [_ip(subnet, 20)], owner_type="lambda", owner_ref="fn-a")
    for i, (subnet, eni) in enumerate(TASKS.items()):
        ref = f"cluster-a/svc-a/task-{i}"
        b.eni(eni, subnet, [_ip(subnet, 30)], owner_type="ecs", owner_ref=ref)
    b.ecs_service("cluster-a", "svc-a", None, eni_ids=tuple(TASKS.values()), desired=2)
    b.eni(NAT, "subnet-a", [_ip("subnet-a", 40)], owner_type="nat", owner_ref="nat-a")
    b.eni(
        WEB,
        "subnet-b",
        [_ip("subnet-b", 50)],
        owner_ref="i-0abc1234",
        instance_id="i-0abc1234",
        instance_name="test-server-a",
    )
    for i, eni in enumerate(LOOSE):
        b.eni(eni, "subnet-c", [_ip("subnet-c", 60 + i)], owner_type="other")
    b.lb_target("lb-a", "tg-fn", "lambda", "fn-a")
    b.lb_target("lb-a", "tg-web", "instance", "i-0abc1234", 80)
    b.ecs_service_lb("cluster-a", "svc-a", "lb-a", "tg-svc")
    b.tag("lambda", "fn-a", "Env", "dev")
    return b


def _logical(db, snap_id, edge_types=logical.EDGE_TYPES):
    with closing(db) as conn:
        data = queries.visual_data(conn, snap_id, VPC, OWNER_LABELS)
    return data, logical_view(data, edge_types)


def _nodes(view):
    return {n["id"]: n for n in view["vpc"]["items"]}


# -- grouping ----------------------------------------------------------------------------------


def test_multi_az_enis_of_one_owner_collapse_into_one_node(db_path, snapshot_builder):
    b = seed(db_path, snapshot_builder)
    data, view = _logical(db_path, b.id)
    nodes = _nodes(view)
    # 12 resource ENIs in the IP view, 7 logical resources.
    assert sum(s["resource_count"] for s in data["vpc"]["subnets"]) == 12
    assert list(nodes) == [
        "elb:lb-a",
        "nat:nat-a",
        "lambda:fn-a",
        "ecs:cluster-a/svc-a",
        "ec2:i-0abc1234",
        "eni:eni-0abc0051",
        "eni:eni-0abc0052",
    ]
    assert view["vpc"]["subnets"] == []
    assert view["logical"] == {"resources": 7, "enis": 12, "zones": 3}

    fn = nodes["lambda:fn-a"]
    assert fn["zones"] == ["us-east-1a", "us-east-1b", "us-east-1c"]
    assert fn["eni_count"] == 3 and fn["name"] == "fn-a" and fn["type_label"] == "Lambda"
    assert fn["tag_values"] == {"Env": ["dev"]}
    assert nodes["elb:lb-a"]["zones"] == list(SUBNETS.values())
    # An ECS service is one node named after the service, not after one of its tasks.
    svc = nodes["ecs:cluster-a/svc-a"]
    assert svc["name"] == "cluster-a/svc-a" and svc["owners"] == ["cluster-a/svc-a"]
    assert svc["zones"] == ["us-east-1a", "us-east-1b"]
    assert nodes["nat:nat-a"]["zones"] == ["us-east-1a"]
    assert nodes["ec2:i-0abc1234"]["name"] == "test-server-a"


def test_logical_nodes_carry_no_ips_or_eni_ids(db_path, snapshot_builder):
    b = seed(db_path, snapshot_builder)
    _, view = _logical(db_path, b.id)
    for n in view["vpc"]["items"]:
        assert n["ips"] == [] and "eni_id" not in n and "subnet_id" not in n
    assert "192.0.2." not in json.dumps(view["vpc"]["items"])
    # Only an ENI without owner, which has no other name, is named after its ENI id.
    owned = [n for n in view["vpc"]["items"] if not n["id"].startswith("eni:")]
    assert len(owned) == 5 and "eni-" not in json.dumps(owned)


def test_shared_lambda_enis_are_one_node_per_function_set(db_path, snapshot_builder):
    b = seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        conn.execute(
            "UPDATE enis SET owner_names=? WHERE owner_type='lambda'",
            (json.dumps(["fn-a", "fn-b"]),),
        )
    _, view = _logical(db_path, b.id)
    fn = _nodes(view)["lambda:fn-a,fn-b"]
    assert fn["owners"] == ["fn-a", "fn-b"] and fn["name"] == "fn-a +1 more"
    assert fn["eni_count"] == 3


def test_identity_rules():
    def r(type_, ref="", owners=(), eni="eni-0abc0099"):
        return {"type": type_, "ref": ref, "owners": list(owners), "eni_id": eni}

    assert identity(r("lambda", "fn-b", ["fn-b", "fn-a"])) == ("lambda", "fn-a,fn-b")
    assert identity(r("ecs", "cluster-a/svc-a/task-1")) == ("ecs", "cluster-a/svc-a")
    assert identity(r("ecs", "cluster-a/task-1")) == ("ecs", "cluster-a/task-1")  # standalone
    assert identity(r("rds", "db-a")) == ("rds", "db-a")
    assert identity(r("vpc_endpoint", "vpce-0abc1234")) == ("vpc_endpoint", "vpce-0abc1234")
    # No owner reference, or the catch-all type: the ENI stays a node of its own.
    assert identity(r("rds")) == ("eni", "eni-0abc0099")
    assert identity(r("other", "EKS")) == ("eni", "eni-0abc0099")


def test_long_node_ids_are_cut_and_hashed():
    owners = ",".join(f"fn-{i:03d}" for i in range(40))
    nid = node_id(("lambda", owners))
    assert len(nid) == logical.MAX_ID and "#" in nid
    assert nid == node_id(("lambda", owners)) != node_id(("lambda", owners + ",fn-x"))
    assert len("res:" + nid) <= viewstate.MAX_NODE_ID


# -- edges -------------------------------------------------------------------------------------


def test_edges_between_collapsed_nodes_are_deduped(db_path, snapshot_builder):
    b = seed(db_path, snapshot_builder)
    data, view = _logical(db_path, b.id)
    ip_edges = [(e["type"], e["source"], e["target"]) for e in data["edges"]]
    # IP view: lb-a -> fn-a once per AZ, svc-a -> lb-a once per task.
    assert sorted(ip_edges) == sorted(
        [("targets", LB[s], FN[s]) for s in SUBNETS]
        + [("targets", LB["subnet-b"], WEB)]
        + [("ecs_lb", TASKS[s], LB[s]) for s in TASKS]
    )
    edges = {(e["type"], e["source"], e["target"]): e for e in view["edges"]}
    assert set(edges) == {
        ("targets", "elb:lb-a", "lambda:fn-a"),
        ("targets", "elb:lb-a", "ec2:i-0abc1234"),
        ("ecs_lb", "ecs:cluster-a/svc-a", "elb:lb-a"),
    }
    fn = edges[("targets", "elb:lb-a", "lambda:fn-a")]
    assert fn["merged"] == 3 and fn["label"] == "tg-fn"
    assert fn["title"] == "lb-a → fn-a (target group tg-fn)"  # identical lines kept once
    assert fn["id"] == "targets:elb:lb-a>lambda:fn-a"
    assert edges[("ecs_lb", "ecs:cluster-a/svc-a", "elb:lb-a")]["merged"] == 2
    counts = {t["type"]: t["count"] for t in view["edge_types"]}
    assert counts == {"targets": 2, "ecs_lb": 1, "reach": 0, "sg": 0}


def test_merged_edge_keeps_distinct_labels_and_titles():
    of_eni = {
        "eni-1": "elb:lb-a",
        "eni-2": "elb:lb-a",
        "eni-3": "lambda:fn-a",
        "eni-4": "lambda:fn-a",
    }
    edges = [
        {"type": "targets", "source": "eni-1", "target": "eni-3", "label": "tg-a", "title": "t1"},
        {"type": "targets", "source": "eni-2", "target": "eni-4", "label": "tg-b", "title": "t2"},
        {"type": "sg", "source": "eni-1", "target": "eni-3", "label": "sg", "title": "t3"},
        {"type": "sg", "source": "eni-1", "target": "eni-2", "label": "self", "title": "t4"},
        {"type": "sg", "source": "eni-1", "target": "eni-9", "label": "gone", "title": "t5"},
    ]
    out = {(e["type"], e["source"], e["target"]): e for e in logical_edges(edges, of_eni)}
    # One edge per type and node pair; inside one resource or to an unknown ENI: none.
    assert set(out) == {("targets", "elb:lb-a", "lambda:fn-a"), ("sg", "elb:lb-a", "lambda:fn-a")}
    merged = out[("targets", "elb:lb-a", "lambda:fn-a")]
    assert (merged["label"], merged["title"], merged["merged"]) == ("tg-a, tg-b", "t1\nt2", 2)


def test_edge_type_selection_keeps_unfiltered_counts(db_path, snapshot_builder):
    b = seed(db_path, snapshot_builder)
    _, view = _logical(db_path, b.id, ("ecs_lb",))
    assert {e["type"] for e in view["edges"]} == {"ecs_lb"}
    assert [(t["type"], t["count"], t["selected"]) for t in view["edge_types"]] == [
        ("targets", 2, False),
        ("ecs_lb", 1, True),
        ("reach", 0, False),
        ("sg", 0, False),
    ]


def test_no_vpc_data_is_returned_unchanged():
    data = {"snapshot_id": 1, "vpcs": [], "vpc": None}
    assert logical_view(data) is data


# -- multi-term name filter (both views) ---------------------------------------------------


@pytest.mark.parametrize(
    "text, terms",
    [
        ("dev, uat", ["dev", "uat"]),
        ("dev,,", ["dev"]),
        ("dev", ["dev"]),
        (" DEV , ,UAT ", ["dev", "uat"]),
        (",, ,", []),
    ],
)
def test_name_filter_parsing(text, terms):
    assert name_terms(text) == terms


FILTER_NODES = [
    {"id": "lambda:fn-dev-a", "type": "lambda", "name": "fn-dev-a", "owners": ["fn-dev-a"]},
    {"id": "lambda:fn-uat-a", "type": "lambda", "name": "fn-uat-a", "owners": ["fn-uat-a"]},
    {"id": "nat:nat-a", "type": "nat", "name": "nat-prod-a", "owners": ["nat-a"]},
]


@pytest.mark.parametrize(
    "text, shown",
    [
        ("dev, uat", ["lambda:fn-dev-a", "lambda:fn-uat-a"]),
        ("dev,,", ["lambda:fn-dev-a"]),
        ("UAT", ["lambda:fn-uat-a"]),
        ("", ["lambda:fn-dev-a", "lambda:fn-uat-a", "nat:nat-a"]),
        ("nat-a", ["nat:nat-a"]),  # an owner reference matches too
    ],
)
def test_name_filter_on_logical_nodes(text, shown):
    assert [n["id"] for n in FILTER_NODES if resource_visible(n, [], text)] == shown


# -- routes and per-view state ----------------------------------------------------------------


@pytest.fixture
def app(home, snapshot_builder):
    app = create_app(home, testing=True)
    seed(app.extensions["iplens"]["paths"].db_path, snapshot_builder)
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _post(client, url, data):
    with client.session_transaction() as s:
        data = {**data, "csrf_token": s["csrf"]}
    return client.post(url, data=data)


def test_data_route_serves_the_logical_view(client):
    data = client.get(f"/visual/data.json?vpc={VPC}&view=logical").get_json()
    assert data["vpc"]["subnets"] == [] and len(data["vpc"]["items"]) == 7
    assert data["logical"]["enis"] == 12
    assert "tgw" not in data and "extended" not in data
    # The IP view is unchanged: per-ENI nodes in their subnets.
    ip = client.get(f"/visual/data.json?vpc={VPC}").get_json()
    assert "logical" not in ip and len(ip["vpc"]["subnets"]) == 3


def test_page_shows_the_logical_tab(client):
    html = client.get(f"/visual?vpc={VPC}&view=logical").get_data(as_text=True)
    assert 'aria-current="page">Logical view</a>' in html
    assert 'data-mode="logical"' in html
    assert f'data-layout-key="{VPC}:logical"' in html
    assert 'name="view" value="logical"' in html  # a VPC change stays in the view
    assert 'id="tgw-note"' not in html
    assert "view=logical" in client.get(f"/visual?vpc={VPC}").get_data(as_text=True)


def test_logical_view_exports(client):
    nodes = [
        {"id": "vpc", "kind": "vpc", "label": VPC, "x": 0, "y": 0, "w": 400, "h": 200},
        {
            "id": "res:lambda:fn-a",
            "kind": "res",
            "parent": "vpc",
            "label": "fn-a\nLambda\n3 AZ",
            "x": 40,
            "y": 60,
            "w": 44,
            "h": 44,
            "icon": queries.TYPE_ICONS["lambda"],
        },
    ]
    view = {"vpc_id": VPC, "mode": "logical", "nodes": nodes, "edges": []}
    resp = _post(client, "/visual/export.svg", {"view": json.dumps(view)})
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].endswith(f"iplens-{VPC}-logical.svg")
    assert "3 AZ" in resp.get_data(as_text=True)


def test_logical_view_state_is_kept_apart(app, client):
    assert _post(client, "/visual/prefs", {"view": "logical", "layout": "dagre"}).status_code == 204
    form = {"view": "logical", "vpc": VPC, "expanded": "[]"}
    assert _post(client, "/visual/prefs", form).status_code == 204
    with closing(app.extensions["iplens"]["paths"].db_path) as conn:
        ref = conn.execute("SELECT MIN(id) FROM accounts").fetchone()[0]
        assert viewstate.get_view_layout(conn, ref, "logical") == "dagre"
        assert viewstate.get_view_layout(conn, ref, "ip") == "grid"
    assert viewstate.layout_key(VPC, "logical") == f"{VPC}:logical"
    assert viewstate.layout_key(VPC, "ip") == VPC
