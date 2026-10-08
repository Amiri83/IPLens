"""Form-based rule editing: snapshot-populated choices, plain-English summaries, YAML
moved under "Advanced". Placeholder data only (10.0.x.x, 123456789012, example names)."""

import pytest

from iplens import rules as r
from iplens.db import closing
from iplens.suggestions import build_context
from iplens.web import create_app

VPC_A, VPC_B = "vpc-0example0000a", "vpc-0example0000b"
SA, SB = "subnet-0000000a", "subnet-0000000b"


def _snapshot(builder, db_path):
    b = builder(db_path)
    b.vpc(VPC_A, "10.0.0.0/17", name="example-vpc-a").vpc(VPC_B, "10.0.128.0/17", name="")
    b.subnet(SA, VPC_A, "10.0.1.0/28", name="example-app-a")
    b.subnet(SB, VPC_B, "10.0.129.0/28")
    b.eni("eni-000000000a", SA, [f"10.0.1.{i}" for i in range(4, 14)])
    b.eni("eni-000000000b", SB, [f"10.0.129.{i}" for i in range(4, 14)])
    b.load_balancer("example-public-alb", VPC_A, scheme="internet-facing")
    b.load_balancer("example-other-alb", VPC_B, scheme="internet-facing")
    b.load_balancer("example-internal-nlb", VPC_A, lb_type="network")
    return b


# -- plain-English summaries ---------------------------------------------------------------


@pytest.mark.parametrize(
    "kind, params, expected",
    [
        ("lambda_vpc_required", {}, "Every Lambda function must be attached to a VPC."),
        (
            "internal_only",
            {"scope": "load_balancer", "lb_names": ["example-public-alb"]},
            "Load balancers must stay internal-only. Load balancers example-public-alb are "
            "reported if internet-facing.",
        ),
        ("internal_only", {"scope": "vpc_endpoint"}, "VPC endpoints must stay internal-only."),
        (
            "subnet_reserved",
            {"subnet_ids": [SA]},
            f"Subnet {SA} (example-app-a) is reserved: no suggestion may change it",
        ),
        (
            "min_free_pct",
            {"percent": 20.0, "subnet_ids": []},
            "Keep at least 20% of the usable IPs free in every subnet.",
        ),
        (
            "min_free_pct",
            {"percent": 12.5, "subnet_ids": [SB], "vpc_ids": [VPC_A]},
            f"Keep at least 12.5% of the usable IPs free in subnets {SB} and every subnet of "
            f"VPC {VPC_A} (example-vpc-a).",
        ),
        (
            "protected_eni",
            {"pattern": "keep-me"},
            "ENIs whose id, description, Name or owner matches “keep-me” must never be removed",
        ),
        ("ecs_scale_down", {"mode": "deny", "pattern": ""}, "No ECS service may be scaled down"),
        (
            "ecs_scale_down",
            {"mode": "deny", "pattern": "^prod/"},
            "ECS services matching “^prod/” must not be scaled down",
        ),
    ],
)
def test_describe_is_plain_english(kind, params, expected):
    names = {SA: "example-app-a", VPC_A: "example-vpc-a"}
    assert expected in r.Rule(name="x", kind=kind, params=params).describe(names)


# -- params from multi-selects --------------------------------------------------------------


def test_normalize_accepts_multiselect_lists_and_new_params():
    assert r.normalize_params(
        "min_free_pct", {"percent": "10", "subnet_ids": [SA, f"{SB}, {SA}"], "vpc_ids": [VPC_A]}
    ) == {"percent": 10.0, "subnet_ids": [SA, SB], "vpc_ids": [VPC_A]}
    assert r.normalize_params(
        "internal_only", {"scope": "both", "lb_names": ["example-public-alb"]}
    ) == {"scope": "both", "lb_names": ["example-public-alb"]}
    # load balancer names mean nothing for an endpoint-only rule
    assert r.normalize_params(
        "internal_only", {"scope": "vpc_endpoint", "lb_names": ["example-public-alb"]}
    ) == {"scope": "vpc_endpoint"}
    with pytest.raises(ValueError, match="invalid VPC id"):
        r.normalize_params("min_free_pct", {"percent": 5, "vpc_ids": ["vpc_bad!"]})
    with pytest.raises(ValueError, match="invalid load balancer name"):
        r.normalize_params("internal_only", {"lb_names": ["bad_name!"]})


def test_vpc_and_lb_scoped_violations(db_path, snapshot_builder):
    snap = _snapshot(snapshot_builder, db_path)
    with closing(db_path) as conn:
        ctx = build_context(conn, snap.id)
    free = r.Rule(name="f", kind="min_free_pct", params={"percent": 50, "vpc_ids": [VPC_B]})
    assert [v.split(" ")[0] for v in free.violations(ctx)] == [SB]
    internal = r.Rule(
        name="i", kind="internal_only", params={"scope": "both", "lb_names": ["example-public-alb"]}
    )
    assert internal.violations(ctx) == ["Load balancer example-public-alb is internet-facing"]


# -- web form -------------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


def test_rule_form_choices_come_from_latest_snapshot(app, client, snapshot_builder):
    _snapshot(snapshot_builder, app.extensions["iplens"]["paths"].db_path)
    page = client.get("/rules/new").data.decode()
    assert '<label for="kind">Rule type</label>' in page
    assert '<select id="subnet_ids" name="subnet_ids" multiple' in page
    assert f'<option value="{SA}" >{SA} · example-app-a (10.0.1.0/28' in page
    assert '<select id="vpc_ids" name="vpc_ids" multiple' in page
    assert f'<option value="{VPC_A}" >{VPC_A} · example-vpc-a' in page
    assert '<option value="example-internal-nlb" >example-internal-nlb (network, internal)' in page
    assert "textarea" not in page  # no YAML on the form

    resp = _post(
        client,
        "/rules/new",
        {
            "name": "keep-free",
            "kind": "min_free_pct",
            "percent": "30",
            "subnet_ids": [SA],
            "vpc_ids": [VPC_B],
            "enabled": "on",
        },
    )
    assert resp.status_code == 302
    page = client.get("/rules").data.decode()
    assert (
        f"Keep at least 30% of the usable IPs free in subnets {SA} (example-app-a) and every "
        f"subnet of VPC {VPC_B}."
    ) in page
    assert f"{SB} (10.0.129.0/28) has" in page  # violation via the VPC selection

    with closing(app.extensions["iplens"]["paths"].db_path) as conn:
        rule = r.list_rules(conn)[0]
    assert rule.params == {"percent": 30.0, "subnet_ids": [SA], "vpc_ids": [VPC_B]}
    page = client.get(f"/rules/{rule.id}/edit").data.decode()
    assert f'<option value="{SA}" selected>' in page
    assert f'<option value="{VPC_B}" selected>' in page
    assert "<b>This rule says:</b> Keep at least 30%" in page


def test_ids_missing_from_snapshot_stay_selected(app, client, snapshot_builder):
    _snapshot(snapshot_builder, app.extensions["iplens"]["paths"].db_path)
    _post(
        client,
        "/rules/new",
        {
            "name": "res",
            "kind": "subnet_reserved",
            "subnet_ids": ["subnet-0000ffff"],
            "enabled": "on",
        },
    )
    page = client.get("/rules/1/edit").data.decode()
    assert (
        '<option value="subnet-0000ffff" selected>subnet-0000ffff (not in the latest snapshot)'
        in page
    )


def test_yaml_lives_under_advanced(client):
    page = client.get("/rules").data.decode()
    advanced = page.split('<details class="advanced">', 1)
    assert len(advanced) == 2
    assert "Advanced: import/export (YAML)" in advanced[1]
    assert "Export YAML" not in advanced[0] and 'name="yaml"' not in advanced[0]
    assert "Export YAML" in advanced[1] and 'name="yaml"' in advanced[1]
