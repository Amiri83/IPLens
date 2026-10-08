"""Terraform ownership: state parsing (v4 and ``terraform show -json``), storage without
state values, unmanaged detection and the Settings / IP List / ENI pages.

Placeholders only: 10.0.x.x, account 123456789012, example names; the "secrets" below
are fake strings used to prove that nothing but ids/addresses/types is kept.
"""

import io
import json
import os

import pytest

from iplens import queries, terraform
from iplens.db import closing
from iplens.web import create_app

FAKE_SECRET = "example-not-a-real-secret-0000"
ACCOUNT = "123456789012"
VPC = "vpc-0example0000001"
SA = "subnet-0000000a"

STATE_V4 = {
    "version": 4,
    "terraform_version": "1.9.0",
    "serial": 7,
    "lineage": "00000000-0000-0000-0000-000000000000",
    "outputs": {"db_password": {"value": FAKE_SECRET, "type": "string", "sensitive": True}},
    "resources": [
        {
            "mode": "managed",
            "type": "aws_subnet",
            "name": "app",
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [
                {
                    "index_key": 0,
                    "schema_version": 1,
                    "attributes": {"id": SA, "cidr_block": "10.0.1.0/24"},
                    "sensitive_attributes": [],
                }
            ],
        },
        {
            "mode": "managed",
            "type": "aws_security_group",
            "name": "vpce",
            "instances": [{"attributes": {"id": "sg-000vpce", "name": "example-vpce-sg"}}],
        },
        {
            "module": "module.lambda",
            "mode": "managed",
            "type": "aws_lambda_function",
            "name": "this",
            "instances": [
                {
                    "index_key": "fn-a",
                    "attributes": {
                        "id": "fn-a",
                        "arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:fn-a",
                        "environment": [{"variables": {"API_TOKEN": FAKE_SECRET}}],
                    },
                    "sensitive_attributes": [[{"type": "get_attr", "value": "environment"}]],
                }
            ],
        },
        {
            "mode": "managed",
            "type": "aws_lb",
            "name": "web",
            "instances": [
                {
                    "attributes": {
                        "id": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:"
                        "loadbalancer/app/example-alb/0123456789abcdef",
                        "name": "example-alb",
                    }
                }
            ],
        },
        {
            "mode": "managed",
            "type": "aws_ecs_service",
            "name": "svc",
            "instances": [
                {
                    "attributes": {
                        "id": f"arn:aws:ecs:us-east-1:{ACCOUNT}:service/example-cluster/example-svc"
                    }
                }
            ],
        },
        {  # a type IPLens does not map: ignored, its password never read into storage
            "mode": "managed",
            "type": "aws_db_instance",
            "name": "db",
            "instances": [{"attributes": {"id": "db-EXAMPLE", "password": FAKE_SECRET}}],
        },
        {  # data sources are not managed by the root
            "mode": "data",
            "type": "aws_vpc",
            "name": "main",
            "instances": [{"attributes": {"id": VPC}}],
        },
        {  # an id marked sensitive is skipped
            "mode": "managed",
            "type": "aws_network_interface",
            "name": "hidden",
            "instances": [
                {
                    "attributes": {"id": "eni-0000000777"},
                    "sensitive_attributes": [[{"type": "get_attr", "value": "id"}]],
                }
            ],
        },
        {  # not shaped like a subnet id: skipped
            "mode": "managed",
            "type": "aws_subnet",
            "name": "bogus",
            "instances": [{"attributes": {"id": FAKE_SECRET}}],
        },
    ],
}

SHOW_JSON = {
    "format_version": "1.0",
    "terraform_version": "1.9.0",
    "values": {
        "outputs": {"token": {"sensitive": True, "value": FAKE_SECRET}},
        "root_module": {
            "resources": [
                {
                    "address": "aws_vpc_endpoint.lambda",
                    "mode": "managed",
                    "type": "aws_vpc_endpoint",
                    "name": "lambda",
                    "values": {"id": "vpce-0example0001", "policy": FAKE_SECRET},
                    "sensitive_values": {},
                },
                {
                    "address": "aws_nat_gateway.a",
                    "mode": "managed",
                    "type": "aws_nat_gateway",
                    "name": "a",
                    "values": {"id": "nat-0example0001"},
                    "sensitive_values": {},
                },
                {
                    "address": "aws_network_interface.secret",
                    "mode": "managed",
                    "type": "aws_network_interface",
                    "name": "secret",
                    "values": {"id": "eni-0000000888"},
                    "sensitive_values": {"id": True},
                },
            ],
            "child_modules": [
                {
                    "address": "module.net",
                    "resources": [
                        {
                            "address": 'module.net.aws_subnet.private["b"]',
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "private",
                            "index": "b",
                            "values": {"id": "subnet-0000000b"},
                            "sensitive_values": {},
                        }
                    ],
                    "child_modules": [
                        {
                            "address": "module.net.module.inner",
                            "resources": [
                                {
                                    "address": "module.net.module.inner.aws_network_interface.x",
                                    "mode": "managed",
                                    "type": "aws_network_interface",
                                    "name": "x",
                                    "values": {"id": "eni-0000000009"},
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    },
}


def _triples(resources):
    return {(r.address, r.kind, r.resource_id) for r in resources}


# -- parsing --------------------------------------------------------------------------


def test_parse_state_v4():
    found = terraform.parse_state(json.dumps(STATE_V4))
    assert _triples(found) == {
        ("aws_subnet.app[0]", "subnet", SA),
        ("aws_security_group.vpce", "sg", "sg-000vpce"),
        ('module.lambda.aws_lambda_function.this["fn-a"]', "lambda", "fn-a"),
        ("aws_lb.web", "lb", "example-alb"),
        ("aws_ecs_service.svc", "ecs_service", "example-cluster/example-svc"),
    }
    assert {r.type for r in found} == {
        "aws_subnet",
        "aws_security_group",
        "aws_lambda_function",
        "aws_lb",
        "aws_ecs_service",
    }
    # only address / type / kind / id exist on the parsed objects
    assert FAKE_SECRET not in repr(found) and "10.0.1.0/24" not in repr(found)


def test_parse_terraform_show_json():
    found = terraform.parse_state(json.dumps(SHOW_JSON).encode())
    assert _triples(found) == {
        ("aws_vpc_endpoint.lambda", "vpce", "vpce-0example0001"),
        ("aws_nat_gateway.a", "nat", "nat-0example0001"),
        ('module.net.aws_subnet.private["b"]', "subnet", "subnet-0000000b"),
        ("module.net.module.inner.aws_network_interface.x", "eni", "eni-0000000009"),
    }
    assert FAKE_SECRET not in repr(found)


def test_parse_old_ecs_service_arn_uses_cluster_attribute():
    state = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_ecs_service",
                "name": "old",
                "instances": [
                    {
                        "attributes": {
                            "id": f"arn:aws:ecs:us-east-1:{ACCOUNT}:service/example-svc",
                            "cluster": f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/example-cluster",
                            "name": "example-svc",
                        }
                    }
                ],
            }
        ],
    }
    (svc,) = terraform.parse_state(json.dumps(state))
    assert (svc.kind, svc.resource_id) == ("ecs_service", "example-cluster/example-svc")


@pytest.mark.parametrize(
    "text, message",
    [
        ("not json", "not a JSON"),
        ("[]", "not a Terraform"),
        ('{"foo": 1}', "not a Terraform"),
        ('{"version": 3, "resources": []}', "version 4"),
    ],
)
def test_parse_state_rejects_other_documents(text, message):
    with pytest.raises(ValueError, match=message):
        terraform.parse_state(text)


def test_parse_errors_never_quote_the_file():
    with pytest.raises(ValueError) as err:
        terraform.parse_state('{"password": "' + FAKE_SECRET + '"')
    assert FAKE_SECRET not in str(err.value)


@pytest.mark.parametrize(
    "filename, expected",
    [
        ("root-a.tfstate", "root-a"),
        ("/x/root-b.json", "root-b"),
        ("we!rd name.tfstate", "we-rd name"),
    ],
)
def test_root_name_from_filename(filename, expected):
    assert terraform.root_name_from_filename(filename) == expected


@pytest.mark.parametrize("name", ["", " ", "x" * 65, "../root", "root;drop"])
def test_validate_root_name_rejects(name):
    with pytest.raises(ValueError):
        terraform.validate_root_name(name)


# -- ownership / unmanaged ------------------------------------------------------------


def _seed(db_path, builder):
    b = builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(SA, VPC, "10.0.1.0/24", name="example-app-a")
    b.eni("eni-0000000001", SA, ["10.0.1.10"], owner_type="lambda", owner_ref="fn-a")
    b.eni(
        "eni-0000000002",
        SA,
        ["10.0.1.20"],
        owner_type="vpc_endpoint",
        owner_ref="vpce-0example0001",
    )
    b.eni(
        "eni-0000000003",
        SA,
        ["10.0.1.30"],
        owner_ref="i-0example0003",
        instance_id="i-0example0003",
    )
    b.endpoint("vpce-0example0001", VPC, "com.amazonaws.us-east-1.lambda", [SA], ["eni-0000000002"])
    return b


def _load_roots(db_path):
    with closing(db_path) as conn:
        terraform.save_root(conn, "root-a", terraform.parse_state(json.dumps(STATE_V4)))
        terraform.save_root(conn, "root-b", terraform.parse_state(json.dumps(SHOW_JSON)))


def test_ownership_and_unmanaged_detection(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    _load_roots(db_path)
    with closing(db_path) as conn:
        rows = {r["eni_id"]: r for r in queries.ip_list(conn, b.id)}
        unmanaged = queries.ip_list(conn, b.id, queries.IpFilter(tf="unmanaged"))
        managed = queries.ip_list(conn, b.id, queries.IpFilter(tf="managed"))
        only_a = queries.ip_list(conn, b.id, queries.IpFilter(tf="root-a"))
        detail = queries.eni_detail(conn, b.id, "eni-0000000003")
    assert [queries.tf_label(m) for m in rows["eni-0000000001"]["tf"]] == [
        'managed by root-a: module.lambda.aws_lambda_function.this["fn-a"]'
    ]
    assert [queries.tf_label(m) for m in rows["eni-0000000002"]["tf"]] == [
        "managed by root-b: aws_vpc_endpoint.lambda"
    ]
    # the EC2 instance's id appears in no root: unmanaged (its subnet being managed
    # does not make the resource managed)
    assert rows["eni-0000000003"]["tf"] == []
    assert [r["ip"] for r in unmanaged] == ["10.0.1.30"]
    assert [r["ip"] for r in managed] == ["10.0.1.10", "10.0.1.20"]
    assert [r["ip"] for r in only_a] == ["10.0.1.10"]
    assert detail["tf"] == []
    assert [m["address"] for m in detail["subnet_tf"]] == ["aws_subnet.app[0]"]


def test_visual_nodes_carry_ownership(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    _load_roots(db_path)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
    nodes = {n["eni_id"]: n for n in data["vpc"]["subnets"][0]["items"]}
    assert [m["root"] for m in nodes["eni-0000000001"]["tf"]] == ["root-a"]
    assert nodes["eni-0000000003"]["tf"] == []
    assert data["tf_roots"] == ["root-a", "root-b"]


def test_save_root_replaces_and_stores_only_ids(db_path):
    with closing(db_path) as conn:
        root_id = terraform.save_root(conn, "root-a", terraform.parse_state(json.dumps(STATE_V4)))
        again = terraform.save_root(conn, "root-a", terraform.parse_state(json.dumps(SHOW_JSON)))
        assert again == root_id
        (root,) = terraform.list_roots(conn)
        assert (root["name"], root["resources"]) == ("root-a", 4)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(tf_resources)")}
        assert cols == {"root_id", "kind", "resource_id", "address", "type"}
        dump = "\n".join(conn.iterdump())
    assert FAKE_SECRET not in dump


# -- web: Settings -> Terraform state, IP List, ENI page -------------------------------


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


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


def _upload(client, *files, name=""):
    data = {"name": name, "path": "", "files": [(io.BytesIO(body), fn) for fn, body in files]}
    return _post(client, "/settings/terraform", data, content_type="multipart/form-data")


def test_upload_roots_and_pages(app, client, snapshot_builder):
    _seed(_db(app), snapshot_builder)
    resp = _upload(
        client,
        ("root-a.tfstate", json.dumps(STATE_V4).encode()),
        ("root-b.json", json.dumps(SHOW_JSON).encode()),
        name="",
    )
    assert resp.status_code == 302
    settings = client.get("/settings").data.decode()
    assert "root-a" in settings and "root-b" in settings and "Terraform state" in settings

    page = client.get("/ips").data.decode()
    assert "<th>Terraform</th>" in page and "<th>Tags</th>" in page
    assert "managed by <b>root-a</b>" in page and "managed by <b>root-b</b>" in page
    assert "unmanaged" in page
    page = client.get("/ips?tf=unmanaged").data.decode()
    assert "10.0.1.30" in page and "10.0.1.10" not in page

    eni = client.get("/enis/eni-0000000001").data.decode()
    assert "managed by <b>root-a</b>" in eni
    eni = client.get("/enis/eni-0000000003").data.decode()
    assert "unmanaged — in no loaded Terraform root" in eni
    assert "subnet managed by <b>root-a</b>" in eni

    # nothing from the state files but ids/addresses/types reached storage or the logs
    with closing(_db(app)) as conn:
        assert FAKE_SECRET not in "\n".join(conn.iterdump())
    log_dir = app.extensions["iplens"]["log_dir"]
    for name in os.listdir(log_dir):
        with open(os.path.join(log_dir, name), encoding="utf-8") as fh:
            assert FAKE_SECRET not in fh.read()
    assert FAKE_SECRET not in settings + page + eni


def test_upload_rejects_invalid_state_and_stores_nothing(app, client):
    resp = _upload(
        client,
        ("ok.tfstate", json.dumps(STATE_V4).encode()),
        ("bad.tfstate", b'{"secret": "' + FAKE_SECRET.encode() + b'"}'),
    )
    assert resp.status_code == 302
    page = client.get("/settings").data.decode()
    assert "Terraform state not loaded" in page and FAKE_SECRET not in page
    with closing(_db(app)) as conn:
        assert terraform.list_roots(conn) == []


def test_named_root_from_local_path_reload_and_remove(app, client, tmp_path):
    state = tmp_path / "state" / "terraform.tfstate"
    state.parent.mkdir()
    state.write_text(json.dumps(STATE_V4))

    resp = _post(client, "/settings/terraform", {"name": "root-a", "path": str(state)})
    assert resp.status_code == 302
    with closing(_db(app)) as conn:
        (root,) = terraform.list_roots(conn)
    assert (root["name"], root["resources"], root["source_path"]) == ("root-a", 5, str(state))

    state.write_text(json.dumps(SHOW_JSON))  # e.g. after a terraform apply
    assert _post(client, f"/settings/terraform/{root['id']}/reload").status_code == 302
    with closing(_db(app)) as conn:
        assert terraform.list_roots(conn)[0]["resources"] == 4
    assert _post(client, f"/settings/terraform/{root['id']}/delete").status_code == 302
    with closing(_db(app)) as conn:
        assert terraform.list_roots(conn) == []
    assert state.exists()  # removing a root never touches the file
    assert _post(client, f"/settings/terraform/{root['id']}/delete").status_code == 404


def test_local_state_file_is_only_read(app, client, tmp_path):
    state = tmp_path / "root-b.json"
    state.write_text(json.dumps(SHOW_JSON))
    os.chmod(state, 0o444)
    before = (state.read_bytes(), state.stat().st_mtime_ns)
    assert _post(client, "/settings/terraform", {"path": str(state)}).status_code == 302
    assert (state.read_bytes(), state.stat().st_mtime_ns) == before
    with closing(_db(app)) as conn:
        assert [r["name"] for r in terraform.list_roots(conn)] == ["root-b"]


def test_missing_path_and_csrf(app, client, tmp_path):
    _post(client, "/settings/terraform", {"path": str(tmp_path / "missing.tfstate")})
    assert "no such file" in client.get("/settings").data.decode()
    assert client.post("/settings/terraform", data={"path": "x"}).status_code == 400
