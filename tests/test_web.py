import io

import boto3
import pytest
from moto import mock_aws

from iplens.db import closing
from iplens.rules import list_rules
from iplens.web import create_app

FAKE_KEY_ID = "AKIAEXAMPLEEXAMPLE00"
FAKE_SECRET = "example/secret/value/for/tests/only/0000"
VPC = "vpc-0example0000001"
SA = "subnet-0000000a"


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _csrf(client) -> str:
    with client.session_transaction() as s:
        return s["csrf"]


def _post(client, url, data=None, **kw):
    data = dict(data or {})
    data["csrf_token"] = _csrf(client)
    return client.post(url, data=data, **kw)


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


@pytest.fixture
def seeded(app, snapshot_builder, ips):
    b = snapshot_builder(_db(app))
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.1.0/24", name="example-private-a")
    b.eni("eni-0000000001", SA, ips("10.0.1.0", 10, 3), owner_ref="i-0example0001",
          description="example app server")
    b.eni("eni-0000000002", SA, ["10.0.1.50"], status="available", owner_type="other",
          description="example detached")
    b.lambda_fn("example-no-vpc", None)
    return b


def test_pages_render_without_snapshot(client):
    for url in ("/", "/ips", "/suggestions", "/rules", "/logs", "/settings", "/rules/new"):
        resp = client.get(url)
        assert resp.status_code == 200, url
    assert b"No snapshot yet" in client.get("/").data


def test_post_requires_csrf(client):
    assert client.post("/refresh").status_code == 400
    assert client.post("/settings", data={"csrf_token": "wrong"}).status_code == 400


def test_overview_subnet_eni_ips(client, seeded):
    page = client.get("/").data.decode()
    assert VPC in page and SA in page and "example-private-a" in page

    page = client.get(f"/subnets/{SA}").data.decode()
    assert "cell-used" in page and "cell-idle" in page and "cell-reserved" in page
    assert "/enis/eni-0000000002" in page
    assert client.get("/subnets/subnet-ffffffff").status_code == 404

    page = client.get("/enis/eni-0000000001").data.decode()
    assert "10.0.1.10" in page and "i-0example0001" in page
    assert client.get("/enis/eni-missing").status_code == 404

    page = client.get("/ips?q=detached").data.decode()
    assert "10.0.1.50" in page and "10.0.1.10" not in page
    page = client.get("/ips?owner=ec2").data.decode()
    assert "10.0.1.12" in page and "10.0.1.50" not in page


def test_settings_secret_never_rendered_or_logged(app, client):
    resp = _post(client, "/settings", {
        "auth_mode": "keys", "region": "eu-west-1", "access_key_id": FAKE_KEY_ID,
        "secret_access_key": FAKE_SECRET, "log_dir": "",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data
    assert FAKE_SECRET.encode() not in resp.data
    assert FAKE_KEY_ID.encode() not in resp.data
    store = app.extensions["iplens"]["store"]
    s = store.load(with_secret=True)
    assert (s.auth_mode, s.region, s.secret_access_key) == ("keys", "eu-west-1", FAKE_SECRET)

    # resubmitting with blank key fields keeps the stored credentials
    _post(client, "/settings", {"auth_mode": "keys", "region": "eu-west-1",
                                "region_custom": "eu-south-2"})
    s = store.load(with_secret=True)
    assert (s.access_key_id, s.secret_access_key, s.region) == (
        FAKE_KEY_ID, FAKE_SECRET, "eu-south-2")

    log_text = (app.extensions["iplens"]["log_dir"] / "iplens.log").read_text()
    assert FAKE_SECRET not in log_text and FAKE_KEY_ID not in log_text
    assert "settings saved" in log_text


def test_settings_validation_error(client):
    resp = _post(client, "/settings", {"auth_mode": "profile", "region": "us-east-1"},
                 follow_redirects=True)
    assert b"profile name is required" in resp.data


def test_settings_log_dir_change(app, client, tmp_path):
    new_dir = tmp_path / "custom-logs"
    _post(client, "/settings", {"auth_mode": "env", "region": "us-east-1",
                                "log_dir": str(new_dir)})
    assert app.extensions["iplens"]["log_dir"] == new_dir
    assert (new_dir / "iplens.log").exists()
    page = client.get("/logs").data.decode()
    assert str(new_dir) in page and "settings saved" in page


@mock_aws
def test_test_connection_and_refresh(client):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    ec2.create_network_interface(SubnetId=subnet_id, PrivateIpAddress="10.0.1.77",
                                 Description="example detached")

    resp = _post(client, "/settings/test", follow_redirects=True)
    assert b"Connected to account 123456789012" in resp.data

    resp = _post(client, "/refresh", follow_redirects=True)
    page = resp.data.decode()
    assert "Snapshot #1" in page and vpc_id in page and subnet_id in page

    page = client.get("/suggestions").data.decode()
    assert "Delete detached ENI" in page

    page = client.get("/logs?q=collection").data.decode()
    assert "collection finished" in page


def test_refresh_failure_is_flashed(app, client):
    def broken(_settings):
        raise ValueError("credentials are incomplete")

    app.extensions["iplens"]["gateway_factory"] = broken
    resp = _post(client, "/refresh", follow_redirects=True)
    assert b"Refresh failed" in resp.data
    resp = _post(client, "/settings/test", follow_redirects=True)
    assert b"Connection failed" in resp.data


def test_rules_crud_and_yaml(app, client, seeded):
    resp = _post(client, "/rules/new", {"name": "lambda-in-vpc", "kind": "lambda_vpc_required",
                                        "enabled": "on", "description": "policy"},
                 follow_redirects=True)
    assert b"created" in resp.data
    assert b"example-no-vpc is not VPC-attached" in resp.data

    resp = _post(client, "/rules/new", {"name": "bad", "kind": "min_free_pct", "percent": "x"})
    assert resp.status_code == 400 and b"percent must be a number" in resp.data

    _post(client, "/rules/new", {"name": "keep-detached", "kind": "protected_eni",
                                 "pattern": "example detached", "enabled": "on"})
    page = client.get("/suggestions").data.decode()
    assert "blocked" in page and "keep-detached" in page

    with closing(_db(app)) as conn:
        rules = {r.name: r for r in list_rules(conn)}
    rid = rules["keep-detached"].id
    assert b"example detached" in client.get(f"/rules/{rid}/edit").data
    _post(client, f"/rules/{rid}/edit", {"name": "keep-detached", "kind": "protected_eni",
                                         "pattern": "something-else"})
    with closing(_db(app)) as conn:
        assert {r.name: r for r in list_rules(conn)}["keep-detached"].params == {
            "pattern": "something-else"}
        assert not {r.name: r for r in list_rules(conn)}["keep-detached"].enabled

    exported = client.get("/rules/export.yaml")
    assert exported.mimetype == "application/x-yaml"
    yaml_text = exported.data.decode()
    assert "lambda-in-vpc" in yaml_text and "keep-detached" in yaml_text

    _post(client, f"/rules/{rid}/delete")
    with closing(_db(app)) as conn:
        assert [r.name for r in list_rules(conn)] == ["lambda-in-vpc"]

    resp = _post(client, "/rules/import", {"yaml": yaml_text, "replace": "on"},
                 follow_redirects=True)
    assert b"Imported 2 rule(s)" in resp.data
    resp = _post(client, "/rules/import", {"yaml": "rules: ["}, follow_redirects=True)
    assert b"Import failed" in resp.data

    assert client.get("/rules/9999/edit").status_code == 404
    assert _post(client, "/rules/9999/delete").status_code == 404


def test_rules_import_file_upload(app, client):
    data = {"file": (io.BytesIO(b"rules:\n  - name: free-20\n    kind: min_free_pct\n"
                                b"    params: {percent: 20}\n"), "rules.yaml")}
    resp = _post(client, "/rules/import", data, content_type="multipart/form-data",
                 follow_redirects=True)
    assert b"Imported 1 rule(s)" in resp.data
