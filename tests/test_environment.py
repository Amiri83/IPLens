"""Environment derivation: Terraform root x environment mapping first, then tags (resource,
subnet, VPC) with configurable keys; IP list column / filter and Visual payload.

Placeholder data only (10.0.x.x, 123456789012, env-dev / env-prod, root-a)."""

from __future__ import annotations

import pytest

from iplens import environment, queries, terraform
from iplens.db import closing
from iplens.settings import DEFAULT_TF_TIMEOUT, SettingsStore
from iplens.web import create_app

VPC = "vpc-0example0000001"
SA, SB, SC = "subnet-0000000a", "subnet-0000000b", "subnet-0000000c"
ENI_TF, ENI_TAG, ENI_SUBNET, ENI_NONE = (
    "eni-000000000a",
    "eni-000000000b",
    "eni-000000000c",
    "eni-000000000d",
)


def _seed(db_path, snapshot_builder, **kw):
    b = snapshot_builder(db_path, **kw)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.1.0/24").subnet(SB, VPC, "10.0.2.0/24").subnet(SC, VPC, "10.0.3.0/24")
    b.eni(ENI_TF, SA, ["10.0.1.10"])  # managed by root-a [dev]; its tag says otherwise
    b.eni(ENI_TAG, SA, ["10.0.1.11"])
    b.eni(ENI_SUBNET, SB, ["10.0.2.10"])
    b.eni(ENI_NONE, SC, ["10.0.3.10"])
    b.tag("eni", ENI_TF, "Environment", "env-prod")
    b.tag("eni", ENI_TAG, "env", "env-dev")  # key matched case-insensitively ("env")
    b.tag("subnet", SB, "stage", "env-prod")
    b.tag("eni", ENI_NONE, "tier", "env-sandbox")  # only with a custom key
    with closing(db_path) as conn:
        terraform.save_root(
            conn,
            "root-a-dev",
            [
                terraform.TfResource(
                    "aws_network_interface.a", "aws_network_interface", "eni", ENI_TF
                )
            ],
            origin="repo",
        )
        conn.execute(
            "INSERT INTO tf_repos(path, added_at) VALUES('/srv/example/infra-repo', '2026-01-01')"
        )
        conn.execute(
            "INSERT INTO tf_repo_envs(repo_id, root_rel, root_label, env, root_name) "
            "VALUES(1, 'apps', 'apps', 'dev', 'root-a-dev')"
        )
    return b


def _rows(db_path, snap_id, flt=None, keys=environment.DEFAULT_TAG_KEYS):
    with closing(db_path) as conn:
        return {r["eni_id"]: r for r in queries.ip_list(conn, snap_id, flt, env_keys=keys)}


def test_terraform_mapping_beats_tags_then_resource_subnet_vpc_tags(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    rows = _rows(db_path, b.id)
    got = {eni: (r["environment"], r["env_source"]) for eni, r in rows.items()}
    assert got == {
        ENI_TF: ("dev", "terraform"),
        ENI_TAG: ("env-dev", "tag"),
        ENI_SUBNET: ("env-prod", "subnet tag"),
        ENI_NONE: ("", ""),
    }
    # The VPC's tag is the last fallback.
    b.tag("vpc", VPC, "Environment", "env-shared")
    assert _rows(db_path, b.id)[ENI_NONE]["environment"] == "env-shared"


def test_tag_keys_are_configurable(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    rows = _rows(db_path, b.id, keys=("tier",))
    assert rows[ENI_NONE]["environment"] == "env-sandbox"
    assert rows[ENI_TAG]["environment"] == ""  # "env" is no longer a key
    assert rows[ENI_TF]["environment"] == "dev"  # Terraform wins regardless of keys
    assert environment.parse_tag_keys("Environment, env  stage,ENV") == (
        "Environment",
        "env",
        "stage",
    )


def test_default_environment_of_a_root_does_not_count(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        conn.execute("UPDATE tf_repo_envs SET env='default'")
    assert _rows(db_path, b.id)[ENI_TF]["environment"] == "env-prod"  # falls back to its tag


def test_environment_filter(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    assert set(_rows(db_path, b.id, queries.IpFilter(env="ENV-PROD"))) == {ENI_SUBNET}
    assert set(_rows(db_path, b.id, queries.IpFilter(env="dev"))) == {ENI_TF}
    not_set = queries.IpFilter(env=environment.FILTER_NOT_SET)
    assert set(_rows(db_path, b.id, not_set)) == {ENI_NONE}
    summary = environment.summary(r["environment"] for r in _rows(db_path, b.id).values())
    assert [(s["label"], s["count"]) for s in summary] == [
        ("dev", 1),
        ("env-dev", 1),
        ("env-prod", 1),
        ("(not set)", 1),
    ]


# -- web ------------------------------------------------------------------------------------


@pytest.fixture
def client(home):
    app = create_app(home, testing=True)
    c = app.test_client()
    c.get("/")
    c.app = app  # type: ignore[attr-defined]
    return c


def _post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


def test_ip_list_column_filter_and_visual_payload(client, snapshot_builder):
    db = client.app.extensions["iplens"]["paths"].db_path
    _seed(db, snapshot_builder)
    page = client.get("/ips").data.decode()
    assert "<th>Environment</th>" in page and 'name="env"' in page
    assert ">env-prod (1)</option>" in page and ">(not set) (1)</option>" in page
    assert "Terraform root" in page and "subnet tag" in page
    filtered = client.get("/ips?env=env-dev").data.decode()
    assert "10.0.1.11" in filtered and "10.0.2.10" not in filtered
    data = client.get(f"/visual/data.json?vpc={VPC}").get_json()
    envs = {n["eni_id"]: n["environment"] for s in data["vpc"]["subnets"] for n in s["items"]}
    assert envs == {ENI_TF: "dev", ENI_TAG: "env-dev", ENI_SUBNET: "env-prod", ENI_NONE: ""}
    # Both views offer the Environment filter and "Group by: environment".
    for view in ("", "&view=extended"):
        visual = client.get(f"/visual?vpc={VPC}{view}").data.decode()
        assert (
            'id="env-filters"' in visual and '<option value="env" >environment</option>' in visual
        )


def test_settings_store_environment_keys_and_terraform_timeout(client, snapshot_builder):
    db = client.app.extensions["iplens"]["paths"].db_path
    _seed(db, snapshot_builder)
    _post(client, "/settings", {"log_dir": "", "env_tag_keys": "tier", "tf_timeout": "120"})
    s = SettingsStore(db).load()
    assert s.env_tag_keys == ("tier",) and s.tf_timeout == 120
    assert "10.0.3.10" in client.get("/ips?env=env-sandbox").data.decode()
    page = _post(client, "/settings", {"tf_timeout": "5"}, follow_redirects=True).data.decode()
    assert "Settings not saved" in page and SettingsStore(db).load().tf_timeout == 120
    # Fields left out keep their value; the defaults apply to a fresh database.
    _post(client, "/settings", {"log_dir": ""})
    assert SettingsStore(db).load().env_tag_keys == ("tier",)
    assert DEFAULT_TF_TIMEOUT == 120
