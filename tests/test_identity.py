"""Snapshot-frozen account labels, AWS account identity tracking, the re-grouping data
migration and the Discovery account dropdown.

Placeholder data only: 10.0.x.x, AWS account ids 123456789012 / 210987654321, example names.
"""

import sqlite3

import boto3
import pytest
from moto import mock_aws

from iplens.accounts import AccountStore, MemoryVault
from iplens.crypto import SecretBox
from iplens.db import closing, init_db
from iplens.web import create_app

OTHER_ID = "210987654321"
VPC_A, SUBNET_A = "vpc-0example0000a", "subnet-0000000a"
VPC_B, SUBNET_B = "vpc-0example0000b", "subnet-0000000b"

_OLD_SCHEMA = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, taken_at TEXT NOT NULL, region TEXT NOT NULL,
    account_id TEXT, account_alias TEXT, status TEXT NOT NULL, error TEXT, warnings TEXT);
CREATE TABLE vpcs (snapshot_id INTEGER NOT NULL, vpc_id TEXT NOT NULL, name TEXT,
    cidrs TEXT NOT NULL, is_default INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (snapshot_id, vpc_id));
"""


@pytest.fixture
def box(tmp_path):
    return SecretBox.from_path(tmp_path / "key")


def _snap(conn, account_id, alias="", region="us-east-1", status="ok", vpc=None):
    cur = conn.execute(
        "INSERT INTO snapshots(taken_at, region, account_id, account_alias, status) "
        "VALUES('2026-01-01T00:00:00+00:00', ?, ?, ?, ?)",
        (region, account_id, alias, status),
    )
    if vpc:
        conn.execute(
            "INSERT INTO vpcs(snapshot_id, vpc_id, name, cidrs) VALUES(?, ?, '', '[]')",
            (cur.lastrowid, vpc),
        )
    return cur.lastrowid


# -- data migration ------------------------------------------------------------------------


def test_migration_regroups_snapshots_by_aws_account_id(tmp_path, box):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(_OLD_SCHEMA)
    conn.execute("INSERT INTO settings VALUES('account_display_name', 'Example Prod')")
    other_1 = _snap(conn, OTHER_ID, alias="example-other", region="eu-west-1", vpc=VPC_B)
    failed = _snap(conn, "", status="failed")
    other_2 = _snap(conn, OTHER_ID, alias="example-other", region="eu-west-1")
    own_1 = _snap(conn, "123456789012", vpc=VPC_A)
    own_2 = _snap(conn, "123456789012")  # newest: the record's credentials resolve here
    conn.commit()
    conn.close()

    init_db(path)
    store = AccountStore(path, box, MemoryVault())
    first, created = store.list()
    assert (first.display_name, first.aws_account_id) == ("Example Prod", "123456789012")
    assert (created.display_name, created.region, created.auth_mode) == (
        "example-other",
        "eu-west-1",
        "env",
    )
    assert created.aws_account_id == OTHER_ID and created.identity_warning == ""
    with closing(path) as c:
        refs = {r["id"]: r["account_ref"] for r in c.execute("SELECT * FROM snapshots")}
        names = {r["id"]: r["account_name"] for r in c.execute("SELECT * FROM snapshots")}
    assert refs == {
        own_1: first.id,
        own_2: first.id,
        failed: first.id,  # no account id: stays put
        other_1: created.id,
        other_2: created.id,
    }
    # frozen labels: the record's name at migration time
    assert names[own_1] == "Example Prod" and names[other_1] == "example-other"

    init_db(path)  # runs once
    assert len(store.list()) == 2


def test_migration_reuses_existing_records_and_copies_layouts(tmp_path, box):
    path = tmp_path / "test.db"
    init_db(path)
    with closing(path) as conn:
        # undo the "already migrated" marker to simulate an older multi-account database
        conn.execute("DELETE FROM settings WHERE key='snapshots_regrouped'")
        conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) "
            "VALUES('example-b', 'us-east-1', 'env')"
        )
        mixed = _snap(conn, OTHER_ID, vpc=VPC_B)
        conn.execute("UPDATE snapshots SET account_ref=1 WHERE id=?", (mixed,))
        conn.execute(
            "INSERT INTO visual_layouts(account_ref, vpc_id, positions) VALUES(1, ?, '{}')",
            (VPC_B,),
        )
        own = _snap(conn, "123456789012")
        conn.execute("UPDATE snapshots SET account_ref=1 WHERE id=?", (own,))
        b_snap = _snap(conn, OTHER_ID)
        conn.execute("UPDATE snapshots SET account_ref=2 WHERE id=?", (b_snap,))
        # a third record of the same AWS account (another region) is never merged
        conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) "
            "VALUES('example-b-eu', 'eu-west-1', 'env')"
        )
        b_eu = _snap(conn, OTHER_ID, region="eu-west-1")
        conn.execute("UPDATE snapshots SET account_ref=3 WHERE id=?", (b_eu,))
    init_db(path)
    with closing(path) as conn:
        refs = {r["id"]: r["account_ref"] for r in conn.execute("SELECT * FROM snapshots")}
        layouts = {
            (r["account_ref"], r["vpc_id"]) for r in conn.execute("SELECT * FROM visual_layouts")
        }
        n_accounts = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    assert refs == {mixed: 2, own: 1, b_snap: 2, b_eu: 3}
    assert n_accounts == 3  # the owner of OTHER_ID already existed
    assert (2, VPC_B) in layouts


# -- identity tracking ------------------------------------------------------------------------


def test_record_identity_keeps_first_and_warns_on_change(db_path, box):
    store = AccountStore(db_path, box)
    assert store.record_identity(1, "123456789012") == ""
    assert store.record_identity(1, "123456789012") == ""
    warning = store.record_identity(1, OTHER_ID)
    assert OTHER_ID in warning and "first connected to 123456789012" in warning
    acct = store.get(1)
    assert (acct.aws_account_id, acct.last_seen_account_id) == ("123456789012", OTHER_ID)
    assert acct.identity_warning == warning
    assert store.record_identity(1, "") == ""  # unknown identity: nothing recorded


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


@mock_aws
def test_refresh_and_settings_warn_when_credentials_change_account(app, client):
    boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.0.0.0/16")
    with closing(_db(app)) as conn:  # first connect went to another AWS account
        conn.execute("UPDATE accounts SET aws_account_id=? WHERE id=1", (OTHER_ID,))
    page = _post(client, "/refresh", follow_redirects=True).data.decode()
    assert "Refreshed 123456789012" in page
    assert (
        f"Warning: credentials now resolve to AWS account 123456789012, but this account was "
        f"first connected to {OTHER_ID}"
    ) in page
    assert "AWS account changed" in page  # header badge
    settings = client.get("/settings").data.decode()
    assert 'class="badge warn identity-warning"' in settings and f"AWS {OTHER_ID}" in settings
    log_text = (app.extensions["iplens"]["log_dir"] / "iplens.log").read_text()
    assert "credentials now resolve to AWS account 123456789012" in log_text


@mock_aws
def test_first_connect_records_the_account_id_without_warning(app, client):
    page = _post(client, "/accounts/1/test", follow_redirects=True).data.decode()
    assert "Connected to account 123456789012" in page and "Warning:" not in page
    assert app.extensions["iplens"]["accounts"].get(1).aws_account_id == "123456789012"
    assert "AWS 123456789012" in client.get("/settings").data.decode()


# -- Discovery account dropdown -----------------------------------------------------------


@pytest.fixture
def two_accounts(app, client, snapshot_builder):
    _post(
        client,
        "/accounts/new",
        {"display_name": "example-b", "region": "us-east-1", "auth_mode": "env"},
    )
    a = snapshot_builder(_db(app), account_ref=1)
    a.vpc(VPC_A, "10.0.0.0/16").subnet(SUBNET_A, VPC_A, "10.0.1.0/24")
    a.eni("eni-000000000a", SUBNET_A, ["10.0.1.10"])
    return a


def test_account_without_snapshot_never_shows_other_data(client, two_accounts):
    _post(client, "/accounts/active", {"account_id": "2", "next": "/"})
    for url in ("/", "/ips", "/visual", "/suggestions", "/scope"):
        page = client.get(url).data.decode()
        assert "No data yet for <b>example-b</b>" in page, url
        assert '<input type="hidden" name="account_id" value="2">' in page, url
        assert VPC_A not in page and "10.0.1.10" not in page, url
        assert "viewing <b>example-b</b> · no data yet" in page, url
    assert client.get("/visual/data.json").get_json()["vpc"] is None


def test_discovery_dropdown_refreshes_the_chosen_account(app, client, two_accounts):
    page = client.get("/").data.decode()
    assert '<select id="refresh-account" name="account_id">' in page
    assert '<option value="2" >example-b · us-east-1</option>' in page
    with mock_aws():
        vpc_id = boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.0.0.0/16")[
            "Vpc"
        ]["VpcId"]
        page = _post(client, "/refresh", {"account_id": "2"}, follow_redirects=True).data.decode()
    assert "Refreshed example-b (123456789012)" in page
    assert "viewing <b>example-b (123456789012)</b>" in page and vpc_id in page
    assert VPC_A not in page
    assert app.extensions["iplens"]["store"].active_account_id() == 2
    with closing(_db(app)) as conn:
        row = conn.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    assert (row["account_ref"], row["account_name"], row["account_id"]) == (
        2,
        "example-b",
        "123456789012",
    )
    assert _post(client, "/refresh", {"account_id": "99"}).status_code == 400
