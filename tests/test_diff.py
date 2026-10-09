"""Snapshot diff: added / removed / changed ENIs and IPs, net delta, top consumers.

Synthetic data only: 10.0.x.x addresses, account 123456789012, example names.
"""

from datetime import UTC, datetime, timedelta

import pytest

from iplens import diff
from iplens.attribution import OWNER_LABELS
from iplens.db import closing
from iplens.web import create_app

VPC = "vpc-0example0000001"
SA = "subnet-0000000a"
SB = "subnet-0000000b"


def _snapshots(db_path, snapshot_builder, ips):
    """Old -> new:

    * eni-a (EC2 example-app, subnet A): 2 IPs -> 4 IPs (+2)
    * eni-b (EC2 example-batch, subnet A): removed (1 IP)
    * eni-c (EC2 example-cache, subnet B): in-use -> available, same IP
    * eni-d (Lambda example-fn, subnet B): added with 3 IPs, Environment=prod
    * eni-e (EC2 example-web, subnet B): unchanged
    * 10.0.1.40 moves from eni-f to eni-g (both EC2 in subnet A)
    """
    now = datetime.now(UTC)
    old = snapshot_builder(db_path, taken_at=now - timedelta(hours=2))
    old.vpc(VPC, "10.0.0.0/16")
    old.subnet(SA, VPC, "10.0.1.0/24", name="example-a")
    old.subnet(SB, VPC, "10.0.2.0/24", name="example-b")
    old.eni("eni-a", SA, ips("10.0.1.0", 10, 2), owner_ref="example-app")
    old.eni("eni-b", SA, ["10.0.1.30"], owner_ref="example-batch")
    old.eni("eni-c", SB, ["10.0.2.10"], owner_ref="example-cache")
    old.eni("eni-e", SB, ["10.0.2.50"], owner_ref="example-web")
    old.eni("eni-f", SA, ["10.0.1.40"], owner_ref="example-old-host")
    new = snapshot_builder(db_path, taken_at=now - timedelta(hours=1))
    new.vpc(VPC, "10.0.0.0/16")
    new.subnet(SA, VPC, "10.0.1.0/24", name="example-a")
    new.subnet(SB, VPC, "10.0.2.0/24", name="example-b")
    new.eni("eni-a", SA, ips("10.0.1.0", 10, 4), owner_ref="example-app")
    new.eni("eni-c", SB, ["10.0.2.10"], owner_ref="example-cache", status="available")
    new.eni("eni-d", SB, ips("10.0.2.0", 20, 3), owner_type="lambda", owner_ref="example-fn")
    new.tag("eni", "eni-d", "Environment", "prod")
    new.eni("eni-e", SB, ["10.0.2.50"], owner_ref="example-web")
    new.eni("eni-g", SA, ["10.0.1.40"], owner_ref="example-new-host")
    return old.id, new.id


@pytest.fixture
def result(db_path, snapshot_builder, ips):
    old_id, new_id = _snapshots(db_path, snapshot_builder, ips)
    with closing(db_path) as conn:
        return diff.diff_snapshots(conn, old_id, new_id, OWNER_LABELS)


def _enis(result, kind):
    return sorted(e.eni_id for g in result.groups for e in g.enis if e.kind == kind)


def _ips(result, kind):
    return sorted(i.ip for g in result.groups for i in g.ips if i.kind == kind)


def test_added_removed_changed_enis(result):
    assert _enis(result, diff.ADDED) == ["eni-d", "eni-g"]
    assert _enis(result, diff.REMOVED) == ["eni-b", "eni-f"]
    assert _enis(result, diff.CHANGED) == ["eni-a", "eni-c"]
    changed = {e.eni_id: e for g in result.groups for e in g.enis if e.kind == diff.CHANGED}
    assert changed["eni-a"].details == ["IPs: +10.0.1.12, +10.0.1.13"]
    assert changed["eni-c"].details == ["status: in-use → available"]
    added = {e.eni_id: e for g in result.groups for e in g.enis if e.kind == diff.ADDED}
    assert added["eni-d"].new_ips == ["10.0.2.20", "10.0.2.21", "10.0.2.22"]


def test_added_removed_changed_ips(result):
    assert _ips(result, diff.ADDED) == [
        "10.0.1.12",
        "10.0.1.13",
        "10.0.2.20",
        "10.0.2.21",
        "10.0.2.22",
    ]
    assert _ips(result, diff.REMOVED) == ["10.0.1.30"]
    moved = [i for g in result.groups for i in g.ips if i.kind == diff.CHANGED]
    assert [(i.ip, i.old_eni, i.new_eni) for i in moved] == [("10.0.1.40", "eni-f", "eni-g")]
    assert moved[0].detail == "moved eni-f → eni-g"
    t = result.totals
    assert (t["enis_added"], t["enis_removed"], t["enis_changed"]) == (2, 2, 2)
    assert (t["ips_added"], t["ips_removed"], t["ips_changed"]) == (5, 1, 1)
    assert t["ip_delta"] == 4  # 6 IPs -> 10 IPs


def test_grouped_by_owner_type_ownership_and_environment(result):
    keys = [(g.type_label, g.owner, g.env) for g in result.groups]
    assert keys == [("EC2", "unmanaged", ""), ("Lambda", "unmanaged", "prod")]
    lam = result.groups[1]
    assert [e.eni_id for e in lam.enis] == ["eni-d"]
    assert lam.count("ips", diff.ADDED) == 3 and lam.ip_delta == 3
    assert result.groups[0].ip_delta == 1  # +2 on eni-a, -1 for eni-b


def test_net_ip_delta_per_subnet(result):
    deltas = {d.subnet_id: (d.old, d.new, d.delta) for d in result.subnets}
    assert deltas == {SA: (4, 5, 1), SB: (2, 5, 3)}
    assert result.subnets[0].subnet_id == SB  # largest change first
    assert result.subnets[0].name == "example-b" and result.subnets[0].cidr == "10.0.2.0/24"


def test_top_consumers(result):
    top = [(c.resource, c.type_label, c.old, c.new, c.delta) for c in result.consumers]
    assert top == [
        ("example-fn", "Lambda", 0, 3, 3),
        ("example-app", "EC2", 2, 4, 2),
        ("example-new-host", "EC2", 0, 1, 1),
    ]


def test_top_consumers_limit(db_path, snapshot_builder, ips):
    old_id, new_id = _snapshots(db_path, snapshot_builder, ips)
    with closing(db_path) as conn:
        res = diff.diff_snapshots(conn, old_id, new_id, OWNER_LABELS, top=1)
    assert [c.resource for c in res.consumers] == ["example-fn"]


def test_identical_snapshots_have_no_changes(db_path, snapshot_builder, ips):
    ids = []
    for _ in range(2):
        b = snapshot_builder(db_path)
        b.vpc(VPC, "10.0.0.0/16").subnet(SA, VPC, "10.0.1.0/24")
        b.eni("eni-a", SA, ips("10.0.1.0", 10, 2), owner_ref="example-app")
        ids.append(b.id)
    with closing(db_path) as conn:
        res = diff.diff_snapshots(conn, *ids, OWNER_LABELS)
    assert res.empty and res.consumers == []
    assert [(d.subnet_id, d.delta) for d in res.subnets] == [(SA, 0)]


def test_default_pair(db_path, snapshot_builder):
    with closing(db_path) as conn:
        assert diff.default_pair(conn, 1) == (None, None)
    a = snapshot_builder(db_path).id
    with closing(db_path) as conn:
        assert diff.default_pair(conn, 1) == (None, a)
    b = snapshot_builder(db_path).id
    snapshot_builder(db_path, status="failed")
    with closing(db_path) as conn:
        assert diff.default_pair(conn, 1) == (a, b)


# -- page --------------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def test_diff_page_defaults_to_latest_vs_previous(app, snapshot_builder, ips):
    db = app.extensions["iplens"]["paths"].db_path
    old_id, new_id = _snapshots(db, snapshot_builder, ips)
    client = app.test_client()
    page = client.get("/diff").data.decode()
    assert f"Snapshot #{old_id}" in page and f"#{new_id}" in page
    assert "+2 added" in page and "−2 removed" in page
    assert "Top consumers" in page and "example-fn" in page
    assert "moved eni-f → eni-g" in page
    assert "env prod" in page
    # Reversed picks are shown older -> newer; equal picks are refused.
    page = client.get(f"/diff?old={new_id}&new={old_id}").data.decode()
    assert f"Snapshot #{old_id}" in page
    page = client.get(f"/diff?old={new_id}&new={new_id}").data.decode()
    assert "Pick two different snapshots." in page
    assert client.get(f"/diff?old=999&new={new_id}").status_code == 404


def test_diff_page_needs_two_snapshots(app, snapshot_builder):
    client = app.test_client()
    assert client.get("/diff").status_code == 200
    snapshot_builder(app.extensions["iplens"]["paths"].db_path).vpc(VPC, "10.0.0.0/16")
    assert "needs two successful snapshots" in client.get("/diff").data.decode()
