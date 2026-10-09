"""Terraform sync: wrong-account detection from state ARNs, "managed elsewhere" drift
markers, the bounded parallel pool, the shared plugin cache and the timeout.

Placeholder data only: AWS accounts 123456789012 / 210987654321, example names."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from iplens import terraform, tfrepo
from iplens.db import closing
from iplens.web import create_app
from tests import test_tfrepo
from tests.test_tfrepo import (
    ACCOUNT,
    TF,
    FakeRunner,
    _confirm,
    _db,
    _discovered,
    _envs,
    _keys_account,
    _post,
    _state,
    _subnet,
    _sync,
    fake_gateway,
)

repo = test_tfrepo.repo  # the synthetic repository fixture
OTHER = "210987654321"
VPC = "vpc-0example0000001"


def _arn_subnet(name: str, sid: str, account: str) -> dict:
    r = _subnet(name, sid)
    r["values"]["arn"] = f"arn:aws:ec2:us-east-1:{account}:subnet/{sid}"
    return r


@pytest.fixture
def app(home):
    return create_app(
        home,
        testing=True,
        terraform_bin=TF,
        terraform_runner=FakeRunner(),
        gateway_factory=fake_gateway,
    )


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _drift(app, acct, snap_id):
    with closing(_db(app)) as conn:
        row = conn.execute("SELECT * FROM snapshots WHERE id=?", (snap_id,)).fetchone()
        return tfrepo.drift(conn, acct, row)


# -- account ids in a state ----------------------------------------------------------------


def test_state_account_ids_keep_only_the_ids():
    doc = _state(_arn_subnet("a", "subnet-0000000a", OTHER), _subnet("b", "subnet-0000000b"))
    assert terraform.state_account_ids(doc) == {OTHER: 1}
    # Without any own "arn" attribute, every ARN in the values counts.
    ref = _subnet("c", "subnet-0000000c")
    ref["values"]["owner_arn"] = f"arn:aws:iam::{ACCOUNT}:role/example-role"
    assert terraform.state_account_ids(_state(ref)) == {ACCOUNT: 1}
    v4 = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_subnet",
                "name": "a",
                "instances": [
                    {
                        "attributes": {
                            "id": "subnet-0000000a",
                            "arn": f"arn:aws:ec2:us-east-1:{OTHER}:subnet/subnet-0000000a",
                        }
                    }
                ],
            }
        ],
    }
    assert terraform.state_account_ids(v4) == {OTHER: 1}
    assert terraform.state_account_ids({"format_version": "1.0"}) == {}
    # AWS-managed ARNs carry no account id.
    managed = _subnet("d", "subnet-0000000d")
    managed["values"]["policy_arn"] = "arn:aws:iam::aws:policy/ExamplePolicy"
    assert terraform.state_account_ids(_state(managed)) == {}


# -- wrong account ------------------------------------------------------------------------------


def test_wrong_account_is_flagged_suggested_and_left_out_of_drift(
    app, client, repo, snapshot_builder
):
    acct = _keys_account(app)  # credentials resolve to ACCOUNT
    other = _keys_account(app, name="env-prod", aws_id=OTHER)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("services", "dev"), acct)
    show = _state(
        _arn_subnet("app", "subnet-0000000a", OTHER), _arn_subnet("gone", "subnet-0000000f", OTHER)
    )
    (result,) = _sync(app, FakeRunner(show=show))
    assert result.status == tfrepo.WRONG_ACCOUNT
    assert result.detail == f"the state's resources are in AWS account {OTHER}, not {ACCOUNT}"
    env = _envs(app, repo_id)[("services", "dev")]
    assert (env["status"], env["state_account"]) == (tfrepo.WRONG_ACCOUNT, OTHER)
    store = app.extensions["iplens"]["accounts"]
    assert tfrepo.suggest_for_state(OTHER, store.list()).id == other

    snap = snapshot_builder(_db(app), account_ref=acct)
    snap.vpc(VPC, "10.0.0.0/16").subnet("subnet-0000000a", VPC, "10.0.1.0/24")
    d = _drift(app, acct, snap.id)
    # The wrong root manages nothing here and is not compared the other way either.
    assert [r["resource_id"] for r in d.not_in_terraform] == [VPC, "subnet-0000000a"]
    assert d.not_in_aws == [] and d.roots == []
    assert [(w["env"], w["state_account"]) for w in d.wrong_account] == [("dev", OTHER)]
    assert "wrong account" in d.skipped_roots[0]["reason"]

    _post(client, "/accounts/active", {"account_id": str(acct)})
    page = client.get("/terraform").data.decode()
    assert "wrong account" in page and "Map it to <b>env-prod</b> instead" in page
    assert "suggested account: <b>env-prod</b>" in page
    assert "Suggested account" in client.get(f"/settings/tfrepos/{repo_id}").data.decode()

    # The mapped account's own state is fine, cross-account references or not.
    ok = _state(_arn_subnet("app", "subnet-0000000a", ACCOUNT), _subnet("b", "subnet-0000000b"))
    (result,) = _sync(app, FakeRunner(show=ok))
    assert result.status == tfrepo.OK
    assert _envs(app, repo_id)[("services", "dev")]["state_account"] == ACCOUNT
    assert _drift(app, acct, snap.id).wrong_account == []


def test_local_backend_state_is_checked_too(app, repo):
    acct = _keys_account(app, aws_id=OTHER)  # the repo's local state names no account
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("apps/envs/staging", "staging"), acct)
    (result,) = _sync(app, FakeRunner())
    assert result.status == tfrepo.OK  # no ARN in the state: nothing to compare


# -- managed elsewhere -----------------------------------------------------------------------


def test_managed_elsewhere_markers_are_excluded_from_drift(app, client, repo, snapshot_builder):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("services", "dev"), acct)
    _sync(
        app,
        FakeRunner(
            show=_state(_subnet("app", "subnet-0000000a"), _subnet("gone", "subnet-0000000f"))
        ),
    )
    snap = snapshot_builder(_db(app), account_ref=acct).vpc(VPC, "10.0.0.0/16")
    for i, sid in enumerate(("subnet-0000000a", "subnet-0000000b", "subnet-0000000c")):
        snap.subnet(sid, VPC, f"10.0.{i + 1}.0/24")
    snap.tag("subnet", "subnet-0000000c", "team", "network")
    before = _drift(app, acct, snap.id)
    assert [r["resource_id"] for r in before.not_in_terraform] == [
        VPC,
        "subnet-0000000b",
        "subnet-0000000c",
    ]
    assert [r["resource_id"] for r in before.not_in_aws] == ["subnet-0000000f"]

    with closing(_db(app)) as conn:
        tfrepo.add_marker(conn, acct, "type", "vpc")  # every VPC
        tfrepo.add_marker(conn, None, "tag", "team = network")  # every account
        tfrepo.add_marker(conn, acct, "resource", "subnet-0000000f")
        assert tfrepo.add_marker(conn, acct, "type", "vpc") == 1  # no duplicates
        for kind, value in (
            ("type", "bogus"),
            ("resource", "id with spaces"),
            ("nope", "x"),
            ("tag", ""),
        ):
            with pytest.raises(ValueError):
                tfrepo.add_marker(conn, acct, kind, value)
    after = _drift(app, acct, snap.id)
    assert [r["resource_id"] for r in after.not_in_terraform] == ["subnet-0000000b"]
    assert after.not_in_aws == []
    assert {(m["side"], m["resource_id"], m["marker"]) for m in after.managed_elsewhere} == {
        ("aws", VPC, "every VPC"),
        ("aws", "subnet-0000000c", "tag team=network"),
        ("terraform", "subnet-0000000f", "subnet-0000000f"),
    }

    # Web: mark one more from the drift list, then remove a marker.
    _post(client, "/accounts/active", {"account_id": str(acct)})
    page = _post(
        client,
        "/terraform/markers",
        {"kind": "resource", "value_resource": "subnet-0000000b"},
        follow_redirects=True,
    ).data.decode()
    assert "Marked as managed elsewhere" in page and "4 excluded" in page
    assert _drift(app, acct, snap.id).not_in_terraform == []
    bad = _post(
        client, "/terraform/markers", {"kind": "type", "value_type": "bogus"}, follow_redirects=True
    )
    assert "Marker not saved: unknown resource type" in bad.data.decode()
    with closing(_db(app)) as conn:
        marker_id = conn.execute(
            "SELECT id FROM tf_managed_elsewhere WHERE kind='type'"
        ).fetchone()[0]
    _post(client, f"/terraform/markers/{marker_id}/delete")
    assert [r["resource_id"] for r in _drift(app, acct, snap.id).not_in_terraform] == [VPC]
    assert _post(client, "/terraform/markers/9999/delete").status_code == 404


# -- pool, plugin cache, timeout ---------------------------------------------------------------


class _SlowRunner(FakeRunner):
    """Records how many terraform commands run at the same time."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.lock = threading.Lock()
        self.active = self.peak = 0

    def __call__(self, argv, **kw):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(0.05)
            return super().__call__(argv, **kw)
        finally:
            with self.lock:
                self.active -= 1


def test_sync_runs_two_roots_at_a_time_with_a_shared_plugin_cache(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    for key in (("services", "dev"), ("services", "prod"), ("platform", "dev")):
        _confirm(app, repo_id, key, acct)
    runner = _SlowRunner(show=_state(_subnet("app", "subnet-0000000a")))
    results = _sync(app, runner, timeout=42)
    assert len(results) == 3 and runner.peak == tfrepo.PARALLEL_ROOTS == 2
    cache = app.extensions["iplens"]["paths"].tf_cache_dir.resolve()
    data_dirs = set()
    for argv, kw in runner.calls:
        assert kw["env"]["TF_PLUGIN_CACHE_DIR"] == str(cache / tfrepo.PLUGIN_CACHE)
        assert Path(kw["env"]["TF_DATA_DIR"]).parent == cache
        assert Path(kw["env"]["TF_DATA_DIR"]).name.startswith(f"repo-{repo_id}-env-")
        data_dirs.add(kw["env"]["TF_DATA_DIR"])
        if argv[1] in ("init", "show"):
            assert kw["timeout"] == 42
        tfrepo.check_allowlisted(argv, TF)  # still only allowlisted commands
    assert len(data_dirs) == 3  # one working directory per root x environment
    assert (cache / tfrepo.PLUGIN_CACHE).is_dir()


def test_sync_progress_and_cancel_between_roots(app, repo):
    from iplens.jobs import JobManager

    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    for key in (("services", "dev"), ("services", "prod"), ("platform", "dev")):
        _confirm(app, repo_id, key, acct)
    manager = JobManager(_db(app))
    seen: list[list] = []

    def work(ctx):
        def runner(argv, **kw):
            ctx.check()  # never reached once cancelled: sync_env checks first
            if argv[1] == "init":
                manager.cancel(ctx.job_id)
            return FakeRunner()(argv, **kw)

        seen.append(_sync(app, runner, progress=ctx, parallel=1))
        ctx.check()

    job = manager.start(acct, "tfsync", work, background=False)
    assert job["state"] == "cancelled" and job["total"] == 3
    assert any("terraform init" in line for line in job["log"])
    statuses = [r.status for r in seen[0]]
    assert statuses == [tfrepo.CANCELLED, tfrepo.CANCELLED, tfrepo.CANCELLED]
    assert [r.detail for r in seen[0]][1:] == ["not started", "not started"]
    manager.close()
