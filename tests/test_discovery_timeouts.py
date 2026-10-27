"""Refresh (discovery) timeouts, per-resource transactions and the hidden progress box.

A resource type running past the per-resource timeout is skipped and the others still
complete; the timeouts come from Settings at every start (no restart); a failed write of
one resource type leaves none of its rows; Cancel stops a hanging resource; and a hidden
progress box stays hidden on other pages (tabs). An abandoned resource's thread writes
nothing more to the job, its AWS calls retry within the timeout, and "Retry skipped"
collects only the skipped resource types. Placeholders only: 192.0.2.N addresses,
example names, moto (no real AWS)."""

from __future__ import annotations

import threading
import time

import boto3
import pytest
from moto import mock_aws

from iplens import aws as aws_mod
from iplens import collector as collector_mod
from iplens import jobs, queries
from iplens import settings as settings_mod
from iplens.aws import AwsGateway
from iplens.collector import Collector
from iplens.db import closing
from iplens.settings import SettingsStore
from iplens.web import create_app

REGION = "us-east-1"
WAIT = 30  # seconds a test waits for a background job at most


@pytest.fixture
def release():
    """Lets every mocked hanging collector return at the end of the test."""
    event = threading.Event()
    yield event
    event.set()


def _aws() -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc_id = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="192.0.2.0/26")["Subnet"]["SubnetId"]
    ec2.create_network_interface(SubnetId=subnet_id, PrivateIpAddress="192.0.2.10")


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _warm_up(db_path) -> None:
    """One untimed Refresh first: moto's first call of a service can take a second."""
    Collector(_gateway(), db_path).run()


def _hang(release: threading.Event):
    """A collector that never answers on its own (until the test ends)."""

    def fetch(self):
        release.wait(WAIT)
        return []

    return fetch


def _count(db_path, table: str, snap_id: int) -> int:
    with closing(db_path) as conn:
        return conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE snapshot_id=?",  # noqa: S608 - test constants
            (snap_id,),
        ).fetchone()[0]


# -- the collector ----------------------------------------------------------------------


@mock_aws
def test_hanging_collector_is_skipped_and_the_others_complete(db_path, monkeypatch, release):
    _aws()
    _warm_up(db_path)
    monkeypatch.setattr(Collector, "_fetch_tagged_resources", _hang(release))
    # Only the hanging resource type gets the 1s per-resource timeout; the real (moto)
    # calls of the others get the overall limit, so a slow call on a loaded machine is
    # not skipped as well.
    real_limit = Collector._limit
    monkeypatch.setattr(
        Collector,
        "_limit",
        lambda self, what: real_limit(self, what) if what == "tag:GetResources" else 60,
    )
    mgr = jobs.JobManager(db_path)
    out = {}

    def work(ctx):
        out["result"] = Collector(
            _gateway(), db_path, progress=ctx, resource_timeout=1, overall_timeout=60
        ).run()

    t0 = time.monotonic()
    job = mgr.start(1, "refresh", work, background=False)
    assert time.monotonic() - t0 < WAIT / 2  # did not wait for the hanging call
    result = out["result"]

    assert job["state"] == jobs.DONE
    assert result.skipped == [("tag:GetResources", "timeout after 1s")]
    assert "tag:GetResources skipped (timeout after 1s)" in result.warnings
    # Every other resource type still ran and the snapshot was saved.
    assert (result.enis, result.ips) == (1, 1) and result.vpcs >= 1 and result.subnets >= 1
    with closing(db_path) as conn:
        status = conn.execute(
            "SELECT status FROM snapshots WHERE id=?", (result.snapshot_id,)
        ).fetchone()[0]
    assert status == "ok"
    rows = {r["name"]: r for r in job["items"]}
    assert rows["tag:GetResources"]["status"] == jobs.SKIPPED
    assert rows["tag:GetResources"]["reason"] == "timeout after 1s"
    assert rows["tag:GetResources"]["timeout"] == 1
    for name in ("ec2:DescribeVpcs", "ec2:DescribeNetworkInterfaces", "cloudformation:ListStacks"):
        assert rows[name]["status"] == jobs.RES_DONE
    assert not [r for r in job["items"] if r["status"] in (jobs.PENDING, jobs.RES_RUNNING)]
    # The required resource types keep their own, longer timeout.
    assert job["limits"] == {"resource": 1, "overall": 60, "required": 120}
    # Bounded by what was left of the 60s overall limit, not by the 1s setting.
    assert rows["ec2:DescribeSubnets"]["timeout"] >= 50
    # Persisted with the job: a reload still shows the rows.
    stored = jobs.JobManager(db_path).current(1)
    assert stored["items"] == job["items"] and stored["limits"] == job["limits"]
    mgr.close()


@mock_aws
def test_abandoned_resource_stops_at_its_next_page(db_path, monkeypatch, release):
    """A slow paginated call is abandoned at the timeout and does not fetch more pages."""
    _aws()
    pages = []

    def slow_paginate(client, op, key, **kwargs):
        if op != "describe_vpc_endpoints":
            return real(client, op, key, **kwargs)
        for i in range(50):
            collector_mod._check_abandoned()
            pages.append(i)
            release.wait(0.2)
        return []

    real = collector_mod._paginate
    monkeypatch.setattr(collector_mod, "_paginate", slow_paginate)
    result = Collector(_gateway(), db_path, resource_timeout=0.5).run()
    assert ("ec2:DescribeVpcEndpoints", "timeout after 1s") in result.skipped
    seen = len(pages)
    time.sleep(0.6)
    assert len(pages) <= seen + 1  # the helper thread gave up instead of finishing
    assert len(pages) < 50


@mock_aws
def test_overall_limit_skips_the_remaining_resources(db_path, monkeypatch, release):
    _aws()
    monkeypatch.setattr(Collector, "_fetch_tagged_resources", _hang(release))
    # Long enough for the required resources on a loaded machine (a cold boto3 client
    # alone can take a second); the hanging one then runs into the overall limit.
    result = Collector(_gateway(), db_path, resource_timeout=30, overall_timeout=5).run()
    reason = "overall time limit of 1 min reached"
    assert ("tag:GetResources", reason) in result.skipped
    assert ("cloudformation:ListStacks", reason) in result.skipped  # never started
    assert result.enis == 1


@mock_aws
def test_required_resource_timeout_fails_the_refresh(db_path, monkeypatch, release):
    _aws()
    real = collector_mod._paginate

    def paginate(client, op, key, **kwargs):
        if op == "describe_subnets":
            release.wait(WAIT)
        return real(client, op, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    # Keep the test fast: the required resources' minimum is 120s by default.
    monkeypatch.setattr(collector_mod, "REQUIRED_RESOURCE_TIMEOUT", 0.5)
    with pytest.raises(collector_mod.ResourceTimeout, match="ec2:DescribeSubnets"):
        Collector(_gateway(), db_path, resource_timeout=0.5).run()
    with closing(db_path) as conn:
        snap = conn.execute("SELECT id, status, error FROM snapshots").fetchone()
    assert snap["status"] == "failed"
    assert snap["error"] == "ec2:DescribeSubnets skipped (timeout after 1s)"
    assert _count(db_path, "vpcs", snap["id"]) == 0


@mock_aws
def test_required_resources_get_at_least_120s(db_path, monkeypatch, release):
    """With the 30s default per-resource setting VPCs, subnets and ENIs still get 120s:
    a subnet listing slower than the optional timeout completes, an optional resource as
    slow is skipped."""
    _aws()
    _warm_up(db_path)
    real = collector_mod._paginate

    def paginate(client, op, key, **kwargs):
        if op in ("describe_subnets", "describe_vpc_endpoints"):
            release.wait(1.5)  # longer than the 1s optional timeout below
        return real(client, op, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    assert Collector(_gateway(), db_path).required_timeout == 120  # 30s default setting
    assert Collector(_gateway(), db_path, resource_timeout=30).required_timeout == 120
    assert Collector(_gateway(), db_path, resource_timeout=300).required_timeout == 300
    collector = Collector(_gateway(), db_path, resource_timeout=1)
    assert collector._limit("ec2:DescribeSubnets") == 120
    assert collector._limit("ec2:DescribeVpcEndpoints") == 1
    result = collector.run()
    assert ("ec2:DescribeVpcEndpoints", "timeout after 1s") in result.skipped
    assert not [what for what, _reason in result.skipped if what in collector_mod.CORE_RESOURCES]
    assert result.subnets >= 1 and result.enis == 1


def test_required_resource_clients_get_their_longer_botocore_timeouts():
    gw = _gateway()
    collector = Collector(gw, "unused.db", resource_timeout=30)
    optional = gw.client("ec2", region=REGION).meta.config
    assert (optional.connect_timeout, optional.read_timeout) == (10, 10)
    required = collector._client("ec2", collector.required_timeout).meta.config
    assert (required.connect_timeout, required.read_timeout) == (10, 40)
    for cfg, timeout in ((optional, 30), (required, 120)):
        assert cfg.retries == {"mode": "standard", "total_max_attempts": 3}
        assert 3 * cfg.read_timeout <= timeout and cfg.connect_timeout <= 10


@mock_aws
def test_cancel_stops_a_hanging_resource(db_path, monkeypatch, release):
    _aws()
    monkeypatch.setattr(Collector, "_fetch_tagged_resources", _hang(release))
    mgr = jobs.JobManager(db_path)
    job = mgr.start(1, "refresh", lambda ctx: Collector(_gateway(), db_path, progress=ctx).run())
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        rows = {r["name"]: r["status"] for r in mgr.status(job["id"])["items"]}
        if rows.get("tag:GetResources") == jobs.RES_RUNNING:
            break
        time.sleep(0.05)
    assert mgr.cancel(job["id"])
    assert mgr.wait(job["id"], 5)  # well before the 30s default timeout
    assert mgr.status(job["id"])["state"] == jobs.CANCELLED
    mgr.close()


def test_collection_clients_get_botocore_timeouts_and_retries():
    gw = _gateway()
    Collector(gw, "unused.db", resource_timeout=240)
    cfg = gw.client("ec2", region=REGION).meta.config
    assert (cfg.connect_timeout, cfg.read_timeout) == (10, 60)
    # botocore: max_attempts 2 retries = 3 attempts in total (not the adaptive 5 retries).
    assert cfg.retries == {"mode": "standard", "total_max_attempts": 3}
    for timeout in (120, 30, 5):
        Collector(gw, "unused.db", resource_timeout=timeout)
        cfg = gw.client("ec2", region=REGION).meta.config
        assert cfg.retries == {"mode": "standard", "total_max_attempts": 3}
        assert 3 * cfg.read_timeout <= timeout
        assert cfg.connect_timeout <= min(10, cfg.read_timeout)
    raw = aws_mod.call_timeouts(120)
    assert raw.retries == {"max_attempts": 2, "mode": "standard"}
    assert (raw.connect_timeout, raw.read_timeout) == (10, 40)


@mock_aws
def test_abandoned_thread_writes_nothing_to_the_job_after_its_skip(db_path, monkeypatch, release):
    _aws()
    _warm_up(db_path)
    late = threading.Event()  # set by the abandoned thread once it has tried to write

    def fetch(self):
        self.progress.log("before the timeout")
        release.wait(WAIT)
        collector_mod.log.info("late log record")
        collector_mod.log.warning("late warning record")
        self.progress.log("late log line")
        self.progress.step("late step", done=99, total=99)
        self.progress.resource("tag:GetResources", jobs.RES_DONE)
        self.progress.resource("late resource", jobs.RES_DONE)
        self.progress.message("ok", "late message")
        late.set()
        return []

    monkeypatch.setattr(Collector, "_fetch_tagged_resources", fetch)
    mgr = jobs.JobManager(db_path)

    def work(ctx):
        Collector(_gateway(), db_path, progress=ctx, resource_timeout=1, overall_timeout=60).run()
        release.set()  # the abandoned thread wakes up while this job is still running
        assert late.wait(WAIT)

    job = mgr.start(1, "refresh", work, background=False)
    assert job["state"] == jobs.DONE
    assert any(line.endswith("before the timeout") for line in job["log"])
    assert not [line for line in job["log"] if "late" in line]
    assert "late" not in job["step"] and job["done"] < 99
    rows = {r["name"]: r for r in job["items"]}
    assert rows["tag:GetResources"]["status"] == jobs.SKIPPED
    assert "late resource" not in rows
    assert not [m for m in job["messages"] if "late" in m["text"]]
    mgr.close()


def test_retry_plan_adds_what_a_type_needs_and_unknown_names_mean_everything():
    base = {*collector_mod.IDENTITY_RESOURCES, *collector_mod.CORE_RESOURCES}
    # The ownership rows merge tags and stacks, so both are collected again together.
    ownership_sources = {"tag:GetResources", "cloudformation:ListStacks"}
    assert collector_mod.retry_plan(["tag:GetResources"]) == {*base, *ownership_sources}
    assert collector_mod.retry_plan(["cloudformation:ListStacks"]) == {*base, *ownership_sources}
    assert collector_mod.retry_plan(["elasticloadbalancing:DescribeTargetHealth"]) == {
        *base,
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
    }
    assert collector_mod.retry_plan(["lambda:ListTags"]) == {
        *base,
        "lambda:ListFunctions",
        "lambda:ListTags",
    }
    assert collector_mod.retry_plan([collector_mod.OWNERSHIP_WRITE]) == {*base, *ownership_sources}
    assert collector_mod.retry_plan(["ec2:DescribeSubnets"]) == base
    # Not one resource type (the tags write spans all of them), or nothing: a full Refresh.
    assert collector_mod.retry_plan(["resource tags"]) is None
    assert collector_mod.retry_plan(["tag:GetResources", "example-unknown"]) is None
    assert collector_mod.retry_plan([]) is None


@mock_aws
def test_retry_collects_only_the_skipped_types(db_path, monkeypatch):
    _aws()
    source = Collector(_gateway(), db_path).run().snapshot_id
    calls: list[str] = []
    real = collector_mod._paginate

    def paginate(client, op, key, **kwargs):
        calls.append(op)
        return real(client, op, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    fetched = []
    monkeypatch.setattr(Collector, "_fetch_tagged_resources", lambda self: fetched.append(1) or [])
    mgr = jobs.JobManager(db_path)
    out = {}

    def work(ctx):
        out["result"] = Collector(
            _gateway(),
            db_path,
            progress=ctx,
            only=["tag:GetResources", "ec2:DescribeInstances"],
            source_snapshot=source,
        ).run()

    job = mgr.start(1, "refresh", work, background=False)
    result = out["result"]
    assert job["state"] == jobs.DONE
    assert sorted(calls) == [
        "describe_instances",
        "describe_network_interfaces",
        "describe_subnets",
        "describe_vpcs",
        "list_stacks",
    ]
    assert fetched == [1]
    assert [r["name"] for r in job["items"]] == [
        "sts:GetCallerIdentity",
        "iam:ListAccountAliases",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstances",
        "tag:GetResources",
        "cloudformation:ListStacks",
    ]
    assert {r["status"] for r in job["items"]} == {jobs.RES_DONE}
    assert (result.enis, result.ips) == (1, 1) and result.skipped == []
    assert (
        "Retry of skipped resources: collected VPCs, subnets, ENIs and ec2:DescribeInstances, "
        "tag:GetResources, cloudformation:ListStacks; the other resource types are copied "
        f"from snapshot {source}"
    ) in result.warnings
    mgr.close()


@mock_aws
def test_failed_optional_write_leaves_no_partial_rows(db_path, monkeypatch):
    _aws()
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": ["192.0.2.0/24"]}])["Vpcs"][0][
        "VpcId"
    ]
    sg_a = ec2.create_security_group(GroupName="sg-a", Description="example", VpcId=vpc_id)
    sg_b = ec2.create_security_group(GroupName="sg-b", Description="example", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg_a["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "UserIdGroupPairs": [{"GroupId": sg_b["GroupId"]}],
            }
        ],
    )

    def broken(_groups):
        raise RuntimeError("example write failure")

    # sg_refs rows are written first, then this fails inside the same resource type.
    monkeypatch.setattr(collector_mod, "sg_cidr_rows", broken)
    result = Collector(_gateway(), db_path).run()
    snap = result.snapshot_id
    assert _count(db_path, "sg_refs", snap) == 0
    assert _count(db_path, "security_groups", snap) == 0
    assert "ec2:DescribeSecurityGroups not saved (RuntimeError)" in result.warnings
    assert ("ec2:DescribeSecurityGroups", "write failed (RuntimeError)") in result.skipped
    # The other resource types were saved.
    assert _count(db_path, "vpcs", snap) >= 1 and _count(db_path, "enis", snap) == 1


@mock_aws
def test_failed_required_write_saves_nothing(db_path, monkeypatch):
    _aws()
    monkeypatch.setattr(
        collector_mod, "eni_private_ips", lambda *_a: (_ for _ in ()).throw(KeyError("x"))
    )
    with pytest.raises(KeyError):
        Collector(_gateway(), db_path).run()
    with closing(db_path) as conn:
        snap = conn.execute("SELECT id, status FROM snapshots").fetchone()
    assert snap["status"] == "failed"
    assert _count(db_path, "vpcs", snap["id"]) == 0
    assert _count(db_path, "subnets", snap["id"]) == 0


# -- settings -----------------------------------------------------------------------------


def test_timeout_settings_defaults_bounds_and_persistence(db_path):
    store = SettingsStore(db_path)
    s = store.load()
    assert (s.resource_timeout, s.discovery_timeout_min) == (30, 15)
    store.save(resource_timeout=45, discovery_timeout_min=5)
    s = store.load()
    assert (s.resource_timeout, s.discovery_timeout_min) == (45, 5)
    for bad in ("5", "3601", "abc", ""):
        with pytest.raises(ValueError, match="per-resource timeout"):
            settings_mod.parse_resource_timeout(bad)
    for bad in ("0", "241", "1.5"):
        with pytest.raises(ValueError, match="overall discovery timeout"):
            settings_mod.parse_discovery_timeout(bad)
    # An out-of-range stored value falls back to the default.
    with closing(db_path) as conn:
        conn.execute("UPDATE settings SET value='1' WHERE key='resource_timeout'")
    assert store.load().resource_timeout == 30


def _post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


@pytest.fixture
def app(home):
    app = create_app(home, testing=True)
    yield app
    app.extensions["iplens"]["jobs"].shutdown(5)


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def test_settings_form_validates_the_timeouts(app, client):
    page = client.get("/settings").data.decode()
    assert 'id="resource_timeout"' in page and 'id="discovery_timeout_min"' in page
    assert 'id="discovery"' in page
    resp = _post(client, "/settings", {"resource_timeout": "5"}, follow_redirects=True)
    assert "Settings not saved" in resp.data.decode()
    resp = _post(client, "/settings", {"discovery_timeout_min": "999"}, follow_redirects=True)
    assert "Settings not saved" in resp.data.decode()
    db = app.extensions["iplens"]["paths"].db_path
    s = SettingsStore(db).load()
    assert (s.resource_timeout, s.discovery_timeout_min) == (30, 15)
    assert "Defaults 30 seconds" in page and "at least 120 seconds" in page
    _post(client, "/settings", {"resource_timeout": "300", "discovery_timeout_min": "30"})
    s = SettingsStore(db).load()
    assert (s.resource_timeout, s.discovery_timeout_min) == (300, 30)


@mock_aws
def test_changed_resource_timeout_is_honoured_without_restart(app, client, monkeypatch, release):
    _aws()
    _warm_up(app.extensions["iplens"]["paths"].db_path)
    monkeypatch.setattr(Collector, "_fetch_tagged_resources", _hang(release))
    monkeypatch.setattr(settings_mod, "MIN_RESOURCE_TIMEOUT", 1)  # keep the test fast
    manager = app.extensions["iplens"]["jobs"]

    def refresh() -> dict:
        body = _post(client, "/refresh", {"background": "1"}).get_json()
        assert body["ok"], body
        assert manager.wait(body["job"]["id"], WAIT)
        return client.get(f"/jobs/{body['job']['id']}").get_json()["job"]

    _post(client, "/settings", {"resource_timeout": "1", "discovery_timeout_min": "2"})
    job = refresh()
    assert job["state"] == jobs.DONE
    assert job["limits"] == {"resource": 1, "overall": 120, "required": 120}
    rows = {r["name"]: r for r in job["items"]}
    assert rows["tag:GetResources"]["status"] == jobs.SKIPPED
    assert rows["tag:GetResources"]["reason"] == "timeout after 1s"
    assert any(m["text"] == "tag:GetResources skipped (timeout after 1s)" for m in job["messages"])

    # Same process, new value: the next Refresh uses it.
    _post(client, "/settings", {"resource_timeout": "2"})
    job = refresh()
    assert job["limits"]["resource"] == 2
    rows = {r["name"]: r for r in job["items"]}
    assert rows["tag:GetResources"]["reason"] == "timeout after 2s"
    assert rows["tag:GetResources"]["elapsed"] >= 1


@mock_aws
def test_refresh_endpoint_passes_the_skipped_types_to_the_collector(app, client, monkeypatch):
    _aws()
    seen = []
    sources = []
    real_init = Collector.__init__

    def init(self, *args, only=None, source_snapshot=None, **kwargs):
        seen.append(None if only is None else list(only))
        sources.append(source_snapshot)
        real_init(self, *args, only=only, source_snapshot=source_snapshot, **kwargs)

    monkeypatch.setattr(Collector, "__init__", init)
    manager = app.extensions["iplens"]["jobs"]

    def refresh(data) -> dict:
        body = _post(client, "/refresh", {"background": "1", **data}).get_json()
        assert body["ok"], body
        assert manager.wait(body["job"]["id"], WAIT)
        return client.get(f"/jobs/{body['job']['id']}").get_json()["job"]

    # A plain Refresh (no "only") collects every resource type.
    job = refresh({})
    assert seen[-1] is None
    assert "ec2:DescribeInstances" in {r["name"] for r in job["items"]}
    first = job["source_snapshot"]  # the snapshot this job wrote
    with closing(app.extensions["iplens"]["paths"].db_path) as conn:
        assert first == queries.latest_snapshot(conn)["id"]
    # Without a source (a job from before it was recorded): the latest snapshot.
    job = refresh({"only": ["elasticloadbalancing:DescribeTags", "lambda:ListTags"]})
    assert seen[-1] == ["elasticloadbalancing:DescribeTags", "lambda:ListTags"]
    assert sources[-1] == first
    assert job["state"] == jobs.DONE
    names = {r["name"] for r in job["items"]}
    assert {"lambda:ListTags", "lambda:ListFunctions", "elasticloadbalancing:DescribeTags"} <= names
    assert "ec2:DescribeInstances" not in names and "tag:GetResources" not in names
    assert job["source_snapshot"] > first  # the retry's own, merged snapshot
    # A newer Refresh meanwhile: the retry of the first job still builds on its snapshot.
    refresh({})
    job = refresh({"only": ["lambda:ListTags"], "source": str(first)})
    assert sources[-1] == first and job["state"] == jobs.DONE
    assert any(f"the rest from snapshot {first}" in line for line in job["log"])


def test_progress_box_has_cancel_banner_and_retry(client):
    page = client.get("/").data.decode()
    for marker in ('id="job-cancel"', 'id="job-limits"', 'id="job-resources"', 'id="job-retry"'):
        assert marker in page
    assert 'data-settings-url="/settings#discovery"' in page
    assert 'data-refresh-url="/refresh"' in page


# -- hide state ---------------------------------------------------------------------------


@pytest.fixture
def running_job(app, client):
    """A Refresh-kind job of the active account that runs until the test releases it."""
    gate = threading.Event()
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        ref = int(
            conn.execute("SELECT value FROM settings WHERE key='active_account'").fetchone()[0]
        )
    manager = app.extensions["iplens"]["jobs"]
    job = manager.start(ref, "refresh", lambda ctx: gate.wait(WAIT))
    yield job
    gate.set()
    manager.wait(job["id"], WAIT)


def test_hidden_progress_box_survives_a_tab_switch(client, running_job):
    job_id = running_job["id"]
    current = client.get("/jobs/current").get_json()
    assert current["job"]["id"] == job_id and current["job"]["running"]
    assert current["hidden"] is False  # shown until the user hides it

    assert _post(client, f"/jobs/{job_id}/hide").get_json() == {"ok": True, "hidden": True}
    # Switch tabs: other pages re-attach to the job and keep the box hidden.
    for page in ("/ips", "/settings", "/"):
        html = client.get(page).data.decode()
        assert 'id="job-badge"' in html
        assert client.get("/jobs/current").get_json()["hidden"] is True

    # Reopened from the badge: shown again everywhere.
    assert _post(client, f"/jobs/{job_id}/show").get_json()["hidden"] is False
    client.get("/ips")
    assert client.get("/jobs/current").get_json()["hidden"] is False


def test_hide_needs_csrf_and_a_known_job(client, running_job):
    assert client.post(f"/jobs/{running_job['id']}/hide").status_code == 400
    assert _post(client, "/jobs/does-not-exist/hide").status_code == 404
