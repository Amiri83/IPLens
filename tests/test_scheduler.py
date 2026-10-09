"""Scheduled Refresh: intervals, due accounts, the one-job-per-account rule.

Synthetic data only; AWS is moto-mocked (account 123456789012, 10.0.x.x).
"""

import threading
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

from iplens import scheduler
from iplens.db import closing
from iplens.jobs import JobBusy, JobManager
from iplens.web import create_app

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def _account(db_path, name="example-b"):
    with closing(db_path) as conn:
        return conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) VALUES(?, 'us-east-1', 'env')",
            (name,),
        ).lastrowid


def test_interval_validation_and_storage(db_path):
    assert scheduler.parse_interval("6") == 6
    for bad in ("2", "x", "", None):
        with pytest.raises(ValueError):
            scheduler.parse_interval(bad)
    with closing(db_path) as conn:
        assert scheduler.get_interval(conn, 1) == 0
        scheduler.set_interval(conn, 1, 24)
        scheduler.set_interval(conn, 1, 1)
        assert scheduler.get_interval(conn, 1) == 1
        assert scheduler.intervals(conn) == {1: 1}


def test_due_accounts(db_path, snapshot_builder):
    b = _account(db_path)
    c = _account(db_path, "example-c")
    with closing(db_path) as conn:
        scheduler.set_interval(conn, 1, 1)  # hourly, last snapshot 2 h ago -> due
        scheduler.set_interval(conn, b, 6)  # 6 h, last snapshot 2 h ago -> not due
        scheduler.set_interval(conn, c, 24)  # never refreshed -> due
    snapshot_builder(db_path, taken_at=NOW - timedelta(hours=2))
    snapshot_builder(db_path, taken_at=NOW - timedelta(hours=2), account_ref=b)
    with closing(db_path) as conn:
        assert scheduler.due_accounts(conn, NOW) == [1, c]
        assert scheduler.due_accounts(conn, NOW + timedelta(hours=4)) == [1, b, c]
        scheduler.set_interval(conn, 1, 0)  # off
        assert scheduler.due_accounts(conn, NOW) == [c]
        # A failed snapshot counts as a run too.
    snapshot_builder(db_path, taken_at=NOW, account_ref=c, status="failed")
    with closing(db_path) as conn:
        assert scheduler.due_accounts(conn, NOW) == []


def test_run_due_marks_the_attempt(db_path):
    started = []
    sched = scheduler.Scheduler(db_path, JobManager(db_path), lambda ref: started.append(ref))
    with closing(db_path) as conn:
        scheduler.set_interval(conn, 1, 1)
    assert sched.run_due(NOW) == [1]
    # The attempt counts even without a snapshot (e.g. bad credentials): no retry each tick.
    assert sched.run_due(NOW + timedelta(minutes=30)) == []
    assert sched.run_due(NOW + timedelta(hours=1)) == [1]
    assert started == [1, 1]


def test_running_job_blocks_the_scheduled_refresh(db_path):
    jobs = JobManager(db_path)
    release = threading.Event()
    blocker = jobs.start(1, "crawl", lambda ctx: release.wait(5))
    calls = []

    def start_refresh(ref):
        calls.append(ref)
        return jobs.start(ref, "refresh", lambda ctx: None, label="Scheduled refresh")

    sched = scheduler.Scheduler(db_path, jobs, start_refresh)
    with closing(db_path) as conn:
        scheduler.set_interval(conn, 1, 1)
    assert sched.run_due(NOW) == []
    assert calls == []  # skipped before trying: the account has a job running
    release.set()
    assert jobs.wait(blocker["id"], 5)
    assert sched.run_due(NOW + timedelta(hours=1)) == [1]
    assert jobs.current(1)["label"] == "Scheduled refresh"


def test_job_busy_race_is_skipped(db_path):
    def busy(ref):
        raise JobBusy({"label": "Refresh from AWS", "elapsed": 1})

    sched = scheduler.Scheduler(db_path, JobManager(db_path), busy)
    with closing(db_path) as conn:
        scheduler.set_interval(conn, 1, 1)
    assert sched.run_due(NOW) == []


def test_one_failing_account_does_not_stop_the_others(db_path):
    b = _account(db_path)
    started = []

    def start(ref):
        if ref == 1:
            raise RuntimeError("example failure")
        started.append(ref)

    sched = scheduler.Scheduler(db_path, JobManager(db_path), start)
    with closing(db_path) as conn:
        scheduler.set_interval(conn, 1, 1)
        scheduler.set_interval(conn, b, 1)
    assert sched.run_due(NOW) == [b]


def test_thread_starts_and_stops(db_path):
    ticked = threading.Event()
    sched = scheduler.Scheduler(db_path, JobManager(db_path), lambda ref: ticked.set(), tick=0.01)
    with closing(db_path) as conn:
        scheduler.set_interval(conn, 1, 1)
    sched.start()
    try:
        assert ticked.wait(5)
    finally:
        sched.stop()
    assert sched._thread is None


def test_schedule_is_deleted_with_its_account(db_path):
    b = _account(db_path)
    with closing(db_path) as conn:
        scheduler.set_interval(conn, b, 6)
        conn.execute("DELETE FROM accounts WHERE id=?", (b,))
        assert scheduler.intervals(conn) == {}


# -- web -----------------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def _post(client, url, data):
    client.get("/")
    with client.session_transaction() as s:
        data = {**data, "csrf_token": s["csrf"]}
    return client.post(url, data=data, follow_redirects=True)


def test_testing_app_does_not_start_the_thread(app):
    assert app.extensions["iplens"]["scheduler"]._thread is None


def test_settings_sets_the_interval(app):
    client = app.test_client()
    page = _post(client, "/accounts/1/schedule", {"interval": "6"}).data.decode()
    assert "Scheduled refresh: every 6 hours" in page
    assert '<option value="6" selected>' in page
    assert _post(client, "/accounts/1/schedule", {"interval": "5"}).status_code == 400
    assert _post(client, "/accounts/99/schedule", {"interval": "6"}).status_code == 404


@mock_aws
def test_scheduled_refresh_runs_the_refresh_job(app):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        scheduler.set_interval(conn, 1, 1)
    sched = app.extensions["iplens"]["scheduler"]
    jobs = app.extensions["iplens"]["jobs"]
    assert sched.run_due() == [1]
    job = jobs.current(1)
    assert job["label"] == "Scheduled refresh" and job["kind"] == "refresh"
    assert jobs.wait(job["id"], 30)
    job = jobs.current(1)
    assert job["state"] == "done", job
    assert any("Refreshed 123456789012" in m["text"] for m in job["messages"])
    with closing(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE status='ok'").fetchone()[0] == 1
    # The new snapshot resets the clock: nothing is due right away.
    assert sched.run_due() == []
