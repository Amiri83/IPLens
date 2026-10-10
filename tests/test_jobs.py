"""Background jobs: progress, cancel, one job per account, persistence and the web flow.

Placeholder data only (10.0.x.x, 123456789012, example names)."""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from iplens import jobs
from iplens.aws import AwsGateway
from iplens.collector import COLLECT_STEPS
from iplens.db import closing
from iplens.web import create_app

WAIT = 30  # seconds a test waits for a background job at most


# -- the job manager --------------------------------------------------------------------


def test_job_reports_progress_log_and_can_be_cancelled(db_path, caplog):
    mgr = jobs.JobManager(db_path)
    started, release = threading.Event(), threading.Event()
    reached_end = []

    def work(ctx: jobs.JobContext) -> None:
        ctx.step("root apps env env-dev · terraform init", done=1, total=3)
        logging.getLogger("iplens.example").info("line from the worker thread")
        logging.getLogger("iplens.example").warning("first line only\nsecond line stays out")
        started.set()
        release.wait(WAIT)
        ctx.check()  # cancelled meanwhile: raises JobCancelled
        reached_end.append(True)

    with caplog.at_level(logging.INFO, logger="iplens"):
        job = mgr.start(1, "tfsync", work)
        assert started.wait(WAIT)
        live = mgr.status(job["id"])
        assert live["running"] and live["state"] == jobs.RUNNING
        assert (live["step"], live["done"], live["total"]) == (
            "root apps env env-dev · terraform init",
            1,
            3,
        )
        tail = "\n".join(live["log"])
        assert "line from the worker thread" in tail
        assert "warning: first line only" in tail and "second line" not in tail
        assert mgr.current(1)["id"] == job["id"]  # a reload re-attaches to it

        assert mgr.cancel(job["id"])
        assert mgr.status(job["id"])["cancel_requested"]
        release.set()
        assert mgr.wait(job["id"], WAIT)

    done = mgr.status(job["id"])
    assert done["state"] == jobs.CANCELLED and not done["running"] and not reached_end
    assert any("cancelled" in m["text"] for m in done["messages"])
    assert not mgr.cancel(job["id"])  # nothing left to cancel
    # Persisted: a restarted app still shows the outcome.
    assert jobs.JobManager(db_path).current(1)["state"] == jobs.CANCELLED
    mgr.close()


def test_one_job_per_account(db_path):
    mgr = jobs.JobManager(db_path)
    release = threading.Event()
    first = mgr.start(1, "refresh", lambda ctx: release.wait(WAIT))
    with pytest.raises(jobs.JobBusy, match="already running"):
        mgr.start(1, "crawl", lambda ctx: None)
    with pytest.raises(jobs.JobBusy):
        mgr.start(1, "refresh", lambda ctx: None, background=False)
    # Another account is independent; inline jobs return once finished.
    other = mgr.start(2, "crawl", lambda ctx: ctx.message("ok", "done"), background=False)
    assert other["state"] == jobs.DONE and other["messages"][0]["text"] == "done"
    assert mgr.status(first["id"], account_ref=2) is None  # never another account's job
    release.set()
    assert mgr.wait(first["id"], WAIT)
    assert mgr.status(first["id"])["state"] == jobs.DONE
    # Free again.
    assert mgr.start(1, "crawl", lambda ctx: None, background=False)["state"] == jobs.DONE
    mgr.close()


def test_failed_job_reports_a_safe_error(db_path, caplog):
    mgr = jobs.JobManager(db_path)

    def boom(ctx):
        raise RuntimeError("detail with arn:aws:iam::123456789012:role/example-role")

    with caplog.at_level(logging.INFO, logger="iplens"):
        job = mgr.start(1, "crawl", boom, background=False)
    assert job["state"] == jobs.ERROR
    assert job["error"] == "Crawl services failed (RuntimeError); see the log"
    assert "arn:aws" not in str(job)
    assert "example-role" in caplog.text  # full details in the log file only
    mgr.close()


def test_job_left_running_by_a_previous_process_is_interrupted(db_path):
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO jobs(id, account_ref, kind, label, state, started_at) "
            "VALUES('job-example', 1, 'refresh', 'Refresh from AWS', 'running', '2026-01-01')"
        )
    mgr = jobs.JobManager(db_path)
    stale = mgr.current(1)
    assert stale["state"] == jobs.ERROR and stale["error"] == jobs.INTERRUPTED
    # Not running, so a new job may start.
    assert mgr.start(1, "refresh", lambda ctx: None, background=False)["state"] == jobs.DONE
    mgr.close()


# -- web ------------------------------------------------------------------------------------


def _post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


@pytest.fixture
def gated(home):
    """App whose AWS gateway is only built once ``gate`` is set (the job blocks there)."""
    gate = threading.Event()

    def factory(account):
        gate.wait(WAIT)
        return AwsGateway.from_account(account)

    app = create_app(home, testing=True, gateway_factory=factory)
    client = app.test_client()
    client.get("/")
    return app, client, gate


@mock_aws
def test_background_refresh_progress_one_per_account_and_reattach(gated):
    app, client, gate = gated
    manager = app.extensions["iplens"]["jobs"]
    boto3.client("ec2", region_name="us-east-1").create_vpc(CidrBlock="10.0.0.0/16")
    body = _post(client, "/refresh", {"background": "1"}).get_json()
    assert body["ok"] and body["job"]["running"] and body["job"]["kind"] == "refresh"
    job_id = body["job"]["id"]
    # A reload re-attaches to the running job.
    current = client.get("/jobs/current").get_json()["job"]
    assert current["id"] == job_id and current["running"]
    # One job per account: a second one is refused (JSON and plain form alike).
    busy = _post(client, "/refresh", {"background": "1"})
    assert busy.status_code == 409 and "already running" in busy.get_json()["error"]
    assert busy.get_json()["job"]["id"] == job_id
    page = _post(client, "/terraform/sync", follow_redirects=True).data.decode()
    assert "already running for this account" in page

    gate.set()
    assert manager.wait(job_id, WAIT)
    job = client.get(f"/jobs/{job_id}").get_json()["job"]
    assert job["state"] == jobs.DONE and job["total"] == COLLECT_STEPS
    assert any(m["text"].startswith("Refreshed 123456789012") for m in job["messages"])
    assert any("collect · ec2:DescribeVpcs" in line for line in job["log"])
    assert client.get("/jobs/does-not-exist").status_code == 404


@mock_aws
def test_background_refresh_cancel(gated):
    app, client, gate = gated
    manager = app.extensions["iplens"]["jobs"]
    job_id = _post(client, "/refresh", {"background": "1"}).get_json()["job"]["id"]
    resp = _post(client, f"/jobs/{job_id}/cancel").get_json()
    assert resp["ok"] and resp["job"]["cancel_requested"]
    gate.set()
    assert manager.wait(job_id, WAIT)
    job = client.get(f"/jobs/{job_id}").get_json()["job"]
    assert job["state"] == jobs.CANCELLED and job["step"] == "cancelled"
    with closing(app.extensions["iplens"]["paths"].db_path) as conn:
        snap = conn.execute("SELECT status, error FROM snapshots ORDER BY id DESC").fetchone()
    assert (snap["status"], snap["error"]) == ("failed", "cancelled")
    # The cancel endpoint needs the CSRF token like every POST.
    assert client.post(f"/jobs/{job_id}/cancel").status_code == 400


def test_pages_carry_the_job_modal_and_job_forms(home, snapshot_builder):
    app = create_app(home, testing=True)
    client = app.test_client()
    page = client.get("/").data.decode()
    assert 'id="job-modal"' in page and "jobs.js" in page
    assert 'data-job="refresh"' in page
    assert 'data-job="tfsync"' in client.get("/terraform").data.decode()
    assert client.get("/jobs/current").get_json()["job"] is None


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_jobs_script_parses():
    path = Path(__file__).parent.parent / "iplens" / "static" / "jobs.js"
    result = subprocess.run(  # noqa: S603 - fixed argv, shipped file
        [shutil.which("node"), "--check", str(path)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr


def test_shutdown_cancels_running_jobs_and_waits_for_them(db_path):
    mgr = jobs.JobManager(db_path)
    started = threading.Event()

    def work(ctx):
        started.set()
        while True:
            ctx.check()
            threading.Event().wait(0.01)

    job = mgr.start(1, "refresh", work)
    assert started.wait(WAIT)
    assert mgr.shutdown(timeout=WAIT) == [job["id"]]
    assert mgr.status(job["id"])["state"] == jobs.CANCELLED
    assert mgr.shutdown() == []  # nothing left running
