"""Terraform sync: cancelling the job (or a timeout) stops the running terraform process.

A fake Popen stands in for terraform in most tests; one POSIX test runs a stub
``terraform`` shell script that sleeps (with a child of its own) and checks nothing is
left running. Placeholder data only (123456789012, example names)."""

from __future__ import annotations

import functools
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from iplens import tfrepo
from iplens.jobs import JobManager
from iplens.web import create_app
from tests import test_tfrepo
from tests.test_tfrepo import (
    TF,
    FakeRunner,
    _confirm,
    _db,
    _discovered,
    _envs,
    _keys_account,
    fake_gateway,
)

repo = test_tfrepo.repo  # the synthetic repository fixture
KEY = ("services", "dev")  # an HTTP-backend root: runs terraform init / workspace / show


@pytest.fixture
def app(home):
    return create_app(
        home,
        testing=True,
        terraform_bin=TF,
        terraform_runner=FakeRunner(),
        gateway_factory=fake_gateway,
    )


class FakePopen:
    """A terraform process that never finishes on its own."""

    def __init__(self, args, *, stubborn: bool = False, **kw):
        self.args, self.kw, self.stubborn = list(args), kw, stubborn
        self.returncode: int | None = None
        self.terminated = self.killed = False

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        if self.returncode is None:
            time.sleep(timeout or 0)
            if self.returncode is None:
                raise subprocess.TimeoutExpired(self.args, timeout)
        return b"", b""

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            time.sleep(timeout or 0)
            if self.returncode is None:
                raise subprocess.TimeoutExpired(self.args, timeout)
        return self.returncode


class Spawner:
    """Popen factory that records every process it starts."""

    def __init__(self, cls=FakePopen, **kw):
        self.cls, self.kw, self.procs = cls, kw, []
        self.started = threading.Event()

    def __call__(self, args, **kw):
        proc = self.cls(args, **self.kw, **kw)
        self.procs.append(proc)
        self.started.set()
        return proc


def _setup(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    env = _confirm(app, repo_id, KEY, acct)
    data_dir = app.extensions["iplens"]["paths"].tf_cache_dir.resolve() / (
        f"repo-{repo_id}-env-{env['id']}"
    )
    return acct, repo_id, data_dir


def _sync(app, runner, terraform_bin=TF, **kw):
    paths = app.extensions["iplens"]["paths"]
    store = app.extensions["iplens"]["accounts"]
    return tfrepo.sync(
        paths.db_path,
        lambda ref: store.get(ref, with_secret=True),
        cache_dir=paths.tf_cache_dir,
        terraform_bin=terraform_bin,
        runner=runner,
        gateway_factory=fake_gateway,
        **kw,
    )


def _cancel_running(app, acct, runner, started: threading.Event, terraform_bin=TF):
    """Start a sync job, cancel it once terraform runs; (results, job, seconds to stop)."""
    manager = JobManager(_db(app))
    seen: list = []

    def work(ctx):
        seen.append(_sync(app, runner, terraform_bin=terraform_bin, progress=ctx))
        ctx.check()

    job = manager.start(acct, "tfsync", work)
    assert started.wait(10), "terraform was never started"
    t0 = time.monotonic()
    assert manager.cancel(job["id"])
    assert manager.wait(job["id"], timeout=10)
    elapsed = time.monotonic() - t0
    status = manager.status(job["id"])
    manager.close()
    return seen[0], status, elapsed


def test_run_process_spawns_argv_without_shell_in_its_own_session(tmp_path):
    spawner = Spawner()
    flag = threading.Event()
    threading.Timer(0.2, flag.set).start()
    with pytest.raises(tfrepo.CommandCancelled):
        tfrepo.run_process(
            [TF, "show", "-json"],
            cwd=str(tmp_path),
            env={"TF_DATA_DIR": str(tmp_path / "cache")},
            timeout=30,
            cancelled=flag.is_set,
            popen=spawner,
        )
    (proc,) = spawner.procs
    assert proc.args == [TF, "show", "-json"]
    assert proc.kw["shell"] is False and proc.kw["cwd"] == str(tmp_path)
    assert proc.kw["stdin"] is subprocess.DEVNULL
    assert proc.kw["stdout"] is subprocess.PIPE and proc.kw["stderr"] is subprocess.PIPE
    assert proc.kw["env"]["TF_DATA_DIR"] == str(tmp_path / "cache")
    assert proc.kw["start_new_session"] is (os.name == "posix")
    assert proc.terminated and not proc.killed and proc.returncode is not None


def test_stop_process_kills_after_the_grace_period():
    assert tfrepo.KILL_GRACE == 5.0
    proc = FakePopen([TF, "show", "-json"], stubborn=True)  # ignores terminate()
    t0 = time.monotonic()
    tfrepo.stop_process(proc, grace=0.2)
    assert time.monotonic() - t0 < 1
    assert proc.terminated and proc.killed and proc.returncode == -9


def test_cancel_terminates_the_running_command_and_cleans_its_data_dir(app, repo):
    acct, _repo_id, data_dir = _setup(app, repo)
    spawner = Spawner()
    runner = functools.partial(tfrepo.run_process, popen=spawner)
    (result,), job, elapsed = _cancel_running(app, acct, runner, spawner.started)
    assert elapsed < 6
    assert job["state"] == "cancelled"
    (proc,) = spawner.procs  # only init ran; nothing started after the cancel
    assert proc.args[1] == "init" and proc.terminated and not proc.killed
    assert proc.returncode is not None  # gone: no orphan
    assert result.status == tfrepo.CANCELLED == "cancelled"
    assert "stopped" in result.detail
    assert _envs(app, _repo_id)[KEY]["status"] == "cancelled"
    assert not data_dir.exists()
    assert (data_dir.parent / tfrepo.PLUGIN_CACHE).is_dir()  # the shared cache stays


def test_cancel_kills_a_process_that_ignores_terminate(app, repo):
    acct, repo_id, data_dir = _setup(app, repo)
    spawner = Spawner(stubborn=True)
    runner = functools.partial(tfrepo.run_process, popen=spawner, grace=0.3)
    (result,), job, elapsed = _cancel_running(app, acct, runner, spawner.started)
    assert elapsed < 6 and job["state"] == "cancelled"
    (proc,) = spawner.procs
    assert proc.terminated and proc.killed and proc.returncode == -9
    assert _envs(app, repo_id)[KEY]["status"] == "cancelled"
    assert not data_dir.exists()


def test_timeout_terminates_the_command_and_cleans_its_data_dir(app, repo):
    _acct, repo_id, data_dir = _setup(app, repo)
    spawner = Spawner()
    runner = functools.partial(tfrepo.run_process, popen=spawner)
    t0 = time.monotonic()
    (result,) = _sync(app, runner, timeout=0.3)
    assert time.monotonic() - t0 < 6
    (proc,) = spawner.procs
    assert proc.terminated and proc.returncode is not None
    assert result.status == tfrepo.INIT_FAILED and result.detail == "timed out"
    assert _envs(app, repo_id)[KEY]["status"] == tfrepo.INIT_FAILED
    assert not data_dir.exists()


def _running(pid: int) -> bool:
    """True while ``pid`` exists and is not a zombie."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="needs Linux /proc")
def test_cancel_leaves_no_orphan_process(app, repo, tmp_path):
    """A real stub terraform that sleeps and starts a sleeping child of its own."""
    acct, repo_id, data_dir = _setup(app, repo)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "terraform"
    pids = bin_dir / "pids"
    stub.write_text(
        '#!/bin/sh\nsleep 60 &\necho "$$ $!" > "$(dirname "$0")/pids.tmp"\n'
        'mv "$(dirname "$0")/pids.tmp" "$(dirname "$0")/pids"\nwait\n'
    )
    stub.chmod(0o700)

    class SpyPopen(subprocess.Popen):
        def terminate(self):
            self.terminated = True
            super().terminate()

    spawner = Spawner(cls=SpyPopen)
    started = threading.Event()

    runner = functools.partial(tfrepo.run_process, popen=spawner)

    def wait_for_pids():
        deadline = time.monotonic() + 10
        while not pids.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        started.set()

    threading.Thread(target=wait_for_pids, daemon=True).start()
    (result,), job, elapsed = _cancel_running(app, acct, runner, started, terraform_bin=str(stub))
    shell_pid, child_pid = map(int, pids.read_text().split())
    assert elapsed < 6 and job["state"] == "cancelled"
    (proc,) = spawner.procs
    assert proc.pid == shell_pid and getattr(proc, "terminated", False)
    assert proc.returncode is not None
    deadline = time.monotonic() + 3
    while (_running(shell_pid) or _running(child_pid)) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _running(shell_pid) and not _running(child_pid)  # no orphan
    assert result.status == tfrepo.CANCELLED
    assert _envs(app, repo_id)[KEY]["status"] == "cancelled"
    assert not data_dir.exists()
