"""Scheduled Refresh: a background thread that starts due Refresh jobs.

Each account has an interval (:data:`INTERVALS`: off, 1 h, 6 h or 24 h, stored in
``refresh_schedules``). While the app runs, :class:`Scheduler` wakes every
:data:`TICK_SECONDS` and starts the Refresh of every account whose last Refresh (a
successful or failed snapshot, or the scheduler's last attempt) is at least one interval
old. Jobs go through :meth:`iplens.jobs.JobManager.start`, so the one-job-per-account
rule applies: an account with a job running is skipped and retried on a later tick.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .db import closing
from .jobs import JobBusy, JobManager
from .retention import parse_taken_at

log = logging.getLogger(__name__)

# Interval (hours) -> label; 0 = off.
INTERVALS = {0: "off", 1: "every hour", 6: "every 6 hours", 24: "every 24 hours"}
TICK_SECONDS = 60.0

# Starts the Refresh job of an account (raises JobBusy if one is running).
StartRefresh = Callable[[int], dict[str, Any]]


def parse_interval(value: str | int | None) -> int:
    """An interval in hours from :data:`INTERVALS`; ValueError otherwise."""
    try:
        hours = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("invalid refresh interval") from None
    if hours not in INTERVALS:
        raise ValueError("the refresh interval must be off, 1, 6 or 24 hours")
    return hours


def get_interval(conn: sqlite3.Connection, account_ref: int) -> int:
    row = conn.execute(
        "SELECT interval_hours FROM refresh_schedules WHERE account_ref=?", (account_ref,)
    ).fetchone()
    return int(row["interval_hours"]) if row else 0


def intervals(conn: sqlite3.Connection) -> dict[int, int]:
    """Account ref -> interval hours (accounts without a schedule are absent)."""
    rows = conn.execute("SELECT account_ref, interval_hours FROM refresh_schedules")
    return {r["account_ref"]: int(r["interval_hours"]) for r in rows}


def set_interval(conn: sqlite3.Connection, account_ref: int, hours: int) -> None:
    hours = parse_interval(hours)
    conn.execute(
        "INSERT INTO refresh_schedules(account_ref, interval_hours) VALUES(?, ?) "
        "ON CONFLICT(account_ref) DO UPDATE SET interval_hours = excluded.interval_hours",
        (account_ref, hours),
    )


def mark_run(conn: sqlite3.Connection, account_ref: int, now: datetime) -> None:
    conn.execute(
        "UPDATE refresh_schedules SET last_run_at=? WHERE account_ref=?",
        (now.isoformat(timespec="seconds"), account_ref),
    )


def due_accounts(conn: sqlite3.Connection, now: datetime | None = None) -> list[int]:
    """Accounts with a schedule whose last Refresh is at least one interval old."""
    now = now or datetime.now(UTC)
    rows = conn.execute(
        "SELECT r.account_ref, r.interval_hours, r.last_run_at, "
        "(SELECT MAX(taken_at) FROM snapshots s WHERE s.account_ref = r.account_ref) AS last_snap "
        "FROM refresh_schedules r JOIN accounts a ON a.id = r.account_ref "
        "WHERE r.interval_hours > 0 ORDER BY r.account_ref"
    ).fetchall()
    due = []
    for r in rows:
        stamps = [parse_taken_at(v) for v in (r["last_run_at"], r["last_snap"]) if v]
        last = max(stamps) if stamps else None
        if last is None or now - last >= timedelta(hours=r["interval_hours"]):
            due.append(r["account_ref"])
    return due


class Scheduler:
    """Background loop starting due Refresh jobs; see the module docstring."""

    def __init__(
        self,
        db_path: Path,
        jobs: JobManager,
        start_refresh: StartRefresh,
        tick: float = TICK_SECONDS,
    ):
        self.db_path = db_path
        self.jobs = jobs
        self.start_refresh = start_refresh
        self.tick = tick
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_due(self, now: datetime | None = None) -> list[int]:
        """One tick: start every due account's Refresh; returns the accounts started."""
        now = now or datetime.now(UTC)
        with closing(self.db_path) as conn:
            due = due_accounts(conn, now)
        started = []
        for ref in due:
            if self.jobs.running(ref) is not None:
                log.info("scheduled refresh of account=%s skipped: a job is running", ref)
                continue
            # Recorded before starting: a Refresh failing before it writes a snapshot
            # (e.g. expired credentials) is retried after one interval, not every tick.
            with closing(self.db_path) as conn:
                mark_run(conn, ref, now)
            try:
                self.start_refresh(ref)
            except JobBusy:
                log.info("scheduled refresh of account=%s skipped: a job is running", ref)
                continue
            except Exception:  # noqa: BLE001 - one account must not stop the others
                log.exception("scheduled refresh of account=%s could not start", ref)
                continue
            log.info("scheduled refresh of account=%s started", ref)
            started.append(ref)
        return started

    def _loop(self) -> None:
        while not self._stop.wait(self.tick):
            try:
                self.run_due()
            except Exception:  # noqa: BLE001 - keep the loop alive
                log.exception("scheduler tick failed")

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="iplens-scheduler", daemon=True)
        self._thread.start()
        log.info("refresh scheduler started (tick %ss)", int(self.tick))

    def stop(self, timeout: float | None = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None
