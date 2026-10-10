"""Background jobs: Refresh (collection), the Extended view crawl and Terraform sync.

At most **one job per account** runs at a time. A job is a plain function run in a
worker thread with a :class:`JobContext`; it reports its current step, done / total
counts and log lines, and checks for cancellation between steps (cooperative: a running
AWS call finishes first; a running ``terraform`` command is terminated, see
:func:`iplens.tfrepo.run_process`). The Flask layer only starts jobs,
polls their state (:meth:`JobManager.status`) and asks them to stop; the work itself
never touches Flask's request state, and every database access in a worker opens its
own SQLite connection (:func:`iplens.db.closing`).

Job records (state, step, counts, result messages and the log tail) are persisted in
the ``jobs`` table when a job starts and ends, so a page reload re-attaches to a running
job and still shows the outcome of the last one; a job left ``running`` by a previous
process is reported as interrupted.

The log tail holds the *first line* of each INFO+ record the job's threads log under the
``iplens`` logger (terraform stderr tails and tracebacks are on later lines and stay in
the log file only), cut to :data:`MAX_LOG_LINE` characters.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .db import closing

log = logging.getLogger(__name__)

RUNNING, DONE, CANCELLED, ERROR = "running", "done", "cancelled", "error"
STATES = (RUNNING, DONE, CANCELLED, ERROR)
KINDS = {
    "refresh": "Refresh from AWS",
    "crawl": "Crawl services",
    "tfsync": "Terraform sync",
}
LOG_TAIL = 200  # log lines kept per job
MAX_LOG_LINE = 240
MAX_STEP = 200
MAX_MESSAGES = 50
INTERRUPTED = "interrupted: IPLens was restarted while the job was running"


class JobCancelled(Exception):  # noqa: N818 - a control-flow signal, not an error
    """Raised by :meth:`JobContext.check` once a job was asked to stop."""

    def __init__(self) -> None:
        super().__init__("cancelled")


class JobFailed(Exception):
    """Ends a job as ``error`` with a safe message (its result lines are already added)."""


class JobBusy(RuntimeError):
    """Another job of the same account is still running."""

    def __init__(self, job: dict[str, Any]):
        self.job = job
        super().__init__(
            f"{job['label']} is already running for this account "
            f"(started {job['elapsed']}s ago); wait for it or cancel it."
        )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _clip(text: str, limit: int) -> str:
    text = str(text).replace("\r", " ").split("\n", 1)[0]
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class Message:
    """A result line shown when the job ends (and flashed by non-JavaScript forms)."""

    category: str  # ok | warn | error
    text: str
    link_url: str = ""
    link_text: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "text": self.text,
            "link_url": self.link_url,
            "link_text": self.link_text,
        }


@dataclass
class Job:
    id: str
    account_ref: int
    kind: str
    label: str
    state: str = RUNNING
    step: str = "starting"
    done: int = 0
    total: int = 0
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""
    started: float = field(default_factory=time.monotonic)
    finished: float | None = None
    error: str = ""
    messages: list[Message] = field(default_factory=list)
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_TAIL))
    cancel_requested: threading.Event = field(default_factory=threading.Event)

    def as_dict(self) -> dict[str, Any]:
        end = self.finished if self.finished is not None else time.monotonic()
        return {
            "id": self.id,
            "account_ref": self.account_ref,
            "kind": self.kind,
            "label": self.label,
            "state": self.state,
            "running": self.state == RUNNING,
            "step": self.step,
            "done": self.done,
            "total": self.total,
            "elapsed": int(end - self.started),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cancel_requested": self.cancel_requested.is_set(),
            "error": self.error,
            "messages": [m.as_dict() for m in self.messages],
            "log": list(self.log),
        }


_local = threading.local()


def current_context() -> JobContext | None:
    """The job context bound to this thread (see :meth:`JobContext.bind`), if any."""
    return getattr(_local, "ctx", None)


class JobContext:
    """What a job function gets: progress reporting and the cancellation check.

    Every method is safe to call from the job's worker thread and from the helper
    threads it starts (e.g. the Terraform sync pool), as long as they :meth:`bind`.
    """

    def __init__(self, manager: JobManager, job: Job):
        self._manager = manager
        self._job = job

    @property
    def job_id(self) -> str:
        return self._job.id

    @property
    def cancelled(self) -> bool:
        return self._job.cancel_requested.is_set()

    def check(self) -> None:
        """Raise :class:`JobCancelled` if the job was asked to stop."""
        if self.cancelled:
            raise JobCancelled()

    def step(self, text: str, *, done: int | None = None, total: int | None = None) -> None:
        with self._manager._lock:
            self._job.step = _clip(text, MAX_STEP)
            if total is not None:
                self._job.total = max(int(total), 0)
            if done is not None:
                self._job.done = max(int(done), 0)
        self.log(text)

    def set_total(self, total: int) -> None:
        with self._manager._lock:
            self._job.total = max(int(total), 0)

    def add_total(self, n: int) -> None:
        with self._manager._lock:
            self._job.total += max(int(n), 0)

    def advance(self, n: int = 1) -> None:
        with self._manager._lock:
            self._job.done += n

    def log(self, text: str) -> None:
        line = _clip(text, MAX_LOG_LINE)
        stamp = time.strftime("%H:%M:%S")
        with self._manager._lock:
            self._job.log.append(f"{stamp} {line}")

    def message(self, category: str, text: str, link_url: str = "", link_text: str = "") -> None:
        with self._manager._lock:
            if len(self._job.messages) < MAX_MESSAGES:
                self._job.messages.append(Message(category, text, link_url, link_text))

    @contextmanager
    def bind(self) -> Iterator[JobContext]:
        """Route this thread's ``iplens`` log records into the job's log tail."""
        previous = getattr(_local, "ctx", None)
        _local.ctx = self
        try:
            yield self
        finally:
            _local.ctx = previous


class _TailHandler(logging.Handler):
    """Copies INFO+ records of threads bound to a job into that job's log tail."""

    def __init__(self) -> None:
        super().__init__(logging.INFO)

    def emit(self, record: logging.LogRecord) -> None:
        ctx = current_context()
        if ctx is None or record.name == __name__:
            return
        try:
            text = record.getMessage()
        except Exception:  # noqa: BLE001 - a bad log call must not break the job
            return
        prefix = "" if record.levelno < logging.WARNING else f"{record.levelname.lower()}: "
        ctx.log(prefix + text)


class NullProgress:
    """Stand-in context for code run outside a job (tests, the CLI)."""

    cancelled = False

    def check(self) -> None:
        return None

    def step(self, text: str, *, done: int | None = None, total: int | None = None) -> None:
        return None

    def set_total(self, total: int) -> None:
        return None

    def add_total(self, n: int) -> None:
        return None

    def advance(self, n: int = 1) -> None:
        return None

    def log(self, text: str) -> None:
        return None

    def message(self, *args: Any, **kwargs: Any) -> None:
        return None

    @contextmanager
    def bind(self) -> Iterator[NullProgress]:
        yield self


Progress = JobContext | NullProgress
JobFn = Callable[[JobContext], None]


class JobManager:
    """Starts, tracks and persists jobs; one running job per account."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._latest: dict[int, str] = {}  # account ref -> id of its newest job
        self._threads: dict[str, threading.Thread] = {}
        self._handler = _TailHandler()
        logging.getLogger("iplens").addHandler(self._handler)
        self._mark_interrupted()

    # -- persistence ----------------------------------------------------------------

    def _mark_interrupted(self) -> None:
        with closing(self.db_path) as conn:
            conn.execute(
                "UPDATE jobs SET state=?, error=?, finished_at=? WHERE state=?",
                (ERROR, INTERRUPTED, _now_iso(), RUNNING),
            )

    def _persist(self, job: Job) -> None:
        with self._lock:
            d = job.as_dict()
        try:
            with closing(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO jobs(id, account_ref, kind, label, state, step, done, total, "
                    "started_at, finished_at, elapsed, error, messages, log) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                    "state=excluded.state, step=excluded.step, done=excluded.done, "
                    "total=excluded.total, finished_at=excluded.finished_at, "
                    "elapsed=excluded.elapsed, error=excluded.error, "
                    "messages=excluded.messages, log=excluded.log",
                    (
                        d["id"],
                        d["account_ref"],
                        d["kind"],
                        d["label"],
                        d["state"],
                        d["step"],
                        d["done"],
                        d["total"],
                        d["started_at"],
                        d["finished_at"],
                        d["elapsed"],
                        d["error"],
                        json.dumps(d["messages"]),
                        json.dumps(d["log"][-LOG_TAIL:]),
                    ),
                )
                # Keep the newest few jobs per account.
                conn.execute(
                    "DELETE FROM jobs WHERE account_ref=? AND id NOT IN (SELECT id FROM jobs "
                    "WHERE account_ref=? ORDER BY started_at DESC, rowid DESC LIMIT 10)",
                    (d["account_ref"], d["account_ref"]),
                )
        except sqlite3.Error:
            log.exception("could not persist job %s", job.id)

    @staticmethod
    def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "account_ref": row["account_ref"],
            "kind": row["kind"],
            "label": row["label"],
            "state": row["state"],
            "running": False,  # a stored job is never running in this process
            "step": row["step"],
            "done": row["done"],
            "total": row["total"],
            "elapsed": row["elapsed"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "cancel_requested": False,
            "error": row["error"],
            "messages": json.loads(row["messages"] or "[]"),
            "log": json.loads(row["log"] or "[]"),
        }

    # -- queries -----------------------------------------------------------------------

    def status(self, job_id: str, account_ref: int | None = None) -> dict[str, Any] | None:
        """A job's state (live, else as persisted); None if unknown / another account's."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                if account_ref is not None and job.account_ref != account_ref:
                    return None
                return job.as_dict()
        with closing(self.db_path) as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None or (account_ref is not None and row["account_ref"] != account_ref):
            return None
        return self._row_dict(row)

    def current(self, account_ref: int) -> dict[str, Any] | None:
        """The account's running job, else its most recent one (for re-attaching)."""
        with self._lock:
            job_id = self._latest.get(account_ref)
            if job_id and job_id in self._jobs:
                return self._jobs[job_id].as_dict()
        with closing(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE account_ref=? ORDER BY started_at DESC, rowid DESC "
                "LIMIT 1",
                (account_ref,),
            ).fetchone()
        return self._row_dict(row) if row else None

    def running(self, account_ref: int) -> dict[str, Any] | None:
        with self._lock:
            job_id = self._latest.get(account_ref)
            job = self._jobs.get(job_id) if job_id else None
            return job.as_dict() if job is not None and job.state == RUNNING else None

    # -- control -----------------------------------------------------------------------

    def start(
        self,
        account_ref: int,
        kind: str,
        fn: JobFn,
        *,
        background: bool = True,
        label: str = "",
    ) -> dict[str, Any]:
        """Start ``fn`` as the account's job; raises :class:`JobBusy` if one is running.

        ``background=False`` runs it in the calling thread (forms without JavaScript)
        and returns once it has finished; the one-job-per-account rule applies either way.
        """
        if kind not in KINDS:
            raise ValueError(f"unknown job kind {kind!r}")
        with self._lock:
            busy = self.running(account_ref)
            if busy is not None:
                raise JobBusy(busy)
            job = Job(
                id=secrets.token_urlsafe(12),
                account_ref=account_ref,
                kind=kind,
                label=label or KINDS[kind],
            )
            self._jobs[job.id] = job
            self._latest[account_ref] = job.id
        self._persist(job)
        log.info("job %s started: %s (account=%s)", job.id, kind, account_ref)
        ctx = JobContext(self, job)
        if not background:
            self._run(ctx, job, fn)
            return self.status(job.id) or {}
        thread = threading.Thread(
            target=self._run, args=(ctx, job, fn), name=f"iplens-job-{kind}", daemon=True
        )
        with self._lock:
            self._threads[job.id] = thread
        thread.start()
        return job.as_dict()

    def cancel(self, job_id: str, account_ref: int | None = None) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or (account_ref is not None and job.account_ref != account_ref):
                return False
            if job.state != RUNNING:
                return False
            job.cancel_requested.set()
            job.step = _clip(f"{job.step} · cancelling…", MAX_STEP)
        log.info("job %s: cancel requested", job_id)
        return True

    def shutdown(self, timeout: float = 10.0) -> list[str]:
        """Cancel every running job and wait up to ``timeout`` seconds in total for
        their threads (a running terraform command is stopped by its cancel check);
        returns the ids of the jobs that were cancelled."""
        with self._lock:
            ids = [j.id for j in self._jobs.values() if j.state == RUNNING]
        cancelled = [job_id for job_id in ids if self.cancel(job_id)]
        deadline = time.monotonic() + timeout
        for job_id in cancelled:
            self.wait(job_id, max(deadline - time.monotonic(), 0.0))
        return cancelled

    def wait(self, job_id: str, timeout: float | None = None) -> bool:
        """Block until a background job ends (tests); True if it has."""
        with self._lock:
            thread = self._threads.get(job_id)
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def _run(self, ctx: JobContext, job: Job, fn: JobFn) -> None:
        state, error = DONE, ""
        with ctx.bind():
            try:
                fn(ctx)
                if ctx.cancelled:
                    state = CANCELLED
            except JobCancelled:
                state = CANCELLED
            except JobFailed as exc:
                state, error = ERROR, str(exc)
            except Exception as exc:  # noqa: BLE001 - reported as the job's error
                # Full details stay in the log file; the UI gets the exception type only.
                log.exception("job %s (%s) failed", job.id, job.kind)
                state, error = ERROR, f"{job.label} failed ({type(exc).__name__}); see the log"
        with self._lock:
            job.state = state
            job.error = error
            job.finished = time.monotonic()
            job.finished_at = _now_iso()
            if state == CANCELLED:
                job.step = "cancelled"
                job.messages.append(Message("warn", f"{job.label} cancelled."))
            elif state == ERROR:
                job.step = "failed"
                if not any(m.category == "error" for m in job.messages):
                    job.messages.append(Message("error", error))
            elif job.step and not job.step.startswith("finished"):
                job.step = "finished"
            self._threads.pop(job.id, None)
        self._persist(job)
        log.info("job %s ended: %s", job.id, state)

    def close(self) -> None:
        logging.getLogger("iplens").removeHandler(self._handler)
