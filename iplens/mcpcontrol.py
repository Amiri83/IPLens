"""The MCP HTTP server as a child process of IPLens (Settings → MCP server).

:class:`McpController` starts ``python -m iplens mcp --http ...`` as a subprocess (never
in-process: the child refuses to import the AWS SDK, IPLens needs it), passes the bearer
token in the environment (never on the command line), writes the child's stdout / stderr
to its own log file (:data:`LOG_FILE`, shown on the Logs page) and watches it:

* states: ``stopped``, ``starting`` (until the port answers), ``running``, ``error``;
* a crash is shown with the last log lines; it is retried at most :data:`MAX_RETRIES`
  times (after a growing pause; a run of :data:`STABLE_SECONDS` resets the count), then
  the server stays in ``error`` until started again by hand;
* :meth:`McpController.stop` (also on IPLens shutdown) asks the child to stop (SIGTERM),
  and kills it after a timeout. The child also stops itself once IPLens is gone (see
  :func:`iplens.mcpserver.watch_parent`).
"""

from __future__ import annotations

import contextlib
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .logging_setup import LOG_FORMAT
from .mcpconfig import TOKEN_ENV, McpSettings
from .mcpserver import PARENT_PID_ENV

log = logging.getLogger(__name__)

LOG_FILE = "mcp-server.log"
MAX_LOG_BYTES = 2_000_000
STOPPED, STARTING, RUNNING, ERROR = "stopped", "starting", "running", "error"
MAX_RETRIES = 3
RETRY_DELAYS = (1.0, 2.0, 4.0)
STABLE_SECONDS = 60.0
STARTUP_TIMEOUT = 30.0
STOP_TIMEOUT = 5.0
TAIL_LINES = 5


class McpStartError(RuntimeError):
    """The server cannot be started (port in use, already running): shown as is."""


def port_free(host: str, port: int) -> bool:
    """True if ``host:port`` can be bound now (the server binds it the same way)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    except OSError:
        return False
    family, kind, proto, _, addr = infos[0]
    with socket.socket(family, kind, proto) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(addr)
        except OSError:
            return False
    return True


def port_answers(host: str, port: int, timeout: float = 0.5) -> bool:
    connect_to = "127.0.0.1" if host in ("0.0.0.0", "::") else host  # noqa: S104
    try:
        with socket.create_connection((connect_to, port), timeout=timeout):
            return True
    except OSError:
        return False


def _log_line(level: str, message: str) -> str:
    """A line of the log file in the IPLens log format (so the Logs page parses it)."""
    record = logging.LogRecord(__name__, logging.getLevelName(level), "", 0, message, (), None)
    return logging.Formatter(LOG_FORMAT).format(record) + "\n"


class McpController:
    """One MCP HTTP server child process. Thread-safe."""

    def __init__(
        self,
        home: Path,
        log_dir: Callable[[], Path],
        *,
        python: str = sys.executable,
        startup_timeout: float = STARTUP_TIMEOUT,
        retry_delays: tuple[float, ...] = RETRY_DELAYS,
    ):
        self.home = home
        self._log_dir = log_dir
        self.python = python
        self.startup_timeout = startup_timeout
        self.retry_delays = retry_delays
        self._lock = threading.RLock()
        self._proc: subprocess.Popen[bytes] | None = None
        self._settings: McpSettings | None = None
        self._token = ""
        self._state = STOPPED
        self._last_error = ""
        self._started_at: float | None = None  # monotonic, while running
        self._retries = 0
        self._generation = 0  # bumped by every start / stop: stale watchers give up
        self._log_path: Path | None = None

    # -- status ---------------------------------------------------------------------------

    @property
    def log_path(self) -> Path:
        return self._log_path or self._log_dir() / LOG_FILE

    @property
    def running(self) -> bool:
        with self._lock:
            return self._state in (STARTING, RUNNING)

    def status(self) -> dict[str, Any]:
        with self._lock:
            s = self._settings
            uptime = (
                int(time.monotonic() - self._started_at)
                if self._state == RUNNING and self._started_at is not None
                else None
            )
            alive = self._proc is not None and self._state in (STARTING, RUNNING)
            return {
                "state": self._state,
                "pid": self._proc.pid if alive and self._proc else None,
                "url": s.url if s else None,
                "remote": bool(s and s.remote),
                "uptime": uptime,
                "uptime_text": _duration(uptime) if uptime is not None else "",
                "last_error": self._last_error,
                "retries": self._retries,
                "max_retries": MAX_RETRIES,
                "log_file": str(self.log_path),
            }

    # -- start / stop -----------------------------------------------------------------------

    def start(self, settings: McpSettings, token: str) -> None:
        """Start the server; McpStartError if it runs already or the port is taken."""
        with self._lock:
            if self.running:
                raise McpStartError("the MCP server is already running")
            self._retries, self._last_error = 0, ""
            self._settings, self._token = settings, token
            self._spawn()

    def stop(self, timeout: float = STOP_TIMEOUT) -> bool:
        """Stop the server (SIGTERM, then SIGKILL after ``timeout``); True if it ran."""
        with self._lock:
            self._generation += 1
            proc, self._proc = self._proc, None
            was_running = self._state in (STARTING, RUNNING)
            # The last error stays visible until the next start.
            self._state, self._started_at = STOPPED, None
        if proc is None or proc.poll() is not None:
            return was_running
        proc.terminate()
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            log.warning("mcp server pid %d did not stop in %.0fs: killed", proc.pid, timeout)
            proc.kill()
            proc.wait(timeout)
        self._append_log("INFO", f"stopped (pid {proc.pid}, exit code {proc.returncode})")
        log.info("mcp server stopped (pid %d)", proc.pid)
        return True

    def restart(self, settings: McpSettings, token: str) -> None:
        self.stop()
        self.start(settings, token)

    def wait_ready(self, timeout: float = STARTUP_TIMEOUT) -> str:
        """Wait while the server is starting; the state then (tests, the CLI)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._state != STARTING:
                    return self._state
            time.sleep(0.05)
        return self.status()["state"]

    # -- internals ------------------------------------------------------------------------

    def _spawn(self) -> None:
        """Start the child (lock held); McpStartError (state error) if it cannot."""
        s = self._settings
        assert s is not None
        self._generation += 1
        if not port_free(s.host, s.port):
            self._fail(f"port {s.port} on {s.host} is already in use")
            raise McpStartError(self._last_error)
        self._log_path = self._log_dir() / LOG_FILE
        out = self._open_log()
        env = {
            **os.environ,
            TOKEN_ENV: self._token,
            PARENT_PID_ENV: str(os.getpid()),
            "PYTHONUNBUFFERED": "1",
        }
        cmd = [self.python, "-m", "iplens", *s.server_args(self.home)]
        kwargs: dict[str, Any] = {}
        if os.name == "posix":
            kwargs["start_new_session"] = True  # Ctrl+C in the terminal is IPLens' to handle
        else:  # pragma: no cover - Windows
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            proc = subprocess.Popen(  # noqa: S603 - our own interpreter and module
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                env=env,
                **kwargs,
            )
        except OSError as exc:
            self._fail(f"cannot start the MCP server: {exc}")
            raise McpStartError(self._last_error) from None
        finally:
            out.close()
        self._proc, self._state, self._started_at = proc, STARTING, None
        log.info("mcp server starting (pid %d) on %s", proc.pid, s.url)
        threading.Thread(
            target=self._watch,
            args=(proc, self._generation),
            name=f"iplens-mcp-{proc.pid}",
            daemon=True,
        ).start()

    def _open_log(self):
        path = self.log_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            if path.stat().st_size > MAX_LOG_BYTES:
                path.replace(path.with_name(path.name + ".1"))
        out = path.open("ab")
        s = self._settings
        assert s is not None
        out.write(_log_line("INFO", f"starting the MCP server on {s.url}").encode())
        out.flush()
        return out

    def _append_log(self, level: str, message: str) -> None:
        with contextlib.suppress(OSError), self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(_log_line(level, message))

    def _fail(self, message: str) -> None:
        self._state, self._last_error, self._started_at = ERROR, message, None
        self._proc = None
        self._append_log("ERROR", message)
        log.error("mcp server: %s", message)

    def _current(self, generation: int) -> bool:
        return generation == self._generation

    def _watch(self, proc: subprocess.Popen[bytes], generation: int) -> None:
        """Mark the server running once its port answers; handle its exit."""
        s = self._settings
        assert s is not None
        deadline = time.monotonic() + self.startup_timeout
        while proc.poll() is None:
            with self._lock:
                if not self._current(generation):
                    return
                if self._state == STARTING and port_answers(s.host, s.port, 0.2):
                    self._state, self._started_at = RUNNING, time.monotonic()
                    log.info("mcp server running (pid %d) on %s", proc.pid, s.url)
                elif self._state == STARTING and time.monotonic() > deadline:
                    self._generation += 1
                    self._fail(f"the MCP server did not answer within {self.startup_timeout:.0f}s")
                    proc.kill()
                    return
            time.sleep(0.1)
        with self._lock:
            if not self._current(generation):  # stopped on purpose
                return
            ran = time.monotonic() - self._started_at if self._started_at is not None else 0.0
            if ran >= STABLE_SECONDS:
                self._retries = 0
            tail = " | ".join(self._tail())
            reason = f"the MCP server exited with code {proc.returncode}"
            self._fail(f"{reason}: {tail}" if tail else reason)
            if self._retries >= MAX_RETRIES:
                self._last_error += f" (gave up after {MAX_RETRIES} retries)"
                return
            delay = self.retry_delays[min(self._retries, len(self.retry_delays) - 1)]
            self._retries += 1
            attempt = self._retries
        log.warning("mcp server crashed; retry %d/%d in %.0fs", attempt, MAX_RETRIES, delay)
        time.sleep(delay)
        with self._lock:
            if not self._current(generation) or self._state != ERROR:
                return  # started / stopped by hand meanwhile
            with contextlib.suppress(McpStartError):
                self._spawn()

    def _tail(self) -> list[str]:
        """The child's last output lines (the reason of a crash, usually)."""
        try:
            with self.log_path.open(encoding="utf-8", errors="replace") as fh:
                lines = deque((ln.rstrip() for ln in fh if ln.strip()), maxlen=TAIL_LINES)
        except OSError:
            return []
        return [ln for ln in lines if "iplens.mcpcontrol:" not in ln][-TAIL_LINES:]


def _duration(seconds: int) -> str:
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"
