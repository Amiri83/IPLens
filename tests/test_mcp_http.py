"""``iplens mcp --http`` and Settings → MCP server: the HTTP transport's guard (bearer
token, Origin, Host), the server as a child process of IPLens (start / stop / restart,
port in use, crash retries, shutdown), the encrypted token and the Settings page.

All data is synthetic (see tests/test_mcp.py): documentation address ranges, the AWS
documentation account id and made-up resource ids / names.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from iplens import mcptools
from iplens.crypto import SecretBox
from iplens.db import closing
from iplens.mcpconfig import (
    DEFAULT_PORT,
    MCP_PATH,
    TOKEN_ENV,
    McpSettings,
    McpStore,
    claude_code_command,
    parse_host,
    parse_port,
    stdio_configs,
    vscode_config,
)
from iplens.mcpcontrol import ERROR, RUNNING, STOPPED, McpController, McpStartError, port_free
from iplens.mcphttp import Guard
from iplens.web import create_app, shutdown_app
from tests.test_mcp import LEAKS, db, mcp_home  # noqa: F401 - fixtures

TOKEN = "test-token-0123456789abcdef"
WILDCARD = "0.0.0.0"  # noqa: S104 - a setting value, nothing is bound to it
needs_mcp = pytest.mark.skipif(
    importlib.util.find_spec("mcp") is None, reason="needs the mcp extra"
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, timeout: float = 30.0, step: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover
        return True
    # A zombie (exited, not reaped yet) is gone as far as serving goes.
    stat = Path(f"/proc/{pid}/stat")
    return not (stat.exists() and stat.read_text().split(") ")[-1].startswith("Z"))


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "iplens-test", "version": "0"},
    },
}


def post(port: int, headers: dict[str, str] | None = None, body: dict | None = None):
    """POST an MCP message: (status, body text)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(
            "POST",
            MCP_PATH,
            body=json.dumps(body or INIT),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **(headers or {}),
            },
        )
        resp = conn.getresponse()
        return resp.status, resp.read().decode(), dict(resp.getheaders())
    finally:
        conn.close()


# -- the guard ------------------------------------------------------------------------------


def test_guard_checks():
    g = Guard(None, TOKEN, "127.0.0.1", 8765)
    assert g.host_ok("127.0.0.1:8765") and g.host_ok("localhost:8765") and g.host_ok("[::1]:8765")
    assert not g.host_ok("127.0.0.1:8766")  # another port
    assert not g.host_ok("127.0.0.1")  # no port
    assert not g.host_ok("attacker.example:8765")  # DNS rebinding
    assert not g.host_ok("192.0.2.10:8765")  # an IP literal only with --allow-remote
    assert Guard(None, TOKEN, WILDCARD, 8765, allow_remote=True).host_ok("192.0.2.10:8765")
    assert g.origin_ok(None)  # CLI / editor clients send no Origin
    assert g.origin_ok("http://127.0.0.1:8765") and g.origin_ok("http://localhost:8765")
    for bad in (
        "https://evil.example",
        "http://127.0.0.1:9999",
        "null",
        "http://evil.example:8765",
    ):
        assert not g.origin_ok(bad), bad
    assert g.token_ok(f"Bearer {TOKEN}") and g.token_ok(f"bearer {TOKEN}")
    for bad in (None, "", TOKEN, f"Basic {TOKEN}", "Bearer ", f"Bearer {TOKEN}x", "Bearer x"):
        assert not g.token_ok(bad), bad


# -- the HTTP server (iplens mcp --http) ----------------------------------------------------


@pytest.fixture
def http_server(mcp_home):  # noqa: F811
    """`python -m iplens mcp --http --redact` on a free port, the token in its environment."""
    port = free_port()
    proc = subprocess.Popen(  # noqa: S603 - our own interpreter and module
        [sys.executable, "-m", "iplens", "mcp", "--http", "--home", str(mcp_home)]
        + ["--port", str(port), "--redact"],
        env={**os.environ, TOKEN_ENV: TOKEN},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        assert wait_for(lambda: not port_free("127.0.0.1", port) or proc.poll() is not None)
        assert proc.poll() is None, proc.stdout.read().decode() if proc.stdout else ""
        yield port, proc
    finally:
        proc.terminate()
        proc.wait(10)


@needs_mcp
def test_http_requires_the_bearer_token(http_server):
    port, _ = http_server
    status, text, headers = post(port)
    assert status == 401 and "bearer token required" in text
    assert headers.get("www-authenticate", "").startswith("Bearer")
    assert post(port, {"Authorization": "Bearer wrong-token-000000000"})[0] == 401
    assert post(port, {"Authorization": TOKEN})[0] == 401  # no scheme
    status, text, _ = post(port, {"Authorization": f"Bearer {TOKEN}"})
    assert status == 200, text
    assert json.loads(text)["result"]["serverInfo"]["name"] == "iplens"


@needs_mcp
def test_http_rejects_a_foreign_origin(http_server):
    port, _ = http_server
    auth = {"Authorization": f"Bearer {TOKEN}"}
    for origin in ("https://evil.example", f"http://evil.example:{port}", "null"):
        status, text, _ = post(port, {**auth, "Origin": origin})
        assert status == 403 and "Origin" in text, origin
    # Its own origin and no Origin at all (non-browser clients) are fine.
    assert post(port, {**auth, "Origin": f"http://127.0.0.1:{port}"})[0] == 200
    assert post(port, auth)[0] == 200
    # The Origin check comes first: a foreign page never learns whether a token is right.
    assert post(port, {"Origin": "https://evil.example"})[0] == 403


@needs_mcp
def test_http_rejects_a_foreign_host(http_server):
    port, _ = http_server
    status, _, _ = post(port, {"Authorization": f"Bearer {TOKEN}", "Host": f"evil.example:{port}"})
    assert status == 421


@needs_mcp
def test_http_end_to_end_with_an_mcp_client(http_server):
    """The SDK's Streamable HTTP client: same tools, same redaction as stdio."""
    import anyio
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    port, _ = http_server

    async def session():
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {TOKEN}"})
        async with (
            http,
            streamable_http_client(f"http://127.0.0.1:{port}{MCP_PATH}", http_client=http) as (
                read,
                write,
            ),
            ClientSession(read, write) as client,
        ):
            await client.initialize()
            listed = await client.list_tools()
            result = await client.call_tool("find_subnet", {"need_ips": 20})
            return [t.name for t in listed.tools], result

    names, result = anyio.run(session)
    assert sorted(names) == sorted(mcptools.TOOLS)
    assert not result.is_error
    out = json.loads(result.content[0].text)
    assert [f["id"] for f in out["items"]] == ["test-subnet-b", "test-subnet-a"]
    assert out["snapshot"]["account_id"] == "<account-id>"
    assert not LEAKS.search(json.dumps(out))


def _iplens_mcp(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "iplens", "mcp", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, **(env or {})},
    )


@needs_mcp
def test_cli_http_errors(mcp_home):  # noqa: F811
    home = str(mcp_home)
    proc = _iplens_mcp("--http", "--home", home, "--host", WILDCARD, env={TOKEN_ENV: TOKEN})
    assert proc.returncode == 2 and "--allow-remote" in proc.stderr
    proc = _iplens_mcp("--home", home, "--port", "8765")
    assert proc.returncode == 2 and "need --http" in proc.stderr
    proc = _iplens_mcp("--http", "--home", home, "--port", "80", env={TOKEN_ENV: TOKEN})
    assert proc.returncode == 2 and "1024-65535" in proc.stderr
    # No token in the environment and none stored.
    env = {k: v for k, v in os.environ.items() if k != TOKEN_ENV}
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "iplens", "mcp", "--http", "--home", home],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert proc.returncode == 2 and "no MCP token" in proc.stderr
    assert not (mcp_home / "secret.key").exists()  # read-only: no key file made
    proc = _iplens_mcp("--http", "--home", home, env={TOKEN_ENV: "short"})
    assert proc.returncode == 2 and "at least 16" in proc.stderr


@needs_mcp
def test_cli_http_port_in_use(mcp_home):  # noqa: F811
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        proc = _iplens_mcp(
            "--http", "--home", str(mcp_home), "--port", str(port), env={TOKEN_ENV: TOKEN}
        )
    assert proc.returncode == 2 and f"cannot listen on 127.0.0.1:{port}" in proc.stderr


@needs_mcp
def test_cli_http_uses_the_stored_token(mcp_home):  # noqa: F811
    store = McpStore(mcp_home / "iplens.db", SecretBox.from_path(mcp_home / "secret.key"))
    token = store.regenerate_token()
    port = free_port()
    env = {k: v for k, v in os.environ.items() if k != TOKEN_ENV}
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "iplens", "mcp", "--http", "--home", str(mcp_home)]
        + ["--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_for(lambda: not port_free("127.0.0.1", port))
        assert post(port, {"Authorization": f"Bearer {token}"})[0] == 200
        assert post(port, {"Authorization": f"Bearer {TOKEN}"})[0] == 401
    finally:
        proc.terminate()
        proc.wait(10)


_NO_AWS_HTTP = """
import json, sys
from pathlib import Path
from iplens.mcptools import AWS_SDK_MODULES, Tools, block_aws_sdk
block_aws_sdk()
import iplens.cli, iplens.mcpconfig, iplens.mcphttp  # noqa: F401
from iplens.mcpserver import build_server
iplens.mcphttp.app(build_server(Tools(Path(sys.argv[1]))), "x" * 20, "127.0.0.1", 8765, False)
print(json.dumps(sorted(m for m in sys.modules if m.split(".")[0] in AWS_SDK_MODULES)))
"""


@needs_mcp
def test_http_code_path_never_imports_the_aws_sdk(db):  # noqa: F811
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _NO_AWS_HTTP, str(db)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []


# -- settings and token ---------------------------------------------------------------------


@pytest.fixture
def store(mcp_home) -> McpStore:  # noqa: F811
    return McpStore(mcp_home / "iplens.db", SecretBox.from_path(mcp_home / "secret.key"))


def test_redact_is_on_by_default(store, mcp_home):  # noqa: F811
    s = store.load()
    assert s == McpSettings()
    assert (s.redact, s.enabled, s.host, s.port) == (True, False, "127.0.0.1", DEFAULT_PORT)
    assert "--redact" in s.server_args(mcp_home)
    off = store.save(
        enabled=False, host="", port=8765, redact=False, account="", allow_remote=False
    )
    assert "--redact" not in off.server_args(mcp_home)
    assert store.load().redact is False


def test_settings_validation(store):
    with pytest.raises(ValueError, match="non-loopback"):
        store.save(
            enabled=True, host=WILDCARD, port=8765, redact=True, account="", allow_remote=False
        )
    with pytest.raises(ValueError, match="1024-65535"):
        store.save(enabled=True, host="", port=80, redact=True, account="", allow_remote=False)
    with pytest.raises(ValueError, match="whole number"):
        parse_port("http")
    with pytest.raises(ValueError, match="not an IP address"):
        parse_host("bad host!")
    assert store.load() == McpSettings()  # nothing stored
    remote = store.save(
        enabled=True, host=WILDCARD, port=9000, redact=True, account="1", allow_remote=True
    )
    assert remote.remote and store.load() == remote
    assert remote.server_args(Path("/h"))[-3:] == ["--account", "1", "--allow-remote"]
    assert parse_host("[::1]") == "::1"


def test_token_is_stored_encrypted(store, mcp_home):  # noqa: F811
    assert store.token() == "" and not store.has_token()
    token, generated = store.ensure_token()
    assert generated and len(token) >= 40
    assert store.ensure_token() == (token, False)
    with closing(mcp_home / "iplens.db") as conn:
        raw = conn.execute("SELECT value FROM settings WHERE key='mcp_token_enc'").fetchone()[0]
    assert token not in raw and store.box.decrypt(raw) == token
    assert store.regenerate_token() != token
    # A key that cannot decrypt it: treated as no token (a new one is generated).
    other = McpStore(store.db_path, SecretBox.from_path(mcp_home / "other.key"))
    assert other.token() == ""
    assert other.ensure_token()[1] is True


def test_client_configs():
    url = "http://127.0.0.1:8765/mcp"
    doc = json.loads(vscode_config(url))
    server = doc["servers"]["iplens"]
    assert server["type"] == "http" and server["url"] == url
    assert server["headers"]["Authorization"] == "Bearer ${input:iplens-mcp-token}"
    assert doc["inputs"][0]["id"] == "iplens-mcp-token" and doc["inputs"][0]["password"] is True
    cmd = claude_code_command(url)
    assert cmd.startswith("claude mcp add --transport http iplens http://127.0.0.1:8765/mcp")
    assert f'"Authorization: Bearer ${TOKEN_ENV}"' in cmd
    stdio = stdio_configs(McpSettings(account="2"))
    assert json.loads(stdio["vscode"])["servers"]["iplens"]["args"] == [
        "mcp",
        "--redact",
        "--account",
        "2",
    ]
    assert stdio["claude"] == "claude mcp add iplens -- iplens mcp --redact --account 2"


# -- the child process ----------------------------------------------------------------------


@pytest.fixture
def controller(mcp_home, tmp_path):  # noqa: F811
    ctl = McpController(mcp_home, lambda: tmp_path / "logs", retry_delays=(0.05,))
    yield ctl
    ctl.stop()


def _settings(**kw) -> McpSettings:
    return McpSettings(**{"port": free_port(), **kw})


@needs_mcp
def test_lifecycle_start_stop_restart(controller):
    s = _settings()
    assert controller.status()["state"] == STOPPED
    controller.start(s, TOKEN)
    assert controller.wait_ready() == RUNNING
    st = controller.status()
    assert st["pid"] and st["url"] == f"http://127.0.0.1:{s.port}/mcp"
    assert st["uptime"] is not None and st["last_error"] == ""
    assert post(s.port, {"Authorization": f"Bearer {TOKEN}"})[0] == 200
    with pytest.raises(McpStartError, match="already running"):
        controller.start(s, TOKEN)
    # The token never shows on the command line (ps), only in the environment.
    cmdline = Path(f"/proc/{st['pid']}/cmdline")
    if cmdline.exists():
        argv = cmdline.read_bytes().split(b"\0")
        assert TOKEN.encode() not in b" ".join(argv)
        assert b"--http" in argv and b"--redact" in argv
    first = st["pid"]
    controller.restart(s, TOKEN)
    assert controller.wait_ready() == RUNNING
    assert controller.status()["pid"] != first and not pid_alive(first)
    second = controller.status()["pid"]
    assert controller.stop() is True
    assert controller.status()["state"] == STOPPED and controller.status()["pid"] is None
    assert not pid_alive(second) and port_free("127.0.0.1", s.port)
    assert controller.stop() is False
    log_text = controller.log_path.read_text()
    assert "starting the MCP server" in log_text and "iplens mcp listening on" in log_text
    assert TOKEN not in log_text


def test_port_in_use(controller):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        with pytest.raises(McpStartError, match="already in use"):
            controller.start(McpSettings(port=port), TOKEN)
    st = controller.status()
    assert st["state"] == ERROR and f"port {port}" in st["last_error"] and st["pid"] is None


@needs_mcp
def test_crash_is_shown_and_retried_at_most_three_times(controller):
    controller.start(_settings(account="nope"), TOKEN)  # the child exits: unknown account
    assert wait_for(lambda: "gave up" in controller.status()["last_error"], timeout=60)
    st = controller.status()
    assert st["state"] == ERROR and st["retries"] == 3
    assert "exited with code 2" in st["last_error"] and "no account 'nope'" in st["last_error"]
    time.sleep(0.5)  # no restart loop
    assert controller.log_path.read_text().count("starting the MCP server") == 4  # 1 + 3


# -- IPLens: settings page, routes, shutdown ------------------------------------------------


def _csrf(client) -> str:
    with client.session_transaction() as s:
        return s["csrf"]


def _post(client, url, data=None, **kw):
    return client.post(url, data={**(data or {}), "csrf_token": _csrf(client)}, **kw)


@pytest.fixture
def app(mcp_home):  # noqa: F811
    app = create_app(mcp_home, testing=True)
    app.extensions["iplens"]["mcp"].retry_delays = (0.05,)
    yield app
    shutdown_app(app)


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _form(port: int, **kw) -> dict[str, str]:
    return {"host": "127.0.0.1", "port": str(port), "redact": "1", "account": "", **kw}


def test_settings_page_mcp_section(client):
    page = client.get("/settings").data.decode()
    assert 'id="mcp"' in page and "MCP server" in page
    assert 'name="redact" value="1" checked' in page  # redact on by default
    assert "type&#34;: &#34;http" in page or '"type": "http"' in page  # VS Code config
    assert "claude mcp add --transport http iplens" in page
    assert "claude mcp add iplens -- iplens mcp" in page  # stdio alternative
    assert 'id="mcp-badge"' not in page  # stopped and not enabled: no header badge
    assert "Remote access is enabled" not in page


def test_settings_save_validates(client, app):
    resp = _post(client, "/settings/mcp", _form(80), follow_redirects=True)
    assert "MCP settings not saved" in resp.data.decode()
    resp = _post(client, "/settings/mcp", _form(9000, host=WILDCARD), follow_redirects=True)
    assert "non-loopback" in resp.data.decode()
    resp = _post(
        client,
        "/settings/mcp",
        _form(9000, host=WILDCARD, allow_remote="1", enabled="1"),
        follow_redirects=True,
    )
    page = resp.data.decode()
    assert "MCP settings saved" in page and "Remote access is enabled" in page
    assert 'id="mcp-badge"' in page  # enabled: the badge shows (stopped)
    saved = app.extensions["iplens"]["mcp_store"].load()
    assert (saved.host, saved.port, saved.enabled, saved.allow_remote) == (
        WILDCARD,
        9000,
        True,
        True,
    )


def test_token_is_shown_once(client, app):
    resp = _post(client, "/settings/mcp/token", follow_redirects=True)
    page = resp.data.decode()
    token = app.extensions["iplens"]["mcp_store"].token()
    assert token and token in page and "shown only once" in page
    again = client.get("/settings").data.decode()
    assert token not in again and "A token is set" in again
    with client.session_transaction() as s:
        assert token not in json.dumps(dict(s))  # never in the session cookie


@needs_mcp
def test_gui_start_stop_and_status(client, app):
    port = free_port()
    _post(client, "/settings/mcp", _form(port))
    resp = _post(client, "/mcp/start", follow_redirects=True)
    page = resp.data.decode()
    assert "MCP server starting" in page
    token = app.extensions["iplens"]["mcp_store"].token()
    assert token and token in page  # generated on the first start: shown once
    ctl = app.extensions["iplens"]["mcp"]
    assert ctl.wait_ready() == RUNNING
    status = client.get("/mcp/status").get_json()
    assert status["state"] == RUNNING and status["pid"] and status["url"].endswith(f":{port}/mcp")
    assert post(port, {"Authorization": f"Bearer {token}"})[0] == 200
    assert 'id="mcp-badge"' in client.get("/").data.decode()
    # The Logs page shows the server's own log.
    logs = client.get("/logs?source=mcp").data.decode()
    assert "starting the MCP server" in logs and "mcp-server.log" in logs
    assert "starting the MCP server" not in client.get("/logs").data.decode()
    resp = _post(client, "/mcp/stop", follow_redirects=True)
    assert "MCP server stopped" in resp.data.decode()
    assert client.get("/mcp/status").get_json()["state"] == STOPPED


@needs_mcp
def test_saving_settings_restarts_a_running_server(client, app):
    port = free_port()
    _post(client, "/settings/mcp", _form(port))
    _post(client, "/mcp/start")
    ctl = app.extensions["iplens"]["mcp"]
    assert ctl.wait_ready() == RUNNING
    old_pid = ctl.status()["pid"]
    new_port = free_port()
    resp = _post(client, "/settings/mcp", _form(new_port), follow_redirects=True)
    assert "MCP server restarting" in resp.data.decode()
    assert ctl.wait_ready() == RUNNING
    st = ctl.status()
    assert st["pid"] != old_pid and st["url"].endswith(f":{new_port}/mcp")
    assert not pid_alive(old_pid) and port_free("127.0.0.1", port)
    token = app.extensions["iplens"]["mcp_store"].token()
    assert post(new_port, {"Authorization": f"Bearer {token}"})[0] == 200
    # A new token restarts it too: the old token stops working.
    _post(client, "/settings/mcp/token")
    assert ctl.wait_ready() == RUNNING
    assert post(new_port, {"Authorization": f"Bearer {token}"})[0] == 401


def test_saving_settings_does_not_start_a_stopped_server(client, app):
    _post(client, "/settings/mcp", _form(free_port(), enabled="1"))
    assert app.extensions["iplens"]["mcp"].status()["state"] == STOPPED


def test_gui_start_port_in_use(client, app):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        _post(client, "/settings/mcp", _form(port))
        resp = _post(client, "/mcp/start", follow_redirects=True)
    page = resp.data.decode()
    if importlib.util.find_spec("mcp") is None:
        assert "aws-iplens[mcp]" in page
        return
    assert "MCP server not started" in page and "already in use" in page
    status = client.get("/mcp/status").get_json()
    assert status["state"] == ERROR and "already in use" in status["last_error"]


@needs_mcp
def test_iplens_shutdown_stops_the_child(mcp_home):  # noqa: F811
    port = free_port()
    app = create_app(mcp_home, testing=True)
    app.extensions["iplens"]["mcp_store"].save(
        enabled=True, host="", port=port, redact=True, account="", allow_remote=False
    )
    shutdown_app(app)
    # Autostart (enabled) with IPLens, then IPLens shuts down.
    app = create_app(mcp_home, testing=True, mcp_autostart=True)
    ctl = app.extensions["iplens"]["mcp"]
    assert ctl.wait_ready() == RUNNING
    pid = ctl.status()["pid"]
    shutdown_app(app)
    assert not pid_alive(pid) and port_free("127.0.0.1", port)
    assert ctl.status()["state"] == STOPPED


_PARENT = """
import sys, time
from pathlib import Path
from iplens.mcpconfig import McpSettings
from iplens.mcpcontrol import McpController
ctl = McpController(Path(sys.argv[1]), lambda: Path(sys.argv[2]))
ctl.start(McpSettings(port=int(sys.argv[3])), "t" * 24)
assert ctl.wait_ready() == "running", ctl.status()
print(ctl.status()["pid"], flush=True)
time.sleep(600)
"""


@needs_mcp
@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_child_stops_when_iplens_is_killed(mcp_home, tmp_path):  # noqa: F811
    """Even a SIGKILLed IPLens leaves no MCP server behind (the child watches its parent)."""
    port = free_port()
    parent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _PARENT, str(mcp_home), str(tmp_path / "logs"), str(port)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert parent.stdout is not None
        child = int(parent.stdout.readline().strip())
        assert pid_alive(child)
    finally:
        parent.send_signal(signal.SIGKILL)
        parent.wait(10)
    assert wait_for(lambda: not pid_alive(child), timeout=15)
    assert wait_for(lambda: port_free("127.0.0.1", port), timeout=5)
