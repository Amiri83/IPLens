"""The ``iplens`` command: server selection, remote-host refusal, banner, shutdown.

No server is started: waitress' ``create_server`` and ``Flask.run`` are replaced by fakes.
Placeholder addresses only (127.0.0.1, 192.0.2.x documentation range)."""

from importlib.metadata import version

import pytest
from flask import Flask

import iplens
from iplens import cli, web
from iplens.cli import main


def test_version_comes_from_package_metadata(capsys):
    assert iplens.__version__ == version("aws-iplens")
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"iplens {iplens.__version__}"


class FakeServer:
    def __init__(self, interrupt: bool = False):
        self.interrupt = interrupt
        self.kwargs: dict = {}
        self.ran = self.closed = False

    def __call__(self, app, **kwargs):  # stands in for waitress.create_server
        self.app, self.kwargs = app, kwargs
        return self

    def run(self):
        self.ran = True
        if self.interrupt:
            raise KeyboardInterrupt

    def close(self):
        self.closed = True


@pytest.fixture
def served(monkeypatch):
    """Fake waitress server, Flask dev server and browser; records what was used."""
    calls: dict = {"server": FakeServer(), "flask_run": [], "browser": [], "shutdown": []}
    monkeypatch.setattr("waitress.create_server", lambda app, **kw: calls["server"](app, **kw))
    monkeypatch.setattr(Flask, "run", lambda self, **kw: calls["flask_run"].append(kw))
    monkeypatch.setattr(cli, "open_browser", calls["browser"].append)
    monkeypatch.setattr(cli, "desktop_session", lambda: True)
    real_shutdown = web.shutdown_app

    def shutdown(app, timeout=10.0):
        calls["shutdown"].append(app)
        real_shutdown(app, timeout)

    monkeypatch.setattr(web, "shutdown_app", shutdown)
    return calls


def test_waitress_serves_by_default(served, home, capsys):
    main(["--home", str(home), "--port", "8099"])
    server = served["server"]
    assert server.ran and server.closed
    assert server.kwargs == {"host": "127.0.0.1", "port": 8099, "threads": 8, "ident": ""}
    assert served["flask_run"] == []
    (app,) = served["shutdown"]
    assert app is server.app
    assert app.extensions["iplens"]["scheduler"]._thread is None  # stopped


def test_debug_uses_the_flask_dev_server(served, home):
    main(["--home", str(home), "--debug", "--port", "8099"])
    assert served["flask_run"] == [{"host": "127.0.0.1", "port": 8099, "debug": True}]
    assert not served["server"].ran
    assert len(served["shutdown"]) == 1


def test_banner_is_one_clean_line(served, home, capsys):
    main(["--home", str(home), "--port", "8099"])
    out, err = capsys.readouterr()
    lines = out.splitlines()
    log_file = home.resolve() / "logs" / "iplens.log"
    assert lines[0] == (
        f"IPLens {iplens.__version__} running at http://127.0.0.1:8099  (Ctrl+C to stop) "
        f"· data: {home.resolve()} · log: {log_file}"
    )
    assert "Serving Flask app" not in out + err and "WARNING" not in err
    assert served["browser"] == ["http://127.0.0.1:8099"]


def test_no_browser_flag(served, home):
    main(["--home", str(home), "--no-browser"])
    assert served["browser"] == []


def test_no_browser_without_a_desktop_session(served, home, monkeypatch):
    monkeypatch.setattr(cli, "desktop_session", lambda: False)
    main(["--home", str(home)])
    assert served["browser"] == []


def test_ctrl_c_shuts_down_cleanly(served, home, capsys):
    served["server"] = FakeServer(interrupt=True)
    main(["--home", str(home)])  # KeyboardInterrupt does not escape
    assert served["server"].closed and len(served["shutdown"]) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "Stopping IPLens…"


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.10", "::", "example.invalid"])  # noqa: S104
def test_non_loopback_host_is_refused(served, home, host, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--home", str(home), "--host", host])
    assert exc.value.code == 2
    assert "--allow-remote" in capsys.readouterr().err
    assert not served["server"].ran and not home.exists()  # nothing was started


def test_allow_remote_binds_and_warns(served, home, capsys):
    main(["--home", str(home), "--host", "192.0.2.10", "--allow-remote", "--port", "8099"])
    assert served["server"].kwargs["host"] == "192.0.2.10"
    out, err = capsys.readouterr()
    assert "running at http://192.0.2.10:8099 " in out
    assert "NO authentication" in err and "192.0.2.10:8099" in err
    assert served["server"].app.extensions["iplens"]["allow_remote"] is True


def test_bind_failure_exits_with_a_message(served, home, monkeypatch):
    def busy(app, **kw):
        raise OSError(98, "Address already in use")

    monkeypatch.setattr("waitress.create_server", busy)
    with pytest.raises(SystemExit) as exc:
        main(["--home", str(home)])
    assert "Address already in use" in str(exc.value.code)
    assert len(served["shutdown"]) == 1


@pytest.mark.parametrize(
    "host, loopback",
    [
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),  # noqa: S104
        ("192.0.2.10", False),
        ("example.invalid", False),
    ],
)
def test_is_loopback(host, loopback):
    assert cli.is_loopback(host) is loopback


@pytest.mark.parametrize(
    "env, ok",
    [({}, False), ({"BROWSER": "true"}, True), ({"DISPLAY": ":0", "BROWSER": "true"}, True)],
)
def test_desktop_session_on_linux(monkeypatch, env, ok):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    for var in ("DISPLAY", "WAYLAND_DISPLAY", "BROWSER"):
        monkeypatch.delenv(var, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert cli.desktop_session() is ok
