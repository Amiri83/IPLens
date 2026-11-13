"""The shared DadsOps theme and the shared environment defaults.

Theme: every page links ``theme/dadsops-theme.css`` before ``style.css``, and the file is
served and packaged. Environment: ``AWS_PROFILE`` / ``AWS_REGION`` pre-fill a new account,
``DADSOPS_LOG_DIR`` moves the default log directory; saved values always win and nothing
from the environment is stored.
"""

import re
import sqlite3
import tomllib
from fnmatch import fnmatch
from pathlib import Path

import pytest

from iplens import envdefaults
from iplens.config import default_paths
from iplens.settings import Settings
from iplens.web import create_app, log_dir_for

ROOT = Path(__file__).parent.parent
THEME_URL = "/static/theme/dadsops-theme.css"
APP_CSS_URL = "/static/style.css"
THEME_HEADER = "/* DadsOps shared theme v1 — master copy, tools copy this file unchanged */"

# The top menu, in order: (endpoint, label).
MENU = [
    ("overview", "Discovery"),
    ("ips", "IP List"),
    ("visual", "Visual"),
    ("trends_page", "Trends"),
    ("diff_page", "Diff"),
    ("headroom_page", "Headroom"),
    ("cidr_planner", "CIDR Planner"),
    ("scope_page", "Scope"),
    ("rules_list", "Rules"),
    ("suggestions", "Suggestions"),
    ("ownership_page", "Ownership"),
    ("settings_page", "Settings"),
    ("logs", "Logs"),
]


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _urls(app) -> dict[str, str]:
    with app.test_request_context():
        from flask import url_for

        return {ep: url_for(ep) for ep, _ in MENU}


def _settings_rows(app) -> dict[str, str]:
    db = app.extensions["iplens"]["paths"].db_path
    with sqlite3.connect(db) as conn:
        return dict(conn.execute("SELECT key, value FROM settings").fetchall())


def _accounts(app) -> list[tuple]:
    db = app.extensions["iplens"]["paths"].db_path
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT id, region, auth_mode, profile FROM accounts").fetchall()


# -- theme ------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", [ep for ep, _ in MENU] + ["account_new"])
def test_every_page_links_the_theme_before_the_app_stylesheet(app, client, endpoint):
    with app.test_request_context():
        from flask import url_for

        url = url_for(endpoint)
    resp = client.get(url)
    assert resp.status_code == 200, url
    page = resp.data.decode()
    theme = page.find(f'<link rel="stylesheet" href="{THEME_URL}">')
    own = page.find(f'<link rel="stylesheet" href="{APP_CSS_URL}">')
    assert theme != -1 and own != -1, url
    assert theme < own, url


def test_theme_file_is_served(client):
    resp = client.get(THEME_URL)
    assert resp.status_code == 200
    assert resp.data.strip()
    assert resp.data.decode().splitlines()[0] == THEME_HEADER
    assert "text/css" in resp.content_type


def test_theme_file_is_packaged():
    package_data = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"][
        "package-data"
    ]["iplens"]
    assert any(fnmatch("static/theme/dadsops-theme.css", g) for g in package_data)
    shipped = ROOT / "iplens" / "static" / "theme" / "dadsops-theme.css"
    assert shipped.read_text().splitlines()[0] == THEME_HEADER


def test_one_top_menu_with_the_same_links_order_and_highlighting(app, client):
    urls = _urls(app)
    for active_ep, _ in MENU:
        page = client.get(urls[active_ep]).data.decode()
        assert page.count('<header class="shell-header">') == 1
        header = page.split("</header>", 1)[0]
        nav = re.search(r'<nav aria-label="Main">(.*?)</nav>', header, re.S).group(1)
        links = re.findall(
            r'<a href="([^"]+)"( class="active" aria-current="page")?>([^<]+)</a>', nav
        )
        assert [(href, label) for href, _, label in links] == [(urls[ep], lb) for ep, lb in MENU]
        active = [label for _, flag, label in links if flag]
        assert active == [dict(MENU)[active_ep]], active_ep
        assert '<span class="ctx"' in header  # account / region context next to the menu


def test_header_context_shows_the_viewed_account_region(client):
    header = client.get("/").data.decode().split("</header>", 1)[0]
    ctx = re.search(r'<span class="ctx"[^>]*>(.*?)</span>', header, re.S).group(1)
    assert "viewing" in ctx and "us-east-1" in ctx


# -- AWS_PROFILE / AWS_REGION -----------------------------------------------------------


def _radio_checked(page: str) -> list[str]:
    return re.findall(r'name="auth_mode" value="(\w+)" checked', page)


def test_new_account_defaults_follow_aws_profile_and_region(app, client, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "example")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    before = (_accounts(app), _settings_rows(app))

    defaults = envdefaults.new_account()
    assert defaults.account.profile == "example" and defaults.account.region == "eu-west-1"
    assert defaults.account.auth_mode == "profile"
    assert defaults.sources == {"profile": "AWS_PROFILE", "region": "AWS_REGION"}

    page = client.get("/accounts/new").data.decode()
    assert _radio_checked(page) == ["profile"]
    assert '<option value="eu-west-1" selected>' in page
    assert re.search(r'<option value="example" selected>example', page)
    assert "from AWS_PROFILE" in page and "from AWS_REGION" in page
    # Showing the form stores nothing.
    assert (_accounts(app), _settings_rows(app)) == before


def test_new_account_defaults_unchanged_without_env(client):
    defaults = envdefaults.new_account()
    assert defaults.sources == {}
    assert (defaults.account.auth_mode, defaults.account.profile, defaults.account.region) == (
        "env",
        "",
        "us-east-1",
    )
    page = client.get("/accounts/new").data.decode()
    assert _radio_checked(page) == ["env"]
    assert '<option value="us-east-1" selected>' in page
    assert "env-hint" not in page.split("<main", 1)[1]


def test_blank_env_values_count_as_unset(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "  ")
    monkeypatch.setenv("AWS_REGION", "")
    assert envdefaults.new_account().sources == {}


def test_saved_account_wins_over_env(app, client, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "example")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    ((acct_id, region, mode, _profile),) = _accounts(app)
    page = client.get(f"/accounts/{acct_id}/edit").data.decode()
    assert _radio_checked(page) == [mode] == ["env"]
    assert f'<option value="{region}" selected>' in page and region == "us-east-1"
    assert "from AWS_REGION" not in page and "from AWS_PROFILE" not in page
    # The header keeps showing the saved region.
    header = client.get("/").data.decode().split("</header>", 1)[0]
    assert "us-east-1" in header and "eu-west-1" not in header


def test_env_mode_account_says_aws_profile_is_in_use(client, monkeypatch):
    page = client.get("/settings").data.decode()
    assert "(from AWS_PROFILE)" not in page
    monkeypatch.setenv("AWS_PROFILE", "example")
    page = client.get("/settings").data.decode()
    assert "(from AWS_PROFILE)" in page
    assert ">example<" not in page  # the variable is named, its value is not printed


# -- DADSOPS_LOG_DIR ----------------------------------------------------------------------


def test_default_log_dir_follows_dadsops_log_dir(tmp_path, monkeypatch):
    shared = tmp_path / "shared-logs"
    paths = default_paths(tmp_path / "home")
    assert paths.default_log_dir == paths.home / "logs" and not paths.log_dir_from_env
    monkeypatch.setenv("DADSOPS_LOG_DIR", str(shared))
    assert paths.default_log_dir == shared and paths.log_dir_from_env
    monkeypatch.setenv("DADSOPS_LOG_DIR", "  ")
    assert paths.default_log_dir == paths.home / "logs"


def test_saved_log_dir_wins_over_dadsops_log_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DADSOPS_LOG_DIR", str(tmp_path / "shared-logs"))
    paths = default_paths(tmp_path / "home")
    saved = tmp_path / "saved-logs"
    assert log_dir_for(paths, Settings(log_dir=str(saved))) == saved
    assert log_dir_for(paths, Settings()) == tmp_path / "shared-logs"


def test_app_writes_logs_to_dadsops_log_dir(home, tmp_path, monkeypatch):
    shared = tmp_path / "shared-logs"
    monkeypatch.setenv("DADSOPS_LOG_DIR", str(shared))
    app = create_app(home, testing=True)
    assert app.extensions["iplens"]["log_dir"] == shared
    assert (shared / "iplens.log").is_file()
    assert "log_dir" not in _settings_rows(app) or _settings_rows(app)["log_dir"] == ""

    client = app.test_client()
    client.get("/")
    settings = client.get("/settings").data.decode()
    assert f'placeholder="{shared}"' in settings and "DADSOPS_LOG_DIR" in settings
    logs = client.get("/logs").data.decode()
    assert str(shared / "iplens.log") in logs and "(from DADSOPS_LOG_DIR)" in logs


def test_app_log_dir_unchanged_without_dadsops_log_dir(home):
    app = create_app(home, testing=True)
    assert app.extensions["iplens"]["log_dir"] == home.resolve() / "logs"
    client = app.test_client()
    client.get("/")
    assert "DADSOPS_LOG_DIR" not in client.get("/settings").data.decode()
    assert "DADSOPS_LOG_DIR" not in client.get("/logs").data.decode()
