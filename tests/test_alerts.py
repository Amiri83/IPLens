"""Alerts: conditions, state-change dedup, message redaction, encrypted settings, delivery
and the post-Refresh run (a failing webhook never fails the Refresh). HTTP is mocked.

Synthetic data only: 192.0.2.0/24 (TEST-NET-1) addresses, placeholder ids, the moto
placeholder account 123456789012 and an example.invalid webhook host.
"""

import http.client
import io
import urllib.error
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

from iplens import alerts, forecast, headroom, jobs
from iplens.crypto import SecretBox
from iplens.db import closing
from iplens.web import create_app

URL = "https://hooks.example.invalid/services/T000/B000/secret-token-a"
VPC = "vpc-a"
SA, SB = "subnet-a", "subnet-b"
ACCOUNT_ID = "123456789012"


class Recorder:
    """A mock webhook sender: records every (url, payload); raises ``error`` if set."""

    def __init__(self, error: Exception | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.error = error

    def __call__(self, url, body):
        self.calls.append((url, body))
        if self.error is not None:
            raise self.error

    @property
    def texts(self) -> list[str]:
        return [body["text"] for _, body in self.calls]


def _row(free=40, usable=59, demand=0, name="app-a", az="us-east-1a", sid=SA):
    sub = headroom.Subnet(sid, VPC, az, "192.0.2.0/26", name, free=free, usable=usable)
    contributors = [headroom.Contributor("asg", "asg-a", demand, "max")] if demand else []
    return headroom.SubnetHeadroom(sub, contributors)


GROWING_SOON = forecast.SubnetForecast(forecast.GROWING, 10, 2.0, 20.0, 12.0)
GROWING_LATE = forecast.SubnetForecast(forecast.GROWING, 10, 0.5, 80.0, 60.0)
STABLE = forecast.SubnetForecast(forecast.STABLE, 10, 0.0)
CFG = alerts.AlertSettings(webhook_url=URL)


# -- conditions -----------------------------------------------------------------------------


def test_no_condition_for_a_healthy_subnet():
    assert alerts.conditions(_row(), STABLE, CFG) == {}


def test_over_condition():
    found = alerts.conditions(_row(free=10, demand=15), STABLE, CFG)
    assert set(found) == {alerts.OVER}
    assert "short by 5 IPs" in found[alerts.OVER]


def test_forecast_condition_uses_the_headroom_days():
    found = alerts.conditions(_row(), GROWING_SOON, CFG)
    assert set(found) == {alerts.FORECAST}
    assert "~12 days" in found[alerts.FORECAST] and "+2.0 IPs/day" in found[alerts.FORECAST]
    assert alerts.conditions(_row(), GROWING_LATE, CFG) == {}  # 60 days > 30


def test_forecast_alert_fires_when_only_the_headroom_is_within_the_horizon():
    # free 4000, demand 3980, +1 IP/day: free = 0 is beyond the horizon, the headroom is ~20 days.
    end = datetime(2026, 1, 31, tzinfo=UTC)
    pts = [(end - timedelta(days=9 - i), 100 + i) for i in range(10)]
    fc = forecast.project(pts, free=4000, demand=3980)
    row = _row(free=4000, usable=4091, demand=3980)
    found = alerts.conditions(row, fc, CFG)
    assert set(found) == {alerts.FORECAST}
    assert "stops fitting in ~20 days" in found[alerts.FORECAST]
    assert "free = 0" not in found[alerts.FORECAST]
    sent = alerts.changes(headroom.Headroom([row]), {SA: fc}, CFG, {})
    assert [(a.subnet_id, a.conditions) for a in sent] == [(SA, (alerts.FORECAST,))]


def test_low_free_condition():
    found = alerts.conditions(_row(free=5), None, CFG)  # 5 / 59 = 8.5%
    assert set(found) == {alerts.LOW_FREE}
    assert "8.5%" in found[alerts.LOW_FREE]


def test_thresholds_can_be_turned_off():
    cfg = alerts.AlertSettings(webhook_url=URL, on_over=False, forecast_days=0, free_pct=0)
    assert alerts.conditions(_row(free=0, demand=20), GROWING_SOON, cfg) == {}


# -- dedup (pure) ---------------------------------------------------------------------------


def test_changes_only_reports_a_different_state():
    h = headroom.Headroom([_row(free=5), _row(sid=SB, name="app-b")])
    first = alerts.changes(h, {}, CFG, {})
    assert [(a.subnet_id, a.conditions) for a in first] == [(SA, (alerts.LOW_FREE,))]
    # The same state again: nothing to send.
    assert alerts.changes(h, {}, CFG, {SA: alerts.LOW_FREE}) == []
    # Cleared: one resolved entry.
    healthy = headroom.Headroom([_row(free=40)])
    resolved = alerts.changes(healthy, {}, CFG, {SA: alerts.LOW_FREE})
    assert len(resolved) == 1 and resolved[0].resolved
    assert resolved[0].previous == (alerts.LOW_FREE,)


# -- message --------------------------------------------------------------------------------

SNAP = {"account_name": "", "account_alias": "alias-a", "account_id": ACCOUNT_ID}


def test_message_uses_subnet_name_and_az_without_ids():
    found = alerts.changes(headroom.Headroom([_row(free=5)]), {}, CFG, {})
    text = alerts.message(
        found, account=alerts.account_text(SNAP, False), region="us-east-1", include_ids=False
    )
    assert "app-a (us-east-1a)" in text
    assert "alias-a" in text
    assert ACCOUNT_ID not in text and SA not in text and VPC not in text


def test_message_with_ids_enabled():
    found = alerts.changes(headroom.Headroom([_row(free=5)]), {}, CFG, {})
    text = alerts.message(
        found, account=alerts.account_text(SNAP, True), region="us-east-1", include_ids=True
    )
    assert f"alias-a ({ACCOUNT_ID})" in text
    assert f"app-a · {SA} (us-east-1a)" in text


def test_message_unnamed_subnet_and_resolved_line():
    a = alerts.SubnetAlert(SB, "", "us-east-1b", (), (), (alerts.OVER, alerts.LOW_FREE))
    text = alerts.message([a], account="account-a", region="", include_ids=False)
    assert "unnamed subnet (us-east-1b): resolved (was: over, low free)" in text
    assert SB not in text


def test_message_is_capped():
    found = [
        alerts.SubnetAlert(f"subnet-{i}", f"app-{i}", "us-east-1a", (alerts.OVER,), ("over",))
        for i in range(30)
    ]
    text = alerts.message(found, account="a", region="", include_ids=False, max_lines=25)
    assert "… and 5 more subnet(s)" in text
    assert alerts.payload(text) == {"text": text}


# -- settings -------------------------------------------------------------------------------


@pytest.fixture
def store(db_path, tmp_path):
    return alerts.AlertStore(db_path, SecretBox.from_path(tmp_path / "secret.key"))


def test_defaults(store):
    cfg = store.load()
    assert not cfg.configured
    assert cfg.on_over and cfg.forecast_days == 30 and cfg.free_pct == 10.0
    assert not cfg.include_ids
    assert cfg.webhook_format == alerts.SLACK


def test_webhook_format_is_stored_and_validated(store):
    store.save(webhook_url=URL, webhook_format="teams")
    assert store.load().webhook_format == alerts.TEAMS
    with pytest.raises(ValueError, match="webhook format"):
        store.save(webhook_format="discord")
    assert store.load().webhook_format == alerts.TEAMS  # nothing stored
    store.save(webhook_format="")
    assert store.load().webhook_format == alerts.SLACK


def test_webhook_url_is_encrypted_at_rest(store, db_path):
    store.save(webhook_url=URL, forecast_days="14", free_pct="5.5", include_ids=True)
    with closing(db_path) as conn:
        raw = conn.execute("SELECT value FROM settings WHERE key='alert_webhook_enc'").fetchone()
        everything = " ".join(r[0] or "" for r in conn.execute("SELECT value FROM settings"))
    assert raw[0] and "secret-token-a" not in everything and "hooks.example" not in everything
    cfg = store.load()
    assert cfg.webhook_url == URL
    assert (cfg.forecast_days, cfg.free_pct, cfg.include_ids) == (14, 5.5, True)
    assert cfg.webhook_display == "https://hooks.example.invalid/…"
    assert "secret-token-a" not in repr(cfg)


def test_empty_url_keeps_and_clear_removes(store, db_path):
    store.save(webhook_url=URL)
    store.save(webhook_url="", forecast_days=7)
    assert store.load().webhook_url == URL
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO alert_state(account_ref, subnet_id, state) VALUES(1, ?, 'over')", (SA,)
        )
    store.save(clear_url=True)
    assert not store.load().configured
    with closing(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM alert_state").fetchone()[0] == 0


@pytest.mark.parametrize(
    "bad",
    ["http://hooks.example.invalid/x", "file:///etc/passwd", "https:///no-host", "https://a b/c"],
)
def test_invalid_url_is_refused_and_not_echoed(store, bad):
    with pytest.raises(ValueError) as exc:
        store.save(webhook_url=bad)
    assert bad not in str(exc.value)
    assert not store.load().configured


def test_invalid_thresholds(store):
    with pytest.raises(ValueError):
        store.save(webhook_url=URL, forecast_days="-1")
    with pytest.raises(ValueError):
        store.save(webhook_url=URL, free_pct="101")


def test_undecryptable_url(store, db_path, tmp_path):
    store.save(webhook_url=URL)
    other = alerts.AlertStore(db_path, SecretBox.from_path(tmp_path / "other.key"))
    cfg = other.load()
    assert not cfg.configured and cfg.undecryptable


# -- delivery (urllib mocked) ---------------------------------------------------------------


class _Resp(io.BytesIO):
    def __init__(self, status):
        super().__init__(b"ok")
        self.status = status


def test_post_json_sends_json(monkeypatch):
    seen = {}

    def fake_open(req, timeout):
        seen.update(url=req.full_url, body=req.data, ctype=req.get_header("Content-type"))
        return _Resp(200)

    monkeypatch.setattr(alerts._OPENER, "open", fake_open)
    alerts.post_json(URL, {"text": "hello"})
    assert seen == {"url": URL, "body": b'{"text": "hello"}', "ctype": "application/json"}


def test_post_json_http_error_hides_the_url(monkeypatch):
    def fake_open(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    monkeypatch.setattr(alerts._OPENER, "open", fake_open)
    with pytest.raises(alerts.WebhookError) as exc:
        alerts.post_json(URL, {"text": "x"})
    assert "HTTP 500" in str(exc.value) and "secret-token-a" not in str(exc.value)


def test_post_json_unreachable(monkeypatch):
    def fake_open(req, timeout):
        raise urllib.error.URLError(ConnectionRefusedError(f"refused {URL}"))

    monkeypatch.setattr(alerts._OPENER, "open", fake_open)
    with pytest.raises(alerts.WebhookError) as exc:
        alerts.post_json(URL, {"text": "x"})
    assert "ConnectionRefusedError" in str(exc.value) and "secret-token-a" not in str(exc.value)


def test_post_json_bad_http_response(monkeypatch):
    def fake_open(req, timeout):
        raise http.client.BadStatusLine("garbage")

    monkeypatch.setattr(alerts._OPENER, "open", fake_open)
    with pytest.raises(alerts.WebhookError, match="BadStatusLine"):
        alerts.post_json(URL, {"text": "x"})


def test_post_json_never_sends_to_a_non_https_url(monkeypatch):
    monkeypatch.setattr(alerts._OPENER, "open", lambda *a, **k: pytest.fail("no request"))
    with pytest.raises(alerts.WebhookError):
        alerts.post_json("http://hooks.example.invalid/x", {"text": "x"})


def test_send_test():
    rec = Recorder()
    alerts.send_test(CFG, rec)
    assert rec.calls == [(URL, {"text": alerts.TEST_TEXT})]
    with pytest.raises(alerts.WebhookError):
        alerts.send_test(alerts.AlertSettings(), rec)


def _card_lines(body):
    """The TextBlock texts of a Teams Workflows Adaptive Card message (checking its shape)."""
    assert set(body) == {"type", "attachments"} and body["type"] == "message"
    [att] = body["attachments"]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    assert all(b["type"] == "TextBlock" and b["wrap"] is True for b in card["body"])
    return [b["text"] for b in card["body"]]


def test_payload_formats():
    text = "IPLens alert · a\n1 subnet(s) alerting, 0 resolved\n• app-a (us-east-1a): over"
    assert alerts.payload(text) == {"text": text}
    assert alerts.payload(text, alerts.SLACK) == {"text": text}
    teams = alerts.payload(text, alerts.TEAMS)
    assert _card_lines(teams) == text.split("\n")
    assert "text" not in teams


def test_send_test_slack_and_teams_targets():
    slack, teams = Recorder(), Recorder()
    alerts.send_test(alerts.AlertSettings(webhook_url=URL, webhook_format=alerts.SLACK), slack)
    alerts.send_test(alerts.AlertSettings(webhook_url=URL, webhook_format=alerts.TEAMS), teams)
    assert slack.calls == [(URL, {"text": alerts.TEST_TEXT})]
    [(url, body)] = teams.calls
    assert url == URL and _card_lines(body) == [alerts.TEST_TEXT]


# -- evaluate against the database ----------------------------------------------------------


def _snapshot(db_path, snapshot_builder, ips, used_a, when=None):
    """Subnet A (/26, 59 usable) holds ``used_a`` IPs, B a steady 3."""
    b = snapshot_builder(db_path, taken_at=when or datetime.now(UTC))
    b.vpc(VPC, "192.0.2.0/24")
    b.subnet(SA, VPC, "192.0.2.0/26", az="us-east-1a", name="app-a")
    b.subnet(SB, VPC, "192.0.2.64/26", az="us-east-1b", name="app-b")
    b.eni("eni-a", SA, ips("192.0.2.0", 4, used_a), owner_ref="i-0abc1234")
    b.eni("eni-b", SB, ips("192.0.2.64", 4, 3), owner_ref="i-0abc5678")
    return b


def _evaluate(db_path, rec, cfg=CFG):
    with closing(db_path) as conn:
        return alerts.evaluate(conn, 1, cfg, sender=rec)


def test_evaluate_sends_once_per_state_change(db_path, snapshot_builder, ips):
    rec = Recorder()
    _snapshot(db_path, snapshot_builder, ips, 55)  # 4 free: 6.8% < 10%
    assert [a.subnet_id for a in _evaluate(db_path, rec)] == [SA]
    assert len(rec.calls) == 1
    assert "app-a (us-east-1a): free 6.8% (< 10%)" in rec.texts[0]
    assert ACCOUNT_ID not in rec.texts[0]
    # Repeated evaluations (and a new snapshot in the same state) send nothing.
    assert _evaluate(db_path, rec) == []
    _snapshot(db_path, snapshot_builder, ips, 56)
    assert _evaluate(db_path, rec) == []
    assert len(rec.calls) == 1
    # Back to healthy: one resolved message, then quiet again.
    _snapshot(db_path, snapshot_builder, ips, 10)
    assert [a.resolved for a in _evaluate(db_path, rec)] == [True]
    assert "resolved (was: low free)" in rec.texts[1]
    assert _evaluate(db_path, rec) == []
    assert len(rec.calls) == 2


def test_evaluate_teams_target_receives_an_adaptive_card(db_path, snapshot_builder, ips):
    rec = Recorder()
    _snapshot(db_path, snapshot_builder, ips, 55)
    cfg = alerts.AlertSettings(webhook_url=URL, webhook_format=alerts.TEAMS)
    assert [a.subnet_id for a in _evaluate(db_path, rec, cfg)] == [SA]
    [(url, body)] = rec.calls
    lines = _card_lines(body)
    assert url == URL and lines[0].startswith("IPLens alert")
    assert "• app-a (us-east-1a): free 6.8% (< 10%): 4 of 59 usable IPs" in lines


def test_evaluate_forecast_condition_from_history(db_path, snapshot_builder, ips):
    now = datetime.now(UTC)
    for i, n in enumerate([20, 22, 24, 26, 28, 30]):  # +2/day, 29 free at the end
        _snapshot(db_path, snapshot_builder, ips, n, when=now - timedelta(days=5 - i, minutes=1))
    rec = Recorder()
    cfg = alerts.AlertSettings(webhook_url=URL, free_pct=0)  # forecast only
    found = _evaluate(db_path, rec, cfg)
    assert [(a.subnet_id, a.conditions) for a in found] == [(SA, (alerts.FORECAST,))]
    assert "free = 0 in ~15 days" in rec.texts[0]  # 29 / 2 = 14.5


def test_failed_send_keeps_the_state_and_is_retried(db_path, snapshot_builder, ips):
    _snapshot(db_path, snapshot_builder, ips, 55)
    with pytest.raises(alerts.WebhookError):
        _evaluate(db_path, Recorder(error=OSError("network down")))
    with closing(db_path) as conn:
        assert alerts.load_state(conn, 1) == {}
    rec = Recorder()
    assert len(_evaluate(db_path, rec)) == 1  # retried
    assert len(rec.calls) == 1


def test_evaluate_without_webhook_or_snapshot(db_path, snapshot_builder, ips):
    rec = Recorder()
    assert _evaluate(db_path, rec) == []  # no snapshot yet
    _snapshot(db_path, snapshot_builder, ips, 55)
    assert _evaluate(db_path, rec, alerts.AlertSettings()) == []  # no webhook
    assert rec.calls == []


def test_subnet_gone_is_dropped_silently(db_path, snapshot_builder, ips):
    _snapshot(db_path, snapshot_builder, ips, 55)
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO alert_state(account_ref, subnet_id, state) "
            "VALUES(1, 'subnet-gone', 'over')"
        )
    rec = Recorder()
    _evaluate(db_path, rec)
    assert "subnet-gone" not in rec.texts[0] and "resolved (was" not in rec.texts[0]
    with closing(db_path) as conn:
        assert set(alerts.load_state(conn, 1)) == {SA}


# -- Settings page and the post-Refresh run -------------------------------------------------


def _post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


@pytest.fixture
def app(home):
    app = create_app(home, testing=True)
    app.test_client().get("/")
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def test_settings_save_test_button_and_url_never_shown(client, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(alerts, "post_json", rec)
    page = client.get("/settings").data.decode()
    assert 'id="alerts"' in page and "Send test" in page
    resp = _post(
        client,
        "/settings/alerts",
        {"webhook_url": URL, "on_over": "1", "forecast_days": "21", "free_pct": "7.5"},
        follow_redirects=True,
    )
    page = resp.data.decode()
    assert "Alert settings saved" in page
    assert "https://hooks.example.invalid/…" in page and "secret-token-a" not in page
    assert 'value="21"' in page and 'value="7.5"' in page
    page = _post(client, "/settings/alerts/test", follow_redirects=True).data.decode()
    assert "Test alert sent" in page
    assert rec.calls == [(URL, {"text": alerts.TEST_TEXT})]


def test_settings_webhook_format_select(client, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(alerts, "post_json", rec)
    page = client.get("/settings").data.decode()
    assert 'name="webhook_format"' in page and '<option value="slack" selected>' in page
    page = _post(
        client,
        "/settings/alerts",
        {"webhook_url": URL, "webhook_format": "teams"},
        follow_redirects=True,
    ).data.decode()
    assert '<option value="teams" selected>' in page
    _post(client, "/settings/alerts/test")
    [(_, body)] = rec.calls
    assert _card_lines(body) == [alerts.TEST_TEXT]
    page = _post(
        client, "/settings/alerts", {"webhook_format": "xml"}, follow_redirects=True
    ).data.decode()
    assert "Alerts not saved" in page and "webhook format" in page


def test_settings_rejects_a_bad_url(client):
    page = _post(
        client, "/settings/alerts", {"webhook_url": "http://x.invalid/a"}, follow_redirects=True
    ).data.decode()
    assert "Alerts not saved" in page and "https://" in page


def test_send_test_failure_is_flashed(client, monkeypatch):
    monkeypatch.setattr(alerts, "post_json", Recorder(error=alerts.WebhookError("HTTP 404")))
    _post(client, "/settings/alerts", {"webhook_url": URL})
    page = _post(client, "/settings/alerts/test", follow_redirects=True).data.decode()
    assert "Test alert not sent: HTTP 404" in page


def _moto_subnet_with_enis(n):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="192.0.2.0/28",  # 11 usable
        AvailabilityZone="us-east-1a",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": "app-a"}]}],
    )["Subnet"]["SubnetId"]
    for _ in range(n):
        ec2.create_network_interface(SubnetId=sub)


def _refresh(app, client):
    assert _post(client, "/refresh").status_code == 302
    return app.extensions["iplens"]["jobs"].current(1)


@mock_aws
def test_repeated_refreshes_send_one_alert(app, client, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(alerts, "post_json", rec)
    _post(client, "/settings/alerts", {"webhook_url": URL, "on_over": "1", "free_pct": "50"})
    _moto_subnet_with_enis(8)  # 3 of 11 free: 27% < 50%
    for _ in range(3):
        job = _refresh(app, client)
        assert job["state"] == jobs.DONE
    assert len(rec.calls) == 1
    assert "app-a (us-east-1a)" in rec.texts[0]
    assert ACCOUNT_ID not in rec.texts[0]
    with closing(app.extensions["iplens"]["paths"].db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE status='ok'").fetchone()[0] == 3


@mock_aws
def test_webhook_failure_does_not_fail_the_refresh(app, client, monkeypatch, caplog):
    def broken(url, body):
        raise ConnectionError(f"cannot reach {url}")

    monkeypatch.setattr(alerts, "post_json", broken)
    _post(client, "/settings/alerts", {"webhook_url": URL, "free_pct": "50"})
    _moto_subnet_with_enis(8)
    job = _refresh(app, client)
    assert job["state"] == jobs.DONE
    texts = [m["text"] for m in job["messages"]]
    assert any(t.startswith("Refreshed ") for t in texts)
    assert any("Alert not sent" in t for t in texts)
    assert "secret-token-a" not in str(job) and "secret-token-a" not in caplog.text
    with closing(app.extensions["iplens"]["paths"].db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE status='ok'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM alert_state").fetchone()[0] == 0


@mock_aws
def test_refresh_without_webhook_sends_nothing(app, client, monkeypatch):
    monkeypatch.setattr(alerts, "post_json", lambda *a: pytest.fail("no webhook is set"))
    _moto_subnet_with_enis(8)
    assert _refresh(app, client)["state"] == jobs.DONE
