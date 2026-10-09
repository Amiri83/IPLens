"""Snapshot retention: window + daily downsample. Synthetic data only."""

from datetime import UTC, datetime, timedelta

import pytest

from iplens import retention
from iplens.db import closing
from iplens.settings import SettingsStore

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def _snap(db_path, snapshot_builder, days=0.0, hours=0.0, status="ok", account_ref=None):
    taken = NOW - timedelta(days=days, hours=hours)
    return snapshot_builder(db_path, taken_at=taken, status=status, account_ref=account_ref).id


def _ids(db_path):
    with closing(db_path) as conn:
        return {r["id"] for r in conn.execute("SELECT id FROM snapshots")}


def test_window_and_daily_downsample(db_path, snapshot_builder):
    expired = _snap(db_path, snapshot_builder, days=120)
    # Three snapshots on one day 30 days ago: only the newest is kept.
    day_old = [_snap(db_path, snapshot_builder, days=30, hours=h) for h in (6, 4, 2)]
    # Another day: the newest is a failed run, so the older successful one is kept.
    ok_older = _snap(db_path, snapshot_builder, days=20, hours=5)
    failed_newer = _snap(db_path, snapshot_builder, days=20, hours=1, status="failed")
    # A day with failures only keeps its newest one.
    fail_a = _snap(db_path, snapshot_builder, days=15, hours=5, status="failed")
    fail_b = _snap(db_path, snapshot_builder, days=15, hours=1, status="failed")
    # Within the downsample threshold: every snapshot is kept (hourly).
    recent = [_snap(db_path, snapshot_builder, days=2, hours=h) for h in (3, 2, 1)]
    latest = _snap(db_path, snapshot_builder, hours=1)
    with closing(db_path) as conn:
        deleted = retention.apply(conn, retention.Policy(90, 7), now=NOW)
    kept = _ids(db_path)
    assert expired not in kept
    assert day_old[2] in kept and not {day_old[0], day_old[1]} & kept
    assert ok_older in kept and failed_newer not in kept
    assert fail_b in kept and fail_a not in kept
    assert set(recent) <= kept and latest in kept
    assert deleted == 5
    assert kept == {day_old[2], ok_older, fail_b, *recent, latest}


def test_history_stays_bounded(db_path, snapshot_builder):
    # 30 days of hourly snapshots -> 7 days hourly + one per day before that.
    for h in range(30 * 24):
        _snap(db_path, snapshot_builder, hours=h + 0.5)
    with closing(db_path) as conn:
        retention.apply(conn, retention.Policy(90, 7), now=NOW)
    kept = len(_ids(db_path))
    assert 7 * 24 <= kept <= 7 * 24 + 24  # + one per older day (23 or 24 days)


def test_latest_successful_snapshot_is_always_kept(db_path, snapshot_builder):
    only = _snap(db_path, snapshot_builder, days=400)
    newer_failed = _snap(db_path, snapshot_builder, days=200, status="failed")
    with closing(db_path) as conn:
        retention.apply(conn, retention.Policy(90, 7), now=NOW)
    assert _ids(db_path) == {only}
    assert newer_failed not in _ids(db_path)


def test_protected_snapshot_is_its_days_sample(db_path, snapshot_builder):
    # Latest successful snapshot 10 days old with a failed one later that day.
    protected = _snap(db_path, snapshot_builder, days=10, hours=6)
    _snap(db_path, snapshot_builder, days=10, hours=1, status="failed")
    with closing(db_path) as conn:
        retention.apply(conn, retention.Policy(90, 7), now=NOW)
    assert _ids(db_path) == {protected}


def test_running_snapshots_are_never_touched(db_path, snapshot_builder):
    running = _snap(db_path, snapshot_builder, days=200, status="running")
    _snap(db_path, snapshot_builder)
    with closing(db_path) as conn:
        retention.apply(conn, now=NOW)
    assert running in _ids(db_path)


def test_accounts_are_downsampled_separately(db_path, snapshot_builder):
    with closing(db_path) as conn:
        other = conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) VALUES('example-b', "
            "'us-east-1', 'env')"
        ).lastrowid
    a = _snap(db_path, snapshot_builder, days=30, hours=2)
    b = _snap(db_path, snapshot_builder, days=30, hours=1, account_ref=other)
    _snap(db_path, snapshot_builder)
    _snap(db_path, snapshot_builder, account_ref=other)
    with closing(db_path) as conn:
        retention.apply(conn, now=NOW)
    assert {a, b} <= _ids(db_path)


def test_child_rows_are_removed(db_path, snapshot_builder):
    old = snapshot_builder(db_path, taken_at=NOW - timedelta(days=120))
    old.vpc("vpc-0example0000001", "10.0.0.0/16")
    _snap(db_path, snapshot_builder)
    with closing(db_path) as conn:
        retention.apply(conn, now=NOW)
        assert conn.execute("SELECT COUNT(*) FROM vpcs").fetchone()[0] == 0


def test_policy_validation():
    retention.Policy(30, 7)
    with pytest.raises(ValueError, match="must not exceed"):
        retention.Policy(5, 7)
    with pytest.raises(ValueError, match="retention window"):
        retention.Policy(0, 0)
    with pytest.raises(ValueError, match="whole number"):
        retention.parse_days("soon", "retention window", 1, 10)


def test_settings_store_round_trip(db_path):
    store = SettingsStore(db_path)
    s = store.load()
    assert (s.retention_days, s.downsample_days) == (
        retention.RETENTION_DAYS,
        retention.DOWNSAMPLE_AFTER_DAYS,
    )
    store.save_retention("30", "3")
    assert store.load().retention_policy == retention.Policy(30, 3)
    with pytest.raises(ValueError):
        store.save_retention("2", "3")
    assert store.load().retention_policy == retention.Policy(30, 3)


def test_settings_form_saves_retention(home):
    from iplens.web import create_app

    app = create_app(home, testing=True)
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as sess:
        token = sess["csrf"]
    page = client.post(
        "/settings",
        data={"csrf_token": token, "retention_days": "60", "downsample_days": "5"},
        follow_redirects=True,
    ).data.decode()
    assert "Settings saved" in page
    assert 'name="retention_days" type="number" value="60"' in page
    page = client.post(
        "/settings",
        data={"csrf_token": token, "retention_days": "3", "downsample_days": "5"},
        follow_redirects=True,
    ).data.decode()
    assert "must not exceed" in page
