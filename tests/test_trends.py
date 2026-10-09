"""Trends: forecast math, series from the snapshot history, SVG and pages.

Synthetic data only: 10.0.x.x addresses, account 123456789012, example names.
"""

from datetime import UTC, datetime, timedelta

import pytest

from iplens import trends
from iplens.db import closing
from iplens.web import create_app

NOW = datetime(2026, 1, 31, 12, 0, tzinfo=UTC)
VPC = "vpc-0example0000001"
SA = "subnet-0000000a"
SB = "subnet-0000000b"


def _series(values, start=NOW - timedelta(days=9), step=timedelta(days=1)):
    return [(start + i * step, v) for i, v in enumerate(values)]


# -- forecast math ------------------------------------------------------------------


def test_linear_fit_exact_line():
    slope, intercept = trends.linear_fit([0, 1, 2, 3], [5, 7, 9, 11])
    assert slope == pytest.approx(2.0)
    assert intercept == pytest.approx(5.0)


def test_growing_series_is_full_in_n_days():
    # +2 IPs/day from 100; the last point (day 9) is 118, the limit 251 -> 66.5 days.
    fc = trends.forecast(_series([100 + 2 * i for i in range(10)]), 251)
    assert fc.status == trends.GROWING
    assert fc.slope_per_day == pytest.approx(2.0)
    assert fc.days_to_full == pytest.approx(66.5)
    assert fc.text == "full in ~67 days"
    assert fc.confidence_note == ""
    assert not fc.soon


def test_fast_growth_is_soon():
    fc = trends.forecast(_series([10, 20, 30, 40, 50]), 59)  # a /26: 59 usable
    assert fc.status == trends.GROWING
    assert fc.days_to_full == pytest.approx(0.9)
    assert fc.text == "full in ~1 day"
    assert fc.soon


@pytest.mark.parametrize("values", [[40] * 6, [50, 48, 45, 44, 40, 39]])
def test_flat_or_declining_is_stable(values):
    fc = trends.forecast(_series(values), 251)
    assert fc.status == trends.STABLE
    assert fc.text == "stable/declining"
    assert fc.days_to_full is None
    assert not fc.soon


def test_growth_far_beyond_the_horizon_is_stable():
    # +1 IP per 1000 days against a /16: not approaching the limit.
    pts = _series([10, 10, 10, 10, 11], step=timedelta(days=250))
    fc = trends.forecast(pts, 65531)
    assert fc.status == trends.STABLE
    assert fc.text == "stable/declining"


@pytest.mark.parametrize("n", [2, 3, 4])
def test_too_few_points_give_a_confidence_note(n):
    fc = trends.forecast(_series([10 + 5 * i for i in range(n)]), 251)
    assert fc.points == n
    assert fc.status == trends.GROWING
    assert f"{n} data point(s)" in fc.confidence_note
    assert "Low confidence" in fc.confidence_note


def test_five_points_have_no_confidence_note():
    assert trends.forecast(_series([1, 2, 3, 4, 5]), 251).confidence_note == ""


def test_single_point_is_insufficient():
    fc = trends.forecast(_series([10]), 251)
    assert fc.status == trends.INSUFFICIENT
    assert fc.text == "not enough data"
    assert "1 data point(s)" in fc.confidence_note


def test_already_full():
    fc = trends.forecast(_series([50, 59]), 59)
    assert fc.status == trends.FULL
    assert fc.text == "full now"
    assert fc.soon


def test_points_need_not_be_sorted():
    pts = _series([100 + 2 * i for i in range(10)])
    assert trends.forecast(list(reversed(pts)), 251).days_to_full == pytest.approx(66.5)


# -- series from the snapshot history -----------------------------------------------------


def _history(db_path, snapshot_builder, ips, counts, days_apart=1):
    """One snapshot per day ending today: subnet A (/26) holds ``counts[i]`` IPs,
    subnet B (/24) a steady 5."""
    now = datetime.now(UTC)
    ids = []
    for i, n in enumerate(counts):
        taken = now - timedelta(days=(len(counts) - 1 - i) * days_apart, minutes=5)
        b = snapshot_builder(db_path, taken_at=taken)
        b.vpc(VPC, "10.0.0.0/16")
        b.subnet(SA, VPC, "10.0.1.0/26", name="example-small")
        b.subnet(SB, VPC, "10.0.2.0/24", name="example-large")
        if n:
            b.eni("eni-0000000a01", SA, ips("10.0.1.0", 4, n), owner_ref="i-0example0001")
        b.eni("eni-0000000b01", SB, ips("10.0.2.0", 4, 5), owner_ref="i-0example0002")
        ids.append(b.id)
    return ids


def test_load_series_and_forecasts(db_path, snapshot_builder, ips):
    _history(db_path, snapshot_builder, ips, [10, 20, 30, 40, 50])
    with closing(db_path) as conn:
        t = trends.load(conn, 1)
    assert t.snapshots == 5
    assert [v.key for v in t.vpcs] == [VPC]
    small, large = t.subnets[VPC]
    assert (small.key, small.capacity) == (SA, 59)
    assert [n for _, n in small.points] == [10, 20, 30, 40, 50]
    assert small.forecast.status == trends.GROWING and small.forecast.soon
    assert large.capacity == 251
    assert large.forecast.text == "stable/declining"
    vpc = t.vpcs[0]
    assert vpc.capacity == 59 + 251
    assert [n for _, n in vpc.points] == [15, 25, 35, 45, 55]
    with closing(db_path) as conn:
        soon = trends.soon_full(conn, 1)
    assert set(soon) == {SA}


def test_window_limits_the_points(db_path, snapshot_builder, ips):
    _history(db_path, snapshot_builder, ips, [10, 20, 30, 40, 50], days_apart=3)
    with closing(db_path) as conn:
        t = trends.load(conn, 1, window=7)
    small = t.subnets[VPC][0]
    assert [n for _, n in small.points] == [30, 40, 50]  # 6, 3 and 0 days ago
    assert "Low confidence" in small.forecast.confidence_note


def test_failed_and_other_account_snapshots_are_ignored(db_path, snapshot_builder, ips):
    _history(db_path, snapshot_builder, ips, [10, 20])
    snapshot_builder(db_path, status="failed")
    with closing(db_path) as conn:
        other = conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) VALUES('example-b', "
            "'us-east-1', 'env')"
        ).lastrowid
    snapshot_builder(db_path, account_ref=other).vpc("vpc-0example0000002", "10.1.0.0/16")
    with closing(db_path) as conn:
        t = trends.load(conn, 1)
    assert t.snapshots == 2
    assert [v.key for v in t.vpcs] == [VPC]


def test_no_history(db_path):
    with closing(db_path) as conn:
        t = trends.load(conn, 1)
    assert (t.vpcs, t.subnets, t.snapshots) == ([], {}, 0)


# -- SVG ---------------------------------------------------------------------------------


def test_svg_chart_is_self_contained_and_escaped():
    s = trends.Series("subnet-<x>", "example", "10.0.1.0/26", 59, VPC, _series([10, 20, 30]))
    s.forecast = trends.forecast(s.points, s.capacity)
    svg = str(trends.svg_chart(s))
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "subnet-&lt;x&gt;" in svg and "subnet-<x>" not in svg
    assert 'class="trend-line"' in svg and 'class="trend-cap"' in svg
    assert 'class="trend-fit"' in svg
    assert svg.count('class="trend-hit"') == 3  # one tooltip target per point
    assert "limit 59" in svg and "30 used" in svg
    assert "<script" not in svg and "http" not in svg.replace("http://www.w3.org", "")
    compact = str(trends.svg_chart(s, width=180, height=40, compact=True))
    assert "trend-axis" not in compact and 'width="180"' in compact


def test_svg_chart_without_points():
    svg = str(trends.svg_chart(trends.Series(SA, "", "10.0.1.0/26", 59)))
    assert "no data" in svg


# -- pages ---------------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


def test_trends_page_and_discovery_badge(app, snapshot_builder, ips):
    _history(_db(app), snapshot_builder, ips, [10, 20, 30, 40, 50])
    client = app.test_client()
    page = client.get("/trends").data.decode()
    assert "<svg" in page and 'class="trend-line"' in page
    assert "full in ~1 day" in page and "stable/declining" in page
    assert f'id="{SA}"' in page
    page = client.get("/").data.decode()
    assert "forecast-badge" in page and "⚠ full in ~1 day" in page
    # The steady subnet gets no badge.
    assert page.count("forecast-badge") == 1


def test_trends_page_confidence_note_and_bad_window(app, snapshot_builder, ips):
    _history(_db(app), snapshot_builder, ips, [10, 20])
    client = app.test_client()
    page = client.get("/trends?window=999").data.decode()
    assert "Low confidence: 2 data point(s)" in page
    assert 'value="30" selected' in page


def test_trends_page_without_data(app):
    assert app.test_client().get("/trends").status_code == 200
