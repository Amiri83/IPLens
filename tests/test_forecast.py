"""Exhaustion forecast: the math (flat, growing, noisy, too few points), the per-subnet
combination with the scale headroom, and the Headroom / subnet / report pages.

Synthetic data only: 192.0.2.0/24 (TEST-NET-1) addresses and placeholder ids.
"""

from datetime import UTC, datetime, timedelta

import pytest

from iplens import forecast, headroom, trends
from iplens.web import create_app

NOW = datetime(2026, 1, 31, 12, 0, tzinfo=UTC)
VPC = "vpc-a"
SA = "subnet-a"
SB = "subnet-b"


def _series(values, end=NOW, step=timedelta(days=1)):
    """One point per ``step``, the last at ``end``."""
    n = len(values)
    return [(end - (n - 1 - i) * step, v) for i, v in enumerate(values)]


# -- math -----------------------------------------------------------------------------------


def test_flat_series_is_stable():
    fc = forecast.project(_series([40] * 8), free=19, demand=5)
    assert fc.status == forecast.STABLE
    assert fc.slope_per_day == pytest.approx(0.0)
    assert fc.days_to_exhaustion is None and fc.days_to_headroom is None
    assert fc.trend_text == "stable"
    assert fc.exhaustion_text == "–" and fc.headroom_text == "–"
    assert not fc.within(30)


def test_shrinking_series_is_stable():
    fc = forecast.project(_series([50, 48, 45, 44, 40, 39]), free=20)
    assert fc.status == forecast.STABLE
    assert fc.slope_per_day < 0
    assert fc.days_to_exhaustion is None


def test_growing_series_days_to_free_zero_and_to_headroom():
    # +2 IPs/day; 50 free now, 20 of them needed at max scale.
    fc = forecast.project(_series([100 + 2 * i for i in range(10)]), free=50, demand=20)
    assert fc.status == forecast.GROWING
    assert fc.points == 10
    assert fc.slope_per_day == pytest.approx(2.0)
    assert fc.days_to_exhaustion == pytest.approx(25.0)
    assert fc.days_to_headroom == pytest.approx(15.0)
    assert fc.trend_text == "+2.0 IPs/day"
    assert fc.exhaustion_text == "~25 days"
    assert fc.headroom_text == "~15 days"
    assert fc.within(30) and not fc.within(15)


def test_noisy_series_follows_the_underlying_trend():
    # 3 IPs/day with +-2 of noise around the line.
    noise = [0, 2, -1, -2, 1, 2, 0, -2, 1, -1, 2, 0, -1, 1]
    fc = forecast.project(_series([200 + 3 * i + e for i, e in enumerate(noise)]), free=60)
    assert fc.status == forecast.GROWING
    assert fc.slope_per_day == pytest.approx(3.0, abs=0.3)
    assert fc.days_to_exhaustion == pytest.approx(20.0, abs=2.5)


@pytest.mark.parametrize("n", [0, 1, 2, 4])
def test_too_few_points_is_not_enough_data(n):
    fc = forecast.project(_series([10 + 5 * i for i in range(n)]), free=10)
    assert fc.status == forecast.INSUFFICIENT
    assert fc.points == n
    assert fc.trend_text == "not enough data"
    assert fc.days_to_exhaustion is None and fc.days_to_headroom is None
    assert not fc.within(10_000)


def test_five_points_are_enough():
    assert forecast.project(_series([1, 2, 3, 4, 5]), free=100).status == forecast.GROWING


def test_points_outside_the_window_are_left_out():
    old = _series([1, 2, 3, 4, 5, 6], end=NOW - timedelta(days=40))
    recent = _series([50, 50, 50], end=NOW)
    fc = forecast.project(old + recent, free=10, window_days=30, now=NOW)
    assert fc.status == forecast.INSUFFICIENT and fc.points == 3


def test_min_points_is_configurable():
    pts = _series([1, 3, 5])
    assert forecast.project(pts, free=10, min_points=3).status == forecast.GROWING


def test_already_over_and_full_is_now():
    fc = forecast.project(_series([10 + i for i in range(6)]), free=0, demand=8)
    assert fc.days_to_exhaustion == 0.0 and fc.days_to_headroom == 0.0
    assert fc.exhaustion_text == "now" and fc.headroom_text == "now"
    assert fc.within(1)


def test_stable_but_demand_already_does_not_fit():
    fc = forecast.project(_series([30] * 6), free=5, demand=8)
    assert fc.status == forecast.STABLE
    assert fc.days_to_exhaustion is None
    assert fc.days_to_headroom == 0.0


def test_growth_beyond_the_horizon_is_stable():
    pts = _series([10, 10, 10, 10, 11], step=timedelta(days=250))
    fc = forecast.project(pts, free=65_000, window_days=2000)
    assert fc.status == forecast.STABLE and fc.days_to_exhaustion is None


def test_headroom_within_the_horizon_is_growing_even_if_free_zero_is_not():
    # +1 IP/day: free = 0 in 4000 days (beyond the 3650-day horizon), but the demand at max
    # scale stops fitting in 20 days. The far-off date must not hide the near one.
    fc = forecast.project(_series([100 + i for i in range(10)]), free=4000, demand=3980)
    assert fc.status == forecast.GROWING
    assert fc.slope_per_day == pytest.approx(1.0)
    assert fc.days_to_headroom == pytest.approx(20.0)
    assert fc.days_to_exhaustion is None  # beyond the horizon
    assert fc.headroom_text == "~20 days" and fc.exhaustion_text == "–"
    assert fc.within(30)


def test_unsorted_points():
    pts = _series([100 + 2 * i for i in range(10)])
    assert forecast.project(list(reversed(pts)), free=50).days_to_exhaustion == pytest.approx(25)


def test_for_subnets_combines_trends_and_headroom():
    sa = headroom.Subnet(SA, VPC, "us-east-1a", "192.0.2.0/26", "app-a", free=39, usable=59)
    sb = headroom.Subnet(SB, VPC, "us-east-1b", "192.0.2.64/26", "app-b", free=50, usable=59)
    h = headroom.Headroom(
        [
            headroom.SubnetHeadroom(sa, [headroom.Contributor("asg", "asg-a", 9, "max 9")]),
            headroom.SubnetHeadroom(sb),
        ]
    )
    t = trends.Trends(
        vpcs=[],
        subnets={
            VPC: [
                trends.Series(SA, "app-a", "192.0.2.0/26", 59, VPC, _series([10, 12, 14, 16, 18])),
                trends.Series(SB, "app-b", "192.0.2.64/26", 59, VPC, _series([9, 9])),
            ]
        },
        window=30,
        snapshots=5,
    )
    out = forecast.for_subnets(h, t)
    assert out[SA].slope_per_day == pytest.approx(2.0)
    assert out[SA].days_to_exhaustion == pytest.approx(19.5)
    assert out[SA].days_to_headroom == pytest.approx(15.0)  # (39 - 9) / 2
    assert out[SB].status == forecast.INSUFFICIENT


# -- pages ----------------------------------------------------------------------------------


def _history(db_path, snapshot_builder, ips, counts):
    """One snapshot per day ending now: subnet A holds ``counts[i]`` IPs, B a steady 3."""
    now = datetime.now(UTC)
    for i, n in enumerate(counts):
        b = snapshot_builder(db_path, taken_at=now - timedelta(days=len(counts) - 1 - i, minutes=5))
        b.vpc(VPC, "192.0.2.0/24", name="vpc-name-a")
        b.subnet(SA, VPC, "192.0.2.0/26", az="us-east-1a", name="app-a")
        b.subnet(SB, VPC, "192.0.2.64/26", az="us-east-1b", name="app-b")
        b.eni("eni-a", SA, ips("192.0.2.0", 4, n), owner_ref="i-0abc1234")
        b.eni("eni-b", SB, ips("192.0.2.64", 4, 3), owner_ref="i-0abc5678")


@pytest.fixture
def grown(home, snapshot_builder, ips):
    """Subnet A grows 2 IPs/day for 6 days (20 used of 59 at the end: 39 free)."""
    _history(home / "iplens.db", snapshot_builder, ips, [10, 12, 14, 16, 18, 20])
    app = create_app(home, testing=True)
    client = app.test_client()
    client.get("/")
    return client


def test_headroom_page_shows_the_forecast(grown):
    page = grown.get("/headroom").data.decode()
    assert "Forecast" in page
    assert "+2.0 IPs/day" in page
    assert "free = 0: ~20 days" in page  # 39 / 2 = 19.5
    assert ">stable<" in page  # B is flat


def test_subnet_page_shows_a_sparkline_and_the_forecast(grown):
    page = grown.get(f"/subnets/{SA}").data.decode()
    assert 'class="trend-chart compact"' in page
    assert "+2.0 IPs/day" in page
    assert "free = 0 in ~20 days" in page
    flat = grown.get(f"/subnets/{SB}").data.decode()
    assert "stable" in flat


def test_subnet_page_without_history_says_not_enough_data(home, snapshot_builder, ips):
    _history(home / "iplens.db", snapshot_builder, ips, [10, 12])
    client = create_app(home, testing=True).test_client()
    page = client.get(f"/subnets/{SA}").data.decode()
    assert "not enough data" in page


def test_report_has_the_forecast_section(grown):
    html = grown.get("/report").data.decode()
    assert 'id="forecast"' in html
    assert "IP exhaustion forecast" in html
    assert "+2.0 IPs/day" in html and "~20 days" in html
    assert "<script" not in html
