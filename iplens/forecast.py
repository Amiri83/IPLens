"""IP exhaustion forecast per subnet: when its free IPs run out, and when the scale headroom
demand (:mod:`iplens.headroom`) no longer fits.

The trend is an ordinary least-squares line (:func:`iplens.trends.linear_fit`) over the
subnet's used-IP points of the last ``window_days`` days (one per snapshot). With a
positive slope of ``s`` IPs/day and ``free`` IPs free now:

- days until free = 0: ``free / s``;
- days until the demand at max scale no longer fits (free - demand = 0):
  ``(free - demand) / s``.

Either is 0 when already reached. A slope <= 0, or a date further away than
:data:`iplens.trends.HORIZON_DAYS`, is "stable"; fewer than ``min_points`` points in the
window is "not enough data". Every function here is pure: the callers load the series
(:func:`iplens.trends.load`) and the headroom (:func:`iplens.headroom.for_snapshot`).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from .trends import DEFAULT_WINDOW, HORIZON_DAYS, MIN_CONFIDENT_POINTS, Point, linear_fit

if TYPE_CHECKING:
    from .headroom import Headroom
    from .trends import Trends

DEFAULT_WINDOW_DAYS = DEFAULT_WINDOW
DEFAULT_MIN_POINTS = MIN_CONFIDENT_POINTS
# Slopes at or below this (IPs/day) are no trend.
_FLAT = 1e-9

GROWING, STABLE, INSUFFICIENT = "growing", "stable", "insufficient"


def _days_text(days: float | None) -> str:
    if days is None:
        return "–"
    if days <= 0:
        return "now"
    n = max(math.ceil(days), 1)
    return f"~{n} day{'' if n == 1 else 's'}"


@dataclass(frozen=True)
class SubnetForecast:
    status: str  # growing | stable | insufficient
    points: int
    slope_per_day: float = 0.0
    days_to_exhaustion: float | None = None  # free = 0 (None: not approaching)
    days_to_headroom: float | None = None  # free - demand = 0 (None: not approaching)

    @property
    def growing(self) -> bool:
        return self.status == GROWING

    @property
    def trend_text(self) -> str:
        """e.g. "+2.5 IPs/day", "stable" or "not enough data"."""
        if self.status == INSUFFICIENT:
            return "not enough data"
        if self.status == STABLE:
            return "stable"
        return f"+{self.slope_per_day:.1f} IPs/day"

    @property
    def exhaustion_text(self) -> str:
        return _days_text(self.days_to_exhaustion)

    @property
    def headroom_text(self) -> str:
        return _days_text(self.days_to_headroom)

    def within(self, days: float) -> bool:
        """The headroom demand stops fitting in fewer than ``days`` days."""
        return self.days_to_headroom is not None and self.days_to_headroom < days


def project(
    points: Sequence[Point],
    free: int,
    demand: int = 0,
    *,
    window_days: int = DEFAULT_WINDOW_DAYS,
    min_points: int = DEFAULT_MIN_POINTS,
    now: datetime | None = None,
) -> SubnetForecast:
    """The forecast of a subnet with used-IP ``points``, ``free`` IPs free now and a scale
    headroom ``demand``. Points older than ``window_days`` before ``now`` (default: the
    newest point) are left out."""
    pts = sorted(points)
    if pts:
        since = (now or pts[-1][0]) - timedelta(days=window_days)
        pts = [p for p in pts if p[0] >= since]
    n = len(pts)
    if n < max(min_points, 2):
        return SubnetForecast(INSUFFICIENT, n)
    t0 = pts[0][0]
    xs = [(t - t0).total_seconds() / 86400 for t, _ in pts]
    slope, _ = linear_fit(xs, [float(v) for _, v in pts])
    left = free - demand
    if slope <= _FLAT:
        # No growth: a limit already reached is still reached.
        return SubnetForecast(
            STABLE, n, slope, 0.0 if free <= 0 else None, 0.0 if left <= 0 else None
        )
    to_free = max(free / slope, 0.0)
    if to_free > HORIZON_DAYS:
        return SubnetForecast(STABLE, n, slope, None, 0.0 if left <= 0 else None)
    return SubnetForecast(GROWING, n, slope, to_free, max(left / slope, 0.0))


def for_subnets(
    headroom: Headroom,
    trends: Trends,
    *,
    min_points: int = DEFAULT_MIN_POINTS,
    now: datetime | None = None,
) -> dict[str, SubnetForecast]:
    """Subnet id -> forecast of every subnet of ``headroom``, from the used-IP series of
    ``trends`` (its window) and the subnet's free IPs and demand at max scale."""
    series = {s.key: s.points for ss in trends.subnets.values() for s in ss}
    return {
        r.subnet.subnet_id: project(
            series.get(r.subnet.subnet_id, ()),
            r.free,
            r.demand,
            window_days=trends.window,
            min_points=min_points,
            now=now,
        )
        for r in headroom.subnets
    }
