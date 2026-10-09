"""Trends: used-IP time series per subnet / VPC, a linear forecast and inline SVG charts.

The series are read from the snapshot history in SQLite (successful snapshots of one
account). "Used" counts every private IP held by an ENI, idle ENIs included (they occupy
addresses just the same); a subnet's limit is its usable size (CIDR minus the five AWS
reserved addresses) and a VPC's the usable size of its current subnets, since an IP can
only be allocated inside a subnet.

The forecast is an ordinary least-squares line over the points of the chosen window.
A positive slope gives "full in ~N days"; a slope <= 0, or a limit further away than
:data:`HORIZON_DAYS`, is "stable/declining". Fewer than :data:`MIN_CONFIDENT_POINTS`
points add a confidence note. Charts are hand-drawn SVG: no JavaScript, no CDN.
"""

from __future__ import annotations

import ipaddress
import json
import math
import sqlite3
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from markupsafe import Markup

from .queries import AWS_RESERVED_HEAD, AWS_RESERVED_TAIL
from .retention import parse_taken_at
from .scope import UNSCOPED, ResolvedScope

WINDOWS = {7: "7 days", 30: "30 days", 90: "90 days"}
DEFAULT_WINDOW = 30
MIN_CONFIDENT_POINTS = 5
# A limit further away than this is "not approaching" it.
HORIZON_DAYS = 3650
# Discovery badges subnets forecast to fill up sooner than this.
SOON_DAYS = 30

FULL, GROWING, STABLE, INSUFFICIENT = "full", "growing", "stable", "insufficient"

Point = tuple[datetime, int]


@dataclass(frozen=True)
class Forecast:
    status: str  # full | growing | stable | insufficient
    points: int
    slope_per_day: float = 0.0
    days_to_full: float | None = None
    capacity: int = 0
    # Fitted line at the first / last point of the window (for the chart's trend line).
    fit: tuple[Point, ...] = ()

    @property
    def text(self) -> str:
        if self.status == INSUFFICIENT:
            return "not enough data"
        if self.status == FULL:
            return "full now"
        if self.status == GROWING and self.days_to_full is not None:
            days = max(math.ceil(self.days_to_full), 1)
            return f"full in ~{days} day{'' if days == 1 else 's'}"
        return "stable/declining"

    @property
    def confidence_note(self) -> str:
        if self.points < MIN_CONFIDENT_POINTS:
            return (
                f"Low confidence: {self.points} data point(s) in the window "
                f"(fewer than {MIN_CONFIDENT_POINTS})."
            )
        return ""

    @property
    def soon(self) -> bool:
        """Full (or forecast full) within :data:`SOON_DAYS`."""
        return self.status == FULL or (
            self.status == GROWING
            and self.days_to_full is not None
            and self.days_to_full < SOON_DAYS
        )


def linear_fit(xs: Sequence[float], ys: Sequence[float]) -> tuple[float, float]:
    """Least-squares (slope, intercept); slope 0 when every x is the same."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / sxx
    return slope, my - slope * mx


def forecast(points: Sequence[Point], capacity: int) -> Forecast:
    """Forecast of a used-IP series against ``capacity`` (see the module docstring)."""
    pts = sorted(points)
    n = len(pts)
    if n and capacity > 0 and pts[-1][1] >= capacity:
        return Forecast(FULL, n, days_to_full=0.0, capacity=capacity)
    if n < 2:
        return Forecast(INSUFFICIENT, n, capacity=capacity)
    t0 = pts[0][0]
    xs = [(t - t0).total_seconds() / 86400 for t, _ in pts]
    ys = [float(v) for _, v in pts]
    slope, intercept = linear_fit(xs, ys)
    fit = tuple((t0 + timedelta(days=x), round(intercept + slope * x)) for x in (xs[0], xs[-1]))
    if slope <= 1e-9 or capacity <= 0:
        return Forecast(STABLE, n, slope, None, capacity, fit)
    now_fit = intercept + slope * xs[-1]
    days = max((capacity - now_fit) / slope, 0.0)
    if days > HORIZON_DAYS:
        return Forecast(STABLE, n, slope, None, capacity, fit)
    return Forecast(GROWING, n, slope, days, capacity, fit)


# -- series from the snapshot history ----------------------------------------------------


@dataclass
class Series:
    key: str  # subnet id or VPC id
    name: str
    cidr: str  # subnet CIDR, or the VPC CIDRs comma-separated
    capacity: int
    vpc_id: str = ""
    points: list[Point] = field(default_factory=list)
    forecast: Forecast | None = None

    @property
    def latest(self) -> int:
        return self.points[-1][1] if self.points else 0


@dataclass
class Trends:
    vpcs: list[Series]
    subnets: dict[str, list[Series]]  # VPC id -> its subnets' series
    window: int
    snapshots: int  # successful snapshots in the window


def _usable(cidr: str) -> int:
    size = ipaddress.IPv4Network(cidr).num_addresses
    return max(size - AWS_RESERVED_HEAD - AWS_RESERVED_TAIL, 0)


def load(
    conn: sqlite3.Connection,
    account_ref: int,
    window: int = DEFAULT_WINDOW,
    scope: ResolvedScope = UNSCOPED,
    now: datetime | None = None,
) -> Trends:
    """Series and forecasts of the account's subnets and VPCs over the last ``window``
    days. Subnets / VPCs are those of the newest snapshot in the window (in ``scope``)."""
    now = now or datetime.now(UTC)
    since = now - timedelta(days=window)
    snaps = [
        (r["id"], parse_taken_at(r["taken_at"]))
        for r in conn.execute(
            "SELECT id, taken_at FROM snapshots WHERE account_ref=? AND status='ok' ORDER BY id",
            (account_ref,),
        )
    ]
    snaps = [(i, t) for i, t in snaps if t >= since]
    if not snaps:
        return Trends([], {}, window, 0)
    taken = dict(snaps)
    ids = list(taken)
    marks = ",".join("?" * len(ids))
    latest = ids[-1]
    # Distinct private IPs per snapshot and subnet (idle ENIs included).
    counts: dict[str, dict[int, int]] = defaultdict(dict)
    for r in conn.execute(
        f"SELECT snapshot_id, subnet_id, COUNT(DISTINCT ip) AS n FROM ips "  # noqa: S608
        f"WHERE snapshot_id IN ({marks}) GROUP BY snapshot_id, subnet_id",
        ids,
    ):
        counts[r["subnet_id"]][r["snapshot_id"]] = r["n"]
    present: dict[str, set[int]] = defaultdict(set)  # subnet -> snapshots it existed in
    for r in conn.execute(
        f"SELECT snapshot_id, subnet_id FROM subnets WHERE snapshot_id IN ({marks})",  # noqa: S608
        ids,
    ):
        present[r["subnet_id"]].add(r["snapshot_id"])
    vpcs: list[Series] = []
    subnets: dict[str, list[Series]] = {}
    vpc_rows = conn.execute(
        "SELECT vpc_id, name, cidrs FROM vpcs WHERE snapshot_id=? ORDER BY vpc_id", (latest,)
    ).fetchall()
    for v in vpc_rows:
        if not scope.vpc_ok(v["vpc_id"]):
            continue
        sub_rows = [
            s
            for s in conn.execute(
                "SELECT subnet_id, name, cidr FROM subnets WHERE snapshot_id=? AND vpc_id=?",
                (latest, v["vpc_id"]),
            )
            if scope.subnet_ok(s["subnet_id"])
        ]
        sub_rows.sort(key=lambda s: int(ipaddress.IPv4Network(s["cidr"]).network_address))
        series = []
        for s in sub_rows:
            sid = s["subnet_id"]
            pts = [(taken[i], counts[sid].get(i, 0)) for i in ids if i in present[sid]]
            ser = Series(sid, s["name"] or "", s["cidr"], _usable(s["cidr"]), v["vpc_id"], pts)
            ser.forecast = forecast(pts, ser.capacity)
            series.append(ser)
        subnets[v["vpc_id"]] = series
        own = {s["subnet_id"] for s in sub_rows}
        vpc_pts = [
            (taken[i], sum(counts[sid].get(i, 0) for sid in own if i in present[sid]))
            for i in ids
            if any(i in present[sid] for sid in own)
        ]
        vs = Series(
            v["vpc_id"],
            v["name"] or "",
            ", ".join(json.loads(v["cidrs"])),
            sum(s.capacity for s in series),
            v["vpc_id"],
            vpc_pts,
        )
        vs.forecast = forecast(vpc_pts, vs.capacity)
        vpcs.append(vs)
    return Trends(vpcs, subnets, window, len(ids))


def soon_full(
    conn: sqlite3.Connection,
    account_ref: int,
    window: int = DEFAULT_WINDOW,
    scope: ResolvedScope = UNSCOPED,
) -> dict[str, Forecast]:
    """Subnet id -> forecast, for subnets full or forecast full within :data:`SOON_DAYS`."""
    t = load(conn, account_ref, window, scope)
    return {
        s.key: s.forecast for ss in t.subnets.values() for s in ss if s.forecast and s.forecast.soon
    }


# -- inline SVG ------------------------------------------------------------------------------


def _fmt_time(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M UTC")


def svg_chart(
    series: Series,
    *,
    width: int = 640,
    height: int = 200,
    compact: bool = False,
) -> Markup:
    """A line chart of ``series`` (used IPs over time) with its limit and trend line.

    ``compact`` draws a sparkline-sized chart without axis labels. Every point carries
    a ``<title>`` tooltip; all text is escaped.
    """
    pts = series.points
    label = f"Used IPs of {series.key} over time"
    if not pts:
        return Markup(
            '<svg class="trend-chart" role="img" aria-label="{0}" width="{1}" height="{2}" '
            'viewBox="0 0 {1} {2}"><text x="4" y="{3}" class="trend-empty">no data</text></svg>'
        ).format(label, width, height, height // 2)
    left, right, top, bottom = (2, 2, 4, 4) if compact else (48, 72, 12, 26)
    pw, ph = width - left - right, height - top - bottom
    fc = series.forecast
    fit = fc.fit if fc else ()
    t_min = pts[0][0]
    t_max = max(pts[-1][0], t_min + timedelta(minutes=1))
    span = (t_max - t_min).total_seconds()
    peak = max(v for _, v in pts)
    y_max = max(peak, *(v for _, v in fit)) if fit else peak
    # The limit is drawn when it is within reach of the data (else the line would be flat).
    show_cap = series.capacity > 0 and series.capacity <= max(y_max, 1) * 4
    if show_cap:
        y_max = max(y_max, series.capacity)
    y_max = max(y_max, 1)

    def x(t: datetime) -> float:
        return left + pw * ((t - t_min).total_seconds() / span if span else 0.5)

    def y(v: float) -> float:
        return top + ph * (1 - max(v, 0) / y_max)

    parts: list[Markup] = [
        Markup(
            '<svg class="trend-chart{0}" role="img" aria-label="{1}" width="{2}" height="{3}" '
            'viewBox="0 0 {2} {3}">'
        ).format(" compact" if compact else "", label, width, height),
        Markup("<title>{0}</title>").format(label),
    ]
    if not compact:
        for v in (0, y_max):
            parts.append(
                Markup(
                    '<line class="trend-grid" x1="{0}" y1="{1:.1f}" x2="{2}" y2="{1:.1f}"/>'
                    '<text class="trend-axis" x="{3}" y="{4:.1f}" text-anchor="end">{5}</text>'
                ).format(left, y(v), left + pw, left - 6, y(v) + 4, v)
            )
        for t, anchor in ((t_min, "start"), (t_max, "end")):
            parts.append(
                Markup(
                    '<text class="trend-axis" x="{0:.1f}" y="{1}" text-anchor="{2}">{3}</text>'
                ).format(x(t), height - 8, anchor, t.strftime("%Y-%m-%d"))
            )
    if show_cap:
        parts.append(
            Markup(
                '<line class="trend-cap" x1="{0}" y1="{1:.1f}" x2="{2}" y2="{1:.1f}">'
                "<title>limit: {3} usable IPs</title></line>"
            ).format(left, y(series.capacity), left + pw, series.capacity)
        )
        if not compact:
            parts.append(
                Markup('<text class="trend-label" x="{0}" y="{1:.1f}">limit {2}</text>').format(
                    left + pw + 6, y(series.capacity) + 4, series.capacity
                )
            )
    if len(fit) == 2:
        (ta, va), (tb, vb) = fit
        parts.append(
            Markup(
                '<line class="trend-fit" x1="{0:.1f}" y1="{1:.1f}" x2="{2:.1f}" y2="{3:.1f}">'
                "<title>trend: {4}</title></line>"
            ).format(x(ta), y(va), x(tb), y(vb), fc.text if fc else "")
        )
    path = " ".join(f"{x(t):.1f},{y(v):.1f}" for t, v in pts)
    parts.append(Markup('<polyline class="trend-line" points="{0}"/>').format(path))
    for t, v in pts:
        parts.append(
            Markup(
                '<circle class="trend-hit" cx="{0:.1f}" cy="{1:.1f}" r="{2}">'
                "<title>{3}: {4} used IPs</title></circle>"
            ).format(x(t), y(v), 6 if not compact else 4, _fmt_time(t), v)
        )
    if not compact:
        t_last, v_last = pts[-1]
        label_y = y(v_last) + 4
        if show_cap and abs(label_y - (y(series.capacity) + 4)) < 14:
            label_y = y(series.capacity) + 18  # keep clear of the "limit" label
        parts.append(
            Markup(
                '<circle class="trend-dot" cx="{0:.1f}" cy="{1:.1f}" r="4"/>'
                '<text class="trend-label" x="{2}" y="{3:.1f}">{4} used</text>'
            ).format(x(t_last), y(v_last), left + pw + 6, label_y, v_last)
        )
    parts.append(Markup("</svg>"))
    return Markup("").join(parts)
