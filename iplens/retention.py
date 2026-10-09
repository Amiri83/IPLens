"""Snapshot retention: a time window plus a daily downsample of older snapshots.

With a scheduled Refresh every hour an account gains 24 snapshots a day, so history is
kept bounded by policy instead of by count:

* snapshots older than ``retention_days`` are deleted;
* snapshots older than ``downsample_days`` are thinned to **one per UTC day** per account
  (the newest successful one of that day; a day without a successful snapshot keeps its
  newest one);
* newer snapshots are all kept, and so is each account's latest successful snapshot
  (:func:`iplens.queries.protected_snapshot_ids`) and every collection still running.

The window and the threshold are global settings (:class:`iplens.settings.Settings`)
defaulting to :data:`RETENTION_DAYS` / :data:`DOWNSAMPLE_AFTER_DAYS`.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .queries import protected_snapshot_ids

RETENTION_DAYS = 90
DOWNSAMPLE_AFTER_DAYS = 7
MIN_RETENTION_DAYS, MAX_RETENTION_DAYS = 1, 3650
MIN_DOWNSAMPLE_DAYS, MAX_DOWNSAMPLE_DAYS = 1, 365


@dataclass(frozen=True)
class Policy:
    retention_days: int = RETENTION_DAYS
    downsample_days: int = DOWNSAMPLE_AFTER_DAYS

    def __post_init__(self) -> None:
        validate(self.retention_days, self.downsample_days)


def parse_days(value: str | int | None, what: str, low: int, high: int) -> int:
    """A whole number of days within [low, high]; ValueError otherwise."""
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"the {what} must be a whole number of days") from None
    if not low <= days <= high:
        raise ValueError(f"the {what} must be {low}-{high} days")
    return days


def validate(retention_days: int, downsample_days: int) -> None:
    parse_days(retention_days, "retention window", MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
    parse_days(downsample_days, "downsample threshold", MIN_DOWNSAMPLE_DAYS, MAX_DOWNSAMPLE_DAYS)
    if downsample_days > retention_days:
        raise ValueError("the downsample threshold must not exceed the retention window")


def parse_taken_at(value: str) -> datetime:
    """A stored ``taken_at`` as an aware UTC datetime (naive values are taken as UTC)."""
    ts = datetime.fromisoformat(value)
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


def plan(conn: sqlite3.Connection, policy: Policy, now: datetime | None = None) -> set[int]:
    """Ids of the snapshots :func:`apply` would delete."""
    now = now or datetime.now(UTC)
    expire = now - timedelta(days=policy.retention_days)
    thin = now - timedelta(days=policy.downsample_days)
    protected = protected_snapshot_ids(conn)
    doomed: set[int] = set()
    # (account, UTC day) -> the snapshot kept for that day, chosen newest-first.
    kept_day: dict[tuple[int | None, str], tuple[int, bool]] = {}
    rows = conn.execute(
        "SELECT id, account_ref, taken_at, status FROM snapshots WHERE status != 'running' "
        "ORDER BY id DESC"
    ).fetchall()
    for r in rows:
        if r["id"] in protected:
            continue
        taken = parse_taken_at(r["taken_at"])
        if taken < expire:
            doomed.add(r["id"])
        elif taken < thin:
            key = (r["account_ref"], taken.date().isoformat())
            ok = r["status"] == "ok"
            have = kept_day.get(key)
            if have is None:
                kept_day[key] = (r["id"], ok)
            elif ok and not have[1]:
                # A successful snapshot beats a newer failed one of the same day.
                doomed.add(have[0])
                kept_day[key] = (r["id"], ok)
            else:
                doomed.add(r["id"])
    # A protected snapshot is that day's sample: drop the others of its day.
    for r in rows:
        if r["id"] in protected:
            taken = parse_taken_at(r["taken_at"])
            if expire <= taken < thin:
                have = kept_day.pop((r["account_ref"], taken.date().isoformat()), None)
                if have is not None:
                    doomed.add(have[0])
    return doomed


def apply(
    conn: sqlite3.Connection, policy: Policy | None = None, now: datetime | None = None
) -> int:
    """Delete what the policy no longer keeps; returns the number deleted."""
    ids = plan(conn, policy or Policy(), now)
    # Child tables are removed by ON DELETE CASCADE.
    conn.executemany("DELETE FROM snapshots WHERE id=?", [(i,) for i in sorted(ids)])
    return len(ids)
