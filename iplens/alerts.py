"""Subnet alerts to a webhook, in the Settings -> Alerts *webhook format*:

- ``slack`` (default): ``{"text": ...}``, as Slack incoming webhooks expect;
- ``teams``: a message with one Adaptive Card 1.4 attachment (a TextBlock per line), as
  Microsoft Teams Workflows ("when a Teams webhook request is received") expect.

After each successful Refresh, :func:`evaluate` checks every subnet of the account's latest
snapshot against the thresholds of Settings -> Alerts:

- **over**: the scale headroom status is "over" (:mod:`iplens.headroom`);
- **forecast**: the headroom demand stops fitting in fewer than ``forecast_days`` days
  (:mod:`iplens.forecast`, the default 30-day window);
- **low free**: less than ``free_pct`` % of the subnet's usable IPs are free.

A subnet's *state* is the set of conditions it meets. A message is only sent when a
subnet's state differs from the last one sent (kept in the ``alert_state`` table), so
repeated Refreshes do not re-send; a subnet that no longer meets any condition gets one
"resolved" line. All changes of one Refresh go out as one message. The state is only
stored once the webhook accepted the message, so a failed send is retried by the next
Refresh.

The webhook URL is a secret (its path is the token): it is Fernet-encrypted at rest
(:class:`iplens.crypto.SecretBox`), never logged and never rendered back. Alert text names
subnets by name and AZ; account and subnet ids are only included when
``include_ids`` is set. This POST is the only outbound call IPLens makes besides AWS.
"""

from __future__ import annotations

import http.client
import json
import logging
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, forecast, headroom, queries, trends
from .crypto import SecretBox
from .db import closing
from .scope import UNSCOPED

log = logging.getLogger(__name__)

OVER, FORECAST, LOW_FREE = "over", "forecast", "low_free"
CONDITION_LABELS = {OVER: "over", FORECAST: "forecast", LOW_FREE: "low free"}
DEFAULT_FORECAST_DAYS = 30
MIN_FORECAST_DAYS, MAX_FORECAST_DAYS = 0, 3650  # 0: off
DEFAULT_FREE_PCT = 10.0
MIN_FREE_PCT, MAX_FREE_PCT = 0.0, 100.0  # 0: off
MAX_URL = 2048
WEBHOOK_TIMEOUT = 10.0
# Subnet lines per message; the rest are counted.
MAX_LINES = 25
TEST_TEXT = "IPLens test alert: this webhook will receive IPLens subnet alerts."
SLACK, TEAMS = "slack", "teams"
FORMAT_LABELS = {SLACK: "Slack", TEAMS: "Microsoft Teams (Workflows)"}
DEFAULT_FORMAT = SLACK

# Settings rows.
_URL_KEY = "alert_webhook_enc"
_ON_OVER_KEY = "alert_on_over"
_DAYS_KEY = "alert_forecast_days"
_PCT_KEY = "alert_free_pct"
_IDS_KEY = "alert_include_ids"
_FORMAT_KEY = "alert_webhook_format"

Sender = Callable[[str, dict[str, Any]], None]


class WebhookError(Exception):
    """The webhook did not accept the message (the text never holds the URL)."""


# -- settings -------------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertSettings:
    webhook_url: str = ""
    on_over: bool = True
    forecast_days: int = DEFAULT_FORECAST_DAYS  # 0: off
    free_pct: float = DEFAULT_FREE_PCT  # 0: off
    include_ids: bool = False  # account / subnet ids in the alert text
    webhook_format: str = DEFAULT_FORMAT  # slack | teams
    # A stored URL that the current secret key cannot decrypt.
    undecryptable: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def webhook_display(self) -> str:
        """Scheme and host only: the path is the webhook's secret."""
        if not self.webhook_url:
            return ""
        parts = urllib.parse.urlsplit(self.webhook_url)
        return f"{parts.scheme}://{parts.hostname or ''}/…"

    def __repr__(self) -> str:  # never expose the URL
        return (
            f"AlertSettings(configured={self.configured}, on_over={self.on_over}, "
            f"forecast_days={self.forecast_days}, free_pct={self.free_pct}, "
            f"include_ids={self.include_ids}, webhook_format={self.webhook_format})"
        )


def parse_webhook_url(value: str) -> str:
    """An https URL with a host; ValueError otherwise (the message never echoes it)."""
    url = (value or "").strip()
    if len(url) > MAX_URL:
        raise ValueError(f"the webhook URL must be at most {MAX_URL} characters")
    if any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError("the webhook URL must not contain spaces or control characters")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("the webhook URL must be an https:// URL")
    return url


def parse_webhook_format(value: str | None) -> str:
    fmt = (value or "").strip().lower() or DEFAULT_FORMAT
    if fmt not in FORMAT_LABELS:
        raise ValueError(f"the webhook format must be one of: {', '.join(FORMAT_LABELS)}")
    return fmt


def parse_forecast_days(value: str | int | None) -> int:
    try:
        days = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("the forecast threshold must be a whole number of days") from None
    if not MIN_FORECAST_DAYS <= days <= MAX_FORECAST_DAYS:
        raise ValueError(
            f"the forecast threshold must be {MIN_FORECAST_DAYS}-{MAX_FORECAST_DAYS} days"
        )
    return days


def parse_free_pct(value: str | float | None) -> float:
    try:
        pct = float(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("the free threshold must be a percentage") from None
    if not MIN_FREE_PCT <= pct <= MAX_FREE_PCT:
        raise ValueError(f"the free threshold must be {MIN_FREE_PCT:g}-{MAX_FREE_PCT:g}%")
    return pct


class AlertStore:
    """Alert settings in the ``settings`` table; the webhook URL encrypted."""

    def __init__(self, db_path: Path, box: SecretBox):
        self.db_path = db_path
        self.box = box

    def _get(self, conn: sqlite3.Connection, key: str) -> str:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return (row["value"] if row else "") or ""

    def load(self) -> AlertSettings:
        with closing(self.db_path) as conn:
            raw = {k: self._get(conn, k) for k in (_URL_KEY, _ON_OVER_KEY, _DAYS_KEY, _PCT_KEY)}
            include_ids = self._get(conn, _IDS_KEY) == "1"
            raw_format = self._get(conn, _FORMAT_KEY)
        url, undecryptable = "", False
        if raw[_URL_KEY]:
            try:
                url = self.box.decrypt(raw[_URL_KEY])
            except ValueError:
                log.warning("alerts: the stored webhook URL cannot be decrypted; set it again")
                undecryptable = True
        try:
            days = parse_forecast_days(raw[_DAYS_KEY] or DEFAULT_FORECAST_DAYS)
        except ValueError:
            days = DEFAULT_FORECAST_DAYS
        try:
            pct = parse_free_pct(raw[_PCT_KEY] or DEFAULT_FREE_PCT)
        except ValueError:
            pct = DEFAULT_FREE_PCT
        try:
            fmt = parse_webhook_format(raw_format)
        except ValueError:
            fmt = DEFAULT_FORMAT
        return AlertSettings(
            webhook_url=url,
            on_over=raw[_ON_OVER_KEY] != "0",
            forecast_days=days,
            free_pct=pct,
            include_ids=include_ids,
            webhook_format=fmt,
            undecryptable=undecryptable,
        )

    def save(
        self,
        *,
        webhook_url: str = "",
        clear_url: bool = False,
        on_over: bool = True,
        forecast_days: str | int = DEFAULT_FORECAST_DAYS,
        free_pct: str | float = DEFAULT_FREE_PCT,
        include_ids: bool = False,
        webhook_format: str = DEFAULT_FORMAT,
    ) -> None:
        """Store the settings; an empty ``webhook_url`` keeps the stored one (``clear_url``
        removes it). ValueError (nothing stored) if a value is invalid."""
        days = parse_forecast_days(forecast_days)
        pct = parse_free_pct(free_pct)
        fmt = parse_webhook_format(webhook_format)
        url = parse_webhook_url(webhook_url) if webhook_url.strip() else ""
        values = {
            _ON_OVER_KEY: "1" if on_over else "0",
            _DAYS_KEY: str(days),
            _PCT_KEY: f"{pct:g}",
            _IDS_KEY: "1" if include_ids else "0",
            _FORMAT_KEY: fmt,
        }
        if clear_url:
            values[_URL_KEY] = ""
        elif url:
            values[_URL_KEY] = self.box.encrypt(url)
        with closing(self.db_path) as conn:
            for key, value in values.items():
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
            if clear_url:  # a new webhook starts from a clean slate
                conn.execute("DELETE FROM alert_state")


# -- evaluation (pure) ----------------------------------------------------------------------


@dataclass(frozen=True)
class SubnetAlert:
    subnet_id: str
    name: str
    az: str
    conditions: tuple[str, ...]  # sorted; () = resolved
    details: tuple[str, ...]  # one per condition
    previous: tuple[str, ...] = ()

    @property
    def state(self) -> str:
        return ",".join(self.conditions)

    @property
    def resolved(self) -> bool:
        return not self.conditions


def conditions(
    row: headroom.SubnetHeadroom,
    fc: forecast.SubnetForecast | None,
    cfg: AlertSettings,
) -> dict[str, str]:
    """Condition -> its detail text, for the conditions ``row`` meets under ``cfg``."""
    found: dict[str, str] = {}
    if cfg.on_over and row.status == headroom.OVER:
        found[OVER] = (
            f"over at max scale: short by {-row.left} IPs "
            f"({row.free} free, {row.demand} demand at max)"
        )
    if cfg.forecast_days > 0 and fc is not None and fc.growing and fc.within(cfg.forecast_days):
        free_zero = (
            f", free = 0 in {fc.exhaustion_text}" if fc.days_to_exhaustion is not None else ""
        )
        found[FORECAST] = (
            f"forecast: demand at max scale stops fitting in {fc.headroom_text}"
            f"{free_zero} ({fc.trend_text})"
        )
    usable = row.subnet.usable
    if cfg.free_pct > 0 and usable > 0:
        pct = 100.0 * max(row.free, 0) / usable
        if pct < cfg.free_pct:
            found[LOW_FREE] = (
                f"free {pct:.1f}% (< {cfg.free_pct:g}%): {max(row.free, 0)} of {usable} usable IPs"
            )
    return found


def changes(
    h: headroom.Headroom,
    forecasts: Mapping[str, forecast.SubnetForecast],
    cfg: AlertSettings,
    last: Mapping[str, str],
) -> list[SubnetAlert]:
    """The subnets whose state differs from ``last`` (subnet id -> last state sent; absent
    = clear), in the headroom's order (worst first)."""
    out = []
    for row in h.subnets:
        sid = row.subnet.subnet_id
        found = conditions(row, forecasts.get(sid), cfg)
        conds = tuple(sorted(found))
        previous = tuple(c for c in last.get(sid, "").split(",") if c)
        if conds == previous:
            continue
        out.append(
            SubnetAlert(
                sid, row.subnet.name, row.subnet.az, conds, tuple(found[c] for c in conds), previous
            )
        )
    return out


def subnet_text(a: SubnetAlert, include_ids: bool) -> str:
    """ "app-a (us-east-1a)"; with ids "app-a · subnet-a (us-east-1a)"."""
    name = a.name or ("" if include_ids else "unnamed subnet")
    label = " · ".join(p for p in (name, a.subnet_id if include_ids else "") if p)
    return f"{label} ({a.az})" if a.az else label


def account_text(snap: Mapping[str, Any], include_ids: bool) -> str:
    """The account's frozen display name / alias; its id only with ``include_ids``."""
    name = snap["account_name"] or snap["account_alias"] or ""
    account_id = snap["account_id"] or ""
    if include_ids and account_id:
        return f"{name} ({account_id})" if name else account_id
    return name or "AWS account"


def message(
    found: Sequence[SubnetAlert],
    *,
    account: str,
    region: str,
    include_ids: bool,
    max_lines: int = MAX_LINES,
) -> str:
    alerting = sum(1 for a in found if not a.resolved)
    head = f"IPLens alert · {account}" + (f" · {region}" if region else "")
    summary = f"{alerting} subnet(s) alerting, {len(found) - alerting} resolved"
    lines = [head, summary]
    for a in found[:max_lines]:
        if a.resolved:
            was = ", ".join(CONDITION_LABELS.get(c, c) for c in a.previous)
            lines.append(f"• {subnet_text(a, include_ids)}: resolved (was: {was})")
        else:
            lines.append(f"• {subnet_text(a, include_ids)}: " + "; ".join(a.details))
    if len(found) > max_lines:
        lines.append(f"… and {len(found) - max_lines} more subnet(s)")
    return "\n".join(lines)


def payload(text: str, fmt: str = DEFAULT_FORMAT) -> dict[str, Any]:
    """The webhook body of ``text`` in the webhook format ``fmt`` (slack | teams)."""
    if fmt == TEAMS:
        body = [{"type": "TextBlock", "text": line, "wrap": True} for line in text.split("\n")]
        body[0]["weight"] = "Bolder"
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                    },
                }
            ],
        }
    return {"text": text}


# -- delivery -------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect is an error: never re-send the alert elsewhere


_OPENER = urllib.request.build_opener(_NoRedirect)


def post_json(url: str, body: dict[str, Any], timeout: float = WEBHOOK_TIMEOUT) -> None:
    """POST ``body`` as JSON to the https ``url``; WebhookError unless a 2xx answers."""
    try:
        parse_webhook_url(url)
    except ValueError as exc:
        raise WebhookError(str(exc)) from None
    req = urllib.request.Request(  # noqa: S310 (https only, checked above)
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"IPLens/{__version__}"},
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        raise WebhookError(f"the webhook answered HTTP {exc.code}") from None
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise WebhookError(f"the webhook could not be reached ({type(reason).__name__})") from None
    if not 200 <= status < 300:
        raise WebhookError(f"the webhook answered HTTP {status}")


def send_test(cfg: AlertSettings, sender: Sender | None = None) -> None:
    """Send :data:`TEST_TEXT`; WebhookError when it fails or no URL is set."""
    if not cfg.configured:
        raise WebhookError("no webhook URL is set")
    (sender or post_json)(cfg.webhook_url, payload(TEST_TEXT, cfg.webhook_format))


# -- state and the post-Refresh run ---------------------------------------------------------


def load_state(conn: sqlite3.Connection, account_ref: int) -> dict[str, str]:
    return {
        r["subnet_id"]: r["state"]
        for r in conn.execute(
            "SELECT subnet_id, state FROM alert_state WHERE account_ref=?", (account_ref,)
        )
    }


def save_state(
    conn: sqlite3.Connection, account_ref: int, sent: Sequence[SubnetAlert], now: datetime
) -> None:
    for a in sent:
        if a.resolved:
            conn.execute(
                "DELETE FROM alert_state WHERE account_ref=? AND subnet_id=?",
                (account_ref, a.subnet_id),
            )
        else:
            conn.execute(
                "INSERT INTO alert_state(account_ref, subnet_id, state, sent_at) VALUES(?,?,?,?) "
                "ON CONFLICT(account_ref, subnet_id) DO UPDATE SET state = excluded.state, "
                "sent_at = excluded.sent_at",
                (account_ref, a.subnet_id, a.state, now.isoformat(timespec="seconds")),
            )


def evaluate(
    conn: sqlite3.Connection,
    account_ref: int,
    cfg: AlertSettings,
    *,
    sender: Sender | None = None,
    now: datetime | None = None,
) -> list[SubnetAlert]:
    """Check the account's latest snapshot and send the changed subnets in one message.

    Returns the subnets sent ([] when nothing changed or no webhook is set). Raises
    WebhookError when the send fails; the state is then left as it was."""
    if not cfg.configured:
        return []
    snap = queries.latest_snapshot(conn, account_ref)
    if snap is None:
        return []
    now = now or datetime.now(UTC)
    # Alerts cover every subnet of the account: the scope only limits what the pages show.
    h = headroom.for_snapshot(conn, snap["id"], UNSCOPED)
    t = trends.load(conn, account_ref, forecast.DEFAULT_WINDOW_DAYS, UNSCOPED, now=now)
    forecasts = forecast.for_subnets(h, t, now=now)
    last = load_state(conn, account_ref)
    # A subnet gone from the snapshot is dropped silently.
    present = {r.subnet.subnet_id for r in h.subnets}
    for sid in set(last) - present:
        conn.execute(
            "DELETE FROM alert_state WHERE account_ref=? AND subnet_id=?", (account_ref, sid)
        )
        del last[sid]
    found = changes(h, forecasts, cfg, last)
    if not found:
        conn.commit()
        return []
    text = message(
        found,
        account=account_text(snap, cfg.include_ids),
        region=snap["region"] or "",
        include_ids=cfg.include_ids,
    )
    try:
        (sender or post_json)(cfg.webhook_url, payload(text, cfg.webhook_format))
    except Exception as exc:
        conn.commit()  # the pruning above still stands
        if isinstance(exc, WebhookError):
            raise
        raise WebhookError(f"sending failed ({type(exc).__name__})") from exc
    save_state(conn, account_ref, found, now)
    conn.commit()
    return found
