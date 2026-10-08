"""Opt-in VPC flow log analysis: ``observed`` evidence for the Extended view.

1. :func:`estimate` finds the VPC's flow logs that are delivered to CloudWatch Logs
   (``ec2:DescribeFlowLogs``) and estimates how many bytes a Logs Insights query over
   the chosen window would scan (``logs:DescribeLogGroups``: stored bytes spread over
   the retained period). The user confirms before anything is queried.
2. :func:`run` starts one Logs Insights query (``logs:StartQuery``, polled with
   ``logs:GetQueryResults``, ``logs:StopQuery`` on timeout - the only non
   Describe/List/Get calls the read-only guard allows). The query itself aggregates
   accepted flows by source address, destination address, destination port and
   protocol; :func:`aggregate` maps addresses to the snapshot's ENIs and only these
   ENI<->ENI/port aggregates are stored. Raw records are never stored or logged, and
   a peer outside the snapshot is kept only as "internet" or "outside".
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .aws import AwsGateway
from .db import closing

log = logging.getLogger(__name__)

WINDOWS = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440}
WINDOW_LABELS = {"15m": "15 minutes", "1h": "1 hour", "6h": "6 hours", "24h": "24 hours"}
DEFAULT_WINDOW = "1h"
# CloudWatch Logs Insights list price per GB scanned (us-east-1), for the estimate only.
PRICE_PER_GB = 0.005
QUERY_TIMEOUT_S = 120
POLL_INTERVAL_S = 2.0
MAX_ROWS = 10000  # Logs Insights' own limit
INTERNET, OUTSIDE = "internet", "outside"
PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}

# ``dstPort < srcPort`` keeps the client -> server direction of a connection (servers
# listen on the lower port), so response traffic to ephemeral ports is not counted
# as a separate "service".
QUERY = (
    'filter action = "ACCEPT" and dstPort < srcPort '
    "| stats count(*) as flows, sum(bytes) as bytes, sum(packets) as packets "
    "by srcAddr, dstAddr, dstPort, protocol "
    f"| sort flows desc | limit {MAX_ROWS}"
)


class FlowLogError(RuntimeError):
    """A safe, user-facing reason the flow log query could not run."""


def parse_window(value: str | None) -> str:
    return value if value in WINDOWS else DEFAULT_WINDOW


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@dataclass
class Estimate:
    window: str
    log_groups: list[str] = field(default_factory=list)
    stored_bytes: int = 0
    estimated_bytes: int = 0
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        gb = self.estimated_bytes / 1024**3
        return {
            "window": self.window,
            "window_label": WINDOW_LABELS[self.window],
            "log_groups": self.log_groups,
            "estimated_bytes": self.estimated_bytes,
            "estimated_label": human_bytes(self.estimated_bytes),
            "cost_label": f"≈ ${gb * PRICE_PER_GB:.4f} at ${PRICE_PER_GB}/GB scanned",
            "warnings": self.warnings,
        }


def vpc_log_groups(gw: AwsGateway, vpc_id: str, subnet_ids: Iterable[str]) -> list[str]:
    """CloudWatch Logs groups receiving flow logs of the VPC or one of its subnets."""
    ec2 = gw.client("ec2")
    ids = [vpc_id, *subnet_ids]
    groups: set[str] = set()
    for i in range(0, len(ids), 200):
        pages = ec2.get_paginator("describe_flow_logs").paginate(
            Filters=[{"Name": "resource-id", "Values": ids[i : i + 200]}]
        )
        for page in pages:
            for fl in page.get("FlowLogs", []):
                if fl.get("LogDestinationType", "cloud-watch-logs") == "cloud-watch-logs" and (
                    fl.get("LogGroupName")
                ):
                    groups.add(fl["LogGroupName"])
    return sorted(groups)


def estimate(
    gw: AwsGateway,
    vpc_id: str,
    subnet_ids: Iterable[str],
    window: str,
    now: datetime | None = None,
) -> Estimate:
    """Estimated bytes a query over ``window`` scans: each group's stored bytes times
    the share of its retained period (retention, or its age if shorter) the window covers."""
    window = parse_window(window)
    now = now or datetime.now(UTC)
    est = Estimate(window, vpc_log_groups(gw, vpc_id, subnet_ids))
    if not est.log_groups:
        est.warnings.append(
            f"No flow logs to CloudWatch Logs found for {vpc_id} (S3 / Firehose "
            "destinations are not queried)."
        )
        return est
    logs = gw.client("logs")
    window_s = WINDOWS[window] * 60
    for name in est.log_groups:
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        g = next((x for x in groups if x.get("logGroupName") == name), None)
        if g is None:
            est.warnings.append(f"Log group {name} not found or not readable.")
            continue
        stored = int(g.get("storedBytes") or 0)
        age_s = max(now.timestamp() - (g.get("creationTime") or 0) / 1000, 1.0)
        retained_s = (g.get("retentionInDays") or 0) * 86400 or age_s
        span = max(min(retained_s, age_s), window_s)
        est.stored_bytes += stored
        est.estimated_bytes += int(stored * window_s / span)
    return est


@dataclass
class RunResult:
    window: str
    log_groups: list[str]
    bytes_scanned: int = 0
    rows: int = 0
    pairs: int = 0
    skipped: int = 0  # rows with no known ENI on either side


def _ip_index(conn: sqlite3.Connection, snap_id: int) -> dict[str, str]:
    return {
        r["ip"]: r["eni_id"]
        for r in conn.execute("SELECT ip, eni_id FROM ips WHERE snapshot_id=?", (snap_id,))
    }


def _peer(addr: str, index: dict[str, str]) -> str:
    if addr in index:
        return index[addr]
    try:
        return OUTSIDE if ipaddress.ip_address(addr).is_private else INTERNET
    except ValueError:
        return OUTSIDE


def aggregate(
    rows: Iterable[dict[str, str]], index: dict[str, str]
) -> tuple[dict[tuple[str, str, str, int], list[int]], int]:
    """ENI<->ENI/port aggregates of Insights rows; returns (aggregates, skipped rows).

    Addresses are mapped to ENI ids (``internet`` / ``outside`` for unknown peers) and
    then discarded; rows without a known ENI on either side are skipped.
    """
    out: dict[tuple[str, str, str, int], list[int]] = {}
    skipped = 0
    for r in rows:
        src, dst = _peer(r.get("srcAddr", ""), index), _peer(r.get("dstAddr", ""), index)
        if src in (INTERNET, OUTSIDE) and dst in (INTERNET, OUTSIDE):
            skipped += 1
            continue
        proto = PROTOCOLS.get(str(r.get("protocol", "")), str(r.get("protocol", "")) or "?")
        try:
            port = int(float(r.get("dstPort") or 0))
            nums = [int(float(r.get(k) or 0)) for k in ("flows", "bytes", "packets")]
        except ValueError:
            skipped += 1
            continue
        agg = out.setdefault((src, dst, proto[:10], port), [0, 0, 0])
        for i, v in enumerate(nums):
            agg[i] += v
    return out, skipped


def _query(
    logs: Any,
    groups: list[str],
    start: datetime,
    end: datetime,
    sleep: Callable[[float], None],
    timeout_s: float,
) -> tuple[list[dict[str, str]], int]:
    qid = logs.start_query(
        logGroupNames=groups,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=QUERY,
        limit=MAX_ROWS,
    )["queryId"]
    waited = 0.0
    while True:
        resp = logs.get_query_results(queryId=qid)
        status = resp.get("status", "")
        if status == "Complete":
            break
        if status in ("Failed", "Cancelled", "Timeout", "Unknown"):
            raise FlowLogError(f"Logs Insights query ended with status {status}.")
        if waited >= timeout_s:
            try:
                logs.stop_query(queryId=qid)
            except Exception:  # noqa: BLE001 - best effort; the query times out anyway
                log.warning("could not stop flow log query")
            raise FlowLogError(f"Logs Insights query did not finish within {timeout_s:.0f}s.")
        sleep(POLL_INTERVAL_S)
        waited += POLL_INTERVAL_S
    rows = [{c["field"]: c.get("value", "") for c in row} for row in resp.get("results", [])]
    scanned = int(float((resp.get("statistics") or {}).get("bytesScanned") or 0))
    return rows, scanned


def run(
    gw: AwsGateway,
    db_path: Path,
    snap_id: int,
    vpc_id: str,
    subnet_ids: Iterable[str],
    window: str,
    *,
    now: datetime | None = None,
    sleep: Callable[[float], None] = time.sleep,
    timeout_s: float = QUERY_TIMEOUT_S,
) -> RunResult:
    """Query the VPC's flow logs over ``window`` and store ENI<->ENI/port aggregates."""
    window = parse_window(window)
    groups = vpc_log_groups(gw, vpc_id, subnet_ids)
    if not groups:
        raise FlowLogError(f"No flow logs to CloudWatch Logs found for {vpc_id}.")
    end = now or datetime.now(UTC)
    start = end - timedelta(minutes=WINDOWS[window])
    rows, scanned = _query(gw.client("logs"), groups, start, end, sleep, timeout_s)
    with closing(db_path) as conn:
        aggs, skipped = aggregate(rows, _ip_index(conn, snap_id))
        del rows  # raw query rows are never stored
        conn.execute(
            "DELETE FROM flow_aggregates WHERE snapshot_id=? AND vpc_id=?", (snap_id, vpc_id)
        )
        conn.executemany(
            "INSERT INTO flow_aggregates(snapshot_id, vpc_id, src_eni, dst_eni, protocol, port, "
            "flows, bytes, packets) VALUES(?,?,?,?,?,?,?,?,?)",
            [(snap_id, vpc_id, *k, *v) for k, v in sorted(aggs.items())],
        )
        conn.execute(
            "INSERT INTO flow_runs(snapshot_id, vpc_id, ran_at, window_minutes, log_groups, "
            "bytes_scanned, rows) VALUES(?,?,?,?,?,?,?) ON CONFLICT(snapshot_id, vpc_id) DO "
            "UPDATE SET ran_at=excluded.ran_at, window_minutes=excluded.window_minutes, "
            "log_groups=excluded.log_groups, bytes_scanned=excluded.bytes_scanned, "
            "rows=excluded.rows",
            (
                snap_id,
                vpc_id,
                end.isoformat(timespec="seconds"),
                WINDOWS[window],
                json.dumps(groups),
                scanned,
                len(aggs),
            ),
        )
    log.info(
        "flow log query snapshot=%s %s window=%s: %d aggregate(s), %d skipped",
        snap_id,
        vpc_id,
        window,
        len(aggs),
        skipped,
    )
    return RunResult(window, groups, scanned, len(aggs) + skipped, len(aggs), skipped)


def latest_run(conn: sqlite3.Connection, snap_id: int, vpc_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT ran_at, window_minutes, log_groups, bytes_scanned, rows FROM flow_runs "
        "WHERE snapshot_id=? AND vpc_id=?",
        (snap_id, vpc_id),
    ).fetchone()
    if row is None:
        return None
    return {
        "ran_at": row["ran_at"],
        "window_minutes": row["window_minutes"],
        "log_groups": json.loads(row["log_groups"] or "[]"),
        "bytes_scanned": row["bytes_scanned"],
        "bytes_label": human_bytes(row["bytes_scanned"]),
        "pairs": row["rows"],
    }
