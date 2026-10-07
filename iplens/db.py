"""SQLite storage: schema and connection helpers."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at    TEXT NOT NULL,
    region      TEXT NOT NULL,
    account_id  TEXT,
    status      TEXT NOT NULL,
    error       TEXT,
    warnings    TEXT
);

CREATE TABLE IF NOT EXISTS vpcs (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    vpc_id      TEXT NOT NULL,
    name        TEXT,
    cidrs       TEXT NOT NULL,      -- JSON list
    is_default  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, vpc_id)
);

CREATE TABLE IF NOT EXISTS subnets (
    snapshot_id        INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    subnet_id          TEXT NOT NULL,
    vpc_id             TEXT NOT NULL,
    name               TEXT,
    cidr               TEXT NOT NULL,
    az                 TEXT,
    available_ip_count INTEGER,
    PRIMARY KEY (snapshot_id, subnet_id)
);

CREATE TABLE IF NOT EXISTS enis (
    snapshot_id       INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    eni_id            TEXT NOT NULL,
    subnet_id         TEXT,
    vpc_id            TEXT,
    az                TEXT,
    status            TEXT,
    interface_type    TEXT,
    requester_id      TEXT,
    requester_managed INTEGER NOT NULL DEFAULT 0,
    description       TEXT,
    instance_id       TEXT,
    security_groups   TEXT,          -- JSON list of group ids
    owner_type        TEXT NOT NULL,
    owner_ref         TEXT,
    name              TEXT,
    PRIMARY KEY (snapshot_id, eni_id)
);

CREATE TABLE IF NOT EXISTS ips (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    ip_int      INTEGER NOT NULL,
    eni_id      TEXT NOT NULL,
    subnet_id   TEXT,
    vpc_id      TEXT,
    is_primary  INTEGER NOT NULL DEFAULT 0,
    public_ip   TEXT,
    owner_type  TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, ip, eni_id)
);
CREATE INDEX IF NOT EXISTS ix_ips_subnet ON ips(snapshot_id, subnet_id);

CREATE TABLE IF NOT EXISTS lambdas (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    vpc_id      TEXT,
    subnet_ids  TEXT,               -- JSON list
    security_groups TEXT,           -- JSON list
    PRIMARY KEY (snapshot_id, name)
);

CREATE TABLE IF NOT EXISTS endpoints (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    endpoint_id   TEXT NOT NULL,
    vpc_id        TEXT,
    service_name  TEXT,
    endpoint_type TEXT,
    subnet_ids    TEXT,             -- JSON list
    eni_ids       TEXT,             -- JSON list
    PRIMARY KEY (snapshot_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS load_balancers (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    lb_type     TEXT,
    scheme      TEXT,
    vpc_id      TEXT,
    PRIMARY KEY (snapshot_id, name)
);

CREATE TABLE IF NOT EXISTS ecs_services (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    cluster         TEXT NOT NULL,
    service         TEXT NOT NULL,
    desired_count   INTEGER,
    running_count   INTEGER,
    last_deployment TEXT,           -- ISO timestamp of the newest deployment
    PRIMARY KEY (snapshot_id, cluster, service)
);

CREATE TABLE IF NOT EXISTS ecs_task_enis (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    eni_id      TEXT NOT NULL,
    cluster     TEXT NOT NULL,
    service     TEXT NOT NULL,      -- '' for standalone tasks
    task_id     TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, eni_id)
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    params      TEXT NOT NULL DEFAULT '{}',   -- JSON object
    enabled     INTEGER NOT NULL DEFAULT 1,
    description TEXT
);
"""


def connect(db_path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), detect_types=0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path | str) -> None:
    with closing(db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def closing(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a connection, commit on success, roll back on error, always close."""
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
