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

-- AWS accounts IPLens can collect from. Secrets are Fernet-encrypted (crypto.SecretBox);
-- memory-only credentials are never written here.
CREATE TABLE IF NOT EXISTS accounts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name      TEXT NOT NULL DEFAULT '',
    region            TEXT NOT NULL,
    auth_mode         TEXT NOT NULL,          -- env | profile | keys | temporary
    profile           TEXT NOT NULL DEFAULT '',
    access_key_id     TEXT NOT NULL DEFAULT '',
    secret_enc        TEXT,                   -- encrypted secret access key
    session_token_enc TEXT,                   -- encrypted session token (temporary)
    expires_at        TEXT,                   -- ISO UTC expiry of temporary credentials
    memory_only       INTEGER NOT NULL DEFAULT 0
);

-- account_ref is the IPLens account record (accounts.id); account_id is the AWS account id.
CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at    TEXT NOT NULL,
    region      TEXT NOT NULL,
    account_id  TEXT,
    account_alias TEXT,             -- IAM account alias; '' if none or not permitted
    status      TEXT NOT NULL,
    error       TEXT,
    warnings    TEXT,
    account_ref INTEGER REFERENCES accounts(id) ON DELETE CASCADE
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

-- Registered load balancer targets. target_id is an instance id, an IP, a Lambda
-- function name or an ALB name (never a full ARN).
CREATE TABLE IF NOT EXISTS lb_targets (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    lb_name      TEXT NOT NULL,
    target_group TEXT NOT NULL,
    target_type  TEXT NOT NULL,     -- instance | ip | lambda | alb
    target_id    TEXT NOT NULL,
    port         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, lb_name, target_group, target_id, port)
);

-- Load balancers an ECS service forwards through (from the service's loadBalancers).
CREATE TABLE IF NOT EXISTS ecs_service_lbs (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    cluster      TEXT NOT NULL,
    service      TEXT NOT NULL,
    lb_name      TEXT NOT NULL,
    target_group TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, cluster, service, lb_name, target_group)
);

-- Security group rules that reference another security group.
CREATE TABLE IF NOT EXISTS sg_refs (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    group_id     TEXT NOT NULL,
    direction    TEXT NOT NULL,     -- ingress | egress
    ref_group_id TEXT NOT NULL,
    ports        TEXT NOT NULL,     -- e.g. "tcp/443", "tcp/8000-8100", "all"
    PRIMARY KEY (snapshot_id, group_id, direction, ref_group_id, ports)
);

-- Security group ingress rules that allow an IPv4 CIDR (IpRanges).
CREATE TABLE IF NOT EXISTS sg_cidr_rules (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL,
    cidr        TEXT NOT NULL,
    ip_protocol TEXT NOT NULL,     -- "tcp", "udp", "icmp", "-1" (all), ...
    from_port   INTEGER,           -- NULL when the rule has no port range
    to_port     INTEGER,
    PRIMARY KEY (snapshot_id, group_id, cidr, ip_protocol, from_port, to_port)
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    params      TEXT NOT NULL DEFAULT '{}',   -- JSON object
    enabled     INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    account_ref INTEGER             -- NULL: all accounts; else only this accounts.id
);

-- Visual page state per account.
CREATE TABLE IF NOT EXISTS visual_prefs (
    account_ref  INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    show_vpc     INTEGER NOT NULL DEFAULT 1,
    show_subnets INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS visual_layouts (
    account_ref INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    vpc_id      TEXT NOT NULL,
    positions   TEXT NOT NULL,      -- JSON {node id: {"x": .., "y": ..}}
    PRIMARY KEY (account_ref, vpc_id)
);
"""


def connect(db_path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), detect_types=0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# Columns added after v0.1, applied to existing databases: (table, column, type).
_ADDED_COLUMNS = (
    ("snapshots", "account_alias", "TEXT"),
    ("snapshots", "account_ref", "INTEGER REFERENCES accounts(id) ON DELETE CASCADE"),
    ("rules", "account_ref", "INTEGER"),
)

# Single-account settings rows from before multi-account support.
_LEGACY_AUTH_KEYS = (
    "auth_mode",
    "profile",
    "access_key_id",
    "region",
    "account_display_name",
    "aws_secret_access_key_enc",
)
_LEGACY_AUTH_MODES = ("env", "profile", "keys")
ACTIVE_ACCOUNT_KEY = "active_account"
_MIGRATED_KEY = "accounts_migrated"


def init_db(db_path: Path | str) -> None:
    with closing(db_path) as conn:
        conn.executescript(SCHEMA)
        for table, column, ddl in _ADDED_COLUMNS:
            cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        # After the ALTERs: on an old database the column only exists from here on.
        conn.execute("CREATE INDEX IF NOT EXISTS ix_snapshots_account ON snapshots(account_ref)")
        migrate_accounts(conn)


def migrate_accounts(conn: sqlite3.Connection) -> int | None:
    """One-off data migration from the single settings object to an account record.

    The legacy auth settings (mode, profile, key id, region, display name and the
    already-encrypted secret, copied as ciphertext) become one account; existing
    snapshots are assigned to it and it becomes the active account. A fresh
    database gets a default account using the environment credential chain, which
    was the previous default. Returns the new account id, or None if already done.
    """
    if conn.execute("SELECT 1 FROM settings WHERE key=?", (_MIGRATED_KEY,)).fetchone():
        return None
    raw = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}
    account_id = None
    if conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0:
        mode = raw.get("auth_mode") or "env"
        cur = conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode, profile, access_key_id, "
            "secret_enc) VALUES(?,?,?,?,?,?)",
            (
                raw.get("account_display_name") or "",
                raw.get("region") or "us-east-1",
                mode if mode in _LEGACY_AUTH_MODES else "env",
                raw.get("profile") or "",
                raw.get("access_key_id") or "",
                raw.get("aws_secret_access_key_enc") or None,
            ),
        )
        account_id = int(cur.lastrowid or 0)
        conn.execute("UPDATE snapshots SET account_ref=? WHERE account_ref IS NULL", (account_id,))
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (ACTIVE_ACCOUNT_KEY, str(account_id)),
        )
    conn.executemany("DELETE FROM settings WHERE key=?", [(k,) for k in _LEGACY_AUTH_KEYS])
    conn.execute("INSERT INTO settings(key, value) VALUES(?, '1')", (_MIGRATED_KEY,))
    return account_id


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
