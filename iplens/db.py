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
    memory_only       INTEGER NOT NULL DEFAULT 0,
    aws_account_id    TEXT,                   -- AWS account id of the first successful connect
    last_seen_account_id TEXT                 -- AWS account id of the latest successful connect
);

-- account_ref is the IPLens account record (accounts.id); account_id is the AWS account id.
CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at    TEXT NOT NULL,
    region      TEXT NOT NULL,
    account_id  TEXT,
    account_alias TEXT,             -- IAM account alias; '' if none or not permitted
    account_name TEXT,              -- account display name, frozen at capture time
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
    owner_names       TEXT,          -- JSON list of every owning resource (shared Lambda ENIs)
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

-- Security group names: the Name tag ('' if none) and the group name.
CREATE TABLE IF NOT EXISTS security_groups (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',   -- Name tag
    group_name  TEXT NOT NULL DEFAULT '',   -- GroupName
    vpc_id      TEXT,
    PRIMARY KEY (snapshot_id, group_id)
);

-- Tags of ENI-owning resources. resource_type: eni | lb | lambda | ecs_service | endpoint | sg;
-- resource_id: ENI id, LB name, function name, "cluster/service", vpce id or SG id.
CREATE TABLE IF NOT EXISTS resource_tags (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    key           TEXT NOT NULL,
    value         TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, resource_type, resource_id, key)
);

-- Terraform roots loaded from local state files (read-only). Only resource ids,
-- addresses and types are kept; attribute values, outputs and secrets never are.
CREATE TABLE IF NOT EXISTS tf_roots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    source      TEXT NOT NULL DEFAULT '',   -- uploaded file name or local path
    source_path TEXT NOT NULL DEFAULT '',   -- local path for "Reload" ('' for uploads)
    loaded_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tf_resources (
    root_id     INTEGER NOT NULL REFERENCES tf_roots(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,              -- subnet | eni | sg | vpce | lb | lambda | ...
    resource_id TEXT NOT NULL,
    address     TEXT NOT NULL,
    type        TEXT NOT NULL,
    PRIMARY KEY (root_id, address, kind, resource_id)
);
CREATE INDEX IF NOT EXISTS ix_tf_resources_id ON tf_resources(kind, resource_id);

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
    show_subnets INTEGER NOT NULL DEFAULT 1,
    shorten_names INTEGER NOT NULL DEFAULT 0,
    evidence     TEXT              -- Extended view evidence filter; NULL: the default levels
);

-- Per-account scope: the VPCs / subnets / IP ranges every view shows (JSON, see scope.py).
CREATE TABLE IF NOT EXISTS scopes (
    account_ref INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    config      TEXT NOT NULL
);

-- Extended view (opt-in "Crawl services", see extended.py), attached to a snapshot.
-- Only resource names, ARNs and *matched* references are stored: environment variable
-- values, IAM policy documents, secret values and message payloads never are.
CREATE TABLE IF NOT EXISTS ext_crawls (
    snapshot_id INTEGER PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
    crawled_at  TEXT NOT NULL,
    warnings    TEXT NOT NULL DEFAULT '[]',   -- JSON list
    sources     TEXT NOT NULL DEFAULT '{}'    -- JSON {source: items found} of sources that ran
);

-- node_id is "<service>:<name>" (lambda:fn-a, sqs:queue-a, tgw:tgw-0example, ...).
CREATE TABLE IF NOT EXISTS ext_nodes (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    node_id      TEXT NOT NULL,
    service      TEXT NOT NULL,
    name         TEXT NOT NULL,
    arn          TEXT NOT NULL DEFAULT '',
    area         TEXT NOT NULL DEFAULT 'regional',  -- regional | external
    broad_access INTEGER NOT NULL DEFAULT 0,        -- IAM statements allowing Resource "*"
    PRIMARY KEY (snapshot_id, node_id)
);

-- One row per evidence line. source/target are node ids, "vpc:<id>" or "eni:<id>".
CREATE TABLE IF NOT EXISTS ext_edges (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    target      TEXT NOT NULL,
    evidence    TEXT NOT NULL,      -- observed | configured | permitted | referenced
    label       TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, source, target, evidence, detail)
);

-- Notes about a subnet / node (route tables, NACLs, broad IAM access).
CREATE TABLE IF NOT EXISTS ext_facts (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL,      -- "subnet:<id>" or a node id
    detail      TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, subject, detail)
);

-- Opt-in flow log analysis (flowlogs.py): only ENI<->ENI/port aggregates are stored,
-- never raw flow records or the addresses of unknown peers.
CREATE TABLE IF NOT EXISTS flow_runs (
    snapshot_id    INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    vpc_id         TEXT NOT NULL,
    ran_at         TEXT NOT NULL,
    window_minutes INTEGER NOT NULL,
    log_groups     TEXT NOT NULL DEFAULT '[]',  -- JSON list of log group names
    bytes_scanned  INTEGER NOT NULL DEFAULT 0,
    rows           INTEGER NOT NULL DEFAULT 0,  -- aggregate rows returned by the query
    PRIMARY KEY (snapshot_id, vpc_id)
);

-- src_eni / dst_eni: an ENI id, "internet" (public peer) or "outside" (private, unknown).
CREATE TABLE IF NOT EXISTS flow_aggregates (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    vpc_id      TEXT NOT NULL,
    src_eni     TEXT NOT NULL,
    dst_eni     TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    port        INTEGER NOT NULL,
    flows       INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    packets     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, vpc_id, src_eni, dst_eni, protocol, port)
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
    ("snapshots", "account_name", "TEXT"),
    ("accounts", "aws_account_id", "TEXT"),
    ("accounts", "last_seen_account_id", "TEXT"),
    ("enis", "owner_names", "TEXT"),
    ("visual_prefs", "shorten_names", "INTEGER NOT NULL DEFAULT 0"),
    ("visual_prefs", "evidence", "TEXT"),
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
_REGROUPED_KEY = "snapshots_regrouped"


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
        regroup_snapshots(conn)


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


def regroup_snapshots(conn: sqlite3.Connection) -> list[int]:
    """One-off data migration: one account record per distinct AWS account id.

    Before snapshot-frozen labels, one account record could collect from several
    AWS accounts (its credentials were edited), so its snapshots mix account ids.
    Snapshots are re-grouped by their stored ``account_id``:

    * a record keeps the AWS account of its newest successful snapshot (its current
      credentials resolve there); that id becomes the record's ``aws_account_id``;
    * every other AWS account id goes to the record that already owns it, else to a
      new record (``env`` auth, the snapshot's region, the IAM alias as display name;
      its credentials must be configured before it can refresh). Visual layouts of
      the VPCs seen in moved snapshots are copied along;
    * snapshots without an account id (failed collections) stay where they are;
    * snapshots without a frozen ``account_name`` get their record's display name.

    Returns the ids of the records created. Runs once per database.
    """
    if conn.execute("SELECT 1 FROM settings WHERE key=?", (_REGROUPED_KEY,)).fetchone():
        return []
    own: dict[int, str] = {}  # account record -> its AWS account id
    for rec in conn.execute("SELECT id FROM accounts ORDER BY id").fetchall():
        newest = conn.execute(
            "SELECT account_id FROM snapshots WHERE account_ref=? AND status='ok' "
            "AND COALESCE(account_id, '') != '' ORDER BY id DESC LIMIT 1",
            (rec["id"],),
        ).fetchone()
        if newest:
            own[rec["id"]] = newest["account_id"]
    # AWS account id -> record for snapshots that must move (first record that owns it).
    owner: dict[str, int] = {}
    for rec_id, aws_id in own.items():
        owner.setdefault(aws_id, rec_id)
    created: list[int] = []
    rows = conn.execute(
        "SELECT id, account_ref, account_id, account_alias, region FROM snapshots "
        "WHERE COALESCE(account_id, '') != '' ORDER BY id DESC"
    ).fetchall()
    for snap in rows:
        if snap["account_ref"] is not None and own.get(snap["account_ref"]) == snap["account_id"]:
            continue  # two records of one AWS account (e.g. two regions) stay apart
        target = owner.get(snap["account_id"])
        if target is None:
            cur = conn.execute(
                "INSERT INTO accounts(display_name, region, auth_mode, aws_account_id, "
                "last_seen_account_id) VALUES(?, ?, 'env', ?, ?)",
                (
                    snap["account_alias"] or "",
                    snap["region"],
                    snap["account_id"],
                    snap["account_id"],
                ),
            )
            target = owner[snap["account_id"]] = int(cur.lastrowid or 0)
            own[target] = snap["account_id"]
            created.append(target)
        if snap["account_ref"] is not None:
            conn.execute(
                "INSERT OR IGNORE INTO visual_layouts(account_ref, vpc_id, positions) "
                "SELECT ?, l.vpc_id, l.positions FROM visual_layouts l "
                "JOIN vpcs v ON v.vpc_id = l.vpc_id AND v.snapshot_id = ? "
                "WHERE l.account_ref = ?",
                (target, snap["id"], snap["account_ref"]),
            )
        conn.execute("UPDATE snapshots SET account_ref=? WHERE id=?", (target, snap["id"]))
    for rec_id, aws_id in own.items():
        conn.execute(
            "UPDATE accounts SET aws_account_id = COALESCE(NULLIF(aws_account_id, ''), ?), "
            "last_seen_account_id = COALESCE(NULLIF(last_seen_account_id, ''), ?) WHERE id=?",
            (aws_id, aws_id, rec_id),
        )
    conn.execute(
        "UPDATE snapshots SET account_name = COALESCE("
        "(SELECT display_name FROM accounts a WHERE a.id = snapshots.account_ref), '') "
        "WHERE account_name IS NULL"
    )
    conn.execute("INSERT INTO settings(key, value) VALUES(?, '1')", (_REGROUPED_KEY,))
    return created


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
