import sqlite3

from iplens import queries, viewstate
from iplens.db import closing, init_db


def test_init_db_adds_account_alias_to_existing_database(tmp_path):
    p = tmp_path / "old.db"
    conn = sqlite3.connect(p)
    conn.execute(
        "CREATE TABLE snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, taken_at TEXT NOT NULL, "
        "region TEXT NOT NULL, account_id TEXT, status TEXT NOT NULL, error TEXT, warnings TEXT)"
    )
    conn.execute(
        "INSERT INTO snapshots(taken_at, region, account_id, status) "
        "VALUES('2026-01-01T00:00:00+00:00', 'us-east-1', '123456789012', 'ok')"
    )
    conn.commit()
    conn.close()

    init_db(p)
    init_db(p)  # idempotent

    with closing(p) as c:
        row = c.execute("SELECT account_id, account_alias, account_ref FROM snapshots").fetchone()
        cols = {r["name"] for r in c.execute("PRAGMA table_info(rules)")}
    # the existing snapshot now belongs to the migrated default account
    assert (row["account_id"], row["account_alias"], row["account_ref"]) == (
        "123456789012",
        None,
        1,
    )
    assert "account_ref" in cols


def test_init_db_adds_shorten_names_to_existing_visual_prefs(tmp_path):
    p = tmp_path / "old.db"
    init_db(p)
    with closing(p) as c:  # a visual_prefs table from before the "Shorten long names" toggle
        c.execute("DROP TABLE visual_prefs")
        c.execute(
            "CREATE TABLE visual_prefs (account_ref INTEGER PRIMARY KEY, "
            "show_vpc INTEGER NOT NULL DEFAULT 1, show_subnets INTEGER NOT NULL DEFAULT 1)"
        )
        c.execute("INSERT INTO visual_prefs VALUES(1, 0, 1)")

    init_db(p)

    with closing(p) as c:
        assert viewstate.get_prefs(c, 1) == {
            "show_vpc": False,
            "show_subnets": True,
            "shorten_names": False,
            "show_legend": True,
        }


def test_init_db_adds_evidence_filter_to_existing_visual_prefs(tmp_path):
    p = tmp_path / "old.db"
    init_db(p)
    with closing(p) as c:  # a visual_prefs table from before the Extended view filter
        c.execute("DROP TABLE visual_prefs")
        c.execute(
            "CREATE TABLE visual_prefs (account_ref INTEGER PRIMARY KEY, "
            "show_vpc INTEGER NOT NULL DEFAULT 1, show_subnets INTEGER NOT NULL DEFAULT 1, "
            "shorten_names INTEGER NOT NULL DEFAULT 0)"
        )
        c.execute("INSERT INTO visual_prefs VALUES(1, 0, 1, 1)")

    init_db(p)

    with closing(p) as c:
        assert viewstate.get_evidence(c, 1) == ("observed", "configured")
        viewstate.save_evidence(c, 1, ("referenced",))
        assert viewstate.get_evidence(c, 1) == ("referenced",)
        assert viewstate.get_prefs(c, 1)["shorten_names"] is True


def test_prune_and_history_are_per_account(db_path, snapshot_builder):
    with closing(db_path) as conn:
        conn.execute("INSERT INTO accounts(region, auth_mode) VALUES('us-east-1', 'env')")
    a = [snapshot_builder(db_path, account_ref=1).id for _ in range(3)]
    a_failed = snapshot_builder(db_path, account_ref=1, status="failed").id
    b = [snapshot_builder(db_path, account_ref=2).id for _ in range(2)]
    running = snapshot_builder(db_path, account_ref=2, status="running").id

    with closing(db_path) as conn:
        assert queries.protected_snapshot_ids(conn) == {a[2], b[1]}
        assert queries.latest_snapshot(conn, 1)["id"] == a[2]
        assert queries.latest_snapshot(conn, 2)["id"] == b[1]
        assert [r["id"] for r in queries.recent_snapshots(conn, 10, 2)] == [running, b[1], b[0]]
        # keep=1 per account: the newest row of account 1 is a failed one, so its latest
        # good snapshot is kept as well; the running collection is never touched
        assert queries.prune_snapshots(conn, keep=1) == 3
        remaining = {r["id"] for r in conn.execute("SELECT id FROM snapshots")}
    assert remaining == {a[2], a_failed, b[1], running}
