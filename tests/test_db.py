import sqlite3

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
        row = c.execute("SELECT account_id, account_alias FROM snapshots").fetchone()
    assert (row["account_id"], row["account_alias"]) == ("123456789012", None)
