"""Account records, credential parsing/storage, profile discovery and the data migration.

Placeholder credentials only: none of these values is a real AWS credential.
"""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from iplens.accounts import (
    EXPIRED_MESSAGE,
    Account,
    AccountStore,
    MemoryVault,
    discover_profiles,
    expires_in_text,
    parse_temporary_credentials,
)
from iplens.crypto import SecretBox
from iplens.db import closing, init_db

FAKE_KEY_ID = "AKIAEXAMPLEEXAMPLE00"
FAKE_TEMP_KEY_ID = "ASIAEXAMPLEEXAMPLE00"
FAKE_SECRET = "example/secret/value/for/tests/only/0000"
FAKE_SESSION_TOKEN = "FakeSessionTokenForTestsOnly0000000000000000000000Example"
EXPIRATION = "2026-10-07T20:30:00+00:00"


@pytest.fixture
def box(tmp_path):
    return SecretBox.from_path(tmp_path / "secret.key")


@pytest.fixture
def store(db_path, box):
    return AccountStore(db_path, box, MemoryVault())


def _dump(db_path) -> str:
    with closing(db_path) as conn:
        return "\n".join(conn.iterdump())


# -- paste parser -------------------------------------------------------------------


def test_parse_three_fields():
    creds = parse_temporary_credentials(
        f"  {FAKE_TEMP_KEY_ID}\n{FAKE_SECRET}\t {FAKE_SESSION_TOKEN}  "
    )
    assert creds.access_key_id == FAKE_TEMP_KEY_ID
    assert creds.secret_access_key == FAKE_SECRET
    assert creds.session_token == FAKE_SESSION_TOKEN
    assert creds.expiration is None


@pytest.mark.parametrize(
    "block",
    [
        f"export AWS_ACCESS_KEY_ID={FAKE_TEMP_KEY_ID}\n"
        f'export AWS_SECRET_ACCESS_KEY="{FAKE_SECRET}"\n'
        f"export AWS_SESSION_TOKEN='{FAKE_SESSION_TOKEN}'\n"
        "export AWS_DEFAULT_REGION=us-east-1\n",
        # comments, blank lines, no "export", Windows "set" and PowerShell "$env:"
        f"# example\n\nAWS_ACCESS_KEY_ID={FAKE_TEMP_KEY_ID}\n"
        f"set AWS_SECRET_ACCESS_KEY={FAKE_SECRET}\n"
        f'$env:AWS_SESSION_TOKEN="{FAKE_SESSION_TOKEN}";\n',
    ],
)
def test_parse_export_block(block):
    creds = parse_temporary_credentials(block)
    assert (creds.access_key_id, creds.secret_access_key, creds.session_token) == (
        FAKE_TEMP_KEY_ID,
        FAKE_SECRET,
        FAKE_SESSION_TOKEN,
    )
    assert creds.expiration is None


def test_parse_export_block_with_expiration():
    creds = parse_temporary_credentials(
        f"export AWS_ACCESS_KEY_ID={FAKE_TEMP_KEY_ID}\n"
        f"export AWS_SECRET_ACCESS_KEY={FAKE_SECRET}\n"
        f"export AWS_SESSION_TOKEN={FAKE_SESSION_TOKEN}\n"
        f"export AWS_CREDENTIAL_EXPIRATION={EXPIRATION}\n"
    )
    assert creds.expiration == datetime(2026, 10, 7, 20, 30, tzinfo=UTC)


def test_parse_sts_get_session_token_json():
    doc = {
        "Credentials": {
            "AccessKeyId": FAKE_TEMP_KEY_ID,
            "SecretAccessKey": FAKE_SECRET,
            "SessionToken": FAKE_SESSION_TOKEN,
            "Expiration": EXPIRATION,
        }
    }
    creds = parse_temporary_credentials(json.dumps(doc, indent=4))
    assert creds.access_key_id == FAKE_TEMP_KEY_ID
    assert creds.secret_access_key == FAKE_SECRET
    assert creds.session_token == FAKE_SESSION_TOKEN
    assert creds.expiration == datetime(2026, 10, 7, 20, 30, tzinfo=UTC)
    # "Z" suffix and a flat object (no "Credentials" wrapper) work too
    flat = dict(doc["Credentials"], Expiration="2026-10-07T20:30:00Z")
    assert parse_temporary_credentials(json.dumps(flat)).expiration == creds.expiration


@pytest.mark.parametrize(
    "text, message",
    [
        ("", "paste the temporary credentials"),
        (f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET}", "expected 3 whitespace-separated fields"),
        (f"short {FAKE_SECRET} {FAKE_SESSION_TOKEN}", "access key id looks malformed"),
        ('{"Credentials": {"AccessKeyId": "' + FAKE_TEMP_KEY_ID + '"}}', "missing secret"),
        ('{"AccessKeyId": ' + "'" + FAKE_SECRET, "could not parse the pasted JSON"),
        (
            json.dumps(
                {
                    "AccessKeyId": FAKE_TEMP_KEY_ID,
                    "SecretAccessKey": FAKE_SECRET,
                    "SessionToken": FAKE_SESSION_TOKEN,
                    "Expiration": "tomorrow " + FAKE_SECRET,
                }
            ),
            "Expiration must be an ISO 8601 timestamp",
        ),
        (
            f"export AWS_ACCESS_KEY_ID={FAKE_TEMP_KEY_ID}\n"
            f"export AWS_SESSION_TOKEN={FAKE_SESSION_TOKEN}",
            "missing secret access key",
        ),
        (f"export AWS_ACCESS_KEY_ID={FAKE_TEMP_KEY_ID}\ngarbage {FAKE_SECRET}", "every line"),
    ],
)
def test_parse_errors_never_echo_input(text, message):
    with pytest.raises(ValueError, match=message) as info:
        parse_temporary_credentials(text)
    err = str(info.value)
    assert FAKE_SECRET not in err and FAKE_SESSION_TOKEN not in err
    assert FAKE_TEMP_KEY_ID not in err


def test_parsed_credentials_repr_hides_secrets():
    creds = parse_temporary_credentials(f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET} {FAKE_SESSION_TOKEN}")
    assert FAKE_SECRET not in repr(creds) and FAKE_SESSION_TOKEN not in repr(creds)


# -- expiry ---------------------------------------------------------------------------


def test_expires_in_text():
    now = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    assert expires_in_text(now + timedelta(minutes=42, seconds=30), now) == "expires in 42m"
    assert expires_in_text(now + timedelta(hours=3, minutes=5), now) == "expires in 3h 5m"
    assert expires_in_text(now - timedelta(seconds=1), now) == "expired"
    assert expires_in_text(None, now) == "expiry unknown"


def test_account_status_and_problem():
    now = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    acct = Account(
        auth_mode="temporary",
        access_key_id=FAKE_TEMP_KEY_ID,
        has_secret=True,
        has_session_token=True,
        expires_at=now + timedelta(minutes=15),
    )
    assert acct.status_text(now) == "expires in 15m"
    assert acct.credential_problem(now) == ""
    later = now + timedelta(minutes=16)
    assert acct.is_expired(later)
    assert (
        acct.credential_problem(later) == EXPIRED_MESSAGE == "credentials expired, paste new ones"
    )
    assert acct.public_dict(later)["expired"] is True
    assert Account(auth_mode="env").credential_problem() == ""


# -- store: encryption at rest, memory-only -----------------------------------------------


def test_keys_are_encrypted_at_rest(store, db_path, box):
    acct_id = store.save(
        None,
        display_name="example-dev",
        region="eu-west-1",
        auth_mode="keys",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    assert FAKE_SECRET not in _dump(db_path)
    with closing(db_path) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (acct_id,)).fetchone()
    # the DB-encryption path (SecretBox/Fernet) was used for the stored value
    assert row["secret_enc"] and box.decrypt(row["secret_enc"]) == FAKE_SECRET
    assert row["session_token_enc"] is None

    acct = store.get(acct_id)
    assert acct.has_secret and acct.secret_access_key == ""
    assert store.get(acct_id, with_secret=True).secret_access_key == FAKE_SECRET


def test_temporary_credentials_encrypted_with_expiry(store, db_path, box):
    acct_id = store.save(
        None,
        display_name="example-temp",
        region="us-east-1",
        auth_mode="temporary",
        paste=f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET} {FAKE_SESSION_TOKEN}",
    )
    dump = _dump(db_path)
    assert FAKE_SECRET not in dump and FAKE_SESSION_TOKEN not in dump
    with closing(db_path) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (acct_id,)).fetchone()
    assert box.decrypt(row["session_token_enc"]) == FAKE_SESSION_TOKEN
    assert box.decrypt(row["secret_enc"]) == FAKE_SECRET

    store.save(
        acct_id,
        display_name="example-temp",
        region="us-east-1",
        auth_mode="temporary",
        paste=json.dumps(
            {
                "Credentials": {
                    "AccessKeyId": FAKE_TEMP_KEY_ID,
                    "SecretAccessKey": FAKE_SECRET,
                    "SessionToken": FAKE_SESSION_TOKEN,
                    "Expiration": EXPIRATION,
                }
            }
        ),
    )
    full = store.get(acct_id, with_secret=True)
    assert full.session_token == FAKE_SESSION_TOKEN
    assert full.expires_at == datetime(2026, 10, 7, 20, 30, tzinfo=UTC)

    # a blank paste keeps the stored credentials and expiry
    store.save(acct_id, display_name="renamed", region="us-east-2", auth_mode="temporary")
    kept = store.get(acct_id, with_secret=True)
    assert (kept.display_name, kept.session_token, kept.expires_at) == (
        "renamed",
        FAKE_SESSION_TOKEN,
        full.expires_at,
    )


def test_memory_only_never_persisted_and_lost_on_restart(store, db_path, box):
    acct_id = store.save(
        None,
        display_name="example-memory",
        region="us-east-1",
        auth_mode="temporary",
        paste=f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET} {FAKE_SESSION_TOKEN}",
        memory_only=True,
    )
    with closing(db_path) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (acct_id,)).fetchone()
    assert row["secret_enc"] is None and row["session_token_enc"] is None
    assert FAKE_SECRET not in _dump(db_path) and FAKE_SESSION_TOKEN not in _dump(db_path)
    acct = store.get(acct_id, with_secret=True)
    assert acct.memory_only and acct.session_token == FAKE_SESSION_TOKEN
    assert FAKE_SECRET not in repr(store.vault)

    # a new process (new vault) no longer has them
    restarted = AccountStore(db_path, box, MemoryVault()).get(acct_id)
    assert not restarted.has_secret
    assert "paste them again" in restarted.credential_problem()

    # turning memory-only off persists the in-memory credentials, encrypted
    store.save(acct_id, display_name="", region="us-east-1", auth_mode="temporary")
    with closing(db_path) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (acct_id,)).fetchone()
    assert box.decrypt(row["session_token_enc"]) == FAKE_SESSION_TOKEN
    assert store.vault.get(acct_id) is None


def test_switching_mode_drops_secrets(store, db_path):
    acct_id = store.save(
        None,
        display_name="",
        region="us-east-1",
        auth_mode="keys",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    store.save(acct_id, display_name="", region="us-east-1", auth_mode="env")
    with closing(db_path) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (acct_id,)).fetchone()
    assert row["secret_enc"] is None and row["access_key_id"] == ""


@pytest.mark.parametrize(
    "kwargs, msg",
    [
        ({"auth_mode": "bogus"}, "auth mode"),
        ({"auth_mode": "env", "region": " "}, "region"),
        ({"auth_mode": "profile"}, "profile"),
        ({"auth_mode": "keys", "access_key_id": FAKE_KEY_ID}, "secret"),
        (
            {"auth_mode": "keys", "access_key_id": "x", "secret_access_key": FAKE_SECRET},
            "malformed",
        ),
        ({"auth_mode": "temporary"}, "paste the temporary credentials"),
        ({"auth_mode": "env", "display_name": "x" * 65}, "display name"),
    ],
)
def test_validation(store, kwargs, msg):
    kwargs = {"display_name": "", "region": "us-east-1", **kwargs}
    with pytest.raises(ValueError, match=msg):
        store.save(None, **kwargs)


def test_public_dict_never_contains_secrets(store):
    acct_id = store.save(
        None,
        display_name="",
        region="us-east-1",
        auth_mode="temporary",
        paste=f"{FAKE_TEMP_KEY_ID} {FAKE_SECRET} {FAKE_SESSION_TOKEN}",
    )
    acct = store.get(acct_id, with_secret=True)
    text = str(acct.public_dict()) + repr(acct)
    assert FAKE_SECRET not in text and FAKE_SESSION_TOKEN not in text
    assert FAKE_TEMP_KEY_ID not in text  # key id is masked


def test_delete_cascades_snapshots(store, db_path, snapshot_builder):
    acct_id = store.save(None, display_name="example-b", region="us-east-1", auth_mode="env")
    b = snapshot_builder(db_path, account_ref=acct_id)
    b.vpc("vpc-0example0000002", "10.1.0.0/16")
    assert store.delete(acct_id)
    with closing(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE id=?", (b.id,)).fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM vpcs WHERE snapshot_id=?", (b.id,)).fetchone()[0]
            == 0
        )
    assert not store.delete(acct_id)


# -- named profiles -------------------------------------------------------------------


def test_discover_profiles_includes_sso(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text(
        "[default]\nregion = us-east-1\n\n"
        "[profile example-readonly]\nregion = us-east-2\n\n"
        "[profile example-sso]\nsso_session = example-org\nsso_account_id = 123456789012\n"
        "sso_role_name = ExampleReadOnly\n\n"
        "[profile example-legacy-sso]\nsso_start_url = https://example.invalid/start\n\n"
        "[sso-session example-org]\nsso_start_url = https://example.invalid/start\n\n"
        "[services example-endpoints]\nec2 =\n  endpoint_url = http://localhost:4566\n"
    )
    creds = tmp_path / "credentials"
    pair = f"aws_access_key_id = {FAKE_KEY_ID}\naws_secret_access_key = {FAKE_SECRET}\n"
    creds.write_text(f"[default]\n{pair}\n[example-keys]\n{pair}")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    profiles = {p.name: p for p in discover_profiles()}
    assert set(profiles) == {
        "default",
        "example-keys",
        "example-legacy-sso",
        "example-readonly",
        "example-sso",
    }
    assert profiles["example-sso"].sso and profiles["example-legacy-sso"].sso
    assert not profiles["example-readonly"].sso
    assert profiles["example-sso"].label == "example-sso (SSO)"
    assert profiles["default"].sources == ("config", "credentials")
    assert profiles["example-keys"].sources == ("credentials",)
    # only names: no credential value leaks into the result
    assert FAKE_SECRET not in repr(profiles) and FAKE_KEY_ID not in repr(profiles)


def test_discover_profiles_missing_or_broken_files(tmp_path, caplog):
    assert discover_profiles(tmp_path / "nope", tmp_path / "nope2") == []
    broken = tmp_path / "broken"
    broken.write_text(f"aws_secret_access_key = {FAKE_SECRET}\n")  # no section header
    assert discover_profiles(broken, tmp_path / "nope") == []
    assert FAKE_SECRET not in caplog.text
    assert "MissingSectionHeaderError" in caplog.text


# -- migration from the single settings object ------------------------------------------------

_OLD_SCHEMA = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, taken_at TEXT NOT NULL, region TEXT NOT NULL,
    account_id TEXT, account_alias TEXT, status TEXT NOT NULL, error TEXT, warnings TEXT);
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1, description TEXT);
"""


def test_migrates_single_settings_into_account(tmp_path, box):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(_OLD_SCHEMA)
    legacy = {
        "auth_mode": "keys",
        "profile": "",
        "access_key_id": FAKE_KEY_ID,
        "region": "eu-west-1",
        "account_display_name": "Example Prod",
        "aws_secret_access_key_enc": box.encrypt(FAKE_SECRET),
        "log_dir": "/srv/example-logs",
    }
    conn.executemany("INSERT INTO settings VALUES(?, ?)", legacy.items())
    conn.execute(
        "INSERT INTO snapshots(taken_at, region, account_id, status) "
        "VALUES('2026-01-01T00:00:00+00:00', 'eu-west-1', '123456789012', 'ok')"
    )
    conn.commit()
    conn.close()

    init_db(path)
    store = AccountStore(path, box, MemoryVault())
    (acct,) = store.list()
    full = store.get(acct.id, with_secret=True)
    assert (full.display_name, full.region, full.auth_mode, full.access_key_id) == (
        "Example Prod",
        "eu-west-1",
        "keys",
        FAKE_KEY_ID,
    )
    assert full.secret_access_key == FAKE_SECRET  # ciphertext carried over unchanged
    with closing(path) as c:
        settings = dict(c.execute("SELECT key, value FROM settings").fetchall())
        assert c.execute("SELECT account_ref FROM snapshots").fetchone()[0] == acct.id
    assert settings["active_account"] == str(acct.id)
    assert settings["log_dir"] == "/srv/example-logs"  # global setting stays
    assert "aws_secret_access_key_enc" not in settings and "auth_mode" not in settings

    init_db(path)  # idempotent
    assert len(store.list()) == 1


def test_fresh_database_gets_default_env_account(db_path, box):
    (acct,) = AccountStore(db_path, box).list()
    assert (acct.auth_mode, acct.region, acct.display_name) == ("env", "us-east-1", "")
    # deleting every account does not resurrect the default on the next start
    AccountStore(db_path, box).delete(acct.id)
    init_db(db_path)
    assert AccountStore(db_path, box).list() == []
