import os
import stat

import pytest

from iplens.crypto import SecretBox
from iplens.db import closing
from iplens.settings import SettingsStore, mask_key_id

FAKE_KEY_ID = "AKIAEXAMPLEEXAMPLE00"
FAKE_SECRET = "example/secret/value/for/tests/only/0000"


@pytest.fixture
def store(db_path, tmp_path):
    return SettingsStore(db_path, SecretBox.from_path(tmp_path / "secret.key"))


def test_defaults(store):
    s = store.load()
    assert s.auth_mode == "env"
    assert s.region == "us-east-1"
    assert not s.has_secret


def test_secret_is_encrypted_at_rest(store, db_path):
    store.save(
        auth_mode="keys",
        region="eu-west-1",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    with closing(db_path) as conn:
        dump = "\n".join(conn.iterdump())
    assert FAKE_SECRET not in dump
    s = store.load()
    assert s.has_secret and s.secret_access_key == ""
    assert store.load(with_secret=True).secret_access_key == FAKE_SECRET


def test_secret_kept_when_blank_and_clearable(store):
    store.save(
        auth_mode="keys",
        region="us-east-1",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    store.save(
        auth_mode="keys", region="us-east-2", access_key_id=FAKE_KEY_ID, secret_access_key=None
    )
    assert store.load(with_secret=True).secret_access_key == FAKE_SECRET
    store.save(auth_mode="env", region="us-east-2", clear_secret=True)
    assert not store.load().has_secret


def test_public_dict_never_contains_secret(store):
    store.save(
        auth_mode="keys",
        region="us-east-1",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    s = store.load(with_secret=True)
    pub = s.public_dict()
    assert FAKE_SECRET not in str(pub)
    assert FAKE_KEY_ID not in str(pub)
    assert FAKE_SECRET not in repr(s)


@pytest.mark.parametrize(
    "kwargs, msg",
    [
        ({"auth_mode": "bogus", "region": "us-east-1"}, "auth_mode"),
        ({"auth_mode": "env", "region": " "}, "region"),
        ({"auth_mode": "profile", "region": "us-east-1"}, "profile"),
        ({"auth_mode": "keys", "region": "us-east-1", "access_key_id": FAKE_KEY_ID}, "secret"),
        (
            {"auth_mode": "env", "region": "us-east-1", "account_display_name": "x" * 65},
            "display name",
        ),
    ],
)
def test_validation(store, kwargs, msg):
    with pytest.raises(ValueError, match=msg):
        store.save(**kwargs)


def test_account_display_name_round_trip(store):
    assert store.load().account_display_name == ""
    store.save(auth_mode="env", region="us-east-1", account_display_name="  Example   Prod ")
    s = store.load()
    assert s.account_display_name == "Example Prod"
    assert s.public_dict()["account_display_name"] == "Example Prod"
    store.save(auth_mode="env", region="us-east-1", account_display_name="")
    assert store.load().account_display_name == ""


def test_invalid_keys_save_does_not_persist(store):
    with pytest.raises(ValueError):
        store.save(auth_mode="keys", region="ap-south-1", access_key_id=FAKE_KEY_ID)
    assert store.load().region == "us-east-1"


def test_key_file_permissions(tmp_path):
    path = tmp_path / "k" / "secret.key"
    box = SecretBox.from_path(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    token = box.encrypt("hello")
    assert SecretBox.from_path(path).decrypt(token) == "hello"
    assert "redacted" in repr(box)


def test_env_key_overrides_file(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("IPLENS_SECRET_KEY", key)
    box = SecretBox.from_path(tmp_path / "unused.key")
    assert not (tmp_path / "unused.key").exists()
    other = SecretBox(Fernet.generate_key())
    with pytest.raises(ValueError):
        other.decrypt(box.encrypt("x"))


def test_mask_key_id():
    assert mask_key_id("") == ""
    assert mask_key_id("short") == "*****"
    masked = mask_key_id(FAKE_KEY_ID)
    assert masked == "AKIA" + "*" * 12 + "LE00"
