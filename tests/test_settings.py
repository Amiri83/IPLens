import os
import stat

import pytest

from iplens.crypto import SecretBox
from iplens.settings import SettingsStore, mask_key_id

FAKE_KEY_ID = "AKIAEXAMPLEEXAMPLE00"


@pytest.fixture
def store(db_path):
    return SettingsStore(db_path)


def test_defaults(store):
    assert store.load().log_dir == ""
    # init_db's migration created the default account and made it active
    assert store.active_account_id() == 1


def test_log_dir_round_trip(store):
    store.save(log_dir="  /srv/example-logs ")
    assert store.load().log_dir == "/srv/example-logs"


def test_active_account_round_trip(store):
    store.set_active_account_id(7)
    assert store.active_account_id() == 7
    store.set_active_account_id(None)
    assert store.active_account_id() is None


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
