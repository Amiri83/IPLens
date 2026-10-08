"""Global application settings (log directory, active account) and shared helpers.

AWS credentials are per account; see :mod:`iplens.accounts`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .db import ACTIVE_ACCOUNT_KEY, closing

# A practical list; the GUI also accepts any free-text region code.
REGIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "sa-east-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-east-1",
    "me-south-1",
    "me-central-1",
    "il-central-1",
    "af-south-1",
)

MAX_DISPLAY_NAME = 64


@dataclass
class Settings:
    log_dir: str = ""


def mask_key_id(key_id: str) -> str:
    if not key_id:
        return ""
    if len(key_id) <= 8:
        return "*" * len(key_id)
    return key_id[:4] + "*" * (len(key_id) - 8) + key_id[-4:]


class SettingsStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _get(self, key: str) -> str:
        with closing(self.db_path) as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return (row["value"] if row else "") or ""

    def _set(self, key: str, value: str) -> None:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def load(self) -> Settings:
        return Settings(log_dir=self._get("log_dir"))

    def save(self, *, log_dir: str = "") -> None:
        self._set("log_dir", log_dir.strip())

    def active_account_id(self) -> int | None:
        value = self._get(ACTIVE_ACCOUNT_KEY)
        return int(value) if value.isdigit() else None

    def set_active_account_id(self, account_id: int | None) -> None:
        self._set(ACTIVE_ACCOUNT_KEY, "" if account_id is None else str(account_id))
