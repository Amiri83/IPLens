"""Global application settings (log directory, active account) and shared helpers.

AWS credentials are per account; see :mod:`iplens.accounts`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .db import ACTIVE_ACCOUNT_KEY, closing
from .environment import DEFAULT_TAG_KEYS, parse_tag_keys

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
# Terraform repo sync: seconds each allowlisted terraform command may run.
DEFAULT_TF_TIMEOUT = 120
MIN_TF_TIMEOUT, MAX_TF_TIMEOUT = 10, 3600


@dataclass
class Settings:
    log_dir: str = ""
    tf_timeout: int = DEFAULT_TF_TIMEOUT
    # Tag keys an environment is read from, in order (see iplens.environment).
    env_tag_keys: tuple[str, ...] = DEFAULT_TAG_KEYS

    @property
    def env_tag_keys_text(self) -> str:
        return ", ".join(self.env_tag_keys)


def parse_tf_timeout(value: str | int | None) -> int:
    """A timeout in seconds within [MIN_TF_TIMEOUT, MAX_TF_TIMEOUT]; ValueError otherwise."""
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("the Terraform timeout must be a whole number of seconds") from None
    if not MIN_TF_TIMEOUT <= seconds <= MAX_TF_TIMEOUT:
        raise ValueError(f"the Terraform timeout must be {MIN_TF_TIMEOUT}-{MAX_TF_TIMEOUT} seconds")
    return seconds


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
        try:
            timeout = parse_tf_timeout(self._get("tf_timeout") or DEFAULT_TF_TIMEOUT)
        except ValueError:
            timeout = DEFAULT_TF_TIMEOUT
        raw_keys = self._get("env_tag_keys")
        return Settings(
            log_dir=self._get("log_dir"),
            tf_timeout=timeout,
            env_tag_keys=parse_tag_keys(raw_keys) if raw_keys else DEFAULT_TAG_KEYS,
        )

    def save(
        self,
        *,
        log_dir: str = "",
        tf_timeout: int | None = None,
        env_tag_keys: str | None = None,
    ) -> None:
        """Store the settings; ``None`` keeps a value unchanged."""
        self._set("log_dir", log_dir.strip())
        if tf_timeout is not None:
            self._set("tf_timeout", str(parse_tf_timeout(tf_timeout)))
        if env_tag_keys is not None:
            keys = parse_tag_keys(env_tag_keys)
            self._set("env_tag_keys", ",".join(keys or DEFAULT_TAG_KEYS))

    def active_account_id(self) -> int | None:
        value = self._get(ACTIVE_ACCOUNT_KEY)
        return int(value) if value.isdigit() else None

    def set_active_account_id(self, account_id: int | None) -> None:
        self._set(ACTIVE_ACCOUNT_KEY, "" if account_id is None else str(account_id))
