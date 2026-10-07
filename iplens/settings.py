"""Persistent application settings (AWS auth, region, log directory).

The AWS secret access key is stored encrypted and is only ever decrypted in
memory when a boto3 session is built.  It is never returned to templates and
never logged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .crypto import SecretBox
from .db import closing

AUTH_MODES = ("env", "profile", "keys")

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

_ENCRYPTED_ROW = "aws_secret_access_key_enc"


@dataclass
class Settings:
    auth_mode: str = "env"
    profile: str = ""
    access_key_id: str = ""
    region: str = "us-east-1"
    log_dir: str = ""
    has_secret: bool = False
    # Decrypted secret; populated only by SettingsStore.load(with_secret=True).
    secret_access_key: str = field(default="", repr=False)

    def public_dict(self) -> dict[str, object]:
        """Safe representation for templates/logs (no secret material)."""
        return {
            "auth_mode": self.auth_mode,
            "profile": self.profile,
            "access_key_id": mask_key_id(self.access_key_id),
            "region": self.region,
            "log_dir": self.log_dir,
            "has_secret": self.has_secret,
        }


def mask_key_id(key_id: str) -> str:
    if not key_id:
        return ""
    if len(key_id) <= 8:
        return "*" * len(key_id)
    return key_id[:4] + "*" * (len(key_id) - 8) + key_id[-4:]


class SettingsStore:
    def __init__(self, db_path: Path, box: SecretBox):
        self.db_path = db_path
        self.box = box

    def _read_all(self) -> dict[str, str]:
        with closing(self.db_path) as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def load(self, *, with_secret: bool = False) -> Settings:
        raw = self._read_all()
        s = Settings(
            auth_mode=raw.get("auth_mode") or "env",
            profile=raw.get("profile") or "",
            access_key_id=raw.get("access_key_id") or "",
            region=raw.get("region") or "us-east-1",
            log_dir=raw.get("log_dir") or "",
            has_secret=bool(raw.get(_ENCRYPTED_ROW)),
        )
        if with_secret and raw.get(_ENCRYPTED_ROW):
            s.secret_access_key = self.box.decrypt(raw[_ENCRYPTED_ROW])
        return s

    def save(
        self,
        *,
        auth_mode: str,
        region: str,
        profile: str = "",
        access_key_id: str = "",
        secret_access_key: str | None = None,
        clear_secret: bool = False,
        log_dir: str = "",
    ) -> None:
        """Persist settings.

        ``secret_access_key=None`` (or empty) keeps the stored secret, so the
        form never has to round-trip it.  ``clear_secret`` removes it.
        """
        if auth_mode not in AUTH_MODES:
            raise ValueError(f"auth_mode must be one of {AUTH_MODES}")
        region = region.strip()
        if not region:
            raise ValueError("region is required")
        if auth_mode == "profile" and not profile.strip():
            raise ValueError("profile name is required for profile auth")
        if auth_mode == "keys":
            will_have_secret = bool(secret_access_key) or (
                self.load().has_secret and not clear_secret
            )
            if not access_key_id.strip() or not will_have_secret:
                raise ValueError("access key id and secret are required for key auth")
        values = {
            "auth_mode": auth_mode,
            "region": region,
            "profile": profile.strip(),
            "access_key_id": access_key_id.strip(),
            "log_dir": log_dir.strip(),
        }
        with closing(self.db_path) as conn:
            for k, v in values.items():
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, v),
                )
            if clear_secret:
                conn.execute("DELETE FROM settings WHERE key = ?", (_ENCRYPTED_ROW,))
            elif secret_access_key:
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (_ENCRYPTED_ROW, self.box.encrypt(secret_access_key.strip())),
                )
