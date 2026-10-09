"""Global application settings (log directory, active account) and shared helpers.

AWS credentials are per account; see :mod:`iplens.accounts`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import ownership, retention
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
# Ownership tag key settings and their defaults; a stored "-" means "not used".
_OWN_KEY_DEFAULTS = {
    "project": ownership.DEFAULT_PROJECT_KEY,
    "env": ownership.DEFAULT_ENV_KEY,
    "team": ownership.DEFAULT_TEAM_KEY,
    "owner": ownership.DEFAULT_OWNER_KEY,
}
_KEY_UNUSED = "-"


@dataclass
class Settings:
    log_dir: str = ""
    tf_timeout: int = DEFAULT_TF_TIMEOUT
    # Tag keys an environment is read from, in order (see iplens.environment).
    env_tag_keys: tuple[str, ...] = DEFAULT_TAG_KEYS
    # Ownership (see iplens.ownership): tag keys, CI role patterns and optional sources.
    own_project_key: str = ownership.DEFAULT_PROJECT_KEY
    own_env_key: str = ownership.DEFAULT_ENV_KEY
    own_team_key: str = ownership.DEFAULT_TEAM_KEY
    own_owner_key: str = ownership.DEFAULT_OWNER_KEY
    ci_patterns: tuple[str, ...] = ownership.DEFAULT_CI_PATTERNS
    tf_enrichment: bool = False  # Terraform state as an ownership source (off by default)
    cloudtrail_lookup: bool = False  # CloudTrail creator of still unowned resources
    # Snapshot retention (see iplens.retention).
    retention_days: int = retention.RETENTION_DAYS
    downsample_days: int = retention.DOWNSAMPLE_AFTER_DAYS

    @property
    def retention_policy(self) -> retention.Policy:
        return retention.Policy(self.retention_days, self.downsample_days)

    @property
    def env_tag_keys_text(self) -> str:
        return ", ".join(self.env_tag_keys)

    @property
    def env_keys(self) -> tuple[str, ...]:
        """Environment tag keys: the Ownership environment key first, then the list."""
        keys = [self.own_env_key] if self.own_env_key else []
        keys += [k for k in self.env_tag_keys if k.lower() != self.own_env_key.lower()]
        return tuple(keys) or DEFAULT_TAG_KEYS

    def ownership_config(self) -> ownership.OwnershipConfig:
        return ownership.OwnershipConfig(
            project_key=self.own_project_key,
            env_key=self.own_env_key,
            team_key=self.own_team_key,
            owner_key=self.own_owner_key,
            ci_patterns=self.ci_patterns,
            tf_enabled=self.tf_enrichment,
            cloudtrail=self.cloudtrail_lookup,
            extra_value_keys=self.env_tag_keys,
        )


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
        try:
            keep = int(self._get("retention_days") or retention.RETENTION_DAYS)
            thin = int(self._get("downsample_days") or retention.DOWNSAMPLE_AFTER_DAYS)
            retention.validate(keep, thin)
        except ValueError:
            keep, thin = retention.RETENTION_DAYS, retention.DOWNSAMPLE_AFTER_DAYS
        raw_keys = self._get("env_tag_keys")
        patterns = self._get("ci_patterns")
        return Settings(
            log_dir=self._get("log_dir"),
            tf_timeout=timeout,
            env_tag_keys=parse_tag_keys(raw_keys) if raw_keys else DEFAULT_TAG_KEYS,
            **{
                f"own_{name}_key": self._key_setting(name, default)
                for name, default in _OWN_KEY_DEFAULTS.items()
            },
            ci_patterns=(
                ()
                if patterns == _KEY_UNUSED
                else ownership.parse_patterns(patterns)
                if patterns
                else ownership.DEFAULT_CI_PATTERNS
            ),
            tf_enrichment=self._get("tf_enrichment") == "1",
            cloudtrail_lookup=self._get("cloudtrail_lookup") == "1",
            retention_days=keep,
            downsample_days=thin,
        )

    def _key_setting(self, name: str, default: str) -> str:
        """A stored ownership tag key; never set: the default; "-": not used ("")."""
        value = self._get(f"own_{name}_key")
        if not value:
            return default
        return "" if value == _KEY_UNUSED else ownership.clean_tag_key(value)

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

    def save_ownership(
        self,
        *,
        keys: dict[str, str] | None = None,
        ci_patterns: str | None = None,
        tf_enrichment: bool | None = None,
        cloudtrail_lookup: bool | None = None,
    ) -> None:
        """Store the Ownership settings; ``None`` keeps a value unchanged. ``keys`` maps
        a field of :data:`iplens.ownership.TAG_FIELDS` to a tag key ('' = not used)."""
        for name, value in (keys or {}).items():
            if name in ownership.TAG_FIELDS:
                self._set(f"own_{name}_key", ownership.clean_tag_key(value) or _KEY_UNUSED)
        if ci_patterns is not None:
            patterns = ownership.parse_patterns(ci_patterns)
            self._set("ci_patterns", ",".join(patterns) or _KEY_UNUSED)
        if tf_enrichment is not None:
            self._set("tf_enrichment", "1" if tf_enrichment else "0")
        if cloudtrail_lookup is not None:
            self._set("cloudtrail_lookup", "1" if cloudtrail_lookup else "0")

    def save_retention(self, retention_days: str | int, downsample_days: str | int) -> None:
        """Store the retention window and downsample threshold; ValueError if invalid."""
        keep = retention.parse_days(
            retention_days,
            "retention window",
            retention.MIN_RETENTION_DAYS,
            retention.MAX_RETENTION_DAYS,
        )
        thin = retention.parse_days(
            downsample_days,
            "downsample threshold",
            retention.MIN_DOWNSAMPLE_DAYS,
            retention.MAX_DOWNSAMPLE_DAYS,
        )
        retention.validate(keep, thin)
        self._set("retention_days", str(keep))
        self._set("downsample_days", str(thin))

    def active_account_id(self) -> int | None:
        value = self._get(ACTIVE_ACCOUNT_KEY)
        return int(value) if value.isdigit() else None

    def set_active_account_id(self, account_id: int | None) -> None:
        self._set(ACTIVE_ACCOUNT_KEY, "" if account_id is None else str(account_id))
