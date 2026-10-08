"""AWS account records: auth configuration, credentials and named-profile discovery.

Secret values (secret access key, session token) are stored Fernet-encrypted
(:class:`~iplens.crypto.SecretBox`) or, for memory-only accounts, held in a
process-local :class:`MemoryVault` and never written anywhere. They are decrypted
only to build a boto3 session, are never part of :meth:`Account.public_dict`, never
logged, and never included in an error message (parser errors describe the shape
of the input, not its content).
"""

from __future__ import annotations

import configparser
import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .crypto import SecretBox
from .db import closing
from .settings import MAX_DISPLAY_NAME, mask_key_id

log = logging.getLogger(__name__)

AUTH_MODES = ("env", "profile", "keys", "temporary")
AUTH_MODE_LABELS = {
    "env": "Environment",
    "profile": "Named profile",
    "keys": "Access key",
    "temporary": "Temporary credentials",
}
SECRET_MODES = ("keys", "temporary")

EXPIRED_MESSAGE = "credentials expired, paste new ones"
NOT_IN_MEMORY_MESSAGE = (
    "memory-only credentials are no longer in memory (IPLens restarted), paste them again"
)

# IAM AccessKeyId: 16-128 word characters (AKIA... long-term, ASIA... temporary).
_KEY_ID_RX = re.compile(r"\w{16,128}")
MAX_PASTE = 16_384


class CredentialError(ValueError):
    """Credentials are missing, incomplete or expired. The message is safe to show."""


# -- account record ----------------------------------------------------------------


def expires_in_text(expires_at: datetime | None, now: datetime | None = None) -> str:
    """``"expires in 42m"`` / ``"expires in 3h 5m"`` / ``"expired"`` / ``"expiry unknown"``."""
    if expires_at is None:
        return "expiry unknown"
    seconds = (expires_at - (now or datetime.now(UTC))).total_seconds()
    if seconds <= 0:
        return "expired"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"expires in {minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"expires in {hours}h {minutes}m"


def identity_mismatch_message(expected: str, seen: str) -> str:
    """Warning text when credentials resolved to ``seen`` instead of ``expected`` ('' if same)."""
    if not expected or not seen or expected == seen:
        return ""
    return (
        f"credentials now resolve to AWS account {seen}, but this account was first "
        f"connected to {expected}"
    )


@dataclass
class Account:
    id: int | None = None
    display_name: str = ""
    region: str = "us-east-1"
    auth_mode: str = "env"
    profile: str = ""
    access_key_id: str = field(default="", repr=False)
    expires_at: datetime | None = None
    memory_only: bool = False
    has_secret: bool = False
    has_session_token: bool = False
    # Decrypted secrets; populated only by AccountStore.get(..., with_secret=True).
    secret_access_key: str = field(default="", repr=False)
    session_token: str = field(default="", repr=False)
    # AWS account id of the first successful connect, and of the latest one.
    aws_account_id: str = ""
    last_seen_account_id: str = ""

    @property
    def mode_label(self) -> str:
        return AUTH_MODE_LABELS.get(self.auth_mode, self.auth_mode)

    @property
    def identity_warning(self) -> str:
        """Set when the credentials now resolve to another AWS account than at first."""
        return identity_mismatch_message(self.aws_account_id, self.last_seen_account_id)

    def is_expired(self, now: datetime | None = None) -> bool:
        return (
            self.auth_mode == "temporary"
            and self.expires_at is not None
            and self.expires_at <= (now or datetime.now(UTC))
        )

    def credential_problem(self, now: datetime | None = None) -> str:
        """Why this account cannot be used right now ('' when it can)."""
        if self.auth_mode not in SECRET_MODES:
            return ""
        if self.is_expired(now):
            return EXPIRED_MESSAGE
        has_secret = self.has_secret or bool(self.secret_access_key)
        missing = not self.access_key_id or not has_secret
        if self.auth_mode == "temporary":
            missing = missing or not (self.has_session_token or self.session_token)
        if missing:
            return NOT_IN_MEMORY_MESSAGE if self.memory_only else "credentials are incomplete"
        return ""

    def status_text(self, now: datetime | None = None) -> str:
        problem = self.credential_problem(now)
        if problem:
            return problem
        if self.auth_mode == "temporary":
            return expires_in_text(self.expires_at, now)
        return ""

    def public_dict(self, now: datetime | None = None) -> dict[str, Any]:
        """Safe representation for templates/logs (no secret material)."""
        return {
            "id": self.id,
            "display_name": self.display_name,
            "region": self.region,
            "auth_mode": self.auth_mode,
            "mode_label": self.mode_label,
            "profile": self.profile,
            "access_key_id": mask_key_id(self.access_key_id),
            "has_secret": self.has_secret,
            "has_session_token": self.has_session_token,
            "memory_only": self.memory_only,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "expired": self.is_expired(now),
            "problem": self.credential_problem(now),
            "status": self.status_text(now),
            "aws_account_id": self.aws_account_id,
            "last_seen_account_id": self.last_seen_account_id,
            "identity_warning": self.identity_warning,
        }


class MemoryVault:
    """Credentials of memory-only accounts, kept in this process only."""

    def __init__(self) -> None:
        self._items: dict[int, tuple[str, str]] = {}

    def put(self, account_id: int, secret: str, token: str) -> None:
        self._items[account_id] = (secret, token)

    def get(self, account_id: int) -> tuple[str, str] | None:
        return self._items.get(account_id)

    def drop(self, account_id: int) -> None:
        self._items.pop(account_id, None)

    def __repr__(self) -> str:  # never expose secrets
        return f"MemoryVault(<{len(self._items)} account(s)>)"


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


class AccountStore:
    def __init__(self, db_path: Path, box: SecretBox, vault: MemoryVault | None = None):
        self.db_path = db_path
        self.box = box
        self.vault = vault if vault is not None else MemoryVault()

    def _from_row(self, r: sqlite3.Row, with_secret: bool) -> Account:
        acct = Account(
            id=r["id"],
            display_name=r["display_name"] or "",
            region=r["region"],
            auth_mode=r["auth_mode"],
            profile=r["profile"] or "",
            access_key_id=r["access_key_id"] or "",
            expires_at=_parse_ts(r["expires_at"]),
            memory_only=bool(r["memory_only"]),
            aws_account_id=r["aws_account_id"] or "",
            last_seen_account_id=r["last_seen_account_id"] or "",
        )
        if acct.memory_only:
            secret, token = self.vault.get(acct.id) or ("", "")
            acct.has_secret, acct.has_session_token = bool(secret), bool(token)
            if with_secret:
                acct.secret_access_key, acct.session_token = secret, token
        else:
            acct.has_secret = bool(r["secret_enc"])
            acct.has_session_token = bool(r["session_token_enc"])
            if with_secret and r["secret_enc"]:
                acct.secret_access_key = self.box.decrypt(r["secret_enc"])
            if with_secret and r["session_token_enc"]:
                acct.session_token = self.box.decrypt(r["session_token_enc"])
        return acct

    def list(self) -> list[Account]:
        with closing(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()
        return [self._from_row(r, False) for r in rows]

    def get(self, account_id: int | None, *, with_secret: bool = False) -> Account | None:
        if account_id is None:
            return None
        with closing(self.db_path) as conn:
            row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return self._from_row(row, with_secret) if row else None

    def save(
        self,
        account_id: int | None,
        *,
        display_name: str,
        region: str,
        auth_mode: str,
        profile: str = "",
        access_key_id: str = "",
        secret_access_key: str | None = None,
        paste: str | None = None,
        memory_only: bool = False,
    ) -> int:
        """Create (``account_id=None``) or update an account; return its id.

        Blank ``access_key_id`` / ``secret_access_key`` / ``paste`` keep the stored
        values of the same auth mode, so the form never round-trips secrets.
        Switching to a mode without secrets drops any stored ones.
        """
        if auth_mode not in AUTH_MODES:
            raise ValueError(f"auth mode must be one of {', '.join(AUTH_MODES)}")
        display_name = " ".join(display_name.split())
        if len(display_name) > MAX_DISPLAY_NAME:
            raise ValueError(f"display name must be at most {MAX_DISPLAY_NAME} characters")
        region = region.strip()
        if not region:
            raise ValueError("region is required")
        profile = profile.strip()
        if auth_mode == "profile" and not profile:
            raise ValueError("choose a named profile")
        existing = None
        if account_id is not None:
            existing = self.get(account_id, with_secret=True)
            if existing is None:
                raise ValueError("unknown account")
        same_mode = existing is not None and existing.auth_mode == auth_mode

        key_id, secret, token, expires = "", "", "", None
        if auth_mode == "keys":
            key_id = access_key_id.strip() or (existing.access_key_id if same_mode else "")
            secret = (secret_access_key or "").strip() or (
                existing.secret_access_key if same_mode else ""
            )
            if not key_id or not secret:
                raise ValueError("access key id and secret are required for key auth")
            if not _KEY_ID_RX.fullmatch(key_id):
                raise ValueError("access key id looks malformed")
        elif auth_mode == "temporary":
            if paste and paste.strip():
                creds = parse_temporary_credentials(paste)
                key_id, secret = creds.access_key_id, creds.secret_access_key
                token, expires = creds.session_token, creds.expiration
            elif same_mode and existing.secret_access_key and existing.session_token:
                key_id, secret = existing.access_key_id, existing.secret_access_key
                token, expires = existing.session_token, existing.expires_at
            else:
                raise ValueError(
                    "paste the temporary credentials (access key id, secret and session token)"
                )
        memory_only = memory_only and auth_mode in SECRET_MODES

        values = (
            display_name,
            region,
            auth_mode,
            profile if auth_mode == "profile" else "",
            key_id,
            None if memory_only or not secret else self.box.encrypt(secret),
            None if memory_only or not token else self.box.encrypt(token),
            expires.astimezone(UTC).isoformat(timespec="seconds") if expires else None,
            int(memory_only),
        )
        cols = (
            "display_name, region, auth_mode, profile, access_key_id, secret_enc, "
            "session_token_enc, expires_at, memory_only"
        )
        with closing(self.db_path) as conn:
            if account_id is None:
                cur = conn.execute(
                    f"INSERT INTO accounts({cols}) VALUES(?,?,?,?,?,?,?,?,?)",  # noqa: S608
                    values,
                )
                account_id = int(cur.lastrowid or 0)
            else:
                sets = ", ".join(f"{c.strip()}=?" for c in cols.split(","))
                conn.execute(
                    f"UPDATE accounts SET {sets} WHERE id=?",  # noqa: S608 - fixed names
                    (*values, account_id),
                )
        if memory_only:
            self.vault.put(account_id, secret, token)
        else:
            self.vault.drop(account_id)
        return account_id

    def record_identity(self, account_id: int, aws_account_id: str) -> str:
        """Remember the AWS account id a successful connect resolved to.

        The first one is kept as the account's identity; returns a warning ('' if
        none) when a later connect resolves to a different AWS account.
        """
        if not aws_account_id:
            return ""
        with closing(self.db_path) as conn:
            conn.execute(
                "UPDATE accounts SET aws_account_id = COALESCE(NULLIF(aws_account_id, ''), ?), "
                "last_seen_account_id = ? WHERE id=?",
                (aws_account_id, aws_account_id, account_id),
            )
            row = conn.execute(
                "SELECT aws_account_id FROM accounts WHERE id=?", (account_id,)
            ).fetchone()
        return identity_mismatch_message(row["aws_account_id"] if row else "", aws_account_id)

    def delete(self, account_id: int) -> bool:
        """Delete an account with its snapshots and Visual state."""
        self.vault.drop(account_id)
        with closing(self.db_path) as conn:
            cur = conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        return cur.rowcount > 0


# -- temporary credential paste parser ------------------------------------------------


@dataclass(frozen=True)
class TemporaryCredentials:
    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expiration: datetime | None = None


_ENV_LINE = re.compile(
    r"^\s*(?:export\s+|set\s+|\$env:)?(AWS_[A-Z_]+)\s*=\s*(.*?)\s*;?\s*$", re.IGNORECASE
)
_ENV_NAMES = {
    "AWS_ACCESS_KEY_ID": "access_key_id",
    "AWS_SECRET_ACCESS_KEY": "secret_access_key",
    "AWS_SESSION_TOKEN": "session_token",
    "AWS_SECURITY_TOKEN": "session_token",
    "AWS_CREDENTIAL_EXPIRATION": "expiration",
}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _parse_expiration(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Expiration must be an ISO 8601 timestamp")
    try:
        ts = datetime.fromisoformat(value.strip())
    except ValueError:
        raise ValueError("Expiration must be an ISO 8601 timestamp") from None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _from_json(text: str) -> dict[str, Any]:
    try:
        doc = json.loads(text)
    except ValueError:
        raise ValueError("could not parse the pasted JSON") from None
    if not isinstance(doc, dict):
        raise ValueError("expected a JSON object")
    creds = doc.get("Credentials", doc)
    if not isinstance(creds, dict):
        raise ValueError("expected a 'Credentials' object")
    out: dict[str, Any] = {
        "access_key_id": creds.get("AccessKeyId"),
        "secret_access_key": creds.get("SecretAccessKey"),
        "session_token": creds.get("SessionToken"),
    }
    if creds.get("Expiration"):
        out["expiration"] = _parse_expiration(creds["Expiration"])
    return out


def _from_env_block(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            raise ValueError("every line must look like: export AWS_NAME=value")
        target = _ENV_NAMES.get(m.group(1).upper())
        if target is None:
            continue  # e.g. AWS_REGION, AWS_DEFAULT_REGION
        value = _unquote(m.group(2))
        out[target] = _parse_expiration(value) if target == "expiration" else value
    return out


def parse_temporary_credentials(text: str) -> TemporaryCredentials:
    """Parse pasted temporary credentials.

    Accepted forms:

    * three whitespace-separated fields: access key id, secret access key, session token;
    * an ``export AWS_ACCESS_KEY_ID=...`` block (``AWS_SECRET_ACCESS_KEY``,
      ``AWS_SESSION_TOKEN``, optional ``AWS_CREDENTIAL_EXPIRATION``; ``set`` and
      PowerShell ``$env:`` prefixes work too);
    * the JSON output of ``aws sts get-session-token`` (or ``assume-role``), including
      ``Expiration``.

    Error messages never contain any part of the input.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("paste the temporary credentials")
    if len(text) > MAX_PASTE:
        raise ValueError("pasted text is too long")
    if text.startswith("{"):
        fields = _from_json(text)
    elif re.search(r"AWS_ACCESS_KEY_ID", text, re.IGNORECASE):
        fields = _from_env_block(text)
    else:
        parts = text.split()
        if len(parts) != 3:
            raise ValueError(
                f"expected 3 whitespace-separated fields (access key id, secret, session "
                f"token), got {len(parts)}"
            )
        fields = dict(
            zip(("access_key_id", "secret_access_key", "session_token"), parts, strict=True)
        )
    missing = [
        label
        for key, label in (
            ("access_key_id", "access key id"),
            ("secret_access_key", "secret access key"),
            ("session_token", "session token"),
        )
        if not isinstance(fields.get(key), str) or not fields[key].strip()
    ]
    if missing:
        raise ValueError(f"missing {', '.join(missing)}")
    key_id = fields["access_key_id"].strip()
    if not _KEY_ID_RX.fullmatch(key_id):
        raise ValueError("access key id looks malformed")
    secret, token = fields["secret_access_key"].strip(), fields["session_token"].strip()
    if any(ch.isspace() for ch in secret + token):
        raise ValueError("secret and session token must not contain whitespace")
    return TemporaryCredentials(key_id, secret, token, fields.get("expiration"))


# -- named profiles -----------------------------------------------------------------


@dataclass(frozen=True)
class ProfileInfo:
    name: str
    sso: bool = False
    sources: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.name} (SSO)" if self.sso else self.name


_SSO_KEYS = {"sso_start_url", "sso_session", "sso_account_id", "sso_role_name"}


def _section_keys(path: Path) -> dict[str, set[str]]:
    """Section name -> option *names* of an AWS ini file. Values are never returned."""
    if not path.is_file():
        return {}
    parser = configparser.RawConfigParser(strict=False, default_section="\0none")
    try:
        with path.open(encoding="utf-8") as fh:
            parser.read_file(fh)
    except (OSError, UnicodeDecodeError, configparser.Error) as exc:
        # The exception text can quote file content (i.e. credentials): type only.
        log.warning("could not read AWS profiles from %s (%s)", path, type(exc).__name__)
        return {}
    return {s: set(parser.options(s)) for s in parser.sections()}


def discover_profiles(
    config_file: str | os.PathLike[str] | None = None,
    credentials_file: str | os.PathLike[str] | None = None,
) -> list[ProfileInfo]:
    """Named profiles from ``~/.aws/config`` and ``~/.aws/credentials``.

    Honours ``AWS_CONFIG_FILE`` / ``AWS_SHARED_CREDENTIALS_FILE``. SSO profiles
    (``sso_start_url`` or ``sso_session``) are flagged; ``[sso-session ...]`` and
    ``[services ...]`` sections are not profiles and are skipped.
    """
    cfg = Path(config_file or os.environ.get("AWS_CONFIG_FILE") or "~/.aws/config").expanduser()
    cred = Path(
        credentials_file or os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or "~/.aws/credentials"
    ).expanduser()
    found: dict[str, dict[str, Any]] = {}
    for section, keys in _section_keys(cfg).items():
        if section == "default":
            name = "default"
        elif section.startswith("profile "):
            name = section[len("profile ") :].strip()
        else:
            continue
        entry = found.setdefault(name, {"sso": False, "sources": set()})
        entry["sso"] = entry["sso"] or bool(keys & _SSO_KEYS)
        entry["sources"].add("config")
    for section in _section_keys(cred):
        name = section.removeprefix("profile ").strip()
        found.setdefault(name, {"sso": False, "sources": set()})["sources"].add("credentials")
    return [
        ProfileInfo(name, e["sso"], tuple(sorted(e["sources"])))
        for name, e in sorted(found.items())
        if name
    ]
