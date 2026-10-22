"""Settings of the MCP server that IPLens runs over HTTP (Settings → MCP server).

Stored in the ``settings`` table; the bearer token is encrypted with the credentials' key
(:class:`iplens.crypto.SecretBox`). The HTTP server process gets the token through the
:data:`TOKEN_ENV` environment variable, never on its command line (``ps`` shows argv).
This module must not import the AWS SDK: ``iplens mcp --http`` reads the token with it.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import shlex
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .crypto import SecretBox
from .db import closing

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MIN_PORT, MAX_PORT = 1024, 65535
MCP_PATH = "/mcp"
# The bearer token of the HTTP server: from this variable, else the stored one.
TOKEN_ENV = "IPLENS_MCP_TOKEN"  # noqa: S105 - a variable name, not a secret
# Bytes of randomness of a generated token (urlsafe base64: 43 characters).
TOKEN_BYTES = 32
MIN_TOKEN_LENGTH = 16
MAX_ACCOUNT = 64
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

# Settings rows.
_ENABLED_KEY = "mcp_enabled"
_HOST_KEY = "mcp_host"
_PORT_KEY = "mcp_port"
_REDACT_KEY = "mcp_redact"
_ACCOUNT_KEY = "mcp_account"
_REMOTE_KEY = "mcp_allow_remote"
_TOKEN_KEY = "mcp_token_enc"  # noqa: S105 - a settings row name
_SETTING_KEYS = (_ENABLED_KEY, _HOST_KEY, _PORT_KEY, _REDACT_KEY, _ACCOUNT_KEY, _REMOTE_KEY)


def is_loopback(host: str) -> bool:
    """True if binding ``host`` keeps the server local (``localhost`` or 127.0.0.0/8, ::1)."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def url_host(host: str) -> str:
    """``host`` as written in a URL: IPv6 in brackets, wildcards as 127.0.0.1."""
    if host in ("0.0.0.0", "::"):  # noqa: S104 - names, nothing is bound here
        return "127.0.0.1"
    return f"[{host.strip('[]')}]" if ":" in host else host


def server_url(host: str, port: int) -> str:
    return f"http://{url_host(host)}:{port}{MCP_PATH}"


def parse_port(value: str | int | None) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("the MCP port must be a whole number") from None
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"the MCP port must be {MIN_PORT}-{MAX_PORT}")
    return port


def parse_host(value: str | None, allow_remote: bool = False) -> str:
    """A bind address (IP literal or host name); a non-loopback one only with
    ``allow_remote``. ValueError otherwise."""
    host = (value or "").strip().removeprefix("[").removesuffix("]") or DEFAULT_HOST
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise ValueError(
                f"the MCP host {host[:64]!r} is not an IP address or host name"
            ) from None
    if not is_loopback(host) and not allow_remote:
        raise ValueError(
            f"refusing to listen on non-loopback host {host!r}: tick 'Allow remote access' "
            "(--allow-remote) to do it anyway"
        )
    return host


def parse_account(value: str | None) -> str:
    account = (value or "").strip()
    if len(account) > MAX_ACCOUNT:
        raise ValueError(f"the MCP account must be at most {MAX_ACCOUNT} characters")
    return account


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def check_token(token: str) -> str:
    token = (token or "").strip()
    if len(token) < MIN_TOKEN_LENGTH or any(c.isspace() for c in token):
        raise ValueError(
            f"the MCP token must be at least {MIN_TOKEN_LENGTH} characters without spaces"
        )
    return token


@dataclass(frozen=True)
class McpSettings:
    enabled: bool = False  # start with IPLens
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    redact: bool = True
    account: str = ""  # "" = the account active in the UI
    allow_remote: bool = False

    @property
    def remote(self) -> bool:
        return not is_loopback(self.host)

    @property
    def url(self) -> str:
        return server_url(self.host, self.port)

    def server_args(self, home: Path) -> list[str]:
        """``iplens mcp`` arguments of the HTTP server (never the token)."""
        args = ["mcp", "--http", "--home", str(home), "--host", self.host]
        args += ["--port", str(self.port)]
        if self.redact:
            args.append("--redact")
        if self.account:
            args += ["--account", self.account]
        if self.allow_remote:
            args.append("--allow-remote")
        return args


def _get(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return (row[0] if row else "") or ""


def read_token(conn: sqlite3.Connection, box: SecretBox) -> str:
    """The stored token ("" if none); ValueError if the key cannot decrypt it."""
    raw = _get(conn, _TOKEN_KEY)
    return box.decrypt(raw) if raw else ""


class McpStore:
    """MCP server settings in the ``settings`` table; the token encrypted."""

    def __init__(self, db_path: Path, box: SecretBox):
        self.db_path = db_path
        self.box = box

    def _set(self, values: dict[str, str]) -> None:
        with closing(self.db_path) as conn:
            for key, value in values.items():
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )

    def load(self) -> McpSettings:
        with closing(self.db_path) as conn:
            raw = {k: _get(conn, k) for k in _SETTING_KEYS}
        allow_remote = raw[_REMOTE_KEY] == "1"
        try:
            host = parse_host(raw[_HOST_KEY], allow_remote)
        except ValueError:
            host = DEFAULT_HOST
        try:
            port = parse_port(raw[_PORT_KEY] or DEFAULT_PORT)
        except ValueError:
            port = DEFAULT_PORT
        return McpSettings(
            enabled=raw[_ENABLED_KEY] == "1",
            host=host,
            port=port,
            redact=raw[_REDACT_KEY] != "0",  # on unless turned off
            account=raw[_ACCOUNT_KEY],
            allow_remote=allow_remote,
        )

    def save(
        self,
        *,
        enabled: bool,
        host: str,
        port: str | int,
        redact: bool,
        account: str,
        allow_remote: bool,
    ) -> McpSettings:
        """Validate and store; ValueError (nothing stored) if a value is invalid."""
        settings = McpSettings(
            enabled=enabled,
            host=parse_host(host, allow_remote),
            port=parse_port(port),
            redact=redact,
            account=parse_account(account),
            allow_remote=allow_remote,
        )
        self._set(
            {
                _ENABLED_KEY: "1" if settings.enabled else "0",
                _HOST_KEY: settings.host,
                _PORT_KEY: str(settings.port),
                _REDACT_KEY: "1" if settings.redact else "0",
                _ACCOUNT_KEY: settings.account,
                _REMOTE_KEY: "1" if settings.allow_remote else "0",
            }
        )
        return settings

    def token(self) -> str:
        """The stored token, "" if none or if it cannot be decrypted."""
        with closing(self.db_path) as conn:
            try:
                return read_token(conn, self.box)
            except ValueError:
                return ""

    def has_token(self) -> bool:
        return bool(self.token())

    def ensure_token(self) -> tuple[str, bool]:
        """The token, generated and stored first if there is none: (token, generated)."""
        token = self.token()
        if token:
            return token, False
        return self.regenerate_token(), True

    def regenerate_token(self) -> str:
        token = new_token()
        self._set({_TOKEN_KEY: self.box.encrypt(token)})
        return token


# -- client configurations (Settings → MCP server → Connect) -----------------------------------


def vscode_config(url: str) -> str:
    """``.vscode/mcp.json``: the token is asked for once and kept by VS Code."""
    doc = {
        "inputs": [
            {
                "type": "promptString",
                "id": "iplens-mcp-token",
                "description": "IPLens MCP token (Settings → MCP server)",
                "password": True,
            }
        ],
        "servers": {
            "iplens": {
                "type": "http",
                "url": url,
                "headers": {"Authorization": "Bearer ${input:iplens-mcp-token}"},
            }
        },
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def claude_code_command(url: str) -> str:
    """``claude mcp add``: the shell expands the token from :data:`TOKEN_ENV`, so it never
    lands in the shell history."""
    header = f"Authorization: Bearer ${TOKEN_ENV}"
    return f'claude mcp add --transport http iplens {shlex.quote(url)} --header "{header}"'


def stdio_args(settings: McpSettings, home: Path | None = None) -> list[str]:
    args = ["mcp"]
    if home is not None:
        args += ["--home", str(home)]
    if settings.redact:
        args.append("--redact")
    if settings.account:
        args += ["--account", settings.account]
    return args


def stdio_configs(settings: McpSettings, home: Path | None = None) -> dict[str, str]:
    """The stdio alternative (no HTTP server, no token): VS Code and Claude Code."""
    args = stdio_args(settings, home)
    vscode = {"servers": {"iplens": {"type": "stdio", "command": "iplens", "args": args}}}
    return {
        "vscode": json.dumps(vscode, indent=2, ensure_ascii=False),
        "claude": "claude mcp add iplens -- iplens " + shlex.join(args),
    }
