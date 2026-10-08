"""boto3 session construction and a hard read-only guard.

Every client created through :class:`AwsGateway` has a botocore ``before-call``
hook that rejects any API operation whose name does not start with
``Describe``, ``List`` or ``Get``.  IPLens never mutates AWS.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, NamedTuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .accounts import EXPIRED_MESSAGE, Account, CredentialError

log = logging.getLogger(__name__)

READ_ONLY_PREFIXES = ("Describe", "List", "Get")

# AWS error codes meaning "these credentials are no longer valid".
EXPIRED_CREDENTIAL_CODES = frozenset(
    {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId"}
)

_BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra="iplens")


class ReadOnlyViolation(RuntimeError):
    """Raised when code attempts a non read-only AWS API call."""


def _guard_read_only(model: Any = None, **_: Any) -> None:
    op_name = getattr(model, "name", "")
    if not op_name.startswith(READ_ONLY_PREFIXES):
        raise ReadOnlyViolation(f"IPLens is read-only; refusing AWS operation {op_name!r}")


def is_credential_failure(exc: BaseException) -> bool:
    """True for errors the user fixes by pasting new credentials."""
    if isinstance(exc, CredentialError):
        return True
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "") in EXPIRED_CREDENTIAL_CODES
    return False


def build_session(account: Account) -> boto3.session.Session:
    """Create a boto3 session for the account's auth mode.

    ``account`` must have been loaded with ``with_secret=True`` for key and
    temporary auth. Raises :class:`CredentialError` (safe message) when the
    credentials are incomplete or already expired.
    """
    problem = account.credential_problem()
    if problem:
        raise CredentialError(problem)
    region = account.region or None
    if account.auth_mode == "profile":
        return boto3.session.Session(profile_name=account.profile, region_name=region)
    if account.auth_mode in ("keys", "temporary"):
        if not account.secret_access_key:
            raise CredentialError("credentials are incomplete")
        return boto3.session.Session(
            aws_access_key_id=account.access_key_id,
            aws_secret_access_key=account.secret_access_key,
            aws_session_token=account.session_token or None,
            region_name=region,
        )
    # "env": the process environment / default chain (env vars, shared config, role, ...)
    return boto3.session.Session(region_name=region)


class AwsGateway:
    def __init__(self, session: boto3.session.Session):
        self.session = session

    @classmethod
    def from_account(cls, account: Account) -> AwsGateway:
        return cls(build_session(account))

    @property
    def region(self) -> str | None:
        return self.session.region_name

    def client(self, service: str) -> Any:
        client = self.session.client(service, config=_BOTO_CONFIG)
        # "before-call" is hierarchical: it fires for every operation of this client.
        client.meta.events.register("before-call", _guard_read_only)
        return client

    def caller_identity(self) -> dict[str, str]:
        ident = self.client("sts").get_caller_identity()
        return {"account": ident.get("Account", ""), "arn": ident.get("Arn", "")}

    def account_aliases(self) -> list[str]:
        """IAM account alias (at most one per account). Needs iam:ListAccountAliases."""
        return list(self.client("iam").list_account_aliases().get("AccountAliases", []))


class ConnectionCheck(NamedTuple):
    ok: bool
    message: str
    credentials_problem: bool = False
    account_id: str = ""  # AWS account the credentials resolved to (on success)


def check_connection(
    account: Account, factory: Callable[[Account], AwsGateway] | None = None
) -> ConnectionCheck:
    """Test the account's credentials without ever echoing them."""
    try:
        gw = (factory or AwsGateway.from_account)(account)
        ident = gw.caller_identity()
        gw.client("ec2").describe_vpcs(MaxResults=5)
    except (BotoCoreError, ClientError, ValueError, ReadOnlyViolation) as exc:
        log.warning("connection test failed: %s", type(exc).__name__)
        if is_credential_failure(exc):
            msg = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
            return ConnectionCheck(False, f"Connection failed: {msg}", True)
        return ConnectionCheck(False, f"Connection failed: {_safe_error(exc)}")
    log.info("connection test succeeded (region=%s)", gw.region)
    return ConnectionCheck(
        True,
        f"Connected to account {ident['account']} in {gw.region}",
        account_id=ident["account"],
    )


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"
