"""boto3 session construction and a hard read-only guard.

Every client created through :class:`AwsGateway` has a botocore ``before-call``
hook that rejects any API operation whose name does not start with
``Describe``, ``List`` or ``Get``.  IPLens never mutates AWS.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .settings import Settings

log = logging.getLogger(__name__)

READ_ONLY_PREFIXES = ("Describe", "List", "Get")

_BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra="iplens")


class ReadOnlyViolation(RuntimeError):
    """Raised when code attempts a non read-only AWS API call."""


def _guard_read_only(model: Any = None, **_: Any) -> None:
    op_name = getattr(model, "name", "")
    if not op_name.startswith(READ_ONLY_PREFIXES):
        raise ReadOnlyViolation(f"IPLens is read-only; refusing AWS operation {op_name!r}")


def build_session(settings: Settings) -> boto3.session.Session:
    """Create a boto3 session for the configured auth mode.

    ``settings`` must have been loaded with ``with_secret=True`` for key auth.
    """
    region = settings.region or None
    if settings.auth_mode == "profile":
        return boto3.session.Session(profile_name=settings.profile, region_name=region)
    if settings.auth_mode == "keys":
        if not settings.access_key_id or not settings.secret_access_key:
            raise ValueError("access key auth selected but credentials are incomplete")
        return boto3.session.Session(
            aws_access_key_id=settings.access_key_id,
            aws_secret_access_key=settings.secret_access_key,
            region_name=region,
        )
    # "env": default credential chain (env vars, shared config, instance role, ...)
    return boto3.session.Session(region_name=region)


class AwsGateway:
    def __init__(self, session: boto3.session.Session):
        self.session = session

    @classmethod
    def from_settings(cls, settings: Settings) -> AwsGateway:
        return cls(build_session(settings))

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


def check_connection(
    settings: Settings, factory: Callable[[Settings], AwsGateway] | None = None
) -> tuple[bool, str]:
    """Return (ok, message) without ever echoing credentials."""
    try:
        gw = (factory or AwsGateway.from_settings)(settings)
        ident = gw.caller_identity()
        gw.client("ec2").describe_vpcs(MaxResults=5)
    except (BotoCoreError, ClientError, ValueError, ReadOnlyViolation) as exc:
        log.warning("connection test failed: %s", type(exc).__name__)
        return False, f"Connection failed: {_safe_error(exc)}"
    log.info("connection test succeeded (region=%s)", gw.region)
    return True, f"Connected to account {ident['account']} in {gw.region}"


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"
