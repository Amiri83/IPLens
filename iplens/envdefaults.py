"""Defaults from the shared DadsOps environment variables.

``AWS_PROFILE`` and ``AWS_REGION`` pre-fill a new account (named profile and region);
``DADSOPS_LOG_DIR`` moves the default log directory (in :class:`iplens.config.AppPaths`).

These are defaults only: anything saved in IPLens (an account's profile and region, the
Settings log directory) always wins, and nothing read here is ever written to the IPLens
database. Unset or blank variables leave IPLens exactly as without them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .accounts import Account

PROFILE_VAR = "AWS_PROFILE"
REGION_VAR = "AWS_REGION"


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def env_profile() -> str:
    """The ``AWS_PROFILE`` value, or "" when unset / blank."""
    return _env(PROFILE_VAR)


def env_region() -> str:
    """The ``AWS_REGION`` value, or "" when unset / blank."""
    return _env(REGION_VAR)


@dataclass
class AccountDefaults:
    """A not yet saved account, and which of its fields came from the environment."""

    account: Account
    # field name ("profile" / "region") -> the variable it came from
    sources: dict[str, str] = field(default_factory=dict)


def new_account() -> AccountDefaults:
    """The pre-filled Add account form.

    With ``AWS_PROFILE`` set, the form starts on "Named profile" with that profile chosen;
    with ``AWS_REGION`` set, on that region. Otherwise it is today's blank form.
    """
    acct = Account()
    sources: dict[str, str] = {}
    if region := env_region():
        acct.region = region
        sources["region"] = REGION_VAR
    if profile := env_profile():
        acct.auth_mode = "profile"
        acct.profile = profile
        sources["profile"] = PROFILE_VAR
    return AccountDefaults(acct, sources)
