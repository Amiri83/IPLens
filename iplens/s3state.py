"""Terraform state of an ``s3`` backend, read straight from S3 (no ``terraform`` at all).

The backend's settings come from the root's ``backend "s3"`` block, the environment's
``-backend-config`` file and the "extra backend-config" ``key=value`` lines a user enters
for values CI normally passes (later sources win, as with ``terraform init``). Missing
keys are allowed: the region falls back to the mapped IPLens account's region and the
workspace key prefix to ``env:``; only a missing bucket or key stops the read.

The state is read with the mapped account's credentials (or, when the backend names a
``role_arn``, a temporary ``sts:AssumeRole`` session used for nothing else) through
:class:`~iplens.aws.AwsGateway`, so the read-only guard applies: ``s3:ListObjectsV2`` and
``s3:GetObject`` only. Every call fails within ~10 seconds (:data:`~iplens.aws.FAST_CONFIG`).

Backend values (bucket, key, role ARN, ...) live in memory for the read only: they are
never logged, and the only one ever shown is the bucket, masked (:func:`mask`).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, fields, replace
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .accounts import Account
from .aws import FAST_CONFIG, AwsGateway
from .terraform import MAX_STATE_BYTES

# Settings of the s3 backend IPLens reads (everything else, e.g. locking, is ignored).
BACKEND_KEYS = ("bucket", "key", "region", "workspace_key_prefix", "role_arn", "profile")
DEFAULT_WORKSPACE_PREFIX = "env:"
DEFAULT_WORKSPACE = "default"
MAX_EXTRA_LINES = 20
MAX_VALUE = 1024
# ``key = "value"`` / ``key = value`` at the start of a line or right after ``{`` (so a
# one-line ``assume_role { role_arn = "..." }`` block is read too).
_ASSIGN_RE = re.compile(
    r'(?m)(?:^|\{)[ \t]*"?(' + "|".join(BACKEND_KEYS) + r')"?[ \t]*=[ \t]*'
    r'(?:"((?:[^"\\\n]|\\.)*)"|([^\s"#,}]+))'
)
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d$")
_ROLE_ARN_RE = re.compile(r"^arn:aws[\w-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
_PROFILE_RE = re.compile(r"^[\w.@+-]{1,128}$")
_EXTRA_KEY_RE = re.compile(r"^[A-Za-z_][\w-]{0,40}$")


@dataclass(frozen=True)
class S3Backend:
    """Resolved s3 backend settings. Values are never part of ``repr`` (logs)."""

    bucket: str = field(default="", repr=False)
    key: str = field(default="", repr=False)
    region: str = field(default="", repr=False)
    workspace_key_prefix: str = field(default="", repr=False)
    role_arn: str = field(default="", repr=False)
    profile: str = field(default="", repr=False)

    def missing(self) -> list[str]:
        return [k for k in ("bucket", "key") if not getattr(self, k)]

    def object_key(self, workspace: str = "") -> str:
        """``key`` for the default workspace, ``<prefix>/<workspace>/<key>`` otherwise."""
        if not workspace or workspace == DEFAULT_WORKSPACE:
            return self.key
        prefix = (self.workspace_key_prefix or DEFAULT_WORKSPACE_PREFIX).strip("/")
        return f"{prefix}/{workspace}/{self.key}"

    def merged(self, values: dict[str, str]) -> S3Backend:
        known = {f.name for f in fields(self)}
        return replace(self, **{k: v for k, v in values.items() if k in known and v})


def mask(value: str) -> str:
    """``exam…cket``: enough to recognise a bucket without showing (or storing) its name."""
    if len(value) <= 8:
        return "…"
    return f"{value[:4]}…{value[-4:]}"


def parse_hcl(text: str) -> dict[str, str]:
    """Backend settings of a ``backend "s3"`` block body or a ``*.tfbackend`` file
    (comments already stripped). The first assignment of each key wins."""
    out: dict[str, str] = {}
    for m in _ASSIGN_RE.finditer(text):
        value = m.group(2) if m.group(2) is not None else m.group(3)
        value = value.replace('\\"', '"').replace("\\\\", "\\").strip()
        if value and "${" not in value:
            out.setdefault(m.group(1), value)
    return out


def _check_value(key: str, value: str) -> None:
    """Validate an extra backend-config value; errors name the key, never the value."""
    ok = {
        "bucket": _BUCKET_RE.match,
        "region": _REGION_RE.match,
        "role_arn": _ROLE_ARN_RE.match,
        "profile": _PROFILE_RE.match,
    }.get(key)
    if ok is not None and not ok(value):
        raise ValueError(f"{key}: not a valid value")
    if key in ("key", "workspace_key_prefix") and (value.startswith("/") or ".." in value):
        raise ValueError(f"{key}: must be a relative object key")


def parse_extra(text: str) -> dict[str, str]:
    """``key=value`` lines (blank lines and ``#`` comments skipped) for :data:`BACKEND_KEYS`.

    Raises ValueError for anything else; the message names the line and the key only.
    """
    out: dict[str, str] = {}
    lines = (text or "").replace("\r\n", "\n").split("\n")
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(out) >= MAX_EXTRA_LINES:
            raise ValueError(f"at most {MAX_EXTRA_LINES} settings")
        key, sep, value = line.partition("=")
        key = key.strip().strip('"').lower()
        if not sep or not _EXTRA_KEY_RE.match(key):
            raise ValueError(f"line {n}: expected key=value")
        if key not in BACKEND_KEYS:
            raise ValueError(f"line {n}: unknown key {key} (allowed: {', '.join(BACKEND_KEYS)})")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not value or len(value) > MAX_VALUE or any(ord(c) < 32 for c in value):
            raise ValueError(f"line {n}: {key} needs a value (one line, up to {MAX_VALUE} chars)")
        _check_value(key, value)
        out[key] = value
    return out


def resolve(
    block: dict[str, str],
    backend_file: dict[str, str],
    extra: dict[str, str],
    *,
    default_region: str = "",
) -> S3Backend:
    """The backend block, then the -backend-config file, then the extra lines win;
    the region falls back to ``default_region`` (the mapped account's)."""
    cfg = S3Backend().merged(block).merged(backend_file).merged(extra)
    if not cfg.region and default_region:
        cfg = replace(cfg, region=default_region)
    return cfg


# -- reading the state ----------------------------------------------------------------------


class StateMissing(Exception):  # noqa: N818 - an outcome, not an error
    """The state object does not exist (NoSuchKey / not listed)."""


class StateUnavailable(Exception):  # noqa: N818
    """The state could not be read; the message is safe to show (no values but masks)."""


def _code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", "") or "")


_DENIED = frozenset({"AccessDenied", "AllAccessDisabled", "403", "Forbidden"})
_MISSING = frozenset({"NoSuchKey", "404", "NotFound"})


class Clients:
    """Gateways (one per IPLens account) and S3 clients (per account, role and region),
    shared by the sync's threads: boto3 clients are thread-safe, creating them is not."""

    def __init__(self, factory: Callable[[Account], AwsGateway] = AwsGateway.from_account):
        self._factory = factory
        self._lock = threading.Lock()
        self._gateways: dict[Any, AwsGateway] = {}
        self._clients: dict[tuple[Any, str, str], Any] = {}

    def gateway(self, account: Account) -> AwsGateway:
        with self._lock:
            key = account.id if account.id is not None else id(account)
            if key not in self._gateways:
                self._gateways[key] = self._factory(account)
            return self._gateways[key]

    def s3(self, account: Account, cfg: S3Backend) -> Any:
        """S3 client in the bucket's region, on the backend's role if it names one."""
        gw = self.gateway(account)
        ckey = (account.id if account.id is not None else id(account), cfg.role_arn, cfg.region)
        with self._lock:
            if ckey not in self._clients:
                if cfg.role_arn:
                    try:
                        gw = gw.assume_role(cfg.role_arn, config=FAST_CONFIG)
                    except ClientError as exc:
                        raise StateUnavailable(
                            f"could not assume the backend role ({_code(exc) or 'error'}); "
                            "is the mapped account allowed to assume it?"
                        ) from None
                    except BotoCoreError as exc:
                        raise StateUnavailable(
                            f"STS not reachable ({type(exc).__name__})"
                        ) from None
                self._clients[ckey] = gw.client("s3", region=cfg.region, config=FAST_CONFIG)
            return self._clients[ckey]


def read_state(client: Any, cfg: S3Backend, workspace: str = "") -> bytes:
    """The raw state object of ``workspace``: listed first (s3:ListObjectsV2, a fast
    existence / access check), then read (s3:GetObject), size-capped.

    Raises :class:`StateMissing` or :class:`StateUnavailable`.
    """
    key = cfg.object_key(workspace)
    bucket = mask(cfg.bucket)
    try:
        listed = client.list_objects_v2(Bucket=cfg.bucket, Prefix=key, MaxKeys=50)
    except ClientError as exc:
        code = _code(exc)
        if code == "NoSuchBucket":
            raise StateUnavailable(f"bucket {bucket} not found (region / account?)") from None
        if code not in _DENIED:  # denied listing: GetObject below may still be allowed
            raise StateUnavailable(f"S3 error listing the state ({code or 'error'})") from None
    except BotoCoreError as exc:
        raise StateUnavailable(f"S3 not reachable ({type(exc).__name__})") from None
    else:
        if not any(o.get("Key") == key for o in listed.get("Contents") or ()):
            raise StateMissing()
    try:
        obj = client.get_object(Bucket=cfg.bucket, Key=key)
        body = obj["Body"]
        try:
            data = body.read(MAX_STATE_BYTES + 1)
        finally:
            body.close()
    except ClientError as exc:
        code = _code(exc)
        if code in _MISSING:
            raise StateMissing() from None
        if code in _DENIED:
            raise StateUnavailable(f"no access to bucket {bucket} (account?)") from None
        if code == "NoSuchBucket":
            raise StateUnavailable(f"bucket {bucket} not found (region / account?)") from None
        raise StateUnavailable(f"S3 error reading the state ({code or 'error'})") from None
    except BotoCoreError as exc:
        raise StateUnavailable(f"S3 not reachable ({type(exc).__name__})") from None
    if len(data) > MAX_STATE_BYTES:
        raise StateUnavailable("state file is too large")
    return data
