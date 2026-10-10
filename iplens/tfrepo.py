"""Local Terraform repositories: discovery, an allowlisted read-only sync, and drift.

Discovery (:func:`discover`) only *reads* ``.tf`` / ``.tfvars`` / backend config files
with a tolerant, best-effort parser; it never runs ``terraform``. It finds root
directories (a ``backend`` / ``cloud`` block or a ``provider`` block outside a
``modules`` directory), their environments (env sub-folders, ``*.tfvars`` files and
workspaces) and guesses each environment's AWS account id and region. Only paths,
names, the backend *type* and those two guesses are kept; variable, provider and
backend values are never stored, logged or displayed.

The sync (:func:`sync`) first checks every mapped account's credentials
(``sts:GetCallerIdentity``, ~10 s timeout; invalid or expired credentials abort the whole
sync with :class:`SyncAborted`). Roots on the ``s3`` backend never run terraform: their
state object is listed and read with boto3 (:mod:`iplens.s3state`, read-only, the mapped
account's credentials or the backend's ``role_arn``), :data:`S3_PARALLEL` at a time.
Roots on the local backend are read straight from their ``.tfstate`` file.

Every other backend runs nothing but the invocations in :data:`ALLOWED_INVOCATIONS`,
checked by :func:`check_allowlisted` right before ``subprocess`` is called with an
explicit argv (no shell), ``cwd`` at the root directory, ``TF_DATA_DIR`` in the app's
cache directory (repo-scoped; the repo stays untouched), ``TF_PLUGIN_CACHE_DIR`` shared
in that cache, the mapped IPLens account's credentials, git set up to fail instead of
prompting (``GIT_TERMINAL_PROMPT=0``, no ``GIT_ASKPASS``) and a configurable timeout; a
cancelled job or a timeout terminates the running command (killed after
:data:`KILL_GRACE` seconds). ``plan``, ``apply``, ``import``, ``destroy``, ``state`` and
every other command or flag are refused. Up to :data:`PARALLEL_ROOTS` of those pairs run
at once. The AWS account ids in the state's ARNs are checked against the mapped account
(a mismatch is ``wrong account`` and left out of drift); nothing else from the state is
kept. Each pair's time is logged.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import botocore.exceptions
from botocore.exceptions import BotoCoreError, ClientError

from . import s3state, terraform
from .accounts import EXPIRED_MESSAGE, Account, CredentialError
from .aws import FAST_CONFIG, AwsGateway, is_credential_failure
from .db import closing
from .jobs import JobCancelled, NullProgress, Progress

log = logging.getLogger(__name__)

# -- discovery --------------------------------------------------------------------------

MAX_DEPTH = 8
MAX_DIRS = 5000
MAX_ROOTS = 500
MAX_FILE_BYTES = 1024 * 1024
MAX_ROOT_TEXT = 8 * 1024 * 1024
SKIP_DIRS = frozenset({"node_modules", "vendor", "terraform.tfstate.d"})
MODULE_DIRS = frozenset({"modules", "module"})
# A root at ``<…>/envs/<env>`` is environment <env> of root ``<…>``.
ENV_PARENT_DIRS = frozenset(
    {"env", "envs", "environment", "environments", "stages", "live", "accounts"}
)
# A root directory with one of these names is that environment of its parent.
KNOWN_ENVS = frozenset(
    {
        "dev",
        "development",
        "test",
        "testing",
        "qa",
        "uat",
        "int",
        "integration",
        "stage",
        "staging",
        "preprod",
        "prod",
        "production",
        "sandbox",
        "sbx",
        "demo",
        "shared",
        "ops",
    }
)
# Sub-directories of a root that hold per-environment ``*.tfvars`` / backend files.
VAR_DIRS = frozenset(
    {
        "env",
        "envs",
        "environments",
        "vars",
        "tfvars",
        "variables",
        "config",
        "configs",
        "stages",
        "backend",
        "backends",
    }
)
DEFAULT_ENV = "default"
_ENV_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_REGION_RE = re.compile(r"\b([a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d)\b")
_ASSIGN_RE = re.compile(r'(?m)^[ \t]*"?([A-Za-z_][\w-]*)"?[ \t]*[=:][ \t]*')
# Keys whose value names the environment's account, most specific first.
_ACCOUNT_KEYS = (
    "account_id",
    "aws_account_id",
    "allowed_account_ids",
    "target_account_id",
    "role_arn",
    "assume_role_arn",
)


def _strip_comments(text: str) -> str:
    """Drop ``#``, ``//`` and ``/* */`` comments outside double-quoted strings."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"' or c == "\n":
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _block_body(text: str, open_idx: int) -> str:
    """Body of the block whose ``{`` is at ``open_idx`` (string-aware brace matching)."""
    depth, in_str, i = 0, False, open_idx
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return text[open_idx + 1 :]


def _blocks(text: str, name: str) -> Iterator[tuple[list[str], str]]:
    """``(labels, body)`` of every ``name "label" … {`` block in ``text``."""
    pattern = re.compile(rf'(?<![\w.-]){re.escape(name)}((?:[ \t]*"[^"\n]*")*)[ \t]*\{{')
    for m in pattern.finditer(text):
        labels = re.findall(r'"([^"\n]*)"', m.group(1))
        yield labels, _block_body(text, m.end() - 1)


def _attr(body: str, key: str) -> str:
    m = re.search(rf'(?m)^[ \t]*{re.escape(key)}[ \t]*=[ \t]*"([^"\n]*)"', body)
    return m.group(1) if m else ""


def _assignments(text: str) -> Iterator[tuple[str, str]]:
    """``(key, raw value text)`` of every ``key = …`` / ``"key": …`` line (lists inlined)."""
    for m in _ASSIGN_RE.finditer(text):
        rest = text[m.end() : m.end() + 2000]
        if rest.startswith("["):
            end = rest.find("]")
            value = rest[: end + 1] if end >= 0 else rest[:200]
        else:
            value = rest.split("\n", 1)[0]
        yield m.group(1).lower(), value


@dataclass
class _Guess:
    account: str = ""
    region: str = ""

    def merge(self, other: _Guess) -> _Guess:
        return _Guess(self.account or other.account, self.region or other.region)


def _guess(text: str) -> _Guess:
    """Account id / region named by well-known keys (values themselves are not kept)."""
    exact: dict[str, str] = {}
    fuzzy_account = fuzzy_region = ""
    for key, value in _assignments(text):
        if key == "region" or key.endswith("_region"):
            m = _REGION_RE.search(value)
            if m and key in ("region", "aws_region"):
                exact.setdefault("region", m.group(1))
            elif m and not fuzzy_region:
                fuzzy_region = m.group(1)
            continue
        m = _ACCOUNT_RE.search(value)
        if not m:
            continue
        if key in _ACCOUNT_KEYS:
            exact.setdefault(key, m.group(1))
        elif "account" in key and not fuzzy_account:
            fuzzy_account = m.group(1)
    account = next((exact[k] for k in _ACCOUNT_KEYS if k in exact), fuzzy_account)
    return _Guess(account, exact.get("region", fuzzy_region))


def _variable_defaults(text: str) -> str:
    """``name = <default>`` lines for ``variable`` blocks that look like account / region."""
    lines = []
    for labels, body in _blocks(text, "variable"):
        name = labels[0].lower() if labels else ""
        if "region" in name or "account" in name or "role_arn" in name:
            m = re.search(r"(?m)^[ \t]*default[ \t]*=[ \t]*(.+)$", body)
            if m:
                lines.append(f"{name} = {m.group(1)[:2000]}")
    return "\n".join(lines)


def _read_text(path: Path) -> str:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@dataclass
class EnvInfo:
    env: str
    kinds: set[str] = field(default_factory=set)  # dir | tfvars | workspace | root
    var_file: str = ""  # relative to the root
    backend_config: str = ""  # relative to the root
    workspace: str = ""  # selected with ``terraform workspace select`` before ``show``
    account: str = ""
    region: str = ""


@dataclass
class RootInfo:
    rel: str  # directory relative to the repo ("." for the repo itself)
    label: str  # root name shown (env folders grouped under their parent)
    backend: str  # backend type; "local" when none is configured
    envs: list[EnvInfo]


def _env_from_dir(rel: str) -> tuple[str, str]:
    """``(root label, env)`` for a root directory (env "" when the dir is no env)."""
    parts = [] if rel == "." else rel.split("/")
    if len(parts) >= 2 and parts[-2].lower() in ENV_PARENT_DIRS:
        return "/".join(parts[:-2]) or ".", parts[-1]
    if parts and parts[-1].lower() in KNOWN_ENVS:
        return "/".join(parts[:-1]) or ".", parts[-1]
    return rel, ""


def _var_files(root: Path) -> dict[str, list[Path]]:
    """Per-environment ``*.tfvars`` files: ``<env>.tfvars``, ``envs/<env>.tfvars``, …
    and ``envs/<env>/*.tfvars``. ``terraform.tfvars`` / ``*.auto.tfvars`` in the root
    apply to every environment and are not one."""
    found: dict[str, list[Path]] = {}

    def add(env: str, p: Path) -> None:
        if _ENV_NAME_RE.match(env):
            found.setdefault(env, []).append(p)

    def stem(p: Path) -> str:
        return p.name.removesuffix(".json").removesuffix(".tfvars")

    for p in sorted(root.glob("*.tfvars")) + sorted(root.glob("*.tfvars.json")):
        if p.name.startswith("terraform.tfvars") or ".auto.tfvars" in p.name:
            continue
        add(stem(p), p)
    for sub in sorted(root.iterdir()) if root.is_dir() else []:
        if not sub.is_dir() or sub.is_symlink() or sub.name.lower() not in VAR_DIRS:
            continue
        for p in sorted(sub.glob("*.tfvars")) + sorted(sub.glob("*.tfvars.json")):
            add(stem(p), p)
        for envdir in sorted(sub.iterdir()):
            if envdir.is_dir() and not envdir.is_symlink():
                for p in sorted(envdir.glob("*.tfvars")) + sorted(envdir.glob("*.tfvars.json")):
                    add(envdir.name, p)
    return found


def _backend_files(root: Path) -> list[Path]:
    """``*.tfbackend`` and ``*.hcl`` files that can be ``-backend-config`` files."""
    dirs = [root] + [
        d
        for d in (sorted(root.iterdir()) if root.is_dir() else [])
        if d.is_dir() and not d.is_symlink() and d.name.lower() in VAR_DIRS
    ]
    dirs += [e for d in dirs[1:] for e in sorted(d.iterdir()) if e.is_dir() and not e.is_symlink()]
    out = []
    for d in dirs:
        for p in sorted(d.iterdir()):
            if p.is_file() and not p.name.startswith(".") and p.suffix in (".tfbackend", ".hcl"):
                out.append(p)
    return out


def _backend_file_for(env: str, files: list[Path]) -> Path | None:
    env_l = env.lower()
    names = {env_l, f"backend-{env_l}", f"backend_{env_l}", f"{env_l}-backend", f"{env_l}_backend"}
    for p in files:
        stem = p.name.removesuffix(p.suffix).lower()
        if stem in names or stem == f"{env_l}.backend" or p.parent.name.lower() == env_l:
            return p
    return None


def _rel(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def _is_root(text: str, rel: str) -> bool:
    """A ``backend`` / ``cloud`` block, or a ``provider`` block outside ``modules/``."""
    for _, body in _blocks(text, "terraform"):
        if next(_blocks(body, "backend"), None) or next(_blocks(body, "cloud"), None):
            return True
    if any(part.lower() in MODULE_DIRS for part in rel.split("/")):
        return False
    return next(_blocks(text, "provider"), None) is not None


def _analyse_root(repo: Path, d: Path, text: str) -> RootInfo:
    rel = "." if d == repo else _rel(d, repo)
    label, dir_env = _env_from_dir(rel)
    backend, backend_body, ws_multi, ws_pinned = "local", "", False, False
    for _, tbody in _blocks(text, "terraform"):
        for labels, body in _blocks(tbody, "backend"):
            backend, backend_body = (labels[0] if labels else "unknown"), body
        for _, body in _blocks(tbody, "cloud"):
            backend, backend_body = "cloud", body
    if backend in ("remote", "cloud"):
        for _, wbody in _blocks(backend_body, "workspaces"):
            if _attr(wbody, "name"):
                ws_pinned = True
            else:  # prefix / tags / project: one workspace per environment
                ws_multi = True
    ws_multi = ws_multi or "terraform.workspace" in text
    local_ws = sorted(
        p.name
        for p in (d / "terraform.tfstate.d").glob("*")
        if p.is_dir() and _ENV_NAME_RE.match(p.name)
    )
    if local_ws:
        ws_multi = True

    common = "\n".join(
        _strip_comments(_read_text(p))
        for p in sorted(d.glob("terraform.tfvars")) + sorted(d.glob("*.auto.tfvars"))
    )
    providers = [
        body for labels, body in _blocks(text, "provider") if labels and labels[0] == "aws"
    ]
    providers.sort(key=lambda b: bool(_attr(b, "alias")))  # the default provider first
    root_guess = (
        _guess(common)
        .merge(_guess(providers[0]) if providers else _Guess())
        .merge(_guess(_variable_defaults(text)))
    )
    backend_guess = _guess(backend_body) if backend == "s3" else _Guess()

    envs: dict[str, EnvInfo] = {}
    var_files = _var_files(d)
    for env, files in var_files.items():
        envs[env] = EnvInfo(env, {"tfvars"}, var_file=_rel(files[0], d))
    if local_ws and (d / "terraform.tfstate").is_file():
        local_ws.insert(0, DEFAULT_ENV)
    for ws in local_ws:
        envs.setdefault(ws, EnvInfo(ws)).kinds.add("workspace")
    if ws_multi and not ws_pinned:
        for e in envs.values():
            if e.env != DEFAULT_ENV:
                e.workspace = e.env
                e.kinds.add("workspace")
    if not envs:
        name = dir_env or DEFAULT_ENV
        envs[name] = EnvInfo(name, {"dir" if dir_env else "root"})
    elif dir_env:
        for e in envs.values():
            e.kinds.add("dir")

    backend_files = _backend_files(d) if backend not in ("local", "cloud") else []
    for e in envs.values():
        # Most specific first: the env's tfvars, the root's own files, then the backend.
        guess = _Guess()
        for p in var_files.get(e.env, []):
            guess = guess.merge(_guess(_strip_comments(_read_text(p))))
        bfile = _backend_file_for(e.env, backend_files)
        if bfile is None and len(envs) == 1 and len(backend_files) == 1:
            bfile = backend_files[0]
        bguess = _Guess()
        if bfile is not None:
            e.backend_config = _rel(bfile, d)
            if backend == "s3":
                bguess = _guess(_strip_comments(_read_text(bfile)))
        guess = guess.merge(root_guess).merge(bguess).merge(backend_guess)
        e.account, e.region = guess.account, guess.region
    return RootInfo(
        rel=rel,
        label=label,
        backend=backend,
        envs=sorted(envs.values(), key=lambda e: e.env),
    )


def _root_text(d: Path, filenames: Iterable[str] | None = None) -> str:
    """The ``.tf`` files of directory ``d``, comments stripped (size-capped)."""
    names = filenames if filenames is not None else (p.name for p in d.glob("*.tf"))
    parts, size = [], 0
    for f in sorted(n for n in names if n.endswith(".tf")):
        t = _read_text(d / f)
        size += len(t)
        if size > MAX_ROOT_TEXT:
            break
        parts.append(_strip_comments(t))
    return "\n".join(parts)


def discover(repo_path: str | os.PathLike[str]) -> list[RootInfo]:
    """Roots and environments of the repository at ``repo_path`` (files are only read)."""
    repo = Path(repo_path).expanduser().resolve()
    if not repo.is_dir():
        raise ValueError("not a directory")
    roots: list[RootInfo] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(repo):
        d = Path(dirpath)
        depth = 0 if d == repo else len(d.relative_to(repo).parts)
        dirnames[:] = sorted(
            n
            for n in dirnames
            if not n.startswith(".") and n not in SKIP_DIRS and depth < MAX_DEPTH
        )
        seen += 1
        if seen > MAX_DIRS or len(roots) >= MAX_ROOTS:
            log.warning("terraform discovery stopped early (repository too large)")
            break
        if not any(f.endswith(".tf") for f in filenames):
            continue
        text = _root_text(d, filenames)
        rel = "." if d == repo else _rel(d, repo)
        if _is_root(text, rel):
            roots.append(_analyse_root(repo, d, text))
    return sorted(roots, key=lambda r: (r.label, r.rel))


def suggest_account(env: EnvInfo, accounts: Sequence[Account]) -> int | None:
    """The IPLens account an environment most likely belongs to, if any."""
    if env.account:
        same = [a for a in accounts if env.account in (a.aws_account_id, a.last_seen_account_id)]
        if same:
            in_region = [a for a in same if env.region and a.region == env.region]
            return (in_region or same)[0].id
    if env.env != DEFAULT_ENV:
        token = re.compile(rf"(?<![a-z0-9]){re.escape(env.env.lower())}(?![a-z0-9])")
        named = [a for a in accounts if token.search(a.display_name.lower())]
        if len(named) == 1:
            return named[0].id
    return None


# -- repo / mapping storage -----------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def validate_repo_path(path: str) -> str:
    p = Path((path or "").strip()).expanduser()
    if not str(p) or not p.is_absolute():
        raise ValueError("enter an absolute path to a local directory")
    if not p.is_dir():
        raise ValueError("no such directory")
    return str(p.resolve())


def add_repo(conn: sqlite3.Connection, path: str) -> int:
    path = validate_repo_path(path)
    row = conn.execute("SELECT id FROM tf_repos WHERE path=?", (path,)).fetchone()
    if row:
        return int(row["id"])
    cur = conn.execute("INSERT INTO tf_repos(path, added_at) VALUES(?, ?)", (path, _now()))
    return int(cur.lastrowid or 0)


def list_repos(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in conn.execute(
            "SELECT p.*, COUNT(e.id) AS envs, "
            "COALESCE(SUM(e.confirmed AND e.present AND e.account_ref IS NOT NULL), 0) "
            "AS confirmed, COUNT(DISTINCT e.root_rel) AS roots "
            "FROM tf_repos p LEFT JOIN tf_repo_envs e ON e.repo_id = p.id "
            "GROUP BY p.id ORDER BY p.path"
        )
    ]


def get_repo(conn: sqlite3.Connection, repo_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM tf_repos WHERE id=?", (repo_id,)).fetchone()
    return dict(row) if row else None


def delete_repo(conn: sqlite3.Connection, repo_id: int) -> bool:
    """Forget a repository, its mapping and the Terraform roots its syncs wrote."""
    names = [
        r["root_name"]
        for r in conn.execute(
            "SELECT root_name FROM tf_repo_envs WHERE repo_id=? AND root_name != ''", (repo_id,)
        )
    ]
    conn.executemany("DELETE FROM tf_roots WHERE name=? AND origin='repo'", [(n,) for n in names])
    return conn.execute("DELETE FROM tf_repos WHERE id=?", (repo_id,)).rowcount > 0


def list_envs(
    conn: sqlite3.Connection, repo_id: int | None = None, account_ref: int | None = None
) -> list[dict[str, Any]]:
    sql = (
        "SELECT e.*, p.path AS repo_path, "
        "(SELECT COUNT(*) FROM tf_resources t JOIN tf_roots r ON r.id = t.root_id "
        " WHERE r.name = e.root_name AND r.origin = 'repo') AS resources "
        "FROM tf_repo_envs e JOIN tf_repos p ON p.id = e.repo_id WHERE 1=1"
    )
    args: list[Any] = []
    if repo_id is not None:
        sql += " AND e.repo_id=?"
        args.append(repo_id)
    if account_ref is not None:
        sql += " AND e.account_ref=? AND e.confirmed=1"
        args.append(account_ref)
    sql += " ORDER BY p.path, e.present DESC, e.root_rel, e.env"
    return [dict(r) for r in conn.execute(sql, args)]


def save_discovery(
    conn: sqlite3.Connection,
    repo_id: int,
    roots: Iterable[RootInfo],
    accounts: Sequence[Account] = (),
) -> int:
    """Store a discovery. Known (root, env) rows keep their mapping; new ones get the
    suggested account, unconfirmed. Rows no longer found are marked absent. Returns
    the number of (root, env) pairs found."""
    conn.execute("UPDATE tf_repo_envs SET present=0 WHERE repo_id=?", (repo_id,))
    count = 0
    for root in roots:
        for e in root.envs:
            count += 1
            fields = (
                ",".join(sorted(e.kinds)),
                e.var_file,
                e.backend_config,
                e.workspace,
                root.backend,
                e.account,
                e.region,
            )
            row = conn.execute(
                "SELECT id FROM tf_repo_envs WHERE repo_id=? AND root_rel=? AND env=?",
                (repo_id, root.rel, e.env),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE tf_repo_envs SET kinds=?, var_file=?, backend_config=?, "
                    "workspace=?, backend=?, guess_account=?, guess_region=?, present=1, "
                    "root_label=? WHERE id=?",
                    (*fields, root.label, row["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO tf_repo_envs(repo_id, root_rel, env, kinds, var_file, "
                    "backend_config, workspace, backend, guess_account, guess_region, "
                    "root_label, account_ref) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        repo_id,
                        root.rel,
                        e.env,
                        *fields,
                        root.label,
                        suggest_account(e, accounts),
                    ),
                )
    conn.execute("UPDATE tf_repos SET discovered_at=? WHERE id=?", (_now(), repo_id))
    return count


def save_mapping(conn: sqlite3.Connection, repo_id: int, mapping: dict[int, int | None]) -> int:
    """Confirm ``{env row id: IPLens account id or None}``; None means "do not sync".
    Unknown row / account ids are ignored. Returns the number of synced pairs."""
    known = {r["id"] for r in conn.execute("SELECT id FROM accounts")}
    for env_id, account_ref in mapping.items():
        ref = account_ref if account_ref in known else None
        conn.execute(
            "UPDATE tf_repo_envs SET account_ref=?, confirmed=? WHERE id=? AND repo_id=?",
            (ref, int(ref is not None), env_id, repo_id),
        )
    return conn.execute(
        "SELECT COUNT(*) FROM tf_repo_envs WHERE repo_id=? AND confirmed=1 AND present=1",
        (repo_id,),
    ).fetchone()[0]


def save_backend_extra(
    conn: sqlite3.Connection,
    repo_id: int,
    env_id: int,
    text: str,
    encrypt: Callable[[str], str],
) -> list[str]:
    """Store an environment's "extra backend-config" ``key=value`` lines (s3 backends).

    The values are what CI passes with ``-backend-config``; they are needed for every
    state read, so they are kept Fernet-encrypted (``encrypt``) and only their key
    names in clear. Empty ``text`` clears them. Returns the key names; ValueError (no
    values in its message) for invalid lines.
    """
    values = s3state.parse_extra(text)
    keys = sorted(values)
    conn.execute(
        "UPDATE tf_repo_envs SET backend_extra_enc=?, backend_extra_keys=? "
        "WHERE id=? AND repo_id=?",
        (encrypt(json.dumps(values)) if values else "", ",".join(keys), env_id, repo_id),
    )
    return keys


def backend_extra(row: dict[str, Any], decrypt: Callable[[str], str] | None) -> dict[str, str]:
    """The decrypted extra backend-config of an env row ({} if none / undecryptable)."""
    enc = row.get("backend_extra_enc") or ""
    if not enc or decrypt is None:
        return {}
    try:
        values = json.loads(decrypt(enc))
    except ValueError:
        log.warning("extra backend-config of env row %s cannot be decrypted", row.get("id"))
        return {}
    return {k: v for k, v in values.items() if k in s3state.BACKEND_KEYS and isinstance(v, str)}


def s3_backend(
    root: Path, row: dict[str, Any], extra: dict[str, str], default_region: str = ""
) -> s3state.S3Backend:
    """The s3 backend settings of a root x environment: its ``backend "s3"`` block, its
    ``-backend-config`` file, then ``extra`` (partial configurations are fine)."""
    block: dict[str, str] = {}
    for _, tbody in _blocks(_root_text(root), "terraform"):
        for labels, body in _blocks(tbody, "backend"):
            if labels and labels[0] == "s3":
                block = s3state.parse_hcl(body)
    from_file: dict[str, str] = {}
    if row.get("backend_config"):
        bfile = (root / row["backend_config"]).resolve()
        if bfile.is_file() and _inside(bfile, root):
            from_file = s3state.parse_hcl(_strip_comments(_read_text(bfile)))
    return s3state.resolve(block, from_file, extra, default_region=default_region)


# -- the command allowlist ---------------------------------------------------------------

_FILE_ARG = "<backend-config file>"
_WORKSPACE_ARG = "<workspace>"
# The only terraform invocations IPLens ever runs (argv after the binary).
ALLOWED_INVOCATIONS: tuple[tuple[str, ...], ...] = (
    ("init", "-input=false", "-lockfile=readonly"),
    ("init", "-input=false", "-lockfile=readonly", f"-backend-config={_FILE_ARG}"),
    ("workspace", "select", _WORKSPACE_ARG),
    ("show", "-json"),
)
TERRAFORM_NAMES = ("terraform", "terraform.exe")
# A relative path inside the root (no leading "-" or "/"; ".." is refused separately).
_BACKEND_FILE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.(?:tfbackend|hcl)$")
_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,89}$")


class CommandNotAllowed(ValueError):
    """A terraform invocation outside :data:`ALLOWED_INVOCATIONS` was attempted."""


def _arg_matches(pattern: str, arg: str) -> bool:
    if pattern == _WORKSPACE_ARG:
        return bool(_WORKSPACE_RE.match(arg))
    prefix, sep, _ = pattern.partition(_FILE_ARG)
    if sep:
        path = arg[len(prefix) :]
        return (
            arg.startswith(prefix)
            and bool(_BACKEND_FILE_RE.match(path))
            and ".." not in path.split("/")
        )
    return arg == pattern


def check_allowlisted(argv: Sequence[str], terraform_bin: str) -> list[str]:
    """Return ``argv`` as a list if it is exactly one allowlisted terraform invocation.

    ``argv[0]`` must be ``terraform_bin`` (an absolute path to a ``terraform``
    executable) and the remaining arguments must match one entry of
    :data:`ALLOWED_INVOCATIONS` element by element. Anything else raises
    :class:`CommandNotAllowed` and is never executed.
    """
    if isinstance(argv, (str, bytes)) or not all(isinstance(a, str) for a in argv):
        raise CommandNotAllowed("terraform commands must be an argument list")
    args = list(argv)
    if (
        not args
        or not terraform_bin
        or args[0] != terraform_bin
        or not os.path.isabs(terraform_bin)
        or os.path.basename(terraform_bin) not in TERRAFORM_NAMES
    ):
        raise CommandNotAllowed("only the configured terraform binary may be run")
    rest = tuple(args[1:])
    for allowed in ALLOWED_INVOCATIONS:
        if len(allowed) == len(rest) and all(map(_arg_matches, allowed, rest)):
            return args
    sub = re.sub(r"[^A-Za-z0-9_-]", "", rest[0])[:20] if rest else ""
    raise CommandNotAllowed(f"terraform command not allowlisted: {sub or '(none)'}")


Runner = Callable[..., subprocess.CompletedProcess]
Popen = Callable[..., subprocess.Popen]

# Seconds a terraform process gets to exit after terminate() before it is kill()ed.
KILL_GRACE = 5.0
# How often a running command checks for a cancel request.
POLL_INTERVAL = 0.1

# Terraform processes run_process() has started and not yet reaped (stop_all_processes).
_live: set[subprocess.Popen] = set()
_live_lock = threading.Lock()


class CommandCancelled(JobCancelled):
    """The job was cancelled while a terraform command ran; the process was stopped."""


def _signal_group(proc: subprocess.Popen, kill: bool) -> None:
    """Signal the process group of ``proc`` (provider plugins terraform started)."""
    if os.name != "posix" or not isinstance(proc, subprocess.Popen):
        return
    with contextlib.suppress(OSError):
        os.killpg(proc.pid, signal.SIGKILL if kill else signal.SIGTERM)


def stop_process(proc: subprocess.Popen, grace: float = KILL_GRACE) -> None:
    """``terminate()`` ``proc``, ``kill()`` it if it has not exited within ``grace``
    seconds, then reap it and close its pipes. Its process group goes with it."""
    if proc.poll() is None:
        proc.terminate()
        _signal_group(proc, kill=False)
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.kill()
            _signal_group(proc, kill=True)
            proc.wait()
    _signal_group(proc, kill=True)  # helpers that ignored SIGTERM or outlived terraform
    with contextlib.suppress(subprocess.TimeoutExpired, OSError, ValueError):
        proc.communicate(timeout=grace)


def run_process(
    args: Sequence[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout: float,
    cancelled: Callable[[], bool] = lambda: False,
    popen: Popen = subprocess.Popen,
    grace: float = KILL_GRACE,
    poll: float = POLL_INTERVAL,
    **_ignored: Any,
) -> subprocess.CompletedProcess:
    """A cancellable ``subprocess.run(args, capture_output=True, timeout=timeout)``.

    The process is spawned with an explicit argv and no shell, in its own session (so
    its plugins can be stopped with it). Every ``poll`` seconds ``cancelled()`` is
    checked: on a cancel request (:class:`CommandCancelled`) or once ``timeout`` has
    passed (``subprocess.TimeoutExpired``) the process is stopped by
    :func:`stop_process` before the exception is raised.
    """
    deadline = time.monotonic() + timeout
    proc = popen(
        list(args),
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=os.name == "posix",
    )
    with _live_lock:
        _live.add(proc)
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=poll)
            except subprocess.TimeoutExpired:
                pass
            else:
                return subprocess.CompletedProcess(list(args), proc.returncode, out, err)
            if cancelled():
                raise CommandCancelled()
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(list(args), timeout)
    except BaseException:
        stop_process(proc, grace)  # cancel, timeout or anything else: never leave it running
        raise
    finally:
        with _live_lock:
            _live.discard(proc)


def stop_all_processes(grace: float = KILL_GRACE) -> int:
    """Stop every terraform process :func:`run_process` still has running (shutdown);
    returns how many were stopped."""
    with _live_lock:
        procs = list(_live)
    for proc in procs:
        stop_process(proc, grace)
    return len(procs)


def run_terraform(
    argv: Sequence[str],
    *,
    terraform_bin: str,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    runner: Runner = run_process,
    cancelled: Callable[[], bool] = lambda: False,
) -> subprocess.CompletedProcess:
    """Run one allowlisted invocation: explicit argv, no shell, ``TF_DATA_DIR`` set."""
    args = check_allowlisted(argv, terraform_bin)
    if not env.get("TF_DATA_DIR"):
        raise CommandNotAllowed("TF_DATA_DIR must point at the IPLens cache")
    log.info("terraform %s (root %s, timeout %ss)", " ".join(args[1:]), cwd, int(timeout))
    started = time.monotonic()
    proc = runner(
        args,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        shell=False,
        check=False,
        cancelled=cancelled,
    )
    log.info(
        "terraform %s exited %s after %.1fs", args[1], proc.returncode, time.monotonic() - started
    )
    return proc


def find_terraform() -> str:
    """Absolute path of the terraform binary (``IPLENS_TERRAFORM_BIN`` or ``PATH``), or ''."""
    configured = os.environ.get("IPLENS_TERRAFORM_BIN", "").strip()
    found = configured if configured else shutil.which("terraform") or ""
    if not found:
        return ""
    path = os.path.abspath(found)
    return path if os.path.basename(path) in TERRAFORM_NAMES and os.path.isfile(path) else ""


# -- sync -----------------------------------------------------------------------------------

OK, INIT_FAILED, NO_STATE, SHOW_FAILED, ERROR, WRONG_ACCOUNT, CANCELLED = (
    "ok",
    "init failed",
    "no state",
    "show failed",
    "error",
    "wrong account",
    "cancelled",
)
# Seconds each terraform command may run (Settings: "Terraform timeout").
DEFAULT_TIMEOUT = 120.0
WORKSPACE_TIMEOUT = 60.0
# Root x environment pairs running terraform at the same time (a small bounded pool).
PARALLEL_ROOTS = 2
# S3-backend pairs read at the same time (a few API calls each, no subprocess).
S3_PARALLEL = 8
# Under the cache directory: provider plugins shared by every sync (TF_PLUGIN_CACHE_DIR).
PLUGIN_CACHE = "plugin-cache"
# Inherited by terraform; AWS credentials come from the mapped account (below).
_PASSTHROUGH_ENV = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "TF_CLI_CONFIG_FILE",
        "TF_PLUGIN_CACHE_DIR",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CA_BUNDLE",
        # git module sources over SSH: the agent and the user's ssh command (see below).
        "SSH_AUTH_SOCK",
        "GIT_SSH_COMMAND",
    }
)
# git must fail at once instead of waiting for a password nobody will type: no terminal
# prompt, no askpass helper (GIT_ASKPASS / SSH_ASKPASS are never passed through), and
# ssh in batch mode unless the user configured their own GIT_SSH_COMMAND.
_GIT_ENV = {"GIT_TERMINAL_PROMPT": "0"}
_GIT_SSH_DEFAULT = "ssh -o BatchMode=yes -o ConnectTimeout=10"
_NEVER_PASSED = ("GIT_ASKPASS", "SSH_ASKPASS")
_PASSTHROUGH_PREFIXES = ("TF_TOKEN_",)  # Terraform Cloud / registry API tokens
_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")


def terraform_env(
    account: Account,
    data_dir: Path,
    base: dict[str, str] | None = None,
    plugin_cache: Path | None = None,
) -> dict[str, str]:
    """Environment for terraform: a small passthrough plus the account's credentials.

    ``data_dir`` (``TF_DATA_DIR``) is the repo-scoped working cache of one root x
    environment; ``plugin_cache`` (``TF_PLUGIN_CACHE_DIR``) the provider cache shared by
    every sync, so providers are downloaded once. ``account`` must have been loaded with
    ``with_secret=True`` for key / temporary auth. The result holds secrets: it is passed
    to the child process and never logged.
    """
    base = dict(os.environ) if base is None else base
    env = {
        k: v
        for k, v in base.items()
        if k in _PASSTHROUGH_ENV or k.startswith(_PASSTHROUGH_PREFIXES)
    }
    if account.auth_mode == "env":
        env.update({k: v for k, v in base.items() if k.startswith("AWS_")})
    elif account.auth_mode == "profile":
        env["AWS_PROFILE"] = account.profile
        env["AWS_SDK_LOAD_CONFIG"] = "1"
    else:
        env["AWS_ACCESS_KEY_ID"] = account.access_key_id
        env["AWS_SECRET_ACCESS_KEY"] = account.secret_access_key
        if account.session_token:
            env["AWS_SESSION_TOKEN"] = account.session_token
    if account.region:
        env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = account.region
    env.update(
        TF_DATA_DIR=str(data_dir),
        TF_IN_AUTOMATION="1",
        TF_INPUT="0",
        CHECKPOINT_DISABLE="1",
        **_GIT_ENV,
    )
    env.setdefault("GIT_SSH_COMMAND", _GIT_SSH_DEFAULT)
    for k in _NEVER_PASSED:
        env.pop(k, None)
    if plugin_cache is not None:
        env["TF_PLUGIN_CACHE_DIR"] = str(plugin_cache)
    return env


def _log_failure(what: str, proc: subprocess.CompletedProcess, secrets: Iterable[str]) -> None:
    """Log the tail of terraform's stderr with credential values and key ids redacted."""
    raw = proc.stderr or b""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    for s in secrets:
        if s and len(s) >= 8:
            text = text.replace(s, "<redacted>")
    text = _KEY_ID_RE.sub("<redacted>", text)
    tail = [line[:300] for line in text.strip().splitlines()[-15:]]
    log.warning("terraform %s failed (exit %s):\n  %s", what, proc.returncode, "\n  ".join(tail))


@dataclass
class SyncResult:
    env_id: int
    label: str
    status: str
    detail: str = ""
    resources: int = 0
    seconds: float = 0.0  # wall time of this pair


class SyncAborted(RuntimeError):
    """A mapped account's credentials are invalid or expired: nothing was synced.
    The message is safe to show (account name and reason, no credential values)."""

    def __init__(self, message: str, account_ref: int | None = None):
        super().__init__(message)
        self.account_ref = account_ref


def root_name_for(repo_path: str, root_rel: str, env: str) -> str:
    """Deterministic, valid ``tf_roots`` name for a repo root x environment."""
    parts = [Path(repo_path).name or "repo"]
    if root_rel != ".":
        parts.append(root_rel)
    parts.append(env)
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", "-".join(parts)).strip("-._") or "root"
    if len(name) > terraform.MAX_ROOT_NAME:
        digest = hashlib.sha256("\0".join((repo_path, root_rel, env)).encode()).hexdigest()[:8]
        name = name[: terraform.MAX_ROOT_NAME - 9].rstrip("-._") + "-" + digest
    return name


def _assign_root_name(conn: sqlite3.Connection, row: dict[str, Any]) -> str:
    if row["root_name"]:
        return row["root_name"]
    name = root_name_for(row["repo_path"], row["root_rel"], row["env"])
    clash = conn.execute(
        "SELECT 1 FROM tf_roots WHERE name=? AND origin != 'repo'", (name,)
    ).fetchone()
    taken = conn.execute(
        "SELECT 1 FROM tf_repo_envs WHERE root_name=? AND id != ?", (name, row["id"])
    ).fetchone()
    if clash or taken:
        name = name[: terraform.MAX_ROOT_NAME - 7] + f"-r{row['id'] % 100000}"
    conn.execute("UPDATE tf_repo_envs SET root_name=? WHERE id=?", (name, row["id"]))
    return name


def _record(conn: sqlite3.Connection, row: dict[str, Any], result: SyncResult) -> SyncResult:
    conn.execute(
        "UPDATE tf_repo_envs SET status=?, status_detail=?, synced_at=? WHERE id=?",
        (result.status, result.detail[:300], _now(), row["id"]),
    )
    log.info(
        "terraform sync %s: %s%s in %.1fs",
        result.label,
        result.status,
        f" ({result.detail})" if result.detail else "",
        result.seconds,
    )
    return result


def _store_resources(
    conn: sqlite3.Connection, row: dict[str, Any], resources: list[terraform.TfResource]
) -> None:
    name = _assign_root_name(conn, row)
    where = Path(row["repo_path"]).name
    if row["root_rel"] != ".":
        where += "/" + row["root_rel"]
    source = f"repo: {where} [{row['env']}]"
    terraform.save_root(conn, name, resources, source=source, origin="repo")


def _inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True


def expected_account_id(account: Account) -> str:
    """AWS account id the mapped IPLens account's credentials resolve to (if known)."""
    return account.last_seen_account_id or account.aws_account_id or ""


def sync_env(
    conn: sqlite3.Connection,
    row: dict[str, Any],
    account: Account,
    *,
    cache_dir: Path,
    terraform_bin: str,
    runner: Runner = run_process,
    timeout: float = DEFAULT_TIMEOUT,
    progress: Progress | None = None,
    s3_clients: s3state.Clients | None = None,
    extra: dict[str, str] | None = None,
    identity: str = "",
) -> SyncResult:
    """Sync one confirmed root x environment (``row`` from :func:`list_envs`).

    An ``s3`` backend's state object is read directly (``s3_clients``; ``extra`` holds
    the decrypted extra backend-config), a local one from its file; any other backend
    runs the allowlisted terraform commands. The AWS account ids in the state's ARNs
    are compared with the mapped account (or ``identity``, the account its credentials
    resolved to in the pre-flight): a state whose resources live in another account is
    ``wrong account`` (its root is left out of drift). ``progress`` reports the current
    step and is checked for cancellation before each one and while a command runs: a
    cancelled or timed-out command is terminated (killed after :data:`KILL_GRACE`
    seconds) and the pair's partial ``TF_DATA_DIR`` removed, so the next run starts clean.
    """
    label = f"{row['root_label']} [{row['env']}]"
    where = f"root {row['root_label']} env {row['env']}"
    progress = progress or NullProgress()
    expected = expected_account_id(account) or identity
    started = time.monotonic()

    def done(status: str, detail: str = "", count: int = 0) -> SyncResult:
        seconds = time.monotonic() - started
        return _record(conn, row, SyncResult(row["id"], label, status, detail, count, seconds))

    def ingest(doc: Any, ok_detail: str) -> SyncResult:
        if not terraform.has_state(doc):
            return done(NO_STATE, "the backend has no state")
        try:
            resources = terraform.parse_document(doc)
        except ValueError as exc:
            return done(SHOW_FAILED, str(exc))
        ids = terraform.state_account_ids(doc)
        found = expected if expected in ids else max(ids, key=lambda k: (ids[k], k), default="")
        _store_resources(conn, row, resources)
        conn.execute("UPDATE tf_repo_envs SET state_account=? WHERE id=?", (found, row["id"]))
        if ids and expected and expected not in ids:
            return done(
                WRONG_ACCOUNT,
                f"the state's resources are in AWS account {found}, not {expected}",
                len(resources),
            )
        return done(OK, ok_detail, len(resources))

    repo = Path(row["repo_path"]).resolve()
    root = (repo / row["root_rel"]).resolve()
    if not root.is_dir() or not _inside(root, repo):
        return done(ERROR, "root directory not found")

    if row["backend"] == "local":
        ws = row["workspace"]
        state = (
            root / "terraform.tfstate.d" / ws / "terraform.tfstate"
            if ws and ws != DEFAULT_ENV
            else root / "terraform.tfstate"
        )
        if not state.is_file():
            return done(NO_STATE, "no local state file")
        progress.step(f"{where} · reading the local state file")
        try:
            _resolved, doc = terraform.read_state_document(str(state))
        except (ValueError, OSError) as exc:
            return done(SHOW_FAILED, str(exc) if isinstance(exc, ValueError) else "unreadable")
        return ingest(doc, "local state file")

    if row["backend"] == "s3":
        try:
            progress.check()
        except JobCancelled:
            return done(CANCELLED, "cancelled before the state was read")
        progress.step(f"{where} · reading the state from S3")
        cfg = s3_backend(root, row, extra or {}, account.region or row["guess_region"])
        missing = cfg.missing()
        if missing:
            return done(
                ERROR,
                f"s3 backend config incomplete: no {' / '.join(missing)} "
                "(add it under extra backend-config)",
            )
        if cfg.profile:
            log.info("%s: the backend's profile is ignored; the mapped account is used", where)
        try:
            client = (s3_clients or s3state.Clients()).s3(account, cfg)
            data = s3state.read_state(client, cfg, row["workspace"])
        except s3state.StateMissing:
            return done(NO_STATE, "no state object in the bucket (workspace not created yet?)")
        except s3state.StateUnavailable as exc:
            return done(ERROR, str(exc))
        except (CredentialError, BotoCoreError, ClientError) as exc:
            if is_credential_failure(exc):
                return done(ERROR, f"account credentials: {EXPIRED_MESSAGE}")
            return done(ERROR, f"S3 state read failed ({type(exc).__name__})")
        try:
            doc = terraform.load_document(data)
        except ValueError as exc:
            return done(SHOW_FAILED, str(exc))
        del data  # nothing but the extracted ids outlives parsing
        return ingest(doc, "s3 state")

    if not terraform_bin:
        return done(ERROR, "terraform binary not found (PATH or IPLENS_TERRAFORM_BIN)")
    problem = account.credential_problem()
    if problem:
        return done(ERROR, f"account credentials: {problem}")
    cache = cache_dir.resolve()
    if _inside(cache, repo):
        return done(ERROR, "the IPLens cache directory must be outside the repository")
    # Repo-scoped working directory (kept between runs: modules and the backend are
    # re-used), and one provider plugin cache shared by every repo and environment.
    data_dir = cache / f"repo-{row['repo_id']}-env-{row['id']}"
    plugins = cache / PLUGIN_CACHE
    for d in (data_dir, plugins):
        d.mkdir(parents=True, exist_ok=True)
    for p in (cache, data_dir, plugins):
        with contextlib.suppress(OSError):
            os.chmod(p, 0o700)
    env = terraform_env(account, data_dir, plugin_cache=plugins)
    secrets = (account.secret_access_key, account.session_token)

    def discard_data_dir() -> None:
        """Drop the pair's working cache a stopped command may have left half-written."""
        shutil.rmtree(data_dir, ignore_errors=True)
        log.info("removed the partial terraform working directory of %s", where)

    def run(argv: list[str], limit: float) -> subprocess.CompletedProcess | None:
        progress.check()
        progress.step(f"{where} · terraform {' '.join(argv[1:3])}")
        try:
            return run_terraform(
                argv,
                terraform_bin=terraform_bin,
                cwd=root,
                env=env,
                timeout=limit,
                runner=runner,
                cancelled=lambda: progress.cancelled,
            )
        except CommandCancelled:
            log.warning("terraform %s stopped: the job was cancelled", argv[1])
            discard_data_dir()
            raise
        except subprocess.TimeoutExpired:
            log.warning("terraform %s timed out after %ss and was stopped", argv[1], int(limit))
            discard_data_dir()
            return None

    init = [terraform_bin, "init", "-input=false", "-lockfile=readonly"]
    if row["backend_config"]:
        bfile = (root / row["backend_config"]).resolve()
        if not bfile.is_file() or not _inside(bfile, root):
            return done(INIT_FAILED, "backend config file not found")
        init.append(f"-backend-config={row['backend_config']}")
    try:
        proc = run(init, timeout)
        if proc is None:
            return done(INIT_FAILED, "timed out")
        if proc.returncode != 0:
            _log_failure("init", proc, secrets)
            return done(INIT_FAILED, f"exit {proc.returncode}; see the log")
        if row["workspace"]:
            proc = run(
                [terraform_bin, "workspace", "select", row["workspace"]],
                min(WORKSPACE_TIMEOUT, timeout),
            )
            if proc is None or proc.returncode != 0:
                if proc is not None:
                    _log_failure("workspace select", proc, secrets)
                return done(INIT_FAILED, "workspace select failed; see the log")
        proc = run([terraform_bin, "show", "-json"], timeout)
    except CommandCancelled:
        return done(CANCELLED, "cancelled: the running terraform command was stopped")
    except JobCancelled:
        return done(CANCELLED, "cancelled before the next terraform command")
    except CommandNotAllowed as exc:
        return done(ERROR, str(exc))
    except OSError as exc:
        return done(ERROR, f"could not run terraform ({type(exc).__name__})")
    if proc is None:
        return done(SHOW_FAILED, "timed out")
    if proc.returncode != 0:
        _log_failure("show", proc, secrets)
        return done(SHOW_FAILED, f"exit {proc.returncode}; see the log")
    try:
        doc = terraform.load_document(proc.stdout or b"")
    except ValueError as exc:
        return done(SHOW_FAILED, str(exc))
    del proc  # nothing but the extracted ids outlives parsing
    return ingest(doc, "")


# Raised while resolving credentials: the user fixes these by changing the account.
_CREDENTIAL_EXCEPTIONS = (
    CredentialError,
    *(
        getattr(botocore.exceptions, n)
        for n in (
            "NoCredentialsError",
            "PartialCredentialsError",
            "ProfileNotFound",
            "CredentialRetrievalError",
            "TokenRetrievalError",
            "SSOTokenLoadError",
            "UnauthorizedSSOTokenError",
        )
        if hasattr(botocore.exceptions, n)
    ),
)
# AWS error codes of credentials that are not (or no longer) valid.
_INVALID_CREDENTIAL_CODES = frozenset(
    {"InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException"}
)


@dataclass
class Preflight:
    identities: dict[int, str] = field(default_factory=dict)  # account ref -> AWS account
    problems: dict[int, str] = field(default_factory=dict)  # account ref -> why skipped


def _credential_reason(exc: BaseException) -> str:
    """Why credentials are unusable ('' if ``exc`` is not a credential failure)."""
    if isinstance(exc, CredentialError):
        return str(exc)
    if isinstance(exc, _CREDENTIAL_EXCEPTIONS):
        return f"credentials could not be loaded ({type(exc).__name__})"
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if is_credential_failure(exc) and code not in _INVALID_CREDENTIAL_CODES:
            return EXPIRED_MESSAGE
        if code in _INVALID_CREDENTIAL_CODES:
            return f"credentials are invalid ({code})"
    return ""


def preflight(accounts: Sequence[Account], clients: s3state.Clients) -> Preflight:
    """``sts:GetCallerIdentity`` for each account (~10 s timeout, in parallel).

    Raises :class:`SyncAborted` when any account's credentials are invalid or expired;
    an account AWS could not be reached for is listed in ``problems`` (its pairs are
    skipped, the others synced)."""
    out = Preflight()

    def check(account: Account) -> tuple[Account, str, str]:
        problem = account.credential_problem()
        if problem:
            return account, "credentials", problem
        try:
            ident = clients.gateway(account).caller_identity(config=FAST_CONFIG)
        except Exception as exc:  # noqa: BLE001 - classified below, details only logged
            reason = _credential_reason(exc)
            if reason:
                return account, "credentials", reason
            log.warning("pre-flight of account=%s failed: %s", account.id, type(exc).__name__)
            if isinstance(exc, ClientError):
                code = exc.response.get("Error", {}).get("Code", "") or "error"
                return account, "failed", f"sts:GetCallerIdentity failed ({code})"
            return account, "failed", f"AWS not reachable ({type(exc).__name__})"
        return account, "ok", str(ident.get("account", ""))

    started = time.monotonic()
    if len(accounts) <= 1:
        checks = [check(a) for a in accounts]
    else:
        with ThreadPoolExecutor(
            max_workers=min(S3_PARALLEL, len(accounts)), thread_name_prefix="iplens-pre"
        ) as pool:
            checks = list(pool.map(check, accounts))
    log.info(
        "terraform sync pre-flight: %d account(s) in %.1fs",
        len(accounts),
        time.monotonic() - started,
    )
    for account, kind, value in checks:
        if kind == "credentials":
            raise SyncAborted(
                f"the credentials of account {account.display_name or account.id} are invalid "
                f"or expired: {value}",
                account.id,
            )
        ref = account.id if account.id is not None else -1
        if kind == "ok":
            out.identities[ref] = value
        else:
            out.problems[ref] = value
    return out


def sync(
    db_path: Path,
    get_account: Callable[[int], Account | None],
    *,
    cache_dir: Path,
    terraform_bin: str,
    account_ref: int | None = None,
    repo_id: int | None = None,
    runner: Runner = run_process,
    timeout: float = DEFAULT_TIMEOUT,
    progress: Progress | None = None,
    parallel: int = PARALLEL_ROOTS,
    gateway_factory: Callable[[Account], AwsGateway] = AwsGateway.from_account,
    decrypt: Callable[[str], str] | None = None,
) -> list[SyncResult]:
    """Sync every confirmed, present root x environment (optionally of one account /
    repository). ``get_account`` returns the account *with* its secrets; ``decrypt``
    opens the stored extra backend-config.

    First the pre-flight (:func:`preflight`) checks every account a non-local pair
    needs: invalid or expired credentials raise :class:`SyncAborted` before anything is
    synced (every pair is marked ``error``). Then s3-backend pairs are read
    :data:`S3_PARALLEL` at a time while the terraform pairs run ``parallel`` at a time.
    Each pair runs in its own thread with its own database connection; once
    ``progress`` is cancelled no further pair is started."""
    progress = progress or NullProgress()
    started = time.monotonic()
    with closing(db_path) as conn:
        rows = [
            r
            for r in list_envs(conn, repo_id=repo_id)
            if r["confirmed"]
            and r["present"]
            and r["account_ref"] is not None
            and (account_ref is None or r["account_ref"] == account_ref)
        ]
    work = []
    for row in rows:
        account = get_account(row["account_ref"])
        if account is not None:
            work.append((row, account))
    progress.step(
        f"terraform sync: {len(work)} root × environment pair(s)", done=0, total=len(work)
    )

    def label(row: dict[str, Any]) -> str:
        return f"{row['root_label']} [{row['env']}]"

    clients = s3state.Clients(gateway_factory)
    needs_aws = {a.id: a for r, a in work if r["backend"] != "local"}
    if needs_aws:
        progress.step(f"terraform sync: checking {len(needs_aws)} account(s)")
        try:
            pre = preflight(list(needs_aws.values()), clients)
        except SyncAborted as exc:
            log.warning("terraform sync aborted: %s", exc)
            with closing(db_path) as conn:
                for row, _a in work:
                    _record(conn, row, SyncResult(row["id"], label(row), ERROR, f"aborted: {exc}"))
            raise
    else:
        pre = Preflight()

    def one(item: tuple[dict[str, Any], Account]) -> SyncResult:
        row, account = item
        with progress.bind():
            if progress.cancelled:
                return SyncResult(row["id"], label(row), CANCELLED, "not started")
            with closing(db_path) as conn:
                problem = pre.problems.get(account.id or -1) if row["backend"] != "local" else None
                if problem:
                    result = _record(
                        conn,
                        row,
                        SyncResult(row["id"], label(row), ERROR, f"pre-flight: {problem}"),
                    )
                else:
                    result = sync_env(
                        conn,
                        row,
                        account,
                        cache_dir=cache_dir,
                        terraform_bin=terraform_bin,
                        runner=runner,
                        timeout=timeout,
                        progress=progress,
                        s3_clients=clients,
                        extra=backend_extra(row, decrypt) if row["backend"] == "s3" else None,
                        identity=pre.identities.get(account.id or -1, ""),
                    )
            progress.advance()
            return result

    def run_all(items: list[tuple[int, Any]], width: int, pool_name: str) -> list[tuple[int, Any]]:
        if width <= 1 or len(items) <= 1:
            return [(i, one(w)) for i, w in items]
        with ThreadPoolExecutor(
            max_workers=min(width, len(items)), thread_name_prefix=pool_name
        ) as p:
            return list(zip((i for i, _ in items), p.map(one, (w for _, w in items)), strict=True))

    indexed = list(enumerate(work))
    fast = [(i, w) for i, w in indexed if w[0]["backend"] in ("s3", "local")]
    slow = [(i, w) for i, w in indexed if w[0]["backend"] not in ("s3", "local")]
    if fast and slow and parallel > 1:
        # The S3 reads finish while terraform still runs; neither waits for the other.
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="iplens-sync") as both:
            f_fast = both.submit(run_all, fast, S3_PARALLEL, "iplens-s3")
            f_slow = both.submit(run_all, slow, parallel, "iplens-tf")
            done_items = f_fast.result() + f_slow.result()
    else:
        done_items = run_all(fast, S3_PARALLEL if parallel > 1 else 1, "iplens-s3") + run_all(
            slow, parallel, "iplens-tf"
        )
    results = [r for _, r in sorted(done_items, key=lambda x: x[0])]
    log.info(
        "terraform sync finished: %d pair(s) (%d s3, %d terraform) in %.1fs",
        len(results),
        sum(1 for r, _a in work if r["backend"] == "s3"),
        len(slow),
        time.monotonic() - started,
    )
    return results


def summarise(results: Sequence[SyncResult]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))


# -- drift ----------------------------------------------------------------------------------

# Kinds compared in both directions; ENIs only "in Terraform, not in AWS" (most ENIs are
# created by AWS services and are never Terraform resources themselves).
DRIFT_KINDS = ("vpc", "subnet", "sg", "vpce", "nat", "instance", "lb", "lambda", "ecs_service")
# Kinds whose inventory is optional (missing permission = empty table): compared only when
# the snapshot has at least one of them.
_OPTIONAL_KINDS = frozenset({"sg", "ecs_service"})


def aws_inventory(conn: sqlite3.Connection, snapshot_id: int) -> dict[str, set[str]]:
    """``kind -> resource ids`` of a snapshot, in the same form Terraform ids are kept.
    Default VPCs (and their subnets) and ``default`` security groups are left out."""

    def ids(sql: str) -> set[str]:
        return {r[0] for r in conn.execute(sql, (snapshot_id,)) if r[0]}

    return {
        "vpc": ids("SELECT vpc_id FROM vpcs WHERE snapshot_id=? AND is_default=0"),
        "subnet": ids(
            "SELECT subnet_id FROM subnets s WHERE snapshot_id=? AND vpc_id NOT IN "
            "(SELECT vpc_id FROM vpcs WHERE snapshot_id=s.snapshot_id AND is_default=1)"
        ),
        "sg": ids(
            "SELECT group_id FROM security_groups WHERE snapshot_id=? AND group_name != 'default'"
        ),
        "vpce": ids("SELECT endpoint_id FROM endpoints WHERE snapshot_id=?"),
        "nat": ids("SELECT owner_ref FROM enis WHERE snapshot_id=? AND owner_type='nat'"),
        "instance": ids(
            "SELECT instance_id FROM enis WHERE snapshot_id=? AND instance_id LIKE 'i-%'"
        ),
        "lb": ids("SELECT name FROM load_balancers WHERE snapshot_id=?"),
        "lambda": ids("SELECT name FROM lambdas WHERE snapshot_id=?"),
        "ecs_service": ids(
            "SELECT cluster || '/' || service FROM ecs_services WHERE snapshot_id=?"
        ),
        "eni": ids("SELECT eni_id FROM enis WHERE snapshot_id=?"),
    }


# -- "managed elsewhere" markers ----------------------------------------------------------

MARKER_KINDS = {
    "type": "resource type",
    "resource": "resource id",
    "tag": "tag (Key or Key=Value)",
}
# Drift kind -> resource_tags.resource_type of the same resource (tag markers).
TAG_TYPES = {
    "vpc": "vpc",
    "subnet": "subnet",
    "sg": "sg",
    "vpce": "endpoint",
    "lb": "lb",
    "lambda": "lambda",
    "ecs_service": "ecs_service",
}
_MARKER_ID_RE = re.compile(r"^[A-Za-z0-9._:/@+=-]{1,256}$")
MAX_MARKER_NOTE = 200


@dataclass(frozen=True)
class Marker:
    id: int
    account_ref: int | None
    kind: str
    value: str
    note: str = ""

    @property
    def label(self) -> str:
        if self.kind == "type":
            return f"every {terraform.KIND_LABELS.get(self.value, self.value)}"
        if self.kind == "tag":
            return f"tag {self.value}"
        return self.value

    def tag_matches(self, tags: dict[str, str]) -> bool:
        key, sep, value = self.value.partition("=")
        if key not in tags:
            return False
        return not sep or tags[key] == value


def validate_marker(kind: str, value: str) -> tuple[str, str]:
    """``(kind, value)`` of a "managed elsewhere" marker; ValueError if invalid."""
    kind, value = (kind or "").strip(), (value or "").strip()
    if kind not in MARKER_KINDS:
        raise ValueError("choose a marker type: resource type, resource id or tag")
    if kind == "type":
        if value not in (*DRIFT_KINDS, "eni"):
            raise ValueError("unknown resource type")
    elif kind == "resource":
        if not _MARKER_ID_RE.match(value):
            raise ValueError("enter a resource id (letters, digits and . _ : / @ + = -)")
    else:
        key, sep, tag_value = value.partition("=")
        key = key.strip()
        if not key or len(key) > 128 or len(tag_value) > 256 or "\n" in value:
            raise ValueError("enter a tag key, or Key=Value (key up to 128 characters)")
        value = f"{key}={tag_value.strip()}" if sep else key
    return kind, value


def add_marker(
    conn: sqlite3.Connection, account_ref: int | None, kind: str, value: str, note: str = ""
) -> int:
    kind, value = validate_marker(kind, value)
    row = conn.execute(
        "SELECT id FROM tf_managed_elsewhere WHERE account_ref IS ? AND kind=? AND value=?",
        (account_ref, kind, value),
    ).fetchone()
    if row:
        return int(row["id"])
    cur = conn.execute(
        "INSERT INTO tf_managed_elsewhere(account_ref, kind, value, note) VALUES(?,?,?,?)",
        (account_ref, kind, value, (note or "").strip()[:MAX_MARKER_NOTE]),
    )
    return int(cur.lastrowid or 0)


def delete_marker(conn: sqlite3.Connection, marker_id: int) -> bool:
    return conn.execute("DELETE FROM tf_managed_elsewhere WHERE id=?", (marker_id,)).rowcount > 0


def list_markers(conn: sqlite3.Connection, account_ref: int | None) -> list[Marker]:
    """Markers of ``account_ref`` and those for every account."""
    return [
        Marker(r["id"], r["account_ref"], r["kind"], r["value"], r["note"])
        for r in conn.execute(
            "SELECT * FROM tf_managed_elsewhere WHERE account_ref IS NULL OR account_ref=? "
            "ORDER BY kind, value",
            (account_ref,),
        )
    ]


class _MarkerIndex:
    def __init__(self, markers: Sequence[Marker], tags: dict[tuple[str, str], dict[str, str]]):
        self.types = {m.value: m for m in markers if m.kind == "type"}
        self.ids = {m.value: m for m in markers if m.kind == "resource"}
        self.tag_markers = [m for m in markers if m.kind == "tag"]
        self.tags = tags

    def match(self, kind: str, rid: str, *, with_tags: bool = True) -> Marker | None:
        hit = self.ids.get(rid) or self.types.get(kind)
        if hit or not with_tags or kind not in TAG_TYPES:
            return hit
        tags = self.tags.get((TAG_TYPES[kind], rid))
        if tags:
            return next((m for m in self.tag_markers if m.tag_matches(tags)), None)
        return None


@dataclass
class Drift:
    roots: list[str] = field(default_factory=list)  # roots compared ("in TF, not in AWS")
    not_in_terraform: list[dict[str, str]] = field(default_factory=list)
    not_in_aws: list[dict[str, str]] = field(default_factory=list)
    skipped_kinds: list[str] = field(default_factory=list)
    skipped_roots: list[dict[str, str]] = field(default_factory=list)
    # Excluded from both lists: matched a "managed elsewhere" marker.
    managed_elsewhere: list[dict[str, str]] = field(default_factory=list)
    # Roots whose state belongs to another AWS account (excluded from both lists).
    wrong_account: list[dict[str, Any]] = field(default_factory=list)
    markers: list[Marker] = field(default_factory=list)


def wrong_account_roots(conn: sqlite3.Connection) -> set[str]:
    """``tf_roots`` names written by a sync whose state is in another AWS account."""
    return {
        r["root_name"]
        for r in conn.execute(
            "SELECT root_name FROM tf_repo_envs WHERE status=? AND root_name != ''",
            (WRONG_ACCOUNT,),
        )
    }


def suggest_for_state(state_account: str, accounts: Sequence[Account]) -> Account | None:
    """The IPLens account whose credentials resolve to ``state_account``, if any."""
    if not state_account:
        return None
    return next(
        (a for a in accounts if state_account in (a.last_seen_account_id, a.aws_account_id)),
        None,
    )


def drift(conn: sqlite3.Connection, account_ref: int, snapshot: Any) -> Drift:
    """Compare the account's latest snapshot with Terraform.

    (a) *in AWS, not in Terraform*: resources of the snapshot that no Terraform root
    (repo-synced or loaded from a file) manages; (b) *in Terraform, not in AWS*:
    resources of the repo roots mapped to this account that the snapshot lacks. Roots
    whose guessed region differs from the snapshot's region are skipped for (b).

    Roots whose state is in another AWS account (``wrong account``) count for neither
    list, and resources matching a "managed elsewhere" marker (by type, id or - for
    (a) - tag) are listed apart instead of as drift.
    """
    out = Drift()
    inv = aws_inventory(conn, snapshot["id"])
    out.skipped_kinds = [
        terraform.KIND_LABELS[k] for k in sorted(_OPTIONAL_KINDS) if not inv.get(k)
    ]
    compared = [k for k in DRIFT_KINDS if k not in _OPTIONAL_KINDS or inv.get(k)]
    wrong = wrong_account_roots(conn)
    managed = {
        (r["kind"], r["resource_id"])
        for r in conn.execute(
            "SELECT t.kind, t.resource_id, r.name FROM tf_resources t "
            "JOIN tf_roots r ON r.id = t.root_id"
        )
        if r["name"] not in wrong
    }
    out.markers = list_markers(conn, account_ref)
    tags: dict[tuple[str, str], dict[str, str]] = {}
    if any(m.kind == "tag" for m in out.markers):
        for r in conn.execute(
            "SELECT resource_type, resource_id, key, value FROM resource_tags WHERE snapshot_id=?",
            (snapshot["id"],),
        ):
            tags.setdefault((r["resource_type"], r["resource_id"]), {})[r["key"]] = r["value"]
    markers = _MarkerIndex(out.markers, tags)

    def elsewhere(side: str, kind: str, rid: str, marker: Marker, root: str = "") -> None:
        out.managed_elsewhere.append(
            {
                "side": side,
                "kind": kind,
                "label": terraform.KIND_LABELS.get(kind, kind),
                "resource_id": rid,
                "root": root,
                "marker": marker.label,
            }
        )

    for kind in compared:
        for rid in sorted(inv.get(kind, ())):
            if (kind, rid) in managed:
                continue
            marker = markers.match(kind, rid)
            if marker:
                elsewhere("aws", kind, rid, marker)
                continue
            out.not_in_terraform.append(
                {"kind": kind, "label": terraform.KIND_LABELS[kind], "resource_id": rid}
            )
    region = snapshot["region"]
    for env in list_envs(conn, account_ref=account_ref):
        if not env["present"] or not env["root_name"]:
            continue
        if env["status"] == WRONG_ACCOUNT:
            out.wrong_account.append(
                {
                    "status": WRONG_ACCOUNT,
                    "root": env["root_name"],
                    "root_label": env["root_label"],
                    "env": env["env"],
                    "repo_id": env["repo_id"],
                    "state_account": env["state_account"],
                }
            )
            out.skipped_roots.append(
                {
                    "root": env["root_name"],
                    "reason": f"wrong account (state in {env['state_account'] or 'another'})",
                }
            )
            continue
        if env["guess_region"] and env["guess_region"] != region:
            out.skipped_roots.append(
                {"root": env["root_name"], "reason": f"region {env['guess_region']} ≠ {region}"}
            )
            continue
        out.roots.append(env["root_name"])
        for r in conn.execute(
            "SELECT t.kind, t.resource_id, t.address, t.type FROM tf_resources t "
            "JOIN tf_roots r ON r.id = t.root_id WHERE r.name=? AND r.origin='repo' "
            "ORDER BY t.address",
            (env["root_name"],),
        ):
            kind = r["kind"]
            if kind not in compared and kind != "eni":
                continue
            if r["resource_id"] in inv.get(kind, set()):
                continue
            marker = markers.match(kind, r["resource_id"], with_tags=False)
            if marker:
                elsewhere("terraform", kind, r["resource_id"], marker, env["root_name"])
                continue
            out.not_in_aws.append(
                {
                    "root": env["root_name"],
                    "address": r["address"],
                    "type": r["type"],
                    "label": terraform.KIND_LABELS.get(kind, kind),
                    "resource_id": r["resource_id"],
                }
            )
    return out
