"""Local Terraform repositories: discovery, an allowlisted read-only sync, and drift.

Discovery (:func:`discover`) only *reads* ``.tf`` / ``.tfvars`` / backend config files
with a tolerant, best-effort parser; it never runs ``terraform``. It finds root
directories (a ``backend`` / ``cloud`` block or a ``provider`` block outside a
``modules`` directory), their environments (env sub-folders, ``*.tfvars`` files and
workspaces) and guesses each environment's AWS account id and region. Only paths,
names, the backend *type* and those two guesses are kept; variable, provider and
backend values are never stored, logged or displayed.

The sync (:func:`sync_env`) runs nothing but the invocations in
:data:`ALLOWED_INVOCATIONS`, checked by :func:`check_allowlisted` right before
``subprocess`` is called with an explicit argv (no shell), ``cwd`` at the root
directory, ``TF_DATA_DIR`` in the app's cache directory (the repo stays untouched),
the mapped IPLens account's credentials and a timeout. ``plan``, ``apply``,
``import``, ``destroy``, ``state`` and every other command or flag are refused.
Roots on the local backend are read straight from their ``.tfstate`` file instead.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import terraform
from .accounts import Account
from .db import closing

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
        tf_files = sorted(f for f in filenames if f.endswith(".tf"))
        if not tf_files:
            continue
        parts, size = [], 0
        for f in tf_files:
            t = _read_text(d / f)
            size += len(t)
            if size > MAX_ROOT_TEXT:
                break
            parts.append(_strip_comments(t))
        text = "\n".join(parts)
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


def run_terraform(
    argv: Sequence[str],
    *,
    terraform_bin: str,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    runner: Runner = subprocess.run,
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

OK, INIT_FAILED, NO_STATE, SHOW_FAILED, ERROR = (
    "ok",
    "init failed",
    "no state",
    "show failed",
    "error",
)
INIT_TIMEOUT = 300.0
WORKSPACE_TIMEOUT = 60.0
SHOW_TIMEOUT = 180.0
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
    }
)
_PASSTHROUGH_PREFIXES = ("TF_TOKEN_",)  # Terraform Cloud / registry API tokens
_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")


def terraform_env(
    account: Account, data_dir: Path, base: dict[str, str] | None = None
) -> dict[str, str]:
    """Environment for terraform: a small passthrough plus the account's credentials.

    ``account`` must have been loaded with ``with_secret=True`` for key / temporary auth.
    The result holds secrets: it is passed to the child process and never logged.
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
    )
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
        "terraform sync %s: %s%s",
        result.label,
        result.status,
        f" ({result.detail})" if result.detail else "",
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


def sync_env(
    conn: sqlite3.Connection,
    row: dict[str, Any],
    account: Account,
    *,
    cache_dir: Path,
    terraform_bin: str,
    runner: Runner = subprocess.run,
) -> SyncResult:
    """Sync one confirmed root x environment (``row`` from :func:`list_envs`)."""
    label = f"{row['root_label']} [{row['env']}]"

    def done(status: str, detail: str = "", count: int = 0) -> SyncResult:
        return _record(conn, row, SyncResult(row["id"], label, status, detail, count))

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
        try:
            _resolved, resources = terraform.read_state_file(str(state))
        except (ValueError, OSError) as exc:
            return done(SHOW_FAILED, str(exc) if isinstance(exc, ValueError) else "unreadable")
        _store_resources(conn, row, resources)
        return done(OK, "local state file", len(resources))

    if not terraform_bin:
        return done(ERROR, "terraform binary not found (PATH or IPLENS_TERRAFORM_BIN)")
    problem = account.credential_problem()
    if problem:
        return done(ERROR, f"account credentials: {problem}")
    cache = cache_dir.resolve()
    if _inside(cache, repo):
        return done(ERROR, "the IPLens cache directory must be outside the repository")
    data_dir = cache / f"env-{row['id']}"
    data_dir.mkdir(parents=True, exist_ok=True)
    for p in (cache, data_dir):
        with contextlib.suppress(OSError):
            os.chmod(p, 0o700)
    env = terraform_env(account, data_dir)
    secrets = (account.secret_access_key, account.session_token)

    def run(argv: list[str], timeout: float) -> subprocess.CompletedProcess | None:
        try:
            return run_terraform(
                argv,
                terraform_bin=terraform_bin,
                cwd=root,
                env=env,
                timeout=timeout,
                runner=runner,
            )
        except subprocess.TimeoutExpired:
            log.warning("terraform %s timed out after %ss", argv[1], int(timeout))
            return None

    init = [terraform_bin, "init", "-input=false", "-lockfile=readonly"]
    if row["backend_config"]:
        bfile = (root / row["backend_config"]).resolve()
        if not bfile.is_file() or not _inside(bfile, root):
            return done(INIT_FAILED, "backend config file not found")
        init.append(f"-backend-config={row['backend_config']}")
    try:
        proc = run(init, INIT_TIMEOUT)
        if proc is None:
            return done(INIT_FAILED, "timed out")
        if proc.returncode != 0:
            _log_failure("init", proc, secrets)
            return done(INIT_FAILED, f"exit {proc.returncode}; see the log")
        if row["workspace"]:
            proc = run([terraform_bin, "workspace", "select", row["workspace"]], WORKSPACE_TIMEOUT)
            if proc is None or proc.returncode != 0:
                if proc is not None:
                    _log_failure("workspace select", proc, secrets)
                return done(INIT_FAILED, "workspace select failed; see the log")
        proc = run([terraform_bin, "show", "-json"], SHOW_TIMEOUT)
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
    if not terraform.has_state(doc):
        return done(NO_STATE, "the backend has no state")
    try:
        resources = terraform.parse_document(doc)
    except ValueError as exc:
        return done(SHOW_FAILED, str(exc))
    del doc
    _store_resources(conn, row, resources)
    return done(OK, "", len(resources))


def sync(
    db_path: Path,
    get_account: Callable[[int], Account | None],
    *,
    cache_dir: Path,
    terraform_bin: str,
    account_ref: int | None = None,
    repo_id: int | None = None,
    runner: Runner = subprocess.run,
) -> list[SyncResult]:
    """Sync every confirmed, present root x environment (optionally of one account /
    repository). ``get_account`` returns the account *with* its secrets."""
    with closing(db_path) as conn:
        rows = [
            r
            for r in list_envs(conn, repo_id=repo_id)
            if r["confirmed"]
            and r["present"]
            and r["account_ref"] is not None
            and (account_ref is None or r["account_ref"] == account_ref)
        ]
    results = []
    for row in rows:
        account = get_account(row["account_ref"])
        if account is None:
            continue
        with closing(db_path) as conn:
            results.append(
                sync_env(
                    conn,
                    row,
                    account,
                    cache_dir=cache_dir,
                    terraform_bin=terraform_bin,
                    runner=runner,
                )
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


@dataclass
class Drift:
    roots: list[str] = field(default_factory=list)  # roots compared ("in TF, not in AWS")
    not_in_terraform: list[dict[str, str]] = field(default_factory=list)
    not_in_aws: list[dict[str, str]] = field(default_factory=list)
    skipped_kinds: list[str] = field(default_factory=list)
    skipped_roots: list[dict[str, str]] = field(default_factory=list)


def drift(conn: sqlite3.Connection, account_ref: int, snapshot: Any) -> Drift:
    """Compare the account's latest snapshot with Terraform.

    (a) *in AWS, not in Terraform*: resources of the snapshot that no Terraform root
    (repo-synced or loaded from a file) manages; (b) *in Terraform, not in AWS*:
    resources of the repo roots mapped to this account that the snapshot lacks. Roots
    whose guessed region differs from the snapshot's region are skipped for (b).
    """
    out = Drift()
    inv = aws_inventory(conn, snapshot["id"])
    out.skipped_kinds = [
        terraform.KIND_LABELS[k] for k in sorted(_OPTIONAL_KINDS) if not inv.get(k)
    ]
    compared = [k for k in DRIFT_KINDS if k not in _OPTIONAL_KINDS or inv.get(k)]
    managed = {
        (r["kind"], r["resource_id"])
        for r in conn.execute("SELECT kind, resource_id FROM tf_resources")
    }
    for kind in compared:
        for rid in sorted(inv.get(kind, ())):
            if (kind, rid) not in managed:
                out.not_in_terraform.append(
                    {"kind": kind, "label": terraform.KIND_LABELS[kind], "resource_id": rid}
                )
    region = snapshot["region"]
    for env in list_envs(conn, account_ref=account_ref):
        if not env["present"] or not env["root_name"]:
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
            if r["resource_id"] not in inv.get(kind, set()):
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
