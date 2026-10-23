"""``iplens mcp``: a read-only MCP server over the local IPLens database.

Built on the official ``mcp`` SDK. It runs only while Settings → MCP server → Enable MCP
server is on: otherwise it exits (status 2) and a running one refuses every tool call.
The tools (:mod:`iplens.mcptools`) read the local SQLite database only, through a
read-only connection; the server never calls AWS (the process refuses to import the AWS
SDK, see :func:`iplens.mcptools.block_aws_sdk`) and never writes anything.

The default transport is stdio: stdout is the protocol channel, messages for people go to
stderr. ``--http`` serves the same tools over Streamable HTTP (see :mod:`iplens.mcphttp`)
behind a required bearer token, read from ``$IPLENS_MCP_TOKEN`` or else the token stored
(encrypted) by Settings → MCP server.
"""

from __future__ import annotations

import argparse
import os
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__, mcphttp
from .config import default_paths
from .mcpconfig import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DISABLED_MESSAGE,
    TOKEN_ENV,
    check_token,
    is_enabled,
    is_loopback,
    parse_port,
    read_token,
)
from .mcptools import (
    DEFAULT_LIMIT,
    DEFAULT_TOP,
    ToolInputError,
    Tools,
    block_aws_sdk,
    open_readonly,
)
from .suggestions import UNUSED_ENDPOINT_DAYS

# Set by IPLens for its child server: the server stops when that process is gone.
PARENT_PID_ENV = "IPLENS_MCP_PARENT_PID"
PARENT_POLL_SECONDS = 1.0

INSTRUCTIONS = """\
IPLens: private IPv4 usage of AWS subnets, from the latest IPLens snapshot on this machine
(read-only; nothing here calls AWS). Every result carries `snapshot_taken_at`: say how old
the data is when it matters. Subnets are given by id or by name. "Headroom" is the worst
case demand if everything that can scale out does (ASG / ECS max, ALB reserve, Lambda
ENIs); status ok / tight (< 20% left at max scale) / over. Use find_subnet to pick where N
new IPs fit, fit_check to verify one subnet like the `iplens check` CI gate, changes for
what changed between snapshots, suggestions for ways to free IPs (vetoed by the saved
rules)."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iplens mcp",
        description="Read-only MCP server over the local IPLens database: subnet usage, "
        "headroom, IP lookup, snapshot diffs, the fit check and suggestions. Never calls "
        "AWS, never "
        "writes. stdio by default; --http serves Streamable HTTP with a bearer token "
        f"(${TOKEN_ENV}, else the token of Settings → MCP server).",
    )
    parser.add_argument(
        "--home", default=None, help="data directory (default: $IPLENS_HOME or ~/.iplens)"
    )
    parser.add_argument(
        "--account",
        metavar="ACCOUNT",
        help="IPLens account id, AWS account id or display name (default: the account "
        "active in the UI)",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="hide account ids, ARNs, ENI / instance ids, IPs and CIDRs; show names only",
    )
    http = parser.add_argument_group("HTTP transport")
    http.add_argument("--http", action="store_true", help="serve Streamable HTTP instead of stdio")
    http.add_argument(
        "--host", default=None, help=f"bind address (default: {DEFAULT_HOST}, local only)"
    )
    http.add_argument("--port", default=None, help=f"port (default: {DEFAULT_PORT})")
    http.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow a non-loopback --host (the bearer token is the only protection)",
    )
    parser.add_argument("--version", action="version", version=f"iplens {__version__}")
    return parser


def remote_warning(host: str, port: int) -> str:
    return (
        f"WARNING: iplens mcp is listening on {host}:{port} and is reachable from other "
        "machines; the bearer token is its only protection and HTTP is not encrypted. Use "
        "--allow-remote only on a trusted network."
    )


_NO_TOKEN = f"no MCP token: generate one in IPLens (Settings → MCP server) or set ${TOKEN_ENV}"


def resolve_token(home: Any) -> str:
    """The bearer token: ``$IPLENS_MCP_TOKEN``, else the stored one (read-only: the key
    file is never created here). ValueError if there is none."""
    from_env = os.environ.get(TOKEN_ENV, "")
    if from_env:
        return check_token(from_env)
    paths = default_paths(home)
    if not (paths.key_path.exists() or os.environ.get("IPLENS_SECRET_KEY")):
        raise ValueError(_NO_TOKEN)
    from .crypto import SecretBox

    try:
        conn = open_readonly(paths.db_path)
    except ToolInputError as exc:
        raise ValueError(str(exc)) from None
    try:
        token = read_token(conn, SecretBox.from_path(paths.key_path))
    finally:
        conn.close()
    if not token:
        raise ValueError(_NO_TOKEN)
    return token


def mcp_enabled(db_path: Path) -> bool:
    """True if Settings → MCP server has the server enabled (read-only; False if the
    database cannot be read)."""
    try:
        conn = open_readonly(db_path)
    except ToolInputError:
        return False
    try:
        return is_enabled(conn)
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def watch_parent(pid: int, poll: float = PARENT_POLL_SECONDS) -> threading.Thread:
    """Stop this process (SIGTERM to itself, a graceful shutdown) once process ``pid``,
    IPLens, is gone: the server never outlives the app that started it."""

    def run() -> None:
        while True:
            time.sleep(poll)
            if os.getppid() != pid:
                os.kill(os.getpid(), signal.SIGTERM)
                return

    thread = threading.Thread(target=run, name="iplens-mcp-parent", daemon=True)
    thread.start()
    return thread


def build_server(tools: Tools) -> MCPServer:
    """The MCP server exposing :data:`iplens.mcptools.TOOLS` (all read-only); every call
    is refused once the server is disabled in Settings (no restart needed)."""
    server = MCPServer("iplens", version=__version__, instructions=INSTRUCTIONS)
    read_only = ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )

    def run(name: str, **arguments: Any) -> dict[str, Any]:
        if not mcp_enabled(tools.db_path):
            raise ToolError(DISABLED_MESSAGE)
        try:
            return tools.call(name, **arguments)
        except ToolInputError as exc:
            raise ToolError(str(exc)) from None

    @server.tool(annotations=read_only)
    def list_subnets(
        vpc: str | None = None,
        az: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Subnets of the latest snapshot: id, name, CIDR, used / idle / free IPs and the
        scale headroom status (ok / tight / over). Optional filters: vpc (id or name), az
        (e.g. us-east-1a). Paginated: pass next_offset as offset for the next page."""
        return run("list_subnets", vpc=vpc, az=az, limit=limit, offset=offset)

    @server.tool(annotations=read_only)
    def find_subnet(
        need_ips: int,
        vpc: str | None = None,
        az: str | None = None,
        limit: int = DEFAULT_TOP,
    ) -> dict[str, Any]:
        """Subnets where need_ips more IPs fit even with every scaling resource at its
        maximum (free - headroom demand - need_ips >= 0), most room left first, with the
        headroom left after placing them. Optional filters: vpc (id or name), az."""
        return run("find_subnet", need_ips=need_ips, vpc=vpc, az=az, limit=limit)

    @server.tool(annotations=read_only)
    def subnet_detail(subnet: str, top: int = DEFAULT_TOP) -> dict[str, Any]:
        """One subnet (id or name): IP usage, the top consumers (resources holding the
        most IPs), the headroom contributors with their assumptions, and the exhaustion
        forecast (days until full / until the headroom no longer fits)."""
        return run("subnet_detail", subnet=subnet, top=top)

    @server.tool(annotations=read_only)
    def lookup_ip(ip: str) -> dict[str, Any]:
        """Who holds a private IPv4 address: its ENI, owning resource, ownership and
        subnet; for an address no ENI holds, whether it is free or reserved by AWS."""
        return run("lookup_ip", ip=ip)

    @server.tool(annotations=read_only)
    def changes(since: str = "latest-1", limit: int = 20) -> dict[str, Any]:
        """What changed from an older snapshot to the latest: IP / ENI totals, net IPs
        per subnet, top growing consumers and ENI changes. since: latest-N (default
        latest-1, the previous snapshot), a snapshot id, or an ISO date / time."""
        return run("changes", since=since, limit=limit)

    @server.tool(annotations=read_only)
    def fit_check(
        subnet: str,
        need: int,
        min_free_pct: float = 0.0,
        include_surge: bool = True,
    ) -> dict[str, Any]:
        """Do `need` more IPs fit in a subnet (id or name)? The exact logic of
        `iplens check --subnet ID --need N`: left = free - headroom demand - need; fails
        below 0, below min_free_pct % of usable IPs, or on a saved rule violation.
        include_surge=false leaves out the ECS rolling-deployment surge."""
        return run(
            "fit_check",
            subnet=subnet,
            need=need,
            min_free_pct=min_free_pct,
            include_surge=include_surge,
        )

    @server.tool(annotations=read_only)
    def suggestions(
        kind: str | None = None,
        include_blocked: bool = True,
        endpoint_days: int = UNUSED_ENDPOINT_DAYS,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Ways to free IPs, as on the Suggestions page: detached ENIs, underused
        subnets, unused / duplicate endpoints, Lambda ENI sprawl, idle ECS services, ...
        each with the IPs it saves and whether a saved rule blocks it. notes lists the
        checks that could not be made (short snapshot history, no flow log data).
        Optional: kind (e.g. unused_endpoint), include_blocked, endpoint_days (the
        unused endpoint window, default 14). Paginated like list_subnets."""
        return run(
            "suggestions",
            kind=kind,
            include_blocked=include_blocked,
            endpoint_days=endpoint_days,
            limit=limit,
            offset=offset,
        )

    return server


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.http and (args.host or args.port or args.allow_remote):
        parser.error("--host, --port and --allow-remote need --http")
    host = (args.host or DEFAULT_HOST).strip().removeprefix("[").removesuffix("]")
    try:
        port = parse_port(args.port or DEFAULT_PORT)
    except ValueError as exc:
        parser.error(str(exc))
    remote = not is_loopback(host)
    if args.http and remote and not args.allow_remote:
        parser.error(
            f"refusing to listen on non-loopback host {host!r}: pass --allow-remote to do "
            "it anyway (the bearer token is the only protection)"
        )
    # Before anything else is imported: the server process must never load the AWS SDK.
    block_aws_sdk()
    tools = Tools(default_paths(args.home).db_path, args.account, args.redact)
    try:
        tools.check()
    except ToolInputError as exc:
        print(f"iplens mcp: error: {exc}", file=sys.stderr)
        return 2
    if not mcp_enabled(tools.db_path):
        print(f"iplens mcp: error: {DISABLED_MESSAGE}", file=sys.stderr)
        return 2
    if not args.http:
        build_server(tools).run("stdio")
        return 0
    return _serve_http(args, tools, host, port, remote)


def _serve_http(args: argparse.Namespace, tools: Tools, host: str, port: int, remote: bool) -> int:
    try:
        token = resolve_token(args.home)
    except ValueError as exc:
        print(f"iplens mcp: error: {exc}", file=sys.stderr)
        return 2
    mcphttp.configure_logging()
    try:
        sock = mcphttp.bind(host, port)
    except OSError as exc:
        print(
            f"iplens mcp: error: cannot listen on {host}:{port}: {exc.strerror or exc}",
            file=sys.stderr,
        )
        return 2
    if remote:
        print(remote_warning(host, port), file=sys.stderr, flush=True)
    parent = os.environ.get(PARENT_PID_ENV, "")
    if parent.isdigit():
        watch_parent(int(parent))
    try:
        asgi = mcphttp.app(build_server(tools), token, host, port, args.allow_remote)
        mcphttp.serve(sock, asgi, host, port)
    finally:
        sock.close()
    return 0
