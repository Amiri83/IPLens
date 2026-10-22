"""``iplens mcp``: a read-only stdio MCP server over the local IPLens database.

Needs the optional extra: ``pip install 'aws-iplens[mcp]'`` (the official ``mcp`` SDK).
The tools (:mod:`iplens.mcptools`) read the local SQLite database only, through a
read-only connection; the server never calls AWS (the process refuses to import the AWS
SDK, see :func:`iplens.mcptools.block_aws_sdk`) and never writes anything. stdout is the
protocol channel: messages for people go to stderr.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Any

from . import __version__
from .config import default_paths
from .mcptools import DEFAULT_LIMIT, DEFAULT_TOP, ToolInputError, Tools, block_aws_sdk

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

INSTALL_HINT = "iplens mcp needs the mcp extra: pip install 'aws-iplens[mcp]'"

INSTRUCTIONS = """\
IPLens: private IPv4 usage of AWS subnets, from the latest IPLens snapshot on this machine
(read-only; nothing here calls AWS). Every result carries `snapshot_taken_at`: say how old
the data is when it matters. Subnets are given by id or by name. "Headroom" is the worst
case demand if everything that can scale out does (ASG / ECS max, ALB reserve, Lambda
ENIs); status ok / tight (< 20% left at max scale) / over. Use find_subnet to pick where N
new IPs fit, fit_check to verify one subnet like the `iplens check` CI gate, changes for
what changed between snapshots."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iplens mcp",
        description="Read-only MCP server (stdio) over the local IPLens database: subnet "
        "usage, headroom, IP lookup, snapshot diffs and the fit check. Never calls AWS, "
        "never writes.",
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
    parser.add_argument("--version", action="version", version=f"iplens {__version__}")
    return parser


def build_server(tools: Tools) -> MCPServer:
    """The MCP server exposing :data:`iplens.mcptools.TOOLS` (all read-only)."""
    from mcp.server.mcpserver import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.types import ToolAnnotations

    server = MCPServer("iplens", version=__version__, instructions=INSTRUCTIONS)
    read_only = ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )

    def run(name: str, **arguments: Any) -> dict[str, Any]:
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

    return server


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Before anything else is imported: the server process must never load the AWS SDK.
    block_aws_sdk()
    try:
        import mcp  # noqa: F401 - only checks that the extra is installed
    except ImportError:
        print(f"iplens mcp: error: {INSTALL_HINT}", file=sys.stderr)
        return 2
    tools = Tools(default_paths(args.home).db_path, args.account, args.redact)
    try:
        tools.check()
    except ToolInputError as exc:
        print(f"iplens mcp: error: {exc}", file=sys.stderr)
        return 2
    build_server(tools).run("stdio")
    return 0
