"""``iplens mcp --http``: the MCP server over Streamable HTTP (see :mod:`iplens.mcpserver`).

Every request passes :class:`Guard` before it reaches the MCP SDK:

* the Host header must name this server (DNS-rebinding protection), with its port;
* an Origin header, when a browser sends one, must be this server's own origin (a request
  without Origin, from a CLI / editor MCP client, is fine);
* ``Authorization: Bearer <token>`` is required, compared in constant time.

The socket is bound before uvicorn starts, so a port in use is a clear error (exit 2).
Logging goes to stderr in the IPLens log format: IPLens writes the child's stderr to its
own log file, viewable on the Logs page.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import sys
from typing import Any

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .logging_setup import LOG_FORMAT, RedactingFilter
from .mcpconfig import MCP_PATH, url_host

log = logging.getLogger("iplens.mcp")

LOCAL_NAMES = ("127.0.0.1", "localhost", "[::1]")
# Seconds uvicorn waits for open connections when told to stop.
GRACEFUL_SECONDS = 3


def _split_host(value: str) -> tuple[str, str]:
    """A Host header / origin authority as (lowercase name, port text)."""
    value = value.strip().lower()
    if value.startswith("["):
        name, _, rest = value.partition("]")
        return name + "]", rest[1:] if rest.startswith(":") else ""
    name, _, port = value.partition(":")
    return name, port


def _ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        return False
    return True


class Guard:
    """ASGI middleware: Host, Origin and bearer token checks on every HTTP request."""

    def __init__(self, app: Any, token: str, host: str, port: int, allow_remote: bool = False):
        self.app = app
        self._token = token.encode()
        self.port = str(port)
        self.allow_remote = allow_remote
        self.names = {*LOCAL_NAMES, url_host(host).lower()}

    def host_ok(self, value: str) -> bool:
        name, port = _split_host(value)
        if port != self.port:
            return False
        # With --allow-remote any IP literal is fine: DNS rebinding needs a host name.
        return name in self.names or (self.allow_remote and _ip_literal(name))

    def origin_ok(self, origin: str | None) -> bool:
        if origin is None:  # not a browser: CLI / editor MCP clients send none
            return True
        scheme, sep, authority = origin.partition("://")
        return bool(sep) and scheme.lower() == "http" and self.host_ok(authority)

    def token_ok(self, authorization: str | None) -> bool:
        scheme, _, value = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            return False
        return secrets.compare_digest(value.strip().encode(), self._token)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":  # lifespan
            await self.app(scope, receive, send)
            return
        headers: dict[str, str] = {}
        for k, v in scope.get("headers", []):
            headers.setdefault(k.decode("latin-1").lower(), v.decode("latin-1"))
        path = scope.get("path", "")
        if not self.host_ok(headers.get("host", "")):
            log.warning(
                "rejected %s: untrusted Host header %r", path, headers.get("host", "")[:100]
            )
            await _reply(send, 421, "invalid Host header")
            return
        if not self.origin_ok(headers.get("origin")):
            log.warning("rejected %s: Origin %r not allowed", path, headers.get("origin", "")[:100])
            await _reply(send, 403, "Origin not allowed")
            return
        if not self.token_ok(headers.get("authorization")):
            log.warning("rejected %s: missing or wrong bearer token", path)
            await _reply(
                send,
                401,
                "bearer token required",
                [(b"www-authenticate", b'Bearer realm="iplens"')],
            )
            return
        await self.app(scope, receive, send)


async def _reply(
    send: Any, status: int, text: str, extra: list[tuple[bytes, bytes]] | None = None
) -> None:
    body = text.encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                *(extra or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def bind(host: str, port: int) -> socket.socket:
    """A listening socket on ``host:port``; OSError if it cannot be bound."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
    family, kind, proto, _, addr = infos[0]
    sock = socket.socket(family, kind, proto)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(addr)
        sock.listen(128)
    except OSError:
        sock.close()
        raise
    sock.set_inheritable(True)
    return sock


def configure_logging() -> None:
    """Formatted, redacted lines on stderr (uvicorn's loggers included)."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


def app(server: MCPServer, token: str, host: str, port: int, allow_remote: bool) -> Guard:
    """The guarded ASGI app: stateless Streamable HTTP with JSON responses at MCP_PATH."""
    inner = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        # Guard checks Host and Origin itself (for remote binds too).
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host=host,
    )
    return Guard(inner, token, host, port, allow_remote)


def serve(sock: socket.socket, asgi: Guard, host: str, port: int) -> None:
    """Serve until SIGTERM / SIGINT (uvicorn shuts down gracefully)."""
    config = uvicorn.Config(
        asgi,
        log_config=None,  # our stderr handler
        log_level="info",
        server_header=False,
        lifespan="on",
        timeout_graceful_shutdown=GRACEFUL_SECONDS,
    )
    log.info("iplens mcp listening on http://%s:%d%s", url_host(host), port, MCP_PATH)
    uvicorn.Server(config).run(sockets=[sock])
