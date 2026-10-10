"""``iplens`` command: run the local web UI."""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import os
import signal
import sys
import threading
import webbrowser
from collections.abc import Callable, Iterator
from typing import Any

from flask import Flask

from . import __version__

# waitress worker threads serving requests (``iplens`` without --debug).
THREADS = 8
# Bind addresses that mean "every interface": the browser URL uses 127.0.0.1 for them.
WILDCARD_HOSTS = ("0.0.0.0", "::")  # noqa: S104 - names, nothing is bound here


def is_loopback(host: str) -> bool:
    """True if binding ``host`` keeps the server local (``localhost`` or 127.0.0.0/8, ::1)."""
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def browse_url(host: str, port: int) -> str:
    if is_loopback(host) or host in WILDCARD_HOSTS:
        return f"http://127.0.0.1:{port}"
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


def banner(url: str, data_dir: object, log_file: object) -> str:
    return (
        f"IPLens {__version__} running at {url}  (Ctrl+C to stop) · data: {data_dir} "
        f"· log: {log_file}"
    )


def remote_warning(host: str, port: int) -> str:
    return (
        f"WARNING: IPLens is listening on {host}:{port} and is reachable from other "
        "machines. It has NO authentication: anyone who can reach this port can see your "
        "AWS inventory and use the configured accounts. Use --allow-remote only on a "
        "trusted network."
    )


def desktop_session() -> bool:
    """True if a browser can be opened for the user (not over a bare SSH session)."""
    if sys.platform in ("darwin", "win32"):
        return True
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        # Without a display only an explicitly configured browser is used.
        return bool(os.environ.get("BROWSER"))
    try:
        webbrowser.get()
    except webbrowser.Error:
        return False
    return True


def open_browser(url: str) -> None:
    threading.Thread(
        target=webbrowser.open, args=(url,), name="iplens-browser", daemon=True
    ).start()


@contextlib.contextmanager
def _sigterm_as_interrupt() -> Iterator[None]:
    """Treat SIGTERM like Ctrl+C so ``kill`` shuts down just as cleanly."""

    def handler(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:  # not the main thread
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def serve_waitress(app: Flask, host: str, port: int, ready: Callable[[], None]) -> None:
    """Serve ``app`` with waitress until Ctrl+C / SIGTERM (no ``Server`` header);
    ``ready`` is called once the port is bound."""
    from waitress import create_server

    server = create_server(app, host=host, port=port, threads=THREADS, ident="")
    try:
        ready()
        server.run()
    finally:
        server.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iplens", description=__doc__)
    parser.add_argument(
        "--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, local only)"
    )
    parser.add_argument("--port", type=int, default=8077)
    parser.add_argument(
        "--home", default=None, help="data directory (default: $IPLENS_HOME or ~/.iplens)"
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow a non-loopback --host (there is NO authentication)",
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="do not open the UI in a web browser"
    )
    parser.add_argument(
        "--debug", action="store_true", help="use the Flask development server with the debugger"
    )
    parser.add_argument("--version", action="version", version=f"iplens {__version__}")
    args = parser.parse_args(argv)

    remote = not is_loopback(args.host)
    if remote and not args.allow_remote:
        parser.error(
            f"refusing to listen on non-loopback host {args.host!r}: IPLens has no "
            "authentication. Pass --allow-remote to do it anyway."
        )

    from .logging_setup import LOG_FILE
    from .web import create_app, shutdown_app

    # With --debug the reloader's watcher process builds the app too: only the serving
    # child (WERKZEUG_RUN_MAIN) runs the scheduled-Refresh thread.
    serving = not args.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    app = create_app(
        args.home, port=args.port, scheduler_enabled=serving, allow_remote=args.allow_remote
    )
    try:
        if args.debug:
            app.run(host=args.host, port=args.port, debug=True)
            return
        ext = app.extensions["iplens"]
        url = browse_url(args.host, args.port)

        def ready() -> None:
            print(banner(url, ext["paths"].home, ext["log_dir"] / LOG_FILE), flush=True)
            if remote:
                print(remote_warning(args.host, args.port), file=sys.stderr, flush=True)
            if not args.no_browser and desktop_session():
                open_browser(url)

        try:
            with _sigterm_as_interrupt(), contextlib.suppress(KeyboardInterrupt):
                serve_waitress(app, args.host, args.port, ready)
        except OSError as exc:  # e.g. the port is already in use
            sys.exit(f"iplens: cannot listen on {args.host}:{args.port}: {exc.strerror or exc}")
        print("Stopping IPLens…", flush=True)
    finally:
        shutdown_app(app)


if __name__ == "__main__":
    main()
