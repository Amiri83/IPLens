"""``iplens`` command: run the local web UI."""

from __future__ import annotations

import argparse

from . import __version__


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="iplens", description=__doc__)
    parser.add_argument(
        "--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, local only)"
    )
    parser.add_argument("--port", type=int, default=8077)
    parser.add_argument(
        "--home", default=None, help="data directory (default: $IPLENS_HOME or ~/.iplens)"
    )
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--version", action="version", version=f"iplens {__version__}")
    args = parser.parse_args(argv)

    from .web import create_app

    app = create_app(args.home, port=args.port)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
