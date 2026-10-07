"""Filesystem locations used by IPLens.

Everything lives under a single data directory (``IPLENS_HOME`` or ``~/.iplens``)
so the app is fully self-contained and easy to wipe.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppPaths:
    home: Path

    @property
    def db_path(self) -> Path:
        return self.home / "iplens.db"

    @property
    def key_path(self) -> Path:
        return self.home / "secret.key"

    @property
    def flask_secret_path(self) -> Path:
        return self.home / "flask.secret"

    @property
    def default_log_dir(self) -> Path:
        return self.home / "logs"

    def ensure(self) -> AppPaths:
        self.home.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.home, 0o700)
        return self


def default_paths(home: str | os.PathLike[str] | None = None) -> AppPaths:
    if home is None:
        home = os.environ.get("IPLENS_HOME") or Path.home() / ".iplens"
    return AppPaths(Path(home).expanduser().resolve())
