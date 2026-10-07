"""File logging with credential redaction, plus a reader for the log viewer."""

from __future__ import annotations

import logging
import re
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FILE = "iplens.log"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_HANDLER_NAME = "iplens-file"
_LINE_RX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (?P<level>[A-Z]+) "
    r"(?P<logger>\S+): (?P<msg>.*)$"
)

_REDACTIONS = (
    # Access key ids (long-term AKIA / temporary ASIA)
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED-KEY-ID]"),
    # Anything labelled as a secret / token / password
    (re.compile(r"(?i)((?:secret|token|password)[\w-]*['\"]?\s*[:=]\s*['\"]?)[^\s'\",}]+"),
     r"\1[REDACTED]"),
    # Bare 40-char secret access keys
    (re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), "[REDACTED]"),
)


def redact(text: str) -> str:
    for rx, repl in _REDACTIONS:
        text = rx.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def configure_logging(log_dir: Path, level: int = logging.INFO) -> Path:
    """(Re)attach the rotating file handler to the ``iplens`` logger."""
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / LOG_FILE
    logger = logging.getLogger("iplens")
    logger.setLevel(level)
    for h in list(logger.handlers):
        if h.get_name() == _HANDLER_NAME:
            logger.removeHandler(h)
            h.close()
    handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    # boto/urllib3 chatter can contain request details; keep it out of our file.
    for noisy in ("botocore", "boto3", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return path


def read_log(
    log_dir: Path, *, min_level: str = "", q: str = "", limit: int = 500
) -> list[dict[str, str]]:
    """Return the newest ``limit`` matching entries (newest first)."""
    path = log_dir / LOG_FILE
    if not path.exists():
        return []
    threshold = LEVELS.index(min_level) if min_level in LEVELS else 0
    needle = q.lower().strip()
    entries: deque[dict[str, str]] = deque(maxlen=limit)
    current: dict[str, str] | None = None

    def flush() -> None:
        if current is None:
            return
        lvl = current["level"]
        if lvl in LEVELS and LEVELS.index(lvl) < threshold:
            return
        if needle and needle not in (current["msg"] + current["logger"]).lower():
            return
        entries.append(current)

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = _LINE_RX.match(line)
            if m:
                flush()
                current = m.groupdict()
            elif current is not None:  # traceback continuation
                current["msg"] += "\n" + line
    flush()
    return list(reversed(entries))
