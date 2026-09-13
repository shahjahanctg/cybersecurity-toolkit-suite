"""Structured logging to file + stdout, with a secret-redaction hook."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict

_REDACTED_KEYS = {
    "password", "pass", "passwd", "secret", "api_key", "apikey", "token",
    "authorization", "key", "psk", "handshake", "private_key", "capture_key",
    "pre_shared_key",
}


def redact_message(msg: str) -> str:
    """Replace common secret assignments in log text (best effort)."""
    out = []
    for token in msg.split():
        low = token.lower()
        for key in _REDACTED_KEYS:
            if f"{key.lower()}=" in low or f"{key.lower()}:" in low:
                token = "***REDACTED***"
                break
        out.append(token)
    return " ".join(out)


class RedactingFormatter(logging.Formatter):
    """Formatter that scrubs known secrets before emitting the record."""

    def format(self, record: logging.LogRecord) -> str:
        record.msg = redact_message(str(record.getMessage()))
        record.args = ()
        record.message = record.msg
        return super().format(record)


_SIMPLE = RedactingFormatter(
    "%(asctime)s %(levelname)-8s [%(name)s] %(message)s")


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    console: bool = True,
) -> logging.Logger:
    root = logging.getLogger("sectoolkit")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(_SIMPLE)
        root.addHandler(ch)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(_SIMPLE)
        root.addHandler(fh)

    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"sectoolkit.{name}")


def audit_entry(level: str, tool: str, scope: str, result: str, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Build a structured audit dict for the run envelope."""
    from datetime import datetime, timezone
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "tool": tool,
        "scope": scope,
        "result": result,
        **(meta or {}),
    }