"""Structured logging for KSEC.

Two hard rules from the spec: logs are structured, and secrets are never
logged. :func:`redact` strips known secret patterns from any log output.
"""
from __future__ import annotations

import logging
import re
import sys

_SECRET_PATTERNS = [
    # Authorization header with scheme: "Authorization: Bearer <token>"
    re.compile(r"(?i)\b(Authorization)(\s*[:=]\s*)(Bearer|Basic)(\s+)[A-Za-z0-9._~+/=-]+"),
    # Generic key=value / key: value secrets
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)(\s*[=:]\s*)[^\s,;\"']+"),
    # Standalone scheme tokens: "Bearer <token>"
    re.compile(r"(?i)\b(Bearer|Basic)(\s+)[A-Za-z0-9._~+/=-]+"),
]


def redact(text: str) -> str:
    """Replace recognized secret patterns with ``<REDACTED>``."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}<REDACTED>", text)
    return text


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts secrets from every emitted record."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return redact(message)


_LOGGER_NAME = "ksec"


def setup_logging(level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """Configure the ``ksec`` logger (idempotent).

    Writes to stderr and optionally to ``log_file``.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    if logger.handlers:
        return logger

    fmt = RedactingFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    logger.addHandler(console)

    if log_file:
        try:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(fmt)
            logger.addHandler(handler)
        except OSError:
            # File logging is best-effort; console logging still works.
            pass
    return logger


def get_logger(name: str = "") -> logging.Logger:
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)