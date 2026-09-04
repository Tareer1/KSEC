"""Structured errors for KSEC.

Every subsystem raises :class:`KSECError` so callers and the CLI can present a
consistent, actionable error surface (spec: Error Architecture).

Structure: Error Code, Component, Severity, Message, Cause, Context,
Recovery Hint, Retryable, Correlation ID.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ErrorInfo:
    """Structured metadata attached to every :class:`KSECError`."""

    code: str
    component: str
    severity: Severity = Severity.ERROR
    cause: str = ""
    context: str = ""
    recovery_hint: str = ""
    retryable: bool = False
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)


class KSECError(Exception):
    """Base structured error for the KSEC platform."""

    def __init__(self, message: str, info: ErrorInfo | None = None):
        super().__init__(message)
        self.message = message
        self.info = info or ErrorInfo(code="KSEC_ERROR", component="core")

    def to_dict(self) -> dict:
        return {
            "code": self.info.code,
            "component": self.info.component,
            "severity": self.info.severity.value,
            "message": self.message,
            "cause": self.info.cause,
            "context": self.info.context,
            "recovery_hint": self.info.recovery_hint,
            "retryable": self.info.retryable,
            "correlation_id": self.info.correlation_id,
        }


class ConfigurationError(KSECError):
    """Configuration could not be loaded or is invalid."""


class DatabaseError(KSECError):
    """Database operation failed."""


class IdentityError(KSECError):
    """User identity or credential operation failed."""


class AuthorizationError(KSECError):
    """Authorization record operation failed."""


class SessionError(KSECError):
    """Session lifecycle operation failed."""