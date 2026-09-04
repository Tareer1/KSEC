"""Safe command construction (spec: COMMAND BUILDER).

Commands are always built as argument lists and executed without a shell.
Targets and arguments are validated to prevent argument/command injection:
no NUL bytes, no shell metacharacters, bounded length.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ksec.core.errors import KSECError

_FORBIDDEN = re.compile(r"[\x00;|&$`<>(){}\[\]!\\]")


@dataclass(frozen=True)
class SafeCommand:
    executable: str
    args: list[str]

    def as_list(self) -> list[str]:
        return [self.executable, *self.args]


def validate_target(target: str) -> str:
    """Validate a target (IP, CIDR, hostname, domain or URL)."""
    target = target.strip()
    if not target:
        raise KSECError("Empty target")
    if len(target) > 1024:
        raise KSECError("Target too long")
    if _FORBIDDEN.search(target):
        raise KSECError(f"Target contains forbidden characters: {target!r}")
    return target


def validate_arg(value: object, label: str = "argument") -> str:
    text = str(value)
    if len(text) > 4096:
        raise KSECError(f"{label} too long")
    if _FORBIDDEN.search(text):
        raise KSECError(f"{label} contains forbidden characters: {text!r}")
    return text


def build_safe_command(executable: str, args: list[object]) -> SafeCommand:
    return SafeCommand(executable=executable, args=[validate_arg(a) for a in args])