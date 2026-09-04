"""Operation modes (spec: THREE OPERATION MODES).

- Beginner:  Target -> Start -> Understand -> Result (plain language).
- Professional: Target -> Profile -> Modules -> Options -> Execute -> Analyze -> Report.
- Expert: exposes tool selection, arguments, adapters, raw output and
  advanced configuration.

Principle: hide complexity, never hide useful information.
"""
from __future__ import annotations

from enum import Enum

MODE_NAMES = ("beginner", "professional", "expert")


class Mode(str, Enum):
    BEGINNER = "beginner"
    PROFESSIONAL = "professional"
    EXPERT = "expert"

    def is_beginner(self) -> bool:
        return self is Mode.BEGINNER

    def is_expert(self) -> bool:
        return self is Mode.EXPERT


def normalize_mode(value: str | None) -> str:
    if value and value.lower() in MODE_NAMES:
        return value.lower()
    return "professional"


def resolve_mode(flag: str | None, config_mode: str | None = None) -> Mode:
    """CLI flag wins, then config, then the professional default."""
    return Mode(normalize_mode(flag) if flag else normalize_mode(config_mode))