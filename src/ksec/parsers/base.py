"""Output parsing (spec: PARSER ENGINE).

Parsers convert raw tool output into structured entities. Unknown output is
never silently discarded: it is preserved on :class:`ParsedResult`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParsedResult:
    tool: str
    entities: list[dict] = field(default_factory=list)
    raw: str = ""
    parsed_at: str = ""


class OutputParser(ABC):
    name: str = ""
    formats: tuple[str, ...] = ("text",)

    @abstractmethod
    def parse(self, output: str) -> ParsedResult: ...