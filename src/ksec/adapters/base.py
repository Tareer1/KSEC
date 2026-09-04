"""Tool adapter interface (spec: TOOL ADAPTER LAYER).

An adapter abstracts one capability provider: it builds validated commands
and knows how to parse the tool's output.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ksec.parsers.registry import get_parser


@dataclass(frozen=True)
class CommandRequest:
    capability: str
    target: str
    options: dict = field(default_factory=dict)
    timeout: int = 300


class ToolAdapter(ABC):
    name: str = ""
    capability: str = ""
    description: str = ""
    safety: str = "ACTIVE_SAFE"  # PASSIVE | ACTIVE_SAFE | ACTIVE_AGGRESSIVE
    default_parser: str = ""

    @abstractmethod
    def build_command(self, request: CommandRequest) -> list[str]:
        """Return ``[executable, arg1, ...]`` (never a shell string)."""

    def parse_output(self, output: str):
        if not self.default_parser:
            return None
        parser = get_parser(self.default_parser)
        if parser is None:
            return None
        return parser.parse(output)