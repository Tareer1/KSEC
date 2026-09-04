"""Map tools to their default parsers."""
from __future__ import annotations

from ksec.parsers.base import OutputParser
from ksec.parsers.dns import DigParser
from ksec.parsers.http_probe import HttpProbeParser
from ksec.parsers.nmap_xml import NmapXmlParser

_PARSERS: dict[str, OutputParser] = {
    "nmap": NmapXmlParser(),
    "dig": DigParser(),
    "curl": HttpProbeParser(),
    "http_probe": HttpProbeParser(),
}


def get_parser(tool: str) -> OutputParser | None:
    return _PARSERS.get(tool)