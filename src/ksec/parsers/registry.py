"""Map tools to their default parsers.

Resolution accepts either a parser's canonical ``name`` (e.g.
``nmap_xml``, which adapters use as ``default_parser``) or a tool alias
(``nmap``, ``dig``, ``curl``).
"""
from __future__ import annotations

from ksec.parsers.base import OutputParser
from ksec.parsers.dns import DigParser
from ksec.parsers.gobuster import GobusterParser
from ksec.parsers.http_probe import HttpProbeParser
from ksec.parsers.nikto import NiktoParser
from ksec.parsers.nmap_xml import NmapXmlParser
from ksec.parsers.tls_scan import TlsScanParser

# Canonical entries keyed by the parser's own name.
_PARSERS: dict[str, OutputParser] = {
    NmapXmlParser().name: NmapXmlParser(),
    DigParser().name: DigParser(),
    HttpProbeParser().name: HttpProbeParser(),
    TlsScanParser().name: TlsScanParser(),
    GobusterParser().name: GobusterParser(),
    NiktoParser().name: NiktoParser(),
}

# Tool-name aliases for convenience / legacy references.
_ALIASES: dict[str, str] = {
    "nmap": "nmap_xml",
    "dig": "dig",
    "curl": "http_probe",
    "sslscan": "tls_scan",
    "gobuster": "gobuster",
    "nikto": "nikto",
}


def get_parser(tool_or_name: str) -> OutputParser | None:
    key = _ALIASES.get(tool_or_name, tool_or_name)
    return _PARSERS.get(key)
