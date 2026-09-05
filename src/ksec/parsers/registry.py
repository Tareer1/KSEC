"""Map tools to their default parsers.

Resolution accepts either a parser's canonical ``name`` (e.g.
``nmap_xml``, which adapters use as ``default_parser``) or a tool alias
(``nmap``, ``dig``, ``curl``).
"""
from __future__ import annotations

from ksec.parsers.aircrack import AircrackNgParser
from ksec.parsers.amass import AmassParser
from ksec.parsers.base import OutputParser
from ksec.parsers.dns import DigParser
from ksec.parsers.dnsenum import DnsenumParser
from ksec.parsers.dnsrecon import DnsreconParser
from ksec.parsers.ffuf import FfufParser
from ksec.parsers.gobuster import GobusterParser
from ksec.parsers.http_probe import HttpProbeParser
from ksec.parsers.hydra import HydraParser
from ksec.parsers.iwlist import IwlistParser
from ksec.parsers.masscan import MasscanJsonParser
from ksec.parsers.nikto import NiktoParser
from ksec.parsers.nmap_xml import NmapXmlParser
from ksec.parsers.nuclei import NucleiParser
from ksec.parsers.nxc import NxcParser
from ksec.parsers.searchsploit import SearchsploitParser
from ksec.parsers.smb import Enum4LinuxParser, SmbMapParser
from ksec.parsers.sqlmap import SqlmapParser
from ksec.parsers.theharvester import TheHarvesterParser
from ksec.parsers.tls_scan import TlsScanParser
from ksec.parsers.wfuzz import WfuzzParser
from ksec.parsers.whatweb import WhatwebParser
from ksec.parsers.wpscan import WpscanParser

# Canonical entries keyed by the parser's own name.
_PARSERS: dict[str, OutputParser] = {
    NmapXmlParser().name: NmapXmlParser(),
    MasscanJsonParser().name: MasscanJsonParser(),
    DigParser().name: DigParser(),
    HttpProbeParser().name: HttpProbeParser(),
    TlsScanParser().name: TlsScanParser(),
    GobusterParser().name: GobusterParser(),
    FfufParser().name: FfufParser(),
    WfuzzParser().name: WfuzzParser(),
    NiktoParser().name: NiktoParser(),
    SearchsploitParser().name: SearchsploitParser(),
    SqlmapParser().name: SqlmapParser(),
    NxcParser().name: NxcParser(),
    NucleiParser().name: NucleiParser(),
    DnsreconParser().name: DnsreconParser(),
    DnsenumParser().name: DnsenumParser(),
    WpscanParser().name: WpscanParser(),
    HydraParser().name: HydraParser(),
    Enum4LinuxParser().name: Enum4LinuxParser(),
    SmbMapParser().name: SmbMapParser(),
    WhatwebParser().name: WhatwebParser(),
    TheHarvesterParser().name: TheHarvesterParser(),
    AmassParser().name: AmassParser(),
    IwlistParser().name: IwlistParser(),
    AircrackNgParser().name: AircrackNgParser(),
}

# Tool-name aliases for convenience / legacy references.
_ALIASES: dict[str, str] = {
    "nmap": "nmap_xml",
    "masscan": "masscan_json",
    "dig": "dig",
    "curl": "http_probe",
    "sslscan": "tls_scan",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "wfuzz": "wfuzz",
    "searchsploit": "searchsploit",
    "sqlmap": "sqlmap",
    "nxc": "nxc",
    "nuclei": "nuclei",
    "nikto": "nikto",
    "dnsrecon": "dnsrecon",
    "dnsenum": "dnsenum",
    "wpscan": "wpscan",
    "hydra": "hydra",
    "enum4linux": "enum4linux",
    "smbmap": "smbmap",
    "whatweb": "whatweb",
    "theharvester": "theharvester",
    "amass": "amass",
    "iwlist": "iwlist",
    "aircrack-ng": "aircrack_ng",
}


def get_parser(tool_or_name: str) -> OutputParser | None:
    key = _ALIASES.get(tool_or_name, tool_or_name)
    return _PARSERS.get(key)