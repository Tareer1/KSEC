"""Adapter registry: capability -> preferred adapter, plus tool selection.

Built-in adapters ship with KSEC. Multiple built-ins may provide the same
capability (e.g. nmap and masscan for ``port_scan``); the first registered
one is the preferred provider and any of them can be selected at dispatch
time with ``options.tool`` (e.g. ``--options '{"tool": "masscan"}'``).

Plugin adapters are registered with their own plugin id so the scheduler can
enforce plugin trust/permission gates (spec: PLUGIN PERMISSIONS / PLUGIN
TRUST LEVELS).
"""
from __future__ import annotations

from ksec.adapters.base import ToolAdapter
from ksec.adapters.aircrack import AircrackNgAdapter
from ksec.adapters.amass import AmassAdapter
from ksec.adapters.curl import CurlAdapter
from ksec.adapters.dns import DigAdapter
from ksec.adapters.dnsenum import DnsenumAdapter
from ksec.adapters.dnsrecon import DnsreconAdapter
from ksec.adapters.enum4linux import Enum4LinuxAdapter
from ksec.adapters.ffuf import FfufAdapter
from ksec.adapters.gobuster import GobusterAdapter
from ksec.adapters.hydra import HydraAdapter
from ksec.adapters.iwlist import IwlistAdapter
from ksec.adapters.john import JohnAdapter
from ksec.adapters.masscan import MasscanAdapter
from ksec.adapters.nikto import NiktoAdapter
from ksec.adapters.onesixtyone import OnesixyoneAdapter
from ksec.adapters.smtp_enum import SmtpUserEnumAdapter
from ksec.adapters.snmpwalk import SnmpwalkAdapter
from ksec.adapters.nmap import NmapAdapter
from ksec.adapters.nuclei import NucleiAdapter
from ksec.adapters.nxc import NxcAdapter
from ksec.adapters.null import NullAdapter
from ksec.adapters.searchsploit import SearchsploitAdapter
from ksec.adapters.smbmap import SmbMapAdapter
from ksec.adapters.sqlmap import SqlmapAdapter
from ksec.adapters.sslscan import SslScanAdapter
from ksec.adapters.theharvester import TheHarvesterAdapter
from ksec.adapters.traceroute import TracerouteAdapter
from ksec.adapters.wfuzz import WfuzzAdapter
from ksec.adapters.whois import WhoisAdapter
from ksec.adapters.whatweb import WhatwebAdapter
from ksec.adapters.wpscan import WpscanAdapter

_BUILTIN_ADAPTERS: tuple[ToolAdapter, ...] = (
    NmapAdapter(),
    MasscanAdapter(),
    DigAdapter(),
    CurlAdapter(),
    SslScanAdapter(),
    GobusterAdapter(),
    FfufAdapter(),
    WfuzzAdapter(),
    NiktoAdapter(),
    NucleiAdapter(),
    DnsreconAdapter(),
    DnsenumAdapter(),
    WpscanAdapter(),
    HydraAdapter(),
    Enum4LinuxAdapter(),
    SmbMapAdapter(),
    NxcAdapter(),
    SqlmapAdapter(),
    SearchsploitAdapter(),
    WhatwebAdapter(),
    TheHarvesterAdapter(),
    AmassAdapter(),
    WhoisAdapter(),
    TracerouteAdapter(),
    JohnAdapter(),
    SnmpwalkAdapter(),
    OnesixyoneAdapter(),
    SmtpUserEnumAdapter(),
    IwlistAdapter(),
    AircrackNgAdapter(),
    NullAdapter(),
)


class AdapterRegistry:
    def __init__(self) -> None:
        # capability -> preferred adapter (first registered wins)
        self._adapters: dict[str, ToolAdapter] = {}
        # tool name -> adapter (used for explicit tool selection)
        self._by_tool: dict[str, ToolAdapter] = {}
        # capability -> owning plugin id (None for built-ins)
        self._owners: dict[str, str | None] = {}
        for adapter in _BUILTIN_ADAPTERS:
            self._adapters.setdefault(adapter.capability, adapter)
            self._by_tool[adapter.name] = adapter
            self._owners.setdefault(adapter.capability, None)

    def get(self, capability: str, tool: str | None = None) -> ToolAdapter | None:
        if tool:
            adapter = self._by_tool.get(tool)
            if adapter is not None and adapter.capability == capability:
                return adapter
        return self._adapters.get(capability)

    def capabilities(self) -> list[str]:
        return sorted(self._adapters)

    def register(self, adapter: ToolAdapter, plugin_id: str | None = None) -> None:
        # Plugins explicitly override the preferred provider for a capability.
        self._adapters[adapter.capability] = adapter
        self._by_tool[adapter.name] = adapter
        self._owners[adapter.capability] = plugin_id

    def unregister(self, capability: str) -> None:
        self._adapters.pop(capability, None)
        self._owners.pop(capability, None)

    def plugin_of(self, capability: str) -> str | None:
        """Return the plugin id that owns ``capability``, or None for built-ins."""
        return self._owners.get(capability)