"""Adapter registry: capability -> adapter instance.

Built-in adapters ship with KSEC. Plugin adapters are registered with their
owning plugin id so the scheduler can enforce plugin trust/permission gates
(spec: PLUGIN PERMISSIONS / PLUGIN TRUST LEVELS).
"""
from __future__ import annotations

from ksec.adapters.base import ToolAdapter
from ksec.adapters.curl import CurlAdapter
from ksec.adapters.dns import DigAdapter
from ksec.adapters.dnsrecon import DnsreconAdapter
from ksec.adapters.enum4linux import Enum4LinuxAdapter
from ksec.adapters.gobuster import GobusterAdapter
from ksec.adapters.hydra import HydraAdapter
from ksec.adapters.nikto import NiktoAdapter
from ksec.adapters.nmap import NmapAdapter
from ksec.adapters.null import NullAdapter
from ksec.adapters.smbmap import SmbMapAdapter
from ksec.adapters.sslscan import SslScanAdapter
from ksec.adapters.theharvester import TheHarvesterAdapter
from ksec.adapters.whatweb import WhatwebAdapter
from ksec.adapters.wpscan import WpscanAdapter

_BUILTIN_ADAPTERS: tuple[ToolAdapter, ...] = (
    NmapAdapter(),
    DigAdapter(),
    CurlAdapter(),
    SslScanAdapter(),
    GobusterAdapter(),
    NiktoAdapter(),
    DnsreconAdapter(),
    WpscanAdapter(),
    HydraAdapter(),
    Enum4LinuxAdapter(),
    SmbMapAdapter(),
    WhatwebAdapter(),
    TheHarvesterAdapter(),
    NullAdapter(),
)


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {
            adapter.capability: adapter for adapter in _BUILTIN_ADAPTERS
        }
        # capability -> owning plugin id (None for built-ins)
        self._owners: dict[str, str | None] = {
            adapter.capability: None for adapter in _BUILTIN_ADAPTERS
        }

    def get(self, capability: str) -> ToolAdapter | None:
        return self._adapters.get(capability)

    def capabilities(self) -> list[str]:
        return sorted(self._adapters)

    def register(self, adapter: ToolAdapter, plugin_id: str | None = None) -> None:
        self._adapters[adapter.capability] = adapter
        self._owners[adapter.capability] = plugin_id

    def unregister(self, capability: str) -> None:
        self._adapters.pop(capability, None)
        self._owners.pop(capability, None)

    def plugin_of(self, capability: str) -> str | None:
        """Return the plugin id that owns ``capability``, or None for built-ins."""
        return self._owners.get(capability)