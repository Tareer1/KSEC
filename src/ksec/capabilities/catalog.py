"""Static catalog of known Kali tools and the capabilities they provide.

The catalog is the *knowledge*; the registry (``registry.py``) checks the
live system. KSEC never hardcodes the whole Kali tool list — this is a
curated seed set, extensible through the plugin architecture.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    package: str
    category: str
    capability: str
    description: str
    binary: str


TOOLS: list[ToolDefinition] = [
    ToolDefinition("nmap", "nmap", "network", "port_scan", "Network exploration and port/service discovery", "nmap"),
    ToolDefinition("masscan", "masscan", "network", "port_scan", "High-speed port scanner", "masscan"),
    ToolDefinition("dig", "dnsutils", "recon", "dns_lookup", "DNS lookup utility", "dig"),
    ToolDefinition("whois", "whois", "recon", "whois_lookup", "Domain registration intelligence", "whois"),
    ToolDefinition("subfinder", "subfinder", "recon", "subdomain_enum", "Passive subdomain discovery", "subfinder"),
    ToolDefinition("nuclei", "nuclei", "web", "web_vuln_scan", "Fast vulnerability scanner for web applications", "nuclei"),
    ToolDefinition("gobuster", "gobuster", "web", "directory_brute", "Directory/file brute-forcing", "gobuster"),
    ToolDefinition("curl", "curl", "web", "http_probe", "HTTP probing", "curl"),
    ToolDefinition("traceroute", "inetutils-traceroute", "network", "traceroute", "Network path discovery", "traceroute"),
    ToolDefinition("john", "john", "cracking", "password_crack", "Password cracking", "john"),
]

# Capability -> permission required to run it (RBAC boundary).
CAPABILITY_PERMISSION: dict[str, str] = {
    "port_scan": "assess.run",
    "http_probe": "assess.run",
    "web_vuln_scan": "assess.run",
    "directory_brute": "assess.run",
    "password_crack": "assess.run",
    "test_scan": "assess.run",
    "dns_lookup": "recon.run",
    "whois_lookup": "recon.run",
    "subdomain_enum": "recon.run",
    "traceroute": "recon.run",
}


def capability_permission(capability: str) -> str:
    return CAPABILITY_PERMISSION.get(capability, "assess.run")