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
    ToolDefinition("nikto", "nikto", "web", "web_vuln_scan", "Web server vulnerability scanner", "nikto"),
    ToolDefinition("gobuster", "gobuster", "web", "directory_brute", "Directory/file brute-forcing", "gobuster"),
    ToolDefinition("sslscan", "sslscan", "web", "tls_scan", "TLS/SSL protocol and cipher enumeration", "sslscan"),
    ToolDefinition("curl", "curl", "web", "http_probe", "HTTP probing", "curl"),
    ToolDefinition("traceroute", "inetutils-traceroute", "network", "traceroute", "Network path discovery", "traceroute"),
    ToolDefinition("john", "john", "cracking", "password_crack", "Password cracking", "john"),
    ToolDefinition("dnsrecon", "dnsrecon", "recon", "dns_enum", "DNS record enumeration", "dnsrecon"),
    ToolDefinition("wpscan", "wpscan", "web", "wpscan", "WordPress vulnerability scanner", "wpscan"),
    ToolDefinition("hydra", "hydra", "cracking", "auth_test", "Online login/authentication testing", "hydra"),
    ToolDefinition("enum4linux", "enum4linux", "network", "smb_enum", "SMB/NetBIOS enumeration", "enum4linux"),
    ToolDefinition("smbmap", "smbmap", "network", "smb_map", "SMB share and access mapping", "smbmap"),
]

# Capability -> permission required to run it (RBAC boundary).
CAPABILITY_PERMISSION: dict[str, str] = {
    "port_scan": "assess.run",
    "http_probe": "assess.run",
    "tls_scan": "assess.run",
    "web_vuln_scan": "assess.run",
    "directory_brute": "assess.run",
    "password_crack": "assess.run",
    "test_scan": "assess.run",
    "dns_lookup": "recon.run",
    "whois_lookup": "recon.run",
    "subdomain_enum": "recon.run",
    "traceroute": "recon.run",
    "dns_enum": "recon.run",
    "wpscan": "assess.run",
    "auth_test": "assess.run",
    "smb_enum": "assess.run",
    "smb_map": "assess.run",
}


def capability_permission(capability: str) -> str:
    return CAPABILITY_PERMISSION.get(capability, "assess.run")