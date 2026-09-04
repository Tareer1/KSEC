"""Tool explanation system (spec: TOOL EXPLANATION SYSTEM / RESULT EXPLANATION).

Every tool exposes plain-language ("what is this and why") and technical
explanations, so the same tool is understandable to a beginner while still
providing professional detail. Mode decides how much is shown:
beginner = simple, professional = technical, expert = everything.
"""
from __future__ import annotations

from dataclasses import dataclass

from ksec.capabilities.catalog import TOOLS
from ksec.modes import Mode


@dataclass(frozen=True)
class ToolExplanation:
    beginner: str          # plain language: what the tool does
    technical: str         # professional description
    why_selected: str      # why KSEC chose this tool for the capability
    data_collected: str    # what data is collected
    risk: str              # safety classification in words
    privilege: str         # privilege requirements
    inputs: str            # what input the tool needs
    outputs: str           # what output it produces
    learn_more: str        # how to learn more


EXPLANATIONS: dict[str, ToolExplanation] = {
    "nmap": ToolExplanation(
        beginner="This tool looks for doors that are open on a computer or network, and what service is behind each door.",
        technical="This capability performs authorized port and service discovery (nmap).",
        why_selected="Default provider for the port_scan capability.",
        data_collected="Host addresses, hostnames, open/closed/filtered ports and service names.",
        risk="ACTIVE_SAFE — sends network probes to the target; bounded by scope rules.",
        privilege="Unprivileged scans work; raw-packet scans may need root.",
        inputs="Target host or CIDR; optional ports, top-ports and service-version options.",
        outputs="Hosts with addresses, hostnames and a structured list of ports and services.",
        learn_more="man nmap, or run: ksec assess TARGET --workflow recon",
    ),
    "masscan": ToolExplanation(
        beginner="A very fast tool that checks many computers for open doors at once.",
        technical="High-speed port scanner; alternative provider for port_scan.",
        why_selected="Alternative provider for port_scan when speed matters.",
        data_collected="Open TCP/UDP ports across large ranges.",
        risk="ACTIVE_AGGRESSIVE — high packet rates; use carefully and in scope.",
        privilege="Usually requires root for raw packets.",
        inputs="Target CIDR and port range.",
        outputs="Lines describing open ports.",
        learn_more="man masscan",
    ),
    "dig": ToolExplanation(
        beginner="This tool asks the internet's phone book (DNS) where a name actually points.",
        technical="This capability performs DNS lookups (dig).",
        why_selected="Default provider for the dns_lookup capability.",
        data_collected="DNS records: A, AAAA, CNAME, MX, NS, TXT, SOA.",
        risk="PASSIVE — sends standard DNS queries.",
        privilege="None.",
        inputs="Domain name; optional record type.",
        outputs="DNS records for the queried name.",
        learn_more="man dig",
    ),
    "whois": ToolExplanation(
        beginner="This tool looks up who registered a domain name and when.",
        technical="Domain registration intelligence (whois).",
        why_selected="Default provider for the whois_lookup capability.",
        data_collected="Registrar, registrant metadata, registration dates and name servers.",
        risk="PASSIVE — queries public registration records.",
        privilege="None.",
        inputs="Domain name.",
        outputs="Registration records.",
        learn_more="man whois",
    ),
    "subfinder": ToolExplanation(
        beginner="This tool finds subdomains that point to the same organization.",
        technical="Passive subdomain discovery from public sources (subfinder).",
        why_selected="Default provider for the subdomain_enum capability.",
        data_collected="Subdomain names and their sources.",
        risk="PASSIVE — queries public data sources.",
        privilege="None.",
        inputs="Root domain.",
        outputs="Discovered subdomains.",
        learn_more="subfinder -h",
    ),
    "nuclei": ToolExplanation(
        beginner="This tool checks a website against a large library of known weaknesses.",
        technical="Fast vulnerability scanner for web applications (nuclei).",
        why_selected="Default provider for the web_vuln_scan capability.",
        data_collected="Template matches: vulnerability names, severity and affected URLs.",
        risk="ACTIVE_SAFE — sends crafted HTTP requests; bounded by scope rules.",
        privilege="None for most checks.",
        inputs="Target URL or host.",
        outputs="Vulnerability matches with severity.",
        learn_more="nuclei -h",
    ),
    "gobuster": ToolExplanation(
        beginner="This tool tries many names to find hidden pages and folders on a website.",
        technical="Directory/file brute-forcing (gobuster).",
        why_selected="Default provider for the directory_brute capability.",
        data_collected="Discovered paths with HTTP status codes.",
        risk="ACTIVE_SAFE — high request volume; respect rate limits.",
        privilege="None.",
        inputs="Target URL and a wordlist.",
        outputs="Found paths and status codes.",
        learn_more="gobuster dir -h",
    ),
    "curl": ToolExplanation(
        beginner="This tool asks a website for its address and reports whether it answered.",
        technical="HTTP probing: fetches status code and content type (curl).",
        why_selected="Default provider for the http_probe capability.",
        data_collected="HTTP status code and content type per URL.",
        risk="ACTIVE_SAFE — ordinary HTTP requests.",
        privilege="None.",
        inputs="Target URL or host.",
        outputs="HTTP response status and content type.",
        learn_more="curl --help",
    ),
    "traceroute": ToolExplanation(
        beginner="This tool shows the path a message takes across the internet to reach its destination.",
        technical="Network path discovery (traceroute).",
        why_selected="Default provider for the traceroute capability.",
        data_collected="Intermediate hops between source and target.",
        risk="ACTIVE_SAFE — lightweight probe packets.",
        privilege="May need root for some probe types.",
        inputs="Target host or IP.",
        outputs="List of hops with response times.",
        learn_more="man traceroute",
    ),
    "john": ToolExplanation(
        beginner="This tool tries to recover passwords from password files.",
        technical="Password cracking (john the ripper).",
        why_selected="Default provider for the password_crack capability.",
        data_collected="Password hashes and recovered plaintext for authorized hashes only.",
        risk="ACTIVE_SAFE — CPU-bound; only ever run on hashes you own or are authorized to test.",
        privilege="None.",
        inputs="A file of password hashes.",
        outputs="Recovered passwords.",
        learn_more="john --help",
    ),
}

_DEFAULT_EXPLANATION = ToolExplanation(
    beginner="This capability performs a security task against the target.",
    technical="This capability performs an authorized security task.",
    why_selected="Selected for this capability by the workflow.",
    data_collected="Task output relevant to the workflow.",
    risk="Bounded by KSEC scope and safety policies.",
    privilege="Depends on the tool.",
    inputs="Workflow step inputs.",
    outputs="Structured results stored as job output.",
    learn_more="Run with --verbose for details, or ksec tools info.",
)

SEVERITY_PLAIN = {
    "info": "low-priority observation",
    "low": "minor issue",
    "medium": "moderate issue that should be addressed",
    "high": "serious issue that needs attention",
    "critical": "critical issue requiring immediate action",
}


def explain_tool(name: str) -> ToolExplanation | None:
    return EXPLANATIONS.get(name)


def tool_for_capability(capability: str) -> str | None:
    for tool in TOOLS:
        if tool.capability == capability:
            return tool.name
    return None


def plain_severity(severity: str) -> str:
    return SEVERITY_PLAIN.get(severity, SEVERITY_PLAIN["info"])


class ExplanationService:
    """Mode-aware tool and capability explanations."""

    def __init__(self, capabilities=None):
        self.capabilities = capabilities

    def explain_tool(self, name: str) -> ToolExplanation | None:
        return explain_tool(name)

    def explain_capability(self, capability: str, mode: Mode) -> dict:
        tool_name = tool_for_capability(capability)
        explanation = EXPLANATIONS.get(tool_name or "", _DEFAULT_EXPLANATION)
        data = {
            "capability": capability,
            "tool": tool_name or "none",
            "category": self._category_for(tool_name),
            "beginner": explanation.beginner,
            "technical": explanation.technical,
            "why_selected": explanation.why_selected,
            "data_collected": explanation.data_collected,
            "risk": explanation.risk,
            "privilege": explanation.privilege,
            "inputs": explanation.inputs,
            "outputs": explanation.outputs,
            "learn_more": explanation.learn_more,
        }
        if mode.is_beginner():
            # Beginner: only the essentials.
            return {
                "capability": capability,
                "beginner": explanation.beginner,
                "why_selected": explanation.why_selected,
                "learn_more": explanation.learn_more,
            }
        if mode.is_expert():
            return data
        # Professional: technical description + safety, minus raw internals.
        data.pop("privilege", None)
        return data

    def _category_for(self, tool_name: str | None) -> str:
        if not tool_name:
            return ""
        for tool in TOOLS:
            if tool.name == tool_name:
                return tool.category
        return ""