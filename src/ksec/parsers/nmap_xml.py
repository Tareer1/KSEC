"""Parse nmap XML output (``nmap -oX -``) into hosts/ports/services."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class NmapXmlParser(OutputParser):
    name = "nmap_xml"
    formats = ("xml",)

    def parse(self, output: str) -> ParsedResult:
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return ParsedResult(tool="nmap", entities=[], raw=output, parsed_at=now_utc())

        entities: list[dict] = []
        for host in root.iter("host"):
            addresses = [a.get("addr") for a in host.iter("address") if a.get("addr")]
            hostnames = [h.get("name") for h in host.iter("hostname") if h.get("name")]
            ports: list[dict] = []
            for port in host.iter("port"):
                state_el = port.find("state")
                service_el = port.find("service")
                ports.append(
                    {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": state_el.get("state") if state_el is not None else "unknown",
                        "service": service_el.get("name") if service_el is not None else "",
                    }
                )
            entities.append(
                {"type": "host", "addresses": addresses, "hostnames": hostnames, "ports": ports}
            )
        return ParsedResult(tool="nmap", entities=entities, raw=output, parsed_at=now_utc())