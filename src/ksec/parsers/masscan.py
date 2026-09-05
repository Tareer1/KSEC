"""Parse ``masscan -oJ -`` JSON output into host entities.

Mirrors the ``nmap_xml`` entity shape (type ``host`` with addresses/ports)
so downstream IOC extraction and asset correlation behave identically.
"""
from __future__ import annotations

import json

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class MasscanJsonParser(OutputParser):
    name = "masscan_json"
    formats = ("json",)

    def parse(self, output: str) -> ParsedResult:
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return ParsedResult(tool="masscan", entities=[], raw=output, parsed_at=now_utc())
        if not isinstance(data, list):
            return ParsedResult(tool="masscan", entities=[], raw=output, parsed_at=now_utc())

        entities: list[dict] = []
        for item in data:
            ip = item.get("ip")
            if not ip:
                continue
            ports = [
                {
                    "port": str(p.get("port", "")),
                    "protocol": p.get("proto", "tcp"),
                    "state": p.get("status", "open"),
                    "service": "",
                }
                for p in item.get("ports") or []
            ]
            entities.append(
                {
                    "type": "host",
                    "addresses": [ip],
                    "hostnames": [],
                    "ports": ports,
                }
            )
        return ParsedResult(tool="masscan", entities=entities, raw=output, parsed_at=now_utc())