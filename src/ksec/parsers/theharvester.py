"""Parse ``theHarvester`` plain-text output into structured entities.

theHarvester prints result sections like::

    [*] Emails found: 2
    ---------------------
    a@example.com
    b@example.com
    [*] Hosts found: 3
    ---------------------
    www.example.com
    *.api.example.com

Non-wildcard hostnames become ``host`` entities (assets + IOC candidates);
wildcard entries stay as ``osint_host`` observations.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_SECTION_RE = re.compile(r"^\[\*\] (Emails|Hosts|IPs) found:\s*(\d+)")
_HOSTNAME_RE = re.compile(
    r"^(?:\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class TheHarvesterParser(OutputParser):
    name = "theharvester"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        section: str | None = None
        for line in output.splitlines():
            text = line.strip()
            header = _SECTION_RE.match(text)
            if header:
                section = header.group(1).lower()
                continue
            if not text:
                continue
            # Banner art borders end with '*'; status/info lines start with
            # '[*]'; '---...' are section separators.
            if (text.startswith("*") and text.endswith("*")) or \
                    text.startswith("[") or text.startswith("---"):
                continue
            if section == "emails" and _EMAIL_RE.match(text):
                entities.append({"type": "osint_email", "value": text})
            elif section == "hosts":
                if text.startswith("*."):
                    entities.append({"type": "osint_host", "host": text, "wildcard": True})
                elif _HOSTNAME_RE.match(text):
                    entities.append({"type": "host", "hostnames": [text]})
            elif section == "ips" and _IP_RE.match(text):
                entities.append({"type": "host", "addresses": [text]})
        return ParsedResult(
            tool="theharvester", entities=entities, raw=output, parsed_at=now_utc()
        )
