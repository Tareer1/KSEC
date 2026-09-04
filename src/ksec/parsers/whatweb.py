"""Parse ``whatweb`` plain-text output into structured entities.

One result line per scanned URL, e.g.::

    https://example.com [200 OK] Country[UNITED STATES][US], HTML5,
    HTTPServer[cloudflare], IP[104.20.23.154], Title[Example Domain],
    WordPress[6.2], jQuery[1.12.4]

Emits a ``host`` entity (auto-registers the IP/domain as an asset) and a
``web_tech`` entity with the technology fingerprints.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_LINE_RE = re.compile(r"^(\S+?)\s+\[(\d{3})[^\]]*\]\s*(.*)$")
_IP_RE = re.compile(r"IP\[([0-9A-Fa-f.:]+)\]")
_SERVER_RE = re.compile(r"HTTPServer\[([^\]]*)\]")
_TITLE_RE = re.compile(r"Title\[([^\]]*)\]")
_PLUGIN_RE = re.compile(r"([A-Za-z0-9_.-]+)\[([^\]]*)\]")
# whatweb metadata keys that are not technologies themselves.
_META_KEYS = {
    "allow", "country", "redirectlocation", "uncommonheaders",
    "httpserver", "ip", "title", "cookies",
}


def _hostname_of(url: str) -> str:
    from urllib.parse import urlparse

    return (urlparse(url).netloc or "").lower()


class WhatwebParser(OutputParser):
    name = "whatweb"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            match = _LINE_RE.match(line.strip())
            if not match:
                continue
            url = match.group(1)
            status = int(match.group(2))
            rest = match.group(3)

            ip_match = _IP_RE.search(rest)
            ip = ip_match.group(1) if ip_match else ""
            server_match = _SERVER_RE.search(rest)
            server = server_match.group(1).strip() if server_match else ""
            title_match = _TITLE_RE.search(rest)
            title = title_match.group(1).strip() if title_match else ""

            hostname = _hostname_of(url)
            if ip or hostname:
                host_entity: dict = {"type": "host"}
                if ip:
                    host_entity["addresses"] = [ip]
                if hostname:
                    host_entity["hostnames"] = [hostname]
                entities.append(host_entity)

            technologies: list[dict] = []
            for name, version in _PLUGIN_RE.findall(rest):
                key = name.lower()
                if key in _META_KEYS:
                    continue
                if key in ("x-powered-by", "poweredby", "generator"):
                    # e.g. X-Powered-By[PHP/7.4.3] -> framework with version
                    technologies.append({"name": name, "version": version})
                    continue
                if version:
                    technologies.append({"name": name, "version": version})
            # Deduplicate identical (name, version) pairs.
            seen: set = set()
            unique: list[dict] = []
            for tech in technologies:
                key = (tech["name"].lower(), tech["version"])
                if key not in seen:
                    seen.add(key)
                    unique.append(tech)
            entities.append(
                {
                    "type": "web_tech",
                    "url": url,
                    "status": status,
                    "server": server,
                    "title": title,
                    "ip": ip,
                    "technologies": unique,
                }
            )
        return ParsedResult(tool="whatweb", entities=entities, raw=output, parsed_at=now_utc())
