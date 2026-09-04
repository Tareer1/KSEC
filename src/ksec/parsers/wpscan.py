"""Parse ``wpscan --format json`` output into structured findings."""
from __future__ import annotations

import json
import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


class WpscanParser(OutputParser):
    name = "wpscan"
    formats = ("json",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            return ParsedResult(tool="wpscan", entities=entities, raw=output, parsed_at=now_utc())

        version = (data.get("version") or {}).get("number", "") if isinstance(data.get("version"), dict) else ""

        def _scan_component(comp_key: str, comp_type: str) -> None:
            components = data.get(comp_key) or {}
            if not isinstance(components, dict):
                return
            for slug, info in components.items():
                if not isinstance(info, dict):
                    continue
                comp_version = (info.get("version") or {}).get("number", "") if isinstance(info.get("version"), dict) else str(info.get("version") or "")
                for vuln in info.get("vulnerabilities") or []:
                    if not isinstance(vuln, dict):
                        continue
                    title = str(vuln.get("title") or "untitled vulnerability")
                    cve = ""
                    refs = vuln.get("references") or {}
                    if isinstance(refs, dict):
                        for value in refs.get("cve", []) or []:
                            cve = str(value)
                            break
                    if not cve:
                        m = _CVE_RE.search(title)
                        if m:
                            cve = m.group(0)
                    entities.append(
                        {
                            "type": "wpscan_vuln",
                            "component": comp_type,
                            "slug": slug,
                            "component_version": comp_version,
                            "cve": cve,
                            "title": title[:500],
                            "fixed_in": str(vuln.get("fixed_in") or ""),
                        }
                    )

        _scan_component("plugins", "plugin")
        _scan_component("themes", "theme")

        for finding in data.get("interesting_findings") or []:
            if not isinstance(finding, dict):
                continue
            entities.append(
                {
                    "type": "wpscan_finding",
                    "url": str(finding.get("url") or ""),
                    "title": str(finding.get("to_s") or finding.get("title") or "")[:500],
                }
            )

        main_theme = data.get("main_theme") or {}
        if isinstance(main_theme, dict) and main_theme.get("slug"):
            theme_version = (main_theme.get("version") or {}).get("number", "") if isinstance(main_theme.get("version"), dict) else ""
            for vuln in main_theme.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                entities.append(
                    {
                        "type": "wpscan_vuln",
                        "component": "theme",
                        "slug": main_theme.get("slug"),
                        "component_version": theme_version,
                        "cve": "",
                        "title": str(vuln.get("title") or "")[:500],
                        "fixed_in": str(vuln.get("fixed_in") or ""),
                    }
                )

        for entity in entities:
            entity["wp_version"] = version
        return ParsedResult(tool="wpscan", entities=entities, raw=output, parsed_at=now_utc())
