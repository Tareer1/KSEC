"""Parse ``iwlist <iface> scan`` text output into wifi_ap entities.

Recognizes cell blocks (``Cell 01 - Address: ...``) with channel, frequency,
ESSID and encryption fields. Only the first mode line per cell is kept.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_CELL_RE = re.compile(r"^Cell\s+\d+\s+-\s+Address:\s*([0-9A-Fa-f:]{17})")
_CHANNEL_RE = re.compile(r"Channel:(\d+)")
_FREQ_RE = re.compile(r"Frequency:([\d.]+ GHz)")
_ESSID_RE = re.compile(r'ESSID:"(.*)"')
_ENCRYPTION_RE = re.compile(r"Encryption key:(on|off)")
_QUALITY_RE = re.compile(r"Quality=(\d+)/(\d+)")


class IwlistParser(OutputParser):
    name = "iwlist"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        current: dict | None = None
        for line in output.splitlines():
            cell = _CELL_RE.match(line.strip())
            if cell:
                if current is not None:
                    entities.append(current)
                current = {"type": "wifi_ap", "bssid": cell.group(1).lower()}
                continue
            if current is None:
                continue
            channel = _CHANNEL_RE.search(line)
            if channel and "channel" not in current:
                current["channel"] = int(channel.group(1))
            freq = _FREQ_RE.search(line)
            if freq and "frequency" not in current:
                current["frequency"] = freq.group(1)
            essid = _ESSID_RE.search(line)
            if essid and "essid" not in current:
                current["essid"] = essid.group(1)
            enc = _ENCRYPTION_RE.search(line)
            if enc and "encryption" not in current:
                current["encryption"] = enc.group(1)
            quality = _QUALITY_RE.search(line)
            if quality and "quality" not in current:
                current["quality"] = (
                    f"{quality.group(1)}/{quality.group(2)}"
                )
        if current is not None:
            entities.append(current)
        return ParsedResult(tool="iwlist", entities=entities, raw=output, parsed_at=now_utc())