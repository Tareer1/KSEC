"""SIEM feed loops (spec: real SOC intake).

Two long-running collectors that turn external log streams into SOC events:

* :func:`listen_udp` — bind a UDP socket and treat every datagram as one log
  record (rsyslog forwarder, custom agents, netcat piping, ...)
* :func:`watch_file` — poll a file (or every file in a directory) and ingest
  each new line appended to it

Both parse via :mod:`ksec.siem.formats` and push each record through the
normal SOC pipeline (``ctx.soc.ingest``) so authorization, deduplication,
correlation, rules, alerts and the audit trail apply exactly as they do for
manual ingestion.
"""
from __future__ import annotations

import socket
import time
from pathlib import Path

from ksec.siem.formats import parse_line


class FeedStats:
    """Counters for one feed run (lines, parsed, ingested, alerts, errors)."""

    def __init__(self) -> None:
        self.lines = 0
        self.parsed = 0
        self.duplicates = 0
        self.ingested = 0
        self.alerts = 0
        self.errors = 0

    def to_dict(self) -> dict:
        return {
            "lines": self.lines,
            "parsed": self.parsed,
            "duplicates": self.duplicates,
            "ingested": self.ingested,
            "alerts": self.alerts,
            "errors": self.errors,
        }


def feed_line(ctx, line: str, source: str, stats: FeedStats, dry_run: bool = False) -> None:
    """Parse one line and push it through the SOC pipeline."""
    stats.lines += 1
    raw = parse_line(line, source=source)
    if raw is None:
        stats.errors += 1
        return
    stats.parsed += 1
    if dry_run:
        return
    try:
        report = ctx.soc.ingest(raw)
    except Exception:  # one bad record never stops the feed
        stats.errors += 1
        return
    if report.get("created"):
        stats.ingested += 1
    else:
        stats.duplicates += 1
    if report.get("alerted"):
        stats.alerts += 1

def listen_udp(
    ctx,
    *,
    host: str = "127.0.0.1",
    port: int = 5514,
    source: str = "syslog",
    run: int = 0,
    dry_run: bool = False,
) -> FeedStats:
    """Blocking UDP listener: each datagram is one log record."""
    stats = FeedStats()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        count = 0
        while True:
            try:
                data, _addr = sock.recvfrom(65535)
            except KeyboardInterrupt:
                break
            line = data.decode("utf-8", "replace")
            feed_line(ctx, line, source, stats, dry_run=dry_run)
            count += 1
            if run and count >= run:
                break
    return stats


def watch_file(
    ctx,
    path: str,
    *,
    source: str = "filewatch",
    poll_seconds: float = 1.0,
    once: bool = False,
    dry_run: bool = False,
) -> FeedStats:
    """Poll a file (or all files in a directory) and ingest appended lines.

    With ``once=True`` the current file contents are ingested and the run
    returns (used for tests, bulk backfills and cron jobs).
    """
    stats = FeedStats()
    target = Path(path)
    if not target.exists():
        print(f"siem: no such file or directory: {path}")
        stats.errors += 1
        return stats
    if target.is_dir():
        files = sorted(
            (p for p in target.iterdir() if p.is_file() and not p.name.startswith(".")),
            key=lambda p: p.stat().st_mtime,
        )
        for file in files:
            _ingest_existing(file, ctx, source, stats, dry_run=dry_run)
        return stats

    offsets: dict[str, int] = {}
    first = True
    while True:
        try:
            current_size = target.stat().st_size
        except FileNotFoundError:
            break
        offset = offsets.get(str(target), 0)
        if first or current_size < offset:  # truncation/rotation
            offset = 0
        if current_size > offset:
            with open(target, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                for line in handle:
                    feed_line(ctx, line, source, stats, dry_run=dry_run)
                offsets[str(target)] = handle.tell()
        first = False
        if once:
            break
        time.sleep(poll_seconds)
    return stats


def _ingest_existing(
    file: Path, ctx, source: str, stats: FeedStats, dry_run: bool = False
) -> None:
    try:
        with open(file, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                feed_line(ctx, line, source, stats, dry_run=dry_run)
    except OSError:
        stats.errors += 1
