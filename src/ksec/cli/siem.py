"""CLI: ``ksec siem listen|watch|demo`` — real SOC auto-ingestion.

Commands push parsed log records (syslog UDP datagrams or appended log
files) through the normal SOC pipeline. See ``ksec ask siem`` for a
plain-language guide.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.siem import formats
from ksec.siem.feeder import FeedStats, listen_udp, watch_file


def cmd_siem_listen(ctx: KsecContext, args) -> int:
    """Blocking UDP syslog-style listener on host:port."""
    stats = listen_udp(
        ctx,
        host=args.host,
        port=args.port,
        source=args.source or "syslog",
        run=args.run,
        dry_run=args.dry_run,
    )
    _report(stats, args)
    return 0


def cmd_siem_watch(ctx: KsecContext, args) -> int:
    """Watch a log file (or directory) and ingest appended records."""
    stats = watch_file(
        ctx,
        args.path,
        source=args.source or "filewatch",
        poll_seconds=args.poll,
        once=args.once,
        dry_run=args.dry_run,
    )
    _report(stats, args)
    return 0


def cmd_siem_demo(ctx: KsecContext, args) -> int:
    """Show format parsing with sample lines (no ingestion unless --ingest)."""
    samples = [
        "<134>Jan  5 10:01:22 web1 sshd[2213]: Failed password for root "
        "from 203.0.113.7 port 51234 ssh2",
        "2026-09-04T06:00:01Z fw01 suricata: ET SCAN Potential TCP Scan "
        "from 198.51.100.10",
        '{"event_id": "zeek-0001", "source": "zeek", "event_type": "conn", '
        '"ip": "203.0.113.9", "severity": "low", "details": {"proto": "tcp", '
        '"port": 4444}}',
        'type=SYSCALL msg=audit(1725433201.123:456): pid=2213 uid=0 auid=1000 '
        'msg="su root" key=privilege',
    ]
    parsed = []
    for line in samples:
        raw = formats.parse_line(line, source=args.source or "siem-demo")
        parsed.append({"line": line, "parsed": raw is not None,
                       "raw": raw if raw else None})
        if raw and args.ingest:
            try:
                ctx.soc.ingest(raw)
            except Exception as exc:  # noqa: BLE001 - demo resilience
                parsed[-1]["error"] = str(exc)
    emit(parsed, args.json, args.quiet)
    return 0


def _report(stats: FeedStats, args) -> None:
    data = stats.to_dict()
    data["dry_run"] = args.dry_run
    emit(data, args.json, args.quiet)
    if args.json or args.quiet:
        return
    print(
        f"siem feed: {data['lines']} line(s), {data['parsed']} parsed,"
        f" {data['ingested']} ingested, {data['duplicates']} duplicate(s),"
        f" {data['alerts']} alert(s), {data['errors']} error(s)"
    )
