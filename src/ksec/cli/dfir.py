"""CLI: ``ksec dfir artifact|event|timeline`` — forensic artifacts and timeline."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_artifact_add(ctx: KsecContext, args) -> int:
    artifact = ctx.dfir.add_artifact(
        args.case,
        args.name,
        args.type,
        host=args.host or "",
        details=args.details or "",
        tool=args.tool or "",
        evidence_id=args.evidence,
        collected_at=args.collected_at,
    )
    emit(
        {
            "created": True,
            "id": artifact.id,
            "case_id": artifact.case_id,
            "type": artifact.artifact_type,
            "name": artifact.name,
            "host": artifact.host,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_artifact_list(ctx: KsecContext, args) -> int:
    artifacts = ctx.dfir.list_artifacts(case_id=args.case, host=args.host)
    data = [
        {
            "id": a.id,
            "case_id": a.case_id,
            "host": a.host,
            "type": a.artifact_type,
            "name": a.name,
            "tool": a.tool,
            "collected_at": a.collected_at,
        }
        for a in artifacts
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for a in artifacts:
            print(a.id)
    else:
        if not data:
            print("no artifacts")
        for d in data:
            print(f"{d['id']:>3}  {d['host']:<20} {d['type']:<10} {d['name']}")
    return 0


def cmd_event_add(ctx: KsecContext, args) -> int:
    event = ctx.dfir.add_event(
        args.case,
        args.time,
        args.type,
        actor=args.actor or "",
        source=args.source or "",
        details=args.details or "",
        artifact_id=args.artifact,
    )
    emit(
        {
            "created": True,
            "id": event.id,
            "case_id": event.case_id,
            "event_time": event.event_time,
            "event_type": event.event_type,
            "actor": event.actor,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_timeline(ctx: KsecContext, args) -> int:
    events = ctx.dfir.timeline(case_id=args.case)
    if args.event_type:
        events = [e for e in events if e.event_type == args.event_type]
    data = [
        {
            "id": e.id,
            "event_time": e.event_time,
            "event_type": e.event_type,
            "actor": e.actor,
            "source": e.source,
            "details": e.details,
            "artifact_id": e.artifact_id,
        }
        for e in events
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for e in events:
            print(e.event_time)
    else:
        if not data:
            print("empty timeline")
        for d in data:
            print(f"{d['event_time']}  {d['event_type']:<14} actor={d['actor']:<16} {d['details']}")
    return 0