"""CLI: ``ksec export`` — auditable structured exports (spec 05 #76-79)."""
from __future__ import annotations

import json

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.identity.users import now_utc


def _envelope(ctx: KsecContext, records: list, source: str) -> dict:
    return {
        "schema_version": "1.0",
        "export_version": "1.0",
        "generated_at": now_utc(),
        "source_system": "ksec",
        "source": source,
        "ksec_version": __import__("ksec", fromlist=["__version__"]).__version__,
        "records": records,
    }


def _write_out(ctx: KsecContext, data: dict, args, default_out: str) -> int:
    text = json.dumps(data, indent=2, default=str)
    if getattr(args, "out", None):
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        emit({"exported": True, "path": args.out, "records": len(data["records"])},
             args.json, args.quiet)
    else:
        emit(data, args.json, args.quiet)
    return 0


def cmd_export_case(ctx: KsecContext, args) -> int:
    case = ctx.cases.get(args.case)
    if case is None:
        emit(f"unknown case: {args.case}", args.json, args.quiet)
        return 1
    findings = [dict(f) for f in ctx.cases.findings(args.case)]
    notes = [
        {"id": n.id, "author": n.author, "content": n.content, "created_at": n.created_at}
        for n in ctx.cases.notes(args.case)
    ]
    timeline = [
        {"id": e.id, "event_type": e.event_type, "details": e.details,
         "actor": e.actor, "created_at": e.created_at}
        for e in ctx.cases.events(args.case)
    ]
    evidence = [
        {"id": ev.id, "tool": ev.tool, "operator": ev.operator, "sha256": ev.sha256,
         "source": ev.source, "created_at": ev.created_at}
        for ev in ctx.evidence.list()
    ]
    iocs = [
        {"id": i.id, "type": i.type, "value": i.value, "confidence": i.confidence}
        for i in ctx.intel.list_iocs()
    ]
    data = _envelope(
        ctx,
        [{
            "case": {
                "id": case.id, "title": case.title, "description": case.description,
                "severity": case.severity, "status": case.status, "owner": case.owner,
                "created_at": case.created_at, "updated_at": case.updated_at,
            },
            "findings": findings,
            "notes": notes,
            "timeline": timeline,
            "evidence": evidence,
            "iocs": iocs,
        }],
        f"case:{args.case}",
    )
    return _write_out(ctx, data, args, f"case-{args.case}.json")


def cmd_export_findings(ctx: KsecContext, args) -> int:
    findings = ctx.findings.list(engagement_id=args.engagement)
    records = [
        {
            "id": f.id, "title": f.title, "description": f.description,
            "severity": f.severity, "confidence": f.confidence, "status": f.status,
            "risk_score": f.risk_score, "risk_level": f.risk_level,
            "recommendation": f.recommendation, "source": f.source,
            "created_at": f.created_at, "updated_at": f.updated_at,
            "remediations": [
                {
                    "id": r.id, "description": r.description, "owner": r.owner,
                    "priority": r.priority, "status": r.status, "due_date": r.due_date,
                }
                for r in ctx.findings.remediations(f.id)
            ],
        }
        for f in findings
    ]
    return _write_out(ctx, _envelope(ctx, records, f"findings:{args.engagement or 'all'}"),
                      args, "findings.json")


def cmd_export_evidence(ctx: KsecContext, args) -> int:
    evidence = ctx.evidence.list(args.engagement)
    records = [
        {
            "id": e.id, "tool": e.tool, "tool_version": e.tool_version,
            "operator": e.operator, "collection_method": e.collection_method,
            "source": e.source, "sha256": e.sha256, "bytes": len(e.content),
            "created_at": e.created_at,
            "chain_of_custody": [
                {"action": c.action, "actor": c.actor, "previous_state": c.previous_state,
                 "new_state": c.new_state, "reason": c.reason, "created_at": c.created_at}
                for c in ctx.evidence.custody_log(e.id)
            ],
        }
        for e in evidence
    ]
    return _write_out(ctx, _envelope(ctx, records, f"evidence:{args.engagement or 'all'}"),
                      args, "evidence.json")


def cmd_export_assets(ctx: KsecContext, args) -> int:
    assets = ctx.assets.list(args.engagement)
    records = [
        {"id": a.id, "target": a.target, "type": a.asset_type, "criticality": a.criticality,
         "owner": a.owner, "tags": a.tags, "source": a.source}
        for a in assets
    ]
    return _write_out(ctx, _envelope(ctx, records, f"assets:{args.engagement or 'all'}"),
                      args, "assets.json")