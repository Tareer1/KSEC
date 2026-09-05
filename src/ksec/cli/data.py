"""CLI: ``ksec asset``, ``ksec finding``, ``ksec evidence``, ``ksec case``."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.risk.engine import calculate_risk


# -- assets ---------------------------------------------------------------

def cmd_asset_list(ctx: KsecContext, args) -> int:
    assets = ctx.assets.list(args.engagement)
    data = [
        {
            "id": a.id,
            "target": a.target,
            "type": a.asset_type,
            "criticality": a.criticality,
            "owner": a.owner,
            "tags": a.tags,
            "source": a.source,
        }
        for a in assets
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for a in assets:
            print(a.target)
    else:
        if not data:
            print("no assets")
        for d in data:
            print(f"{d['id']:>3}  {d['target']:<28} {d['type']:<10} crit={d['criticality']}")
    return 0


# -- findings -------------------------------------------------------------

def cmd_finding_create(ctx: KsecContext, args) -> int:
    risk = None
    if args.risk:
        risk = calculate_risk(
            severity=args.severity,
            asset_criticality=args.criticality or "low",
            exploitability=args.exploitability or "none",
            exposure=args.exposure or "internal",
            business_impact=args.impact or "low",
            confidence=args.confidence,
            evidence_quality=args.evidence or "none",
        )
    finding = ctx.findings.create(
        title=args.title,
        description=args.description or "",
        severity=args.severity,
        confidence=args.confidence,
        recommendation=args.recommendation or "",
        asset_id=args.asset,
        engagement_id=args.engagement,
        source=args.source or "",
        risk=risk,
    )
    data = {
        "created": True,
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
    }
    if risk is not None and args.verbose:
        data["risk_reasoning"] = risk.reasoning
    # Threat intelligence correlation: does this finding reference known IOCs?
    ioc_matches = ctx.intel.correlate_finding(finding)
    if ioc_matches:
        data["ioc_matches"] = [
            {"id": i.id, "type": i.type, "value": i.value, "confidence": i.confidence}
            for i in ioc_matches
        ]
    emit(data, args.json, args.quiet)
    return 0


def cmd_finding_explain(ctx: KsecContext, args) -> int:
    """Explain a finding (spec: RESULT EXPLANATION) — mode-aware.

    Answers: What happened? Why does it matter? What evidence supports it?
    What should happen next? (and for risk: why did KSEC mark it this way?)
    """
    from ksec.capabilities.explain import plain_severity
    from ksec.modes import resolve_mode

    mode = resolve_mode(args.mode, ctx.config.mode)
    finding = ctx.findings.get(args.id)
    if finding is None:
        emit(f"unknown finding: {args.id}", args.json, args.quiet)
        return 1

    base = {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "what_happened": finding.description or finding.title,
        "why_it_matters": (
            f"This is a {plain_severity(finding.severity)} "
            f"(severity={finding.severity})."
        ),
        "evidence_support": finding.source or "No evidence source recorded.",
        "what_should_happen_next": finding.recommendation
        or "Review the finding, confirm it, and remediate or dismiss it.",
    }
    if finding.risk_level:
        base["why_this_risk"] = (
            f"KSEC rated this {finding.risk_level} (score {finding.risk_score}) from "
            "severity, asset criticality, exploitability, exposure, impact, "
            "confidence and evidence quality."
        )
    if mode.is_beginner():
        data = {
            "id": finding.id,
            "title": finding.title,
            "what_happened": base["what_happened"],
            "why_it_matters": base["why_it_matters"],
            "what_should_happen_next": base["what_should_happen_next"],
        }
    elif mode.is_expert():
        data = base
        ioc_matches = ctx.intel.correlate_finding(finding)
        data["ioc_matches"] = [
            {"id": i.id, "type": i.type, "value": i.value} for i in ioc_matches
        ]
        data["confidence"] = finding.confidence
        data["recommendation"] = finding.recommendation
        data["created_at"] = finding.created_at
    else:
        data = base
    emit(data, args.json, args.quiet)
    return 0


def cmd_finding_list(ctx: KsecContext, args) -> int:
    findings = ctx.findings.list(
        engagement_id=args.engagement, status=args.status or None, severity=args.severity or None
    )
    data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "risk_level": f.risk_level,
            "risk_score": f.risk_score,
        }
        for f in findings
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for f in findings:
            print(f.id)
    else:
        if not data:
            print("no findings")
        for d in data:
            print(
                f"{d['id']:>3}  {d['severity']:<8} {d['status']:<12} {d['risk_level'] or '-':<8} {d['title']}"
            )
    return 0


def cmd_finding_update(ctx: KsecContext, args) -> int:
    """Update a finding's status (spec: FALSE-POSITIVE HANDLING / finding
    lifecycle — status transitions are audited)."""
    from ksec.identity.users import UserRepository

    actor = None
    if getattr(args, "user", None):
        try:
            actor = UserRepository(ctx.db).authenticate(args.user, args.password).username
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    if not getattr(args, "status", None):
        emit("finding update requires --status", args.json, args.quiet)
        return 1
    try:
        finding = ctx.findings.update_status(args.id, args.status)
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    ctx.audit.record(
        event_type="finding.status",
        actor=actor,
        action=f"finding.status:{args.status}",
        target=f"finding:{args.id}",
        outcome="success",
    )
    emit(
        {"id": finding.id, "status": finding.status, "updated": True},
        args.json,
        args.quiet,
    )
    return 0


def cmd_finding_remediations(ctx: KsecContext, args) -> int:
    """List remediation tasks + verification records for a finding."""
    finding = ctx.findings.get(args.id)
    if finding is None:
        emit(f"unknown finding: {args.id}", args.json, args.quiet)
        return 1
    rems = ctx.findings.remediations(args.id)
    data = []
    for r in rems:
        verifications = ctx.findings.verifications(r.id)
        data.append(
            {
                "remediation_id": r.id,
                "description": r.description,
                "owner": r.owner,
                "priority": r.priority,
                "status": r.status,
                "due_date": r.due_date,
                "verifications": [
                    {
                        "id": v.id,
                        "method": v.method,
                        "result": v.result,
                        "evidence_id": v.evidence_id,
                        "verified_by": v.verified_by,
                        "created_at": v.created_at,
                    }
                    for v in verifications
                ],
            }
        )
    emit({"finding_id": args.id, "remediations": data}, args.json, args.quiet)
    return 0


def cmd_finding_remediate(ctx: KsecContext, args) -> int:
    """Create a remediation task for a finding (spec 08 #56)."""
    try:
        rem = ctx.findings.add_remediation(
            args.id,
            description=args.description or "",
            owner=args.owner or "",
            priority=args.priority,
            due_date=args.due,
        )
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    ctx.audit.record(
        event_type="remediation.create",
        actor=args.owner or None,
        action="remediation.create",
        target=f"finding:{args.id}",
        outcome="success",
    )
    emit(
        {"created": True, "remediation_id": rem.id, "finding_id": args.id, "status": rem.status},
        args.json,
        args.quiet,
    )
    return 0


def cmd_finding_verify(ctx: KsecContext, args) -> int:
    """Record a remediation verification (spec 08 #57, spec 05 #38)."""
    actor = None
    if getattr(args, "user", None):
        try:
            from ksec.identity.users import UserRepository

            actor = UserRepository(ctx.db).authenticate(args.user, args.password).username
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    try:
        verification = ctx.findings.verify_remediation(
            args.remediation,
            method=args.method,
            result=args.result,
            evidence_id=args.evidence,
            verified_by=actor or args.user or "",
            details=args.details or "",
        )
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    ctx.audit.record(
        event_type="remediation.verify",
        actor=actor,
        action=f"remediation.verify:{args.result}",
        target=f"remediation:{args.remediation}",
        outcome="success",
    )
    emit(
        {
            "recorded": True,
            "verification_id": verification.id,
            "remediation_id": args.remediation,
            "result": verification.result,
        },
        args.json,
        args.quiet,
    )
    return 0


# -- evidence -------------------------------------------------------------

def cmd_evidence_add(ctx: KsecContext, args) -> int:
    content = args.content
    if args.file:
        from pathlib import Path

        content = Path(args.file).read_text(encoding="utf-8", errors="replace")
    evidence = ctx.evidence.add(
        content,
        tool=args.tool or "",
        operator=args.operator or "",
        collection_method=args.method or "",
        source=args.source or "",
        engagement_id=args.engagement,
    )
    emit(
        {
            "created": True,
            "id": evidence.id,
            "sha256": evidence.sha256,
            "tool": evidence.tool,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_evidence_list(ctx: KsecContext, args) -> int:
    rows = ctx.evidence.list(args.engagement)
    data = [
        {
            "id": e.id,
            "tool": e.tool,
            "operator": e.operator,
            "sha256": e.sha256[:16],
            "bytes": len(e.content),
            "created_at": e.created_at,
        }
        for e in rows
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for e in rows:
            print(e.id)
    else:
        if not data:
            print("no evidence")
        for d in data:
            print(f"{d['id']:>3}  {d['tool']:<14} {d['sha256']}  {d['bytes']} bytes")
    return 0


def cmd_evidence_verify(ctx: KsecContext, args) -> int:
    ok, reason = ctx.evidence.verify(args.id)
    emit({"id": args.id, "verified": ok, "reason": reason}, args.json, args.quiet)
    return 0 if ok else 1


def cmd_evidence_custody(ctx: KsecContext, args) -> int:
    """Show the full chain of custody for an evidence object (spec 05 #30)."""
    evidence = ctx.evidence.get(args.id)
    if evidence is None:
        emit(f"unknown evidence: {args.id}", args.json, args.quiet)
        return 1
    events = ctx.evidence.custody_log(args.id)
    data = [
        {
            "id": e.id,
            "action": e.action,
            "actor": e.actor,
            "previous_state": e.previous_state,
            "new_state": e.new_state,
            "reason": e.reason,
            "created_at": e.created_at,
        }
        for e in events
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for e in events:
            print(f"{e.action:<10} {e.created_at}")
    else:
        print(f"evidence #{args.id} chain of custody ({len(data)} events):")
        for d in data:
            print(
                f"  {d['action']:<10} {d['created_at']}  actor={d['actor'] or '-':<10}"
                f" {d['previous_state']} -> {d['new_state']}  {d['reason']}"
            )
    return 0


# -- cases ----------------------------------------------------------------

def cmd_case_create(ctx: KsecContext, args) -> int:
    case = ctx.cases.create(
        title=args.title,
        description=args.description or "",
        severity=args.severity,
        owner=args.owner or "",
        engagement_id=args.engagement,
    )
    emit(
        {"created": True, "id": case.id, "title": case.title, "status": case.status},
        args.json,
        args.quiet,
    )
    return 0


def cmd_case_list(ctx: KsecContext, args) -> int:
    cases = ctx.cases.list()
    data = [
        {
            "id": c.id,
            "title": c.title,
            "severity": c.severity,
            "status": c.status,
            "owner": c.owner,
            "findings": len(ctx.cases.findings(c.id)),
        }
        for c in cases
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for c in cases:
            print(c.id)
    else:
        if not data:
            print("no cases")
        for d in data:
            print(f"{d['id']:>3}  {d['severity']:<8} {d['status']:<12} findings={d['findings']:<3} {d['title']}")
    return 0


def cmd_case_add_finding(ctx: KsecContext, args) -> int:
    actor = None
    if getattr(args, "user", None):
        try:
            from ksec.identity.users import UserRepository

            actor = UserRepository(ctx.db).authenticate(args.user, args.password).username
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    try:
        ctx.cases.add_finding(args.case, args.finding, actor=actor)
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {"case_id": args.case, "finding_id": args.finding, "linked": True},
        args.json,
        args.quiet,
    )
    return 0


def cmd_case_close(ctx: KsecContext, args) -> int:
    actor = None
    if getattr(args, "user", None):
        try:
            from ksec.identity.users import UserRepository

            actor = UserRepository(ctx.db).authenticate(args.user, args.password).username
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    try:
        case = ctx.cases.close(args.id, actor=actor)
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit({"closed": True, "id": case.id, "status": case.status}, args.json, args.quiet)
    return 0


def cmd_case_reopen(ctx: KsecContext, args) -> int:
    """Reopen a closed case with a recorded reason (spec 05 #92)."""
    actor = None
    if getattr(args, "user", None):
        try:
            from ksec.identity.users import UserRepository

            actor = UserRepository(ctx.db).authenticate(args.user, args.password).username
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    try:
        case = ctx.cases.reopen(args.id, reason=args.reason or "", actor=actor)
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit({"reopened": True, "id": case.id, "status": case.status}, args.json, args.quiet)
    return 0


def cmd_case_note_add(ctx: KsecContext, args) -> int:
    try:
        note = ctx.cases.add_note(args.case, args.content, author=args.author or "")
    except (KSECError, ValueError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit({"added": True, "note_id": note.id, "case_id": args.case}, args.json, args.quiet)
    return 0


def cmd_case_note_list(ctx: KsecContext, args) -> int:
    notes = ctx.cases.notes(args.case)
    data = [
        {"id": n.id, "author": n.author, "content": n.content, "created_at": n.created_at}
        for n in notes
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for n in notes:
            print(n.id)
    else:
        if not data:
            print("no notes")
        for d in data:
            print(f"{d['id']:>3}  {d['author'] or '-':<10} {d['created_at']}  {d['content']}")
    return 0


def cmd_case_timeline(ctx: KsecContext, args) -> int:
    case_id = getattr(args, "case", None) or getattr(args, "id", None)
    if case_id is None:
        emit("case id required", args.json, args.quiet)
        return 1
    events = ctx.cases.events(case_id)
    data = [
        {
            "id": e.id,
            "event_type": e.event_type,
            "details": e.details,
            "actor": e.actor,
            "created_at": e.created_at,
        }
        for e in events
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for e in events:
            print(e.id)
    else:
        if not data:
            print("no events")
        for d in data:
            print(f"{d['id']:>3}  {d['event_type']:<16} {d['created_at']}  {d['details']}  ({d['actor']})")
    return 0