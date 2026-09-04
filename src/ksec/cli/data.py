"""CLI: ``ksec asset``, ``ksec finding``, ``ksec evidence``, ``ksec case``."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
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
    ctx.cases.add_finding(args.case, args.finding)
    emit(
        {"case_id": args.case, "finding_id": args.finding, "linked": True},
        args.json,
        args.quiet,
    )
    return 0