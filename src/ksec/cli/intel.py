"""CLI: ``ksec intel ...`` — threat intelligence (IOCs, actors, campaigns, TTPs)."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def _actor_id(ctx: KsecContext, name: str | None) -> int | None:
    if not name:
        return None
    for actor in ctx.intel.list_actors():
        if actor.name.lower() == name.lower():
            return actor.id
    emit(f"unknown actor: {name}")
    return None


def cmd_ioc_add(ctx: KsecContext, args) -> int:
    actor_id = _actor_id(ctx, args.actor) if getattr(args, "actor", None) else None
    if getattr(args, "actor", None) and actor_id is None:
        return 1
    campaign_id = None
    if getattr(args, "campaign", None):
        campaign_id = _campaign_id(ctx, args.campaign)
        if campaign_id is None:
            return 1
    try:
        ioc = ctx.intel.register_ioc(
            args.value,
            args.type,
            confidence=args.confidence,
            source=args.source or "",
            first_seen=args.first_seen,
            last_seen=args.last_seen,
            actor_id=actor_id,
            campaign_id=campaign_id,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {
            "created": True,
            "id": ioc.id,
            "type": ioc.type,
            "value": ioc.value,
            "normalized": ioc.normalized_value,
            "confidence": ioc.confidence,
        },
        args.json,
        args.quiet,
    )
    return 0


def _campaign_id(ctx: KsecContext, name: str) -> int | None:
    for campaign in ctx.intel.list_campaigns():
        if campaign.name.lower() == name.lower():
            return campaign.id
    emit(f"unknown campaign: {name}")
    return None


def cmd_ioc_list(ctx: KsecContext, args) -> int:
    iocs = ctx.intel.list_iocs(ioc_type=args.type, status=args.status)
    data = [
        {
            "id": i.id,
            "type": i.type,
            "value": i.value,
            "confidence": i.confidence,
            "status": i.status,
            "source": i.source,
        }
        for i in iocs
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for i in iocs:
            print(i.value)
    else:
        if not data:
            print("no IOCs")
        for d in data:
            print(f"{d['id']:>3}  {d['type']:<8} {d['confidence']:<8} {d['status']:<7} {d['value']}")
    return 0


def cmd_ioc_correlate(ctx: KsecContext, args) -> int:
    matches = ctx.intel.correlate(args.value)
    data = [
        {
            "id": i.id,
            "type": i.type,
            "value": i.value,
            "confidence": i.confidence,
            "source": i.source,
        }
        for i in matches
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for i in matches:
            print(i.value)
    else:
        if not data:
            print("no IOC matches")
        for d in data:
            print(f"MATCH {d['type']:<8} {d['value']} (confidence={d['confidence']})")
    return 0


def cmd_ioc_enrich(ctx: KsecContext, args) -> int:
    try:
        enriched = ctx.intel.enrich(args.ioc)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    ioc = enriched["ioc"]
    actor = enriched["actor"]
    campaign = enriched["campaign"]
    data = {
        "ioc": {"id": ioc.id, "type": ioc.type, "value": ioc.value},
        "actor": {"name": actor.name, "aliases": actor.aliases} if actor else None,
        "campaign": {"name": campaign.name, "confidence": campaign.confidence} if campaign else None,
        "ttps": [{"technique_id": t.technique_id, "name": t.name} for t in enriched["ttps"]],
        "related_findings": [
            {"id": f["id"], "title": f["title"], "severity": f["severity"]}
            for f in enriched["related_findings"]
        ],
    }
    emit(data, args.json, args.quiet)
    return 0


def cmd_ioc_extract(ctx: KsecContext, args) -> int:
    """Extract and auto-register IOCs from job/evidence/text sources."""
    try:
        if args.job:
            result = ctx.intel.extract_from_job_result(args.job, source=args.source or "")
        elif args.evidence:
            result = ctx.intel.extract_from_evidence(args.evidence, source=args.source or "")
        elif args.text:
            result = ctx.intel.extract_and_register(
                raw_text=args.text,
                source=args.source or "cli:text",
                default_confidence=args.confidence,
            )
        else:
            emit("provide --job, --evidence or --text", args.json, args.quiet)
            return 1
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1

    data = {
        "total_candidates": result["total_candidates"],
        "registered": result["registered"],
        "already_known": result["already_known"],
        "candidates": result["candidates"],
    }
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for candidate in result["candidates"]:
            print(f"{candidate['type']}:{candidate['value']}")
    else:
        print(
            f"extracted {result['total_candidates']} candidate(s)"
            f" — {result['registered']} new, {result['already_known']} already known"
        )
        for candidate in result["candidates"]:
            print(f"  {candidate['type']:<8} {candidate['value']:<45} conf={candidate['confidence']}")
    return 0


def cmd_actor_add(ctx: KsecContext, args) -> int:
    try:
        actor = ctx.intel.add_actor(
            args.name,
            description=args.description or "",
            aliases=args.alias or [],
            sources=args.source or [],
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {"created": True, "id": actor.id, "name": actor.name, "aliases": actor.aliases},
        args.json,
        args.quiet,
    )
    return 0


def cmd_actor_list(ctx: KsecContext, args) -> int:
    actors = ctx.intel.list_actors()
    data = [
        {"id": a.id, "name": a.name, "aliases": a.aliases, "confidence": a.confidence}
        for a in actors
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for a in actors:
            print(a.name)
    else:
        if not data:
            print("no actors")
        for d in data:
            print(f"{d['id']:>3}  {d['name']:<24} {d['confidence']:<8} aliases={','.join(d['aliases'])}")
    return 0


def cmd_campaign_add(ctx: KsecContext, args) -> int:
    actor_id = _actor_id(ctx, args.actor) if args.actor else None
    if args.actor and actor_id is None:
        return 1
    try:
        campaign = ctx.intel.add_campaign(
            args.name,
            description=args.description or "",
            actor_id=actor_id,
            confidence=args.confidence,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {"created": True, "id": campaign.id, "name": campaign.name, "actor_id": actor_id},
        args.json,
        args.quiet,
    )
    return 0


def cmd_campaign_list(ctx: KsecContext, args) -> int:
    campaigns = ctx.intel.list_campaigns()
    data = [
        {
            "id": c.id,
            "name": c.name,
            "actor_id": c.threat_actor_id,
            "confidence": c.confidence,
            "ttps": [t.technique_id for t in ctx.intel.campaign_ttps(c.id)],
        }
        for c in campaigns
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for c in campaigns:
            print(c.name)
    else:
        if not data:
            print("no campaigns")
        for d in data:
            print(f"{d['id']:>3}  {d['name']:<24} actor={d['actor_id'] or '-'}  ttps={','.join(d['ttps']) or '-'}")
    return 0


def cmd_ttp_add(ctx: KsecContext, args) -> int:
    try:
        ttp = ctx.intel.add_ttp(
            args.technique_id,
            args.name,
            description=args.description or "",
            tactic=args.tactic or "",
            source=args.source or "",
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {"created": True, "id": ttp.id, "technique_id": ttp.technique_id, "name": ttp.name},
        args.json,
        args.quiet,
    )
    return 0


def cmd_ttp_list(ctx: KsecContext, args) -> int:
    ttps = ctx.intel.list_ttps()
    data = [
        {
            "id": t.id,
            "framework": t.framework,
            "technique_id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
        }
        for t in ttps
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for t in ttps:
            print(t.technique_id)
    else:
        if not data:
            print("no TTPs")
        for d in data:
            print(f"{d['id']:>3}  {d['technique_id']:<8} {d['name']:<32} {d['tactic']}")
    return 0


def cmd_link_ttp(ctx: KsecContext, args) -> int:
    ctx.intel.link_ttp(args.campaign, args.ttp)
    emit(
        {"campaign_id": args.campaign, "ttp_id": args.ttp, "linked": True},
        args.json,
        args.quiet,
    )
    return 0