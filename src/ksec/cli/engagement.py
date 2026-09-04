"""CLI: ``ksec engagement ...`` — authorizations and scope."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_engagement_create(ctx: KsecContext, args) -> int:
    engagement = ctx.authz.create_engagement(args.name, description=args.description or "")
    emit(
        {
            "created": True,
            "id": engagement.id,
            "name": engagement.name,
            "status": engagement.status,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_engagement_list(ctx: KsecContext, args) -> int:
    engagements = ctx.authz.list_engagements()
    data = [
        {
            "id": e.id,
            "name": e.name,
            "description": e.description,
            "status": e.status,
            "created_at": e.created_at,
        }
        for e in engagements
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for e in engagements:
            print(e.id)
    else:
        if not data:
            print("no engagements")
        for e in data:
            print(f"{e['id']:>3}  {e['name']:<24} {e['status']:<8} {e['created_at']}")
    return 0


def cmd_engagement_scope_add(ctx: KsecContext, args) -> int:
    rule_id = ctx.authz.add_authorization(
        args.engagement,
        args.target,
        action=args.action or "*",
        effect=args.effect or "allow",
    )
    emit(
        {
            "created": True,
            "id": rule_id,
            "engagement_id": args.engagement,
            "target": args.target,
            "effect": args.effect or "allow",
            "action": args.action or "*",
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_engagement_scope_list(ctx: KsecContext, args) -> int:
    rules = ctx.authz.list_authorizations(args.engagement)
    data = [
        {"id": r["id"], "target": r["target"], "action": r["action"], "effect": r["effect"]}
        for r in rules
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in rules:
            print(r["target"])
    else:
        if not data:
            print("no scope rules")
        for r in data:
            print(f"{r['id']:>3}  {r['effect']:<6} {r['action']:<12} {r['target']}")
    return 0