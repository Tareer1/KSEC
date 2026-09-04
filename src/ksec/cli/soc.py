"""CLI: ``ksec soc ...`` — SOC alert pipeline (spec 08#16-17).

Commands: ingest (raw event -> pipeline), event list, alert list/show/
ack/resolve, rule add/list/enable/disable/delete.
"""
from __future__ import annotations

import json

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError


def cmd_soc_ingest(ctx: KsecContext, args) -> int:
    """Ingest one event through the pipeline (normalize->...->alert->case)."""
    raw: dict = {}
    if args.event_json:
        try:
            raw = json.loads(args.event_json)
        except json.JSONDecodeError as exc:
            emit(f"invalid --event-json: {exc}", args.json, args.quiet)
            return 1
        # CLI flags fill any keys missing from the JSON payload instead of
        # being silently dropped when the two are combined.
        for key, value in {
            "event_id": args.event_id,
            "source": args.source,
            "event_type": args.event_type,
            "severity": args.severity,
            "ip": args.ip or None,
            "domain": args.domain or None,
            "host": args.host or None,
            "username": args.username or None,
            "process": args.process or None,
        }.items():
            if value not in (None, "") and key not in raw:
                raw[key] = value
        if args.details_json:
            try:
                raw["details"] = json.loads(args.details_json)
            except json.JSONDecodeError as exc:
                emit(f"invalid --details-json: {exc}", args.json, args.quiet)
                return 1
    else:
        raw = {
            "event_id": args.event_id,
            "source": args.source,
            "event_type": args.event_type,
            "severity": args.severity,
            "ip": args.ip or None,
            "domain": args.domain or None,
            "host": args.host or None,
            "username": args.username or None,
            "process": args.process or None,
        }
        if args.details_json:
            try:
                raw["details"] = json.loads(args.details_json)
            except json.JSONDecodeError as exc:
                emit(f"invalid --details-json: {exc}", args.json, args.quiet)
                return 1

    try:
        report = ctx.soc.ingest(raw)
    except (ValueError, KSECError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1

    if args.json:
        emit(report, True, False)
        return 0
    if args.quiet:
        print(report["event_id"])
        return 0

    print(f"event {report['event_id']} {'(duplicate)' if not report.get('created') else '(new)'}")
    norm = report["normalized"]
    print(
        f"  normalized: {norm['event_type']} [{norm['severity']}] src={norm['source']}"
        f" ip={norm['ip'] or '-'} domain={norm['domain'] or '-'} host={norm['host'] or '-'}"
    )
    enrich = report["enrichment"]
    ioc = enrich["ioc"]
    asset = enrich["asset"]
    print(
        f"  enriched: asset={'yes' if asset else 'no'} ioc={'yes' if ioc else 'no'}"
        f" findings={len(enrich['related_findings'])}"
    )
    if ioc:
        print(f"    ioc match: {ioc['value']} ({ioc['type']}, conf={ioc['confidence']})")
    corr = report["correlation"]
    print(
        f"  correlated: {corr['related_event_count']} related event(s)"
        f" sources={','.join(corr['distinct_sources']) or '-'}"
    )
    rules = report["rules_matched"]
    if rules:
        print(f"  rules: {', '.join(r['name'] for r in rules)}")
    else:
        print("  rules: none matched")
    print(
        f"  risk score: {report['risk_score']}/10 (severity {report['severity']})"
    )
    if report.get("alerted"):
        alert = report["alert"]
        print(f"  ALERT #{alert['id']} [{alert['severity'].upper()}] {alert['summary']}")
        if report.get("case"):
            case = report["case"]
            print(f"  case #{case['id']} opened: {case['title']}")
    else:
        print(f"  no alert ({report.get('reason_not_alerted', 'below threshold')})")
    return 0


def cmd_soc_event_list(ctx: KsecContext, args) -> int:
    events = ctx.soc_events.list(limit=args.limit, event_type=args.event_type, entity=args.entity)
    data = [e.to_dict() for e in events]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for e in events:
            print(e.event_id)
    else:
        if not data:
            print("no events")
        for e in data:
            print(
                f"{e['id']:>4}  {e['event_type']:<16} {e['severity']:<8}"
                f" {e['ip'] or e['domain'] or e['host'] or '-':<24} {e['source']}"
            )
    return 0


def cmd_soc_alert_list(ctx: KsecContext, args) -> int:
    alerts = ctx.soc_alerts.list(limit=args.limit, status=args.status, severity=args.severity)
    data = [a.to_dict() for a in alerts]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for a in alerts:
            print(a.alert_id)
    else:
        if not data:
            print("no alerts")
        for a in data:
            print(
                f"{a['id']:>4}  [{a['severity'].upper():<8}] risk={a['risk_score']:<4}"
                f" {a['status']:<12} {a['type']:<16} {a['summary'][:60]}"
            )
        print(
            f"\n{ctx.soc_alerts.count()} alert(s) —"
            f" {ctx.soc_alerts.count(status='open')} open"
        )
    return 0


def cmd_soc_alert_show(ctx: KsecContext, args) -> int:
    alert = ctx.soc_alerts.get(args.id)
    if alert is None:
        emit(f"unknown alert: {args.id}", args.json, args.quiet)
        return 1
    emit(alert.to_dict(), args.json, args.quiet)
    return 0


def cmd_soc_alert_action(ctx: KsecContext, args) -> int:
    alert = ctx.soc_alerts.get(args.id)
    if alert is None:
        emit(f"unknown alert: {args.id}", args.json, args.quiet)
        return 1
    actor = None
    if getattr(args, "user", None):
        try:
            from ksec.identity.users import UserRepository

            actor = UserRepository(ctx.db).authenticate(
                args.user, getattr(args, "password", None)
            ).username
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    if args.action == "ack":
        updated = ctx.soc_alerts.acknowledge(args.id, actor=actor)
    elif args.action == "resolve":
        updated = ctx.soc_alerts.resolve(args.id, case_id=args.case, actor=actor)
    elif args.action == "close":
        updated = ctx.soc_alerts.set_status(args.id, "closed", actor=actor)
    else:
        emit(f"unknown action: {args.action}", args.json, args.quiet)
        return 1
    emit(updated.to_dict(), args.json, args.quiet)
    return 0


def cmd_soc_rule_add(ctx: KsecContext, args) -> int:
    try:
        rule = ctx.soc_rules.create(
            args.name,
            description=args.description or "",
            event_type=args.event_type or "",
            field=args.field,
            operator=args.operator,
            value=args.value or "",
            severity=args.severity,
            risk_boost=args.risk_boost or 0.0,
            open_case=not args.no_case,
        )
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    emit(rule.to_dict(), args.json, args.quiet)
    return 0


def cmd_soc_rule_list(ctx: KsecContext, args) -> int:
    rules = ctx.soc_rules.list(enabled_only=args.enabled_only)
    data = [r.to_dict() for r in rules]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in rules:
            print(r.name)
    else:
        if not data:
            print("no rules")
        for d in data:
            state = "on " if d["enabled"] else "off"
            print(
                f"{state} {d['name']:<28} {d['field']:<10} {d['operator']:<12}"
                f" {d['value'] or '*':<20} -> {d['severity']}"
            )
    return 0


def cmd_soc_rule_toggle(ctx: KsecContext, args) -> int:
    try:
        rule = ctx.soc_rules.set_enabled(args.id, enabled=args.enable)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    emit(rule.to_dict(), args.json, args.quiet)
    return 0


def cmd_soc_rule_delete(ctx: KsecContext, args) -> int:
    rule = ctx.soc_rules.get(args.id)
    if rule is None:
        emit(f"unknown rule: {args.id}", args.json, args.quiet)
        return 1
    ctx.soc_rules.delete(args.id)
    emit({"deleted": True, "id": args.id, "name": rule.name}, args.json, args.quiet)
    return 0
