"""CLI: ``ksec audit list`` — read the append-only audit log.

Audit is security-sensitive: reading it requires the ``audit.read``
permission (admin / auditor roles). Rows are returned newest-first.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository


def _require_audit_read(ctx: KsecContext, args) -> None:
    if not (args.user and args.password):
        raise KSECError("--user and --password are required to read the audit log")
    user = UserRepository(ctx.db).authenticate(args.user, args.password)
    decision = ctx.policy.evaluate(user=user, action="audit.read")
    if decision.decision.value != "ALLOW":
        raise KSECError(f"authorization denied: {decision.reason}")


def cmd_audit_list(ctx: KsecContext, args) -> int:
    try:
        _require_audit_read(ctx, args)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1

    rows = ctx.audit.list(
        limit=args.limit, event_type=args.event_type, actor=args.actor
    )
    data = [
        {
            "event_id": r["event_id"],
            "created_at": r["created_at"],
            "event_type": r["event_type"],
            "actor": r["actor"],
            "session_id": r["session_id"],
            "workspace": r["workspace"],
            "action": r["action"],
            "target": r["target"],
            "outcome": r["outcome"],
            "correlation_id": r["correlation_id"],
        }
        for r in rows
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in rows:
            print(r["event_id"])
    else:
        if not data:
            print("no audit events")
        for d in data:
            short = (d["event_id"] or "")[:12]
            who = d["actor"] or "-"
            what = d["action"] or d["event_type"]
            print(
                f"{short}  {d['created_at'][:19]}  {d['event_type']:<14} "
                f"{who:<10} {d['outcome']:<7} {what}"
            )
        print(f"\n{len(data)} audit event(s)")
    return 0
