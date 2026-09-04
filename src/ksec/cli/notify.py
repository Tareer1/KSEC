"""CLI: ``ksec notify`` — notification store and provider test."""

from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_notify_list(ctx: KsecContext, args) -> int:
    rows = ctx.notifications.list(limit=args.limit)
    data = [
        {
            "id": r["id"],
            "channel": r["channel"],
            "event_type": r["event_type"],
            "title": r["title"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in rows:
            print(r["id"])
    else:
        if not data:
            print("no notifications")
        for d in data:
            print(f"{d['id']:>3}  {d['channel']:<10} {d['event_type']:<20} {d['title'][:60]}")
    return 0


def cmd_notify_test(ctx: KsecContext, args) -> int:
    """Send a test notification through configured providers (best-effort)."""
    providers = ctx.notifications.providers
    if not providers:
        emit(
            {"sent": False, "message": "no providers configured in [notifications.providers]"},
            args.json,
            args.quiet,
        )
        return 1
    results = ctx.notifications.deliver(
        event_type="notify.test", title=args.title or "KSEC test notification",
        body=args.body or "This is a test notification from KSEC.",
    )
    emit({"sent": True, "providers": results}, args.json, args.quiet)
    ok = all(r.get("ok") for r in results.values())
    return 0 if ok else 1