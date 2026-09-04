"""CLI: ``ksec atomic`` — atomic red tests for detection validation."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.redteam import get_atomic


def cmd_atomic_list(ctx: KsecContext, args) -> int:
    from ksec.redteam import atomics

    data = [a.to_dict() for a in atomics()]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for a in data:
            print(a["id"])
    else:
        for a in data:
            print(f"{a['id']:<18} {a['technique']:<10} {a['tactic']:<18} {a['name']}")
    return 0


def cmd_atomic_info(ctx: KsecContext, args) -> int:
    atomic = get_atomic(args.id)
    if atomic is None:
        emit(f"unknown atomic test: {args.id}", args.json, args.quiet)
        return 1
    data = atomic.to_dict()
    data["options"] = dict(atomic.options or {})
    if args.json:
        emit(data, True, False)
    else:
        for k, v in data.items():
            print(f"{k}: {v}")
    return 0


def cmd_atomic_run(ctx: KsecContext, args) -> int:
    try:
        user = UserRepository(ctx.db).authenticate(args.user, args.password)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    session = ctx.sessions.open(user, args.workspace, role_name=args.role)
    try:
        result = ctx.atomic.run(
            atomic_id=args.id,
            target=args.target,
            user=user,
            session=session,
            engagement_id=args.engagement,
        )
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    emit(result, args.json, args.quiet)
    return 0 if result["status"] == "completed" else 1
