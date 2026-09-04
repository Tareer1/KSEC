"""CLI: ``ksec tools install`` — controlled tool installation."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository


def cmd_tools_install(ctx: KsecContext, args) -> int:
    # Policy gate: tools.install is admin-only; safe mode requires confirmation.
    try:
        user = UserRepository(ctx.db).authenticate(args.user, args.password)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1

    decision = ctx.policy.evaluate(user=user, action="tools.install")
    if decision.decision.value != "ALLOW":
        emit(
            {"blocked": True, "decision": decision.decision.value, "reason": decision.reason},
            args.json,
            args.quiet,
        )
        return 1

    try:
        plan = ctx.installer.plan(args.capability, package=args.package, dry_run=True)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1

    if args.dry_run:
        emit(
            {
                "capability": plan.capability,
                "provider": plan.provider,
                "package": plan.package,
                "command": plan.command,
                "approval_required": not args.yes,
            },
            args.json,
            args.quiet,
        )
        return 0

    if not args.yes:
        emit(
            {
                "error": "approval required",
                "message": "rerun with --yes to install "
                f"{plan.package} (command: {' '.join(plan.command)})",
            },
            args.json,
            args.quiet,
        )
        return 1

    result = ctx.installer.install(
        args.capability, package=args.package, approved=True, dry_run=False
    )
    emit(
        {
            "capability": result.capability,
            "provider": result.provider,
            "installed": result.installed,
            "verified": result.verified,
            "message": result.message,
        },
        args.json,
        args.quiet,
    )
    return 0 if result.installed else 1