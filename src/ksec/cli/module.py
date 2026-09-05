"""CLI: ``ksec module ...`` — domain modules (API, wireless, cloud,
container, Kubernetes) with tool readiness + deterministic posture checks."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_module_list(ctx: KsecContext, args) -> int:
    modules = ctx.modules.list_modules()
    if args.json:
        emit(modules, True, False)
    elif args.quiet:
        for module in modules:
            print(module["id"])
    else:
        for module in modules:
            print(f"{module['id']:<12} {module['title']:<22} audience: {', '.join(module['audience'])}")
            print(f"    {module['description']}")
    return 0


def cmd_module_info(ctx: KsecContext, args) -> int:
    info = ctx.modules.info(args.module)
    if info is None:
        emit(f"unknown module: {args.module}", args.json, args.quiet)
        return 1
    emit(info, args.json, args.quiet)
    return 0


def cmd_module_check(ctx: KsecContext, args) -> int:
    """Run the module's deterministic offline posture checks."""
    try:
        payload = ctx.modules.check(args.module, actor=getattr(args, "user", None) or "module")
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    if args.json:
        emit(payload, True, False)
    elif args.quiet:
        print(f"module={payload['module']} checks={len(payload['checks'])}")
    else:
        print(f"Module posture checks — {payload['module']} ({payload['generated_at']})")
        for check in payload["checks"]:
            mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "INFO": "[INFO]"}.get(check["status"], "[----]")
            print(f"  {mark} {check['check_id']:<26} {check['detail']}")
    return 0
