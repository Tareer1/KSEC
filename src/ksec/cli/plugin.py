"""CLI: ``ksec plugin list|info|install|enable|disable|uninstall|check``.

Plugin lifecycle per spec 06#43-45 (source verification, permission
declaration, trust levels, user approval) and 10 (plugin inventory/health).
"""
from __future__ import annotations

from pathlib import Path

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.plugins.manager import STATUS_BLOCKED, STATUS_DISABLED, STATUS_ENABLED


def _require_admin(ctx: KsecContext, args) -> None:
    """Plugin lifecycle commands are admin-only (policy: plugin.manage)."""
    if not (args.user and args.password):
        raise KSECError("--user and --password are required for plugin administration")
    user = UserRepository(ctx.db).authenticate(args.user, args.password)
    decision = ctx.policy.evaluate(user=user, action="plugin.manage")
    if decision.decision.value != "ALLOW":
        raise KSECError(f"authorization denied: {decision.reason}")


def cmd_plugin_list(ctx: KsecContext, args) -> int:
    plugins = ctx.plugins.discover()
    data = [p.to_dict() for p in plugins]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for p in plugins:
            print(p.plugin_id)
    else:
        if not data:
            print("no plugins installed")
        for p in data:
            mark = {
                "ENABLED": "on ",
                "INSTALLED": "-- ",
                "DISABLED": "off",
                "BLOCKED": "!! ",
            }.get(p["status"], "?? ")
            exec_note = "" if p["executable"] else " (not executable)"
            print(
                f"{mark} {p['plugin_id']:<28} v{p['version']:<8} {p['trust_level']:<14}"
                f" {p['status']:<9} {p['category']}{exec_note}"
            )
        print(f"\n{len(data)} plugin(s)")
    return 0


def cmd_plugin_info(ctx: KsecContext, args) -> int:
    plugin = ctx.plugins.get(args.name)
    if plugin is None:
        emit(f"unknown plugin: {args.name}", args.json, args.quiet)
        return 1
    emit(plugin.to_dict(), args.json, args.quiet)
    return 0


def cmd_plugin_install(ctx: KsecContext, args) -> int:
    try:
        _require_admin(ctx, args)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1

    source = Path(args.path).resolve()
    # Show what will be installed and require approval (spec 06#43).
    try:
        from ksec.plugins.manifest import load_manifest

        manifest = load_manifest(source)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1

    if not args.yes:
        emit(
            {
                "error": "approval required",
                "message": f"plugin {manifest.id!r} ({manifest.name} v{manifest.version})"
                f" requests trust level {args.trust}, permissions"
                f" {', '.join(manifest.permissions)} — rerun with --yes to approve",
            },
            args.json,
            args.quiet,
        )
        return 1

    try:
        info = ctx.plugins.install(
            source,
            trust_level=args.trust,
            installed_by=args.user,
            approve=True,
        )
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1

    loaded = info.status == STATUS_ENABLED and info.executable
    emit(
        {
            "installed": True,
            "plugin_id": info.plugin_id,
            "name": info.name,
            "version": info.version,
            "trust_level": info.trust_level,
            "status": info.status,
            "permissions": list(info.permissions),
            "capabilities": list(info.capabilities),
            "loaded": loaded,
            "message": "plugin loaded" if loaded else "plugin installed but not loaded (enable it)",
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_plugin_enable(ctx: KsecContext, args) -> int:
    try:
        _require_admin(ctx, args)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    try:
        info = ctx.plugins.set_status(args.name, STATUS_ENABLED, actor=args.user)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    emit(
        {
            "plugin_id": info.plugin_id,
            "status": info.status,
            "executable": info.executable,
            "loaded": info.executable,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_plugin_disable(ctx: KsecContext, args) -> int:
    try:
        _require_admin(ctx, args)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    try:
        info = ctx.plugins.set_status(args.name, STATUS_DISABLED, actor=args.user)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    emit({"plugin_id": info.plugin_id, "status": info.status}, args.json, args.quiet)
    return 0


def cmd_plugin_block(ctx: KsecContext, args) -> int:
    try:
        _require_admin(ctx, args)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    try:
        info = ctx.plugins.set_status(args.name, STATUS_BLOCKED, actor=args.user)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    emit({"plugin_id": info.plugin_id, "status": info.status}, args.json, args.quiet)
    return 0


def cmd_plugin_uninstall(ctx: KsecContext, args) -> int:
    try:
        _require_admin(ctx, args)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    if not args.yes:
        emit(
            {
                "error": "approval required",
                "message": f"uninstalling plugin {args.name!r} removes it from disk;"
                " rerun with --yes",
            },
            args.json,
            args.quiet,
        )
        return 1
    try:
        ctx.plugins.uninstall(args.name, actor=args.user)
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1
    emit({"uninstalled": True, "plugin_id": args.name}, args.json, args.quiet)
    return 0


def cmd_plugin_check(ctx: KsecContext, args) -> int:
    results = ctx.plugins.check()
    if args.json:
        emit(results, True, False)
        return 0 if all(r["ok"] for r in results) else 1
    if not results:
        print("no plugins found")
        return 0
    bad = 0
    for r in results:
        if r["ok"]:
            print(f"ok   {r['plugin_id']}")
        else:
            bad += 1
            print(f"FAIL {r['plugin_id']}: {'; '.join(r['errors']) or 'unknown error'}")
    print(f"\n{len(results) - bad}/{len(results)} plugins healthy")
    return 0 if bad == 0 else 1