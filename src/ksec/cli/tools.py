"""CLI: ``ksec tools list|info|search|docs|capabilities|health|update|remove``
— capability discovery (spec 03)."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def _tool_dict(t) -> dict:
    return {
        "name": t.name,
        "capability": t.capability,
        "package": t.package,
        "category": t.category,
        "binary": t.binary_path,
        "version": t.version,
        "ready": t.ready,
    }


def cmd_tools_list(ctx: KsecContext, args) -> int:
    discovered = ctx.capabilities.discover()
    category = getattr(args, "category", None)
    installed = getattr(args, "installed", False)
    missing = getattr(args, "missing", False)
    broken = getattr(args, "broken", False)
    selected = discovered
    if category:
        selected = [t for t in selected if t.category.lower() == category.lower()]
    if installed:
        selected = [t for t in selected if t.ready]
    if missing:
        selected = [t for t in selected if not t.ready]
    if broken:
        # Installed binary that failed version probing (or a stale registry row).
        selected = [t for t in selected if t.ready and not t.version]
    data = [_tool_dict(t) for t in selected]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for t in selected:
            print(t.name)
    else:
        for t in data:
            mark = "ok " if t["ready"] else "-- "
            print(f"{mark} {t['name']:<12} {t['capability']:<20} {t['version'] or '(not installed)'}")
        ready = sum(1 for t in data if t["ready"])
        print(f"\n{ready}/{len(data)} tools ready")
    return 0


def cmd_tools_search(ctx: KsecContext, args) -> int:
    """Search tools by name, capability or category (spec 03)."""
    query = (args.query or "").strip().lower()
    discovered = ctx.capabilities.discover()
    selected = [
        t
        for t in discovered
        if not query
        or query in t.name.lower()
        or query in t.capability.lower()
        or query in t.category.lower()
    ]
    data = [_tool_dict(t) for t in selected]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for t in selected:
            print(t.name)
    else:
        if not data:
            print(f"no tools match {args.query!r}")
        for t in data:
            mark = "ok " if t["ready"] else "-- "
            print(f"{mark} {t['name']:<12} {t['capability']:<20} [{t['category']}] {t['version'] or '(not installed)'}")
    return 0


def cmd_tools_docs(ctx: KsecContext, args) -> int:
    """Show the full mode-aware documentation for a tool (spec 03)."""
    return cmd_tools_explain(ctx, args)


def cmd_tools_capabilities(ctx: KsecContext, args) -> int:
    """List every capability with its ready/missing state (spec 03)."""
    discovered = ctx.capabilities.discover()
    by_cap: dict[str, dict] = {}
    for t in discovered:
        entry = by_cap.setdefault(
            t.capability, {"capability": t.capability, "tools": [], "ready": False}
        )
        entry["tools"].append(t.name)
        if t.ready:
            entry["ready"] = True
    data = sorted(by_cap.values(), key=lambda c: c["capability"])
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for c in data:
            print(c["capability"])
    else:
        if not data:
            print("no capabilities")
        for c in data:
            mark = "ok " if c["ready"] else "-- "
            print(f"{mark} {c['capability']:<24} {', '.join(c['tools'])}")
    return 0


def cmd_tools_update(ctx: KsecContext, args) -> int:
    """Re-discover installed tools and refresh the persisted registry."""
    discovered = ctx.capabilities.discover(persist=True)
    ready = sum(1 for t in discovered if t.ready)
    emit(
        {
            "refreshed": True,
            "total": len(discovered),
            "ready": ready,
            "checked_at": discovered[0].version if discovered else "",
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_tools_remove(ctx: KsecContext, args) -> int:
    """Remove a tool from the persisted registry (does not uninstall the binary)."""
    name = args.tool
    removed = ctx.capabilities.remove_from_registry(name)
    if not removed:
        emit(f"tool {name!r} not found in registry", args.json, args.quiet)
        return 1
    emit({"removed": True, "tool": name}, args.json, args.quiet)
    return 0


def cmd_tools_info(ctx: KsecContext, args) -> int:
    name = args.tool
    discovered = {t.name: t for t in ctx.capabilities.discover()}
    tool = discovered.get(name)
    if tool is None:
        emit(f"unknown tool: {name}", args.json, args.quiet)
        return 1
    data = {
        "name": tool.name,
        "package": tool.package,
        "category": tool.category,
        "capability": tool.capability,
        "description": tool.description,
        "binary": tool.binary_path,
        "version": tool.version,
        "ready": tool.ready,
    }
    emit(data, args.json, args.quiet)
    return 0


def cmd_tools_explain(ctx: KsecContext, args) -> int:
    """Explain a tool with mode-aware depth (spec: TOOL EXPLANATION SYSTEM)."""
    from ksec.modes import resolve_mode

    mode = resolve_mode(args.mode, ctx.config.mode)
    explanation = ctx.explain.explain_tool(args.tool)
    if explanation is None:
        emit(f"no explanation available for tool {args.tool!r}", args.json, args.quiet)
        return 1
    if mode.is_beginner():
        data = {"tool": args.tool, "explanation": explanation.beginner}
    elif mode.is_expert():
        data = {
            "tool": args.tool,
            "beginner": explanation.beginner,
            "technical": explanation.technical,
            "why_selected": explanation.why_selected,
            "data_collected": explanation.data_collected,
            "risk": explanation.risk,
            "privilege": explanation.privilege,
            "inputs": explanation.inputs,
            "outputs": explanation.outputs,
            "learn_more": explanation.learn_more,
        }
    else:
        data = {
            "tool": args.tool,
            "technical": explanation.technical,
            "why_selected": explanation.why_selected,
            "data_collected": explanation.data_collected,
            "risk": explanation.risk,
            "learn_more": explanation.learn_more,
        }
    emit(data, args.json, args.quiet)
    return 0


def cmd_tools_health(ctx: KsecContext, args) -> int:
    discovered = ctx.capabilities.discover()
    missing = ctx.capabilities.missing_capabilities()
    data = {
        "tools": [
            {"tool": t.name, "ready": t.ready, "binary": t.binary_path, "version": t.version}
            for t in discovered
        ],
        "ready_count": sum(1 for t in discovered if t.ready),
        "total": len(discovered),
        "missing_capabilities": missing,
    }
    emit(data, args.json, args.quiet)
    return 0