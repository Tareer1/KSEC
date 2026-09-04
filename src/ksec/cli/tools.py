"""CLI: ``ksec tools list|info|health`` — capability discovery."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_tools_list(ctx: KsecContext, args) -> int:
    discovered = ctx.capabilities.discover()
    data = [
        {
            "name": t.name,
            "capability": t.capability,
            "package": t.package,
            "category": t.category,
            "binary": t.binary_path,
            "version": t.version,
            "ready": t.ready,
        }
        for t in discovered
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for t in discovered:
            print(t.name)
    else:
        for t in data:
            mark = "ok " if t["ready"] else "-- "
            print(f"{mark} {t['name']:<12} {t['capability']:<20} {t['version'] or '(not installed)'}")
        ready = sum(1 for t in data if t["ready"])
        print(f"\n{ready}/{len(data)} tools ready")
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