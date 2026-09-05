"""CLI: ``ksec tui`` and ``ksec dashboard start``."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_tui(ctx: KsecContext, args) -> int:
    from ksec.modes import resolve_mode
    from ksec.tui.app import KsecTui

    mode = resolve_mode(args.mode, ctx.config.mode)
    return KsecTui(ctx, mode=mode).run()


def cmd_dashboard_start(ctx: KsecContext, args) -> int:
    from ksec.dashboard.server import DashboardServer

    require_auth = getattr(args, "require_auth", False)
    server = DashboardServer(
        ctx, host=args.host, port=args.port, require_auth=require_auth
    )
    emit(
        {
            "started": True,
            "url": f"http://{args.host}:{server.bound_port()}/",
            "require_auth": require_auth,
        },
        args.json,
        args.quiet,
    )
    if args.background:
        server.start()
        return 0
    server.serve_forever()
    return 0