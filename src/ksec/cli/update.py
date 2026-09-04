"""CLI: ``ksec update check`` — offline update-readiness (spec 01#36-37)."""

from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_update_check(ctx: KsecContext, args) -> int:
    report = ctx.updates.check()
    if args.json:
        emit(report, True, False)
        return 0 if report["ok"] else 1
    print(f"ksec {report['ksec_version']} — offline update check")
    for check in report["checks"]:
        mark = "ok  " if check["ok"] else "FAIL"
        print(f"{mark} {check['name']:<10} {check['detail']}")
    if args.quiet:
        return 0 if report["ok"] else 1
    print(f"\n{report['summary']}")
    if not report["ok"]:
        print("resolve the failures above, then create a fresh backup before updating.")
    return 0 if report["ok"] else 1