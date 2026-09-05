"""CLI: ``ksec grc`` — GRC/Compliance (spec 08 #36-37)."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.grc.frameworks import controls, frameworks


def cmd_grc_frameworks(ctx: KsecContext, args) -> int:
    data = [{"framework": f} for f in frameworks()]
    emit(data, args.json, args.quiet)
    return 0


def cmd_grc_controls(ctx: KsecContext, args) -> int:
    items = controls(args.framework)
    data = [
        {
            "framework": c.framework,
            "control_id": c.control_id,
            "title": c.title,
            "checks": list(c.check_ids),
        }
        for c in items
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for c in items:
            print(f"{c.framework} {c.control_id}")
    else:
        for d in data:
            print(f"{d['framework']:<12} {d['control_id']:<12} {d['title']}")
            print(f"    checks: {', '.join(d['checks'])}")
    return 0


def cmd_grc_status(ctx: KsecContext, args) -> int:
    data = ctx.grc.status(args.framework)
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        print(f"passed={data['passed']} failed={data['failed']} not_run={data['not_run']}")
    else:
        print(f"GRC status (framework: {data['framework']}, version {data['grc_version']})")
        print(f"  passed={data['passed']}  failed={data['failed']}  not_run={data['not_run']}\n")
        for c in data["controls"]:
            mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "NOT_RUN": "[----]"}[c["status"]]
            print(f"  {mark} {c['framework']} {c['control_id']} — {c['title']}")
    return 0


def cmd_grc_check(ctx: KsecContext, args) -> int:
    """Run deterministic checks and store the snapshot as evidence + audit."""
    data = ctx.grc.snapshot(target=getattr(args, "target", None), actor="grc")
    if args.json:
        emit(data["payload"], True, False)
    elif args.quiet:
        print(f"evidence_id={data['evidence_id']} checks={len(data['payload']['checks'])}")
    else:
        print(f"GRC snapshot stored (evidence #{data['evidence_id']}, version {data['payload']['grc_version']})")
        for check in data["payload"]["checks"]:
            mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "NOT_APPLICABLE": "[N/A ]",
                    "NOT_RUN": "[----]"}[check["status"]]
            print(f"  {mark} {check['check_id']:<22} {check['detail']}")
    return 0