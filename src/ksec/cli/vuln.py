"""CLI: ``ksec vuln`` — authorized, deterministic vulnerability checks.

Checks are read-only probes (TLS version, HTTP security headers,
dev-server banners) that only ever run against engagement-authorized
targets; each positive outcome is recorded as a finding.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.vuln import checks as checklib


def cmd_vuln_checks(ctx: KsecContext, args) -> int:
    data = list(checklib.CHECKS)
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for c in data:
            print(c["id"])
    else:
        for c in data:
            print(f"{c['id']:<26} {c['severity_base']:<7} {c['name']}")
            print(f"      {c['description']}")
    return 0


def cmd_vuln_check(ctx: KsecContext, args) -> int:
    try:
        user = UserRepository(ctx.db).authenticate(args.user, args.password)
        report = ctx.vuln.run(
            target=args.target,
            user=user,
            engagement_id=args.engagement,
            port=args.port,
        )
    except KSECError as exc:
        emit({"error": exc.message}, args.json, args.quiet)
        return 1

    data = {
        "target": report.target,
        "url": report.url,
        "checks_run": report.checks_run,
        "findings_created": report.findings_created,
        "findings_existing": report.findings_existing,
        "outcomes": report.outcomes,
    }
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for o in report.outcomes:
            print(f"{o['severity']:<8} {o['title']}")
    else:
        if not report.outcomes:
            print(f"no issues found on {report.url}")
        for o in report.outcomes:
            print(f"[{o['severity'].upper():<8}] {o['title']}")
            print(f"      {o['description']}")
        if report.findings_created:
            print(f"\n{len(report.findings_created)} finding(s) created: "
                  f"{', '.join(str(i) for i in report.findings_created)}")
        if report.findings_existing:
            print(f"{report.findings_existing} finding(s) already existed (skipped)")
    return 0
