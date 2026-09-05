"""CLI: ``ksec report create|list|show|preview|export``."""
from __future__ import annotations

from pathlib import Path

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_report_create(ctx: KsecContext, args) -> int:
    report = ctx.reports.generate(
        args.engagement,
        title=args.title or "",
        fmt=args.format,
        created_by=args.user or "",
    )
    if args.out:
        path = Path(args.out)
        if args.format == "pdf":
            path.write_bytes(ctx.reports.to_pdf(report))
        else:
            path.write_text(report.content, encoding="utf-8")
        emit(
            {"created": True, "id": report.id, "format": report.format, "path": str(path)},
            args.json,
            args.quiet,
        )
        return 0
    emit(
        {
            "created": True,
            "id": report.id,
            "title": report.title,
            "format": report.format,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_report_preview(ctx: KsecContext, args) -> int:
    """Render a report without persisting it (spec: report preview)."""
    try:
        rendered = ctx.reports.render(
            getattr(args, "engagement", None),
            title=args.title or "",
            fmt=args.format,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    if args.json:
        emit(
            {
                "title": rendered["title"],
                "format": rendered["format"],
                "engagement_id": rendered["engagement_id"],
                "counts": rendered["counts"],
                "preview": rendered["content"][:2000],
            },
            True,
            False,
        )
    elif args.quiet:
        print(f"assets={rendered['counts']['assets']} findings={rendered['counts']['findings']}")
    else:
        print(rendered["content"][:4000])
    return 0


def cmd_report_export(ctx: KsecContext, args) -> int:
    """Export a stored report as PDF bytes to a file (spec: PDF export)."""
    report = ctx.reports.get(args.id)
    if report is None:
        emit(f"unknown report: {args.id}", args.json, args.quiet)
        return 1
    path = Path(args.out or f"report-{args.id}.pdf")
    path.write_bytes(ctx.reports.to_pdf(report))
    emit(
        {
            "exported": True,
            "id": report.id,
            "format": "pdf",
            "path": str(path),
            "bytes": path.stat().st_size,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_report_list(ctx: KsecContext, args) -> int:
    reports = ctx.reports.list()
    data = [
        {
            "id": r.id,
            "title": r.title,
            "format": r.format,
            "engagement_id": r.engagement_id,
            "created_at": r.created_at,
        }
        for r in reports
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in reports:
            print(r.id)
    else:
        if not data:
            print("no reports")
        for d in data:
            print(f"{d['id']:>3}  {d['format']:<10} {d['title']}")
    return 0


def cmd_report_show(ctx: KsecContext, args) -> int:
    report = ctx.reports.get(args.id)
    if report is None:
        emit(f"unknown report: {args.id}", args.json, args.quiet)
        return 1
    if args.raw:
        print(report.content)
    else:
        emit(
            {
                "id": report.id,
                "title": report.title,
                "format": report.format,
                "engagement_id": report.engagement_id,
                "created_at": report.created_at,
                "content": report.content[:2000],
            },
            args.json,
            args.quiet,
        )
    return 0
