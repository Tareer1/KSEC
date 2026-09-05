"""CLI: ``ksec history`` (activity timeline) and ``ksec graph`` (relationships).

Both are read-only views over the shared database — no execution happens.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_history(ctx: KsecContext, args) -> int:
    """Chronological activity timeline across sessions, jobs and audit events."""
    limit = getattr(args, "limit", 30) or 30
    events: list[dict] = []

    # Latest workflow runs (they carry the "what ran" semantics).
    try:
        rows = ctx.db.query_all(
            "SELECT id, workflow, target, status, created_at, completed_at"
            " FROM workflow_runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        for row in rows:
            events.append(
                {
                    "when": row["created_at"],
                    "kind": "workflow",
                    "what": row["workflow"],
                    "target": row["target"] or "",
                    "detail": f"status={row['status']}",
                }
            )
    except Exception:  # pragma: no cover - pre-migration safety
        pass

    # Latest audit events (security-relevant actions).
    try:
        for row in ctx.audit.list(limit=limit):
            events.append(
                {
                    "when": row["created_at"],
                    "kind": "audit",
                    "what": row["event_type"],
                    "target": row["target"] or "",
                    "detail": f"actor={row['actor'] or '-'} action={row['action'] or '-'}",
                }
            )
    except Exception:  # pragma: no cover
        pass

    # Jobs as activity entries.
    try:
        for job in ctx.jobs.list(limit=limit):
            events.append(
                {
                    "when": job.created_at,
                    "kind": "job",
                    "what": job.capability,
                    "target": job.target or "",
                    "detail": f"state={job.state} workflow={job.workflow or '-'}",
                }
            )
    except Exception:  # pragma: no cover
        pass

    events.sort(key=lambda e: e["when"], reverse=True)
    events = events[:limit]
    if args.json:
        emit(events, True, False)
    elif args.quiet:
        for e in events:
            print(f"{e['when']} {e['kind']} {e['what']}")
    else:
        if not events:
            print("no activity recorded yet")
        for e in events:
            print(f"{e['when']}  {e['kind']:<9} {e['what']:<16} {e['target']}  {e['detail']}")
    return 0


def cmd_graph(ctx: KsecContext, args) -> int:
    """Relationship graph: engagements -> assets -> findings -> evidence/cases.

    Nodes are printed as ``TYPE[id] label`` and edges show how records link.
    """
    engagement_id = getattr(args, "engagement", None)
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def add_node(kind: str, node_id: int, label: str) -> None:
        key = (kind, node_id)
        if key not in seen:
            seen.add(key)
            nodes.append({"id": f"{kind}[{node_id}]", "kind": kind, "label": label})

    def edge(a: str, b: str, via: str = "") -> None:
        edges.append({"from": a, "to": b, "via": via})

    # Engagements -> assets -> findings -> evidence + cases.
    engagements = ctx.db.query_all(
        "SELECT id, name FROM engagements ORDER BY id"
    )
    for eng in engagements:
        if engagement_id is not None and eng["id"] != engagement_id:
            continue
        add_node("engagement", eng["id"], eng["name"])
        assets = ctx.db.query_all(
            "SELECT id, target FROM assets WHERE engagement_id = ? ORDER BY id",
            (eng["id"],),
        )
        for asset in assets:
            add_node("asset", asset["id"], asset["target"])
            edge(f"engagement[{eng['id']}]", f"asset[{asset['id']}]", "scope")
            findings = ctx.db.query_all(
                "SELECT id, title FROM findings WHERE asset_id = ? ORDER BY id",
                (asset["id"],),
            )
            for finding in findings:
                add_node("finding", finding["id"], finding["title"])
                edge(f"asset[{asset['id']}]", f"finding[{finding['id']}]", "found_on")
        findings = ctx.db.query_all(
            "SELECT id, title FROM findings WHERE engagement_id = ? AND asset_id IS NULL"
            " ORDER BY id",
            (eng["id"],),
        )
        for finding in findings:
            add_node("finding", finding["id"], finding["title"])
            edge(f"engagement[{eng['id']}]", f"finding[{finding['id']}]", "reported")
        cases = ctx.db.query_all(
            "SELECT id, title FROM cases WHERE engagement_id = ? ORDER BY id", (eng["id"],)
        )
        for case in cases:
            add_node("case", case["id"], case["title"])
            edge(f"engagement[{eng['id']}]", f"case[{case['id']}]", "opened")

    evidence = ctx.db.query_all(
        "SELECT id, tool, engagement_id FROM evidence ORDER BY id"
    )
    for item in evidence:
        add_node("evidence", item["id"], f"{item['tool']} evidence")
        if item["engagement_id"]:
            edge(f"engagement[{item['engagement_id']}]", f"evidence[{item['id']}]", "collected")

    if not nodes:
        emit({"nodes": [], "edges": []}, args.json, args.quiet)
        if not args.json and not args.quiet:
            print("graph is empty — create an engagement, assets and findings first")
        return 0

    if args.json:
        emit({"nodes": nodes, "edges": edges}, True, False)
    elif args.quiet:
        for e in edges:
            print(f"{e['from']} -> {e['to']}")
    else:
        for n in nodes:
            print(f"  {n['id']}  {n['label']}")
        if edges:
            print("edges:")
            for e in edges:
                via = f" [{e['via']}]" if e["via"] else ""
                print(f"  {e['from']} -> {e['to']}{via}")
    return 0
