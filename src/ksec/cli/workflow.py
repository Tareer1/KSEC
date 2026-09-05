"""CLI: ``ksec workflow create|list|edit|validate|run|history`` (spec: AUTOMATION)."""
from __future__ import annotations

import json

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.workflows.definitions import list_workflows


def _steps_from_args(args) -> list[dict]:
    """Build the steps list from ``--step`` repeats and/or ``--steps-json``."""
    if args.steps_json is not None:
        if getattr(args, "step", None):
            raise KSECError("use either --step repeats or --steps-json, not both")
        try:
            steps = json.loads(args.steps_json)
        except json.JSONDecodeError as exc:
            raise KSECError(f"invalid --steps-json: {exc}") from exc
        if not isinstance(steps, list):
            raise KSECError("--steps-json must be a JSON list of step objects")
        return steps
    steps = []
    for capability in getattr(args, "step", None) or []:
        steps.append({"capability": capability})
    return steps


def _step_summary(workflow) -> str:
    parts = []
    for step in workflow.steps:
        opts = step.get("options", {})
        suffix = f" ({', '.join(f'{k}={v}' for k, v in opts.items())})" if opts else ""
        parts.append(step["capability"] + suffix)
    return " -> ".join(parts)


def cmd_workflow_list(ctx: KsecContext, args) -> int:
    data = []
    for workflow in list_workflows():
        data.append(
            {
                "name": workflow.name,
                "description": workflow.description,
                "source": "builtin",
                "steps": [s.capability for s in workflow.steps],
            }
        )
    for workflow in ctx.workflow_store.list():
        data.append(
            {
                "name": workflow.name,
                "description": workflow.description,
                "source": "custom",
                "enabled": workflow.enabled,
                "version": workflow.version,
                "steps": [s["capability"] for s in workflow.steps],
            }
        )
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for d in data:
            print(d["name"])
    else:
        if not data:
            print("no workflows")
        for d in data:
            mark = "ok " if d.get("enabled", True) else "-- "
            version = f" v{d['version']}" if "version" in d else ""
            print(f"{mark} {d['name']:<24} [{d['source']:<7}]{version:<5} {d['description']}")
    return 0


def cmd_workflow_create(ctx: KsecContext, args) -> int:
    steps = _steps_from_args(args)
    workflow = ctx.workflow_store.create(
        args.name,
        steps,
        description=args.description or "",
        created_by=args.user or "",
    )
    emit(
        {
            "created": True,
            "id": workflow.id,
            "name": workflow.name,
            "steps": [s["capability"] for s in workflow.steps],
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_workflow_edit(ctx: KsecContext, args) -> int:
    workflow = ctx.workflow_store.get_by_name(args.name)
    if workflow is None:
        emit(f"unknown workflow: {args.name}", args.json, args.quiet)
        return 1
    kwargs = {}
    steps = _steps_from_args(args)
    if steps:
        kwargs["steps"] = steps
    if args.description is not None:
        kwargs["description"] = args.description
    if args.disable:
        kwargs["enabled"] = False
    if args.enable:
        kwargs["enabled"] = True
    try:
        updated = ctx.workflow_store.update(args.name, **kwargs)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    emit(
        {
            "updated": True,
            "id": updated.id,
            "name": updated.name,
            "enabled": updated.enabled,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_workflow_validate(ctx: KsecContext, args) -> int:
    workflow = ctx.workflow_store.get_by_name(args.name)
    if workflow is None:
        emit(f"unknown workflow: {args.name}", args.json, args.quiet)
        return 1
    errors = ctx.workflow_store.validate_steps(workflow.steps)
    if errors:
        emit(
            {"name": workflow.name, "valid": False, "errors": errors},
            args.json,
            args.quiet,
        )
        return 1
    emit(
        {
            "name": workflow.name,
            "valid": True,
            "steps": [s["capability"] for s in workflow.steps],
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_workflow_run(ctx: KsecContext, args) -> int:
    definition = ctx.workflow_store.resolve(args.name)
    if definition is None:
        emit(f"unknown workflow: {args.name}", args.json, args.quiet)
        return 1
    try:
        user = UserRepository(ctx.db).authenticate(args.user, args.password)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    session = ctx.sessions.open(user, args.workspace, role_name=args.role)

    if args.dry_run:
        outcomes = ctx.workflows.plan(
            definition,
            user=user,
            session=session,
            target=args.target,
            engagement_id=args.engagement,
        )
        data = {
            "workflow": definition.name,
            "target": args.target,
            "mode": "dry-run",
            "steps": [
                {"capability": o.capability, "policy": o.policy_decision, "reason": o.policy_reason}
                for o in outcomes
            ],
            "blocked": any(o.policy_decision != "ALLOW" for o in outcomes),
        }
        emit(data, args.json, args.quiet)
        return 1 if data["blocked"] else 0

    run = ctx.workflows.run(
        definition,
        user=user,
        session=session,
        target=args.target,
        engagement_id=args.engagement,
    )
    data = {
        "run_id": run.run_id,
        "workflow": run.workflow,
        "target": run.target,
        "status": run.status,
        "error": run.error,
        "steps": [
            {
                "capability": o.capability,
                "policy": o.policy_decision,
                "state": o.state,
                "job_id": o.job_id,
                "entities": o.entities,
                "error": o.error,
            }
            for o in run.steps
        ],
    }
    emit(data, args.json, args.quiet)
    return 0 if run.status == "completed" else 1


def cmd_workflow_history(ctx: KsecContext, args) -> int:
    rows = ctx.workflows.runs(workflow=args.name or None, limit=args.limit)
    data = [
        {
            "run_id": r["id"],
            "workflow": r["workflow"],
            "target": r["target"],
            "status": r["status"],
            "version": r["definition_version"],
            "snapshot": json.loads(r["definition_snapshot"] or "{}"),
            "steps": f"{r['steps_completed']}/{r['steps_total']}",
            "created_at": r["created_at"],
            "error": r["error"],
        }
        for r in rows
    ]
    if args.json:
        emit(data, True, False)
        return 0
    elif args.quiet:
        for d in data:
            print(d["run_id"])
    else:
        if not data:
            print("no workflow runs")
        for d in data:
            print(
                f"{d['run_id'][:12]:<12} {d['workflow']:<16} {d['target']:<20}"
                f" {d['status']:<10} v{d['version']} steps={d['steps']}"
            )
    return 0
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for d in data:
            print(d["run_id"])
    else:
        if not data:
            print("no workflow runs")
        for d in data:
            print(
                f"{d['run_id'][:12]:<12} {d['workflow']:<16} {d['target']:<20}"
                f" {d['status']:<10} steps={d['steps']}"
            )
    return 0