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


# -- event triggers (spec 07: beyond cron schedules) ------------------------

def cmd_workflow_trigger_add(ctx: KsecContext, args) -> int:
    try:
        trigger = ctx.triggers.create(
            name=args.name,
            event_type=args.event_type,
            workflow=args.workflow,
            event_glob=getattr(args, "event_glob", None) or "*",
            target_field=getattr(args, "target_field", None) or "target",
            workspace=getattr(args, "workspace", None) or "RED_TEAM",
            created_by=getattr(args, "user", None) or "",
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(trigger.to_dict(), args.json, args.quiet)
    return 0


def cmd_workflow_trigger_list(ctx: KsecContext, args) -> int:
    triggers = ctx.triggers.list()
    data = [t.to_dict() for t in triggers]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for t in triggers:
            print(t.id)
    else:
        if not data:
            print("no triggers")
        for t in data:
            flag = "on " if t["enabled"] else "off"
            print(
                f"#{t['id']:<3} [{flag}] {t['event_type']:<14} -> {t['workflow']:<16}"
                f" on {t['target_field']} ~ {t['event_glob']}"
            )
    return 0


def cmd_workflow_trigger_remove(ctx: KsecContext, args) -> int:
    if not ctx.triggers.remove(args.id):
        emit(f"unknown trigger: {args.id}", args.json, args.quiet)
        return 1
    emit({"removed": True, "id": args.id}, args.json, args.quiet)
    return 0


def cmd_workflow_trigger_enable(ctx: KsecContext, args) -> int:
    trigger = ctx.triggers.set_enabled(args.id, True)
    if trigger is None:
        emit(f"unknown trigger: {args.id}", args.json, args.quiet)
        return 1
    emit({"id": trigger.id, "enabled": True}, args.json, args.quiet)
    return 0


def cmd_workflow_trigger_disable(ctx: KsecContext, args) -> int:
    trigger = ctx.triggers.set_enabled(args.id, False)
    if trigger is None:
        emit(f"unknown trigger: {args.id}", args.json, args.quiet)
        return 1
    emit({"id": trigger.id, "enabled": False}, args.json, args.quiet)
    return 0


def cmd_workflow_trigger_fire(ctx: KsecContext, args) -> int:
    """Fire an event: run every enabled trigger whose pattern matches.

    Each matched trigger's workflow is resolved and executed against the
    event's target after normal authorization checks (never bypassed).
    """
    try:
        user = UserRepository(ctx.db).authenticate(args.user, args.password)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    payload: dict = {}
    if getattr(args, "payload", None):
        try:
            parsed = json.loads(args.payload)
        except json.JSONDecodeError as exc:
            emit(f"invalid --payload JSON: {exc}", args.json, args.quiet)
            return 1
        if not isinstance(parsed, dict):
            emit("--payload must be a JSON object", args.json, args.quiet)
            return 1
        payload = parsed
    if getattr(args, "target", None):
        payload.setdefault("target", args.target)
    matched = ctx.triggers.matches(args.event_type, payload)
    if not matched:
        emit({"fired": False, "event_type": args.event_type, "matched": 0},
             args.json, args.quiet)
        return 0
    fired: list[dict] = []
    target = str(payload.get("target") or "")
    for trigger in matched:
        definition = ctx.workflow_store.resolve(trigger.workflow)
        if definition is None:
            fired.append({"trigger": trigger.id, "status": "skipped",
                          "reason": f"unknown workflow {trigger.workflow}"})
            continue
        session = ctx.sessions.open(user, trigger.workspace, role_name=getattr(args, "role", None))
        outcomes = ctx.workflows.plan(
            definition,
            user=user,
            session=session,
            target=target,
            engagement_id=getattr(args, "engagement", None),
        )
        blocked = [o for o in outcomes if o.policy_decision != "ALLOW"]
        if blocked:
            fired.append({"trigger": trigger.id, "status": "blocked",
                          "reason": blocked[0].policy_reason})
            continue
        run = ctx.workflows.run(
            definition,
            user=user,
            session=session,
            target=target,
            engagement_id=getattr(args, "engagement", None),
        )
        ctx.triggers.mark_fired(trigger.id)
        fired.append({"trigger": trigger.id, "status": run.status, "run_id": run.run_id})
    emit({"fired": True, "event_type": args.event_type, "matched": len(matched),
          "runs": fired}, args.json, args.quiet)
    return 0