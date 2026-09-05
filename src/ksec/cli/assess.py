"""CLI: ``ksec assess TARGET`` — policy-gated workflow execution.

Runs the spec's core example: an end-to-end authorized assessment where the
user interacts with KSEC, not with dozens of separate tools.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.workflows.definitions import list_workflows


def _mode(ctx: KsecContext, args):
    from ksec.modes import resolve_mode

    return resolve_mode(args.mode, ctx.config.mode)


def _step_explanations(ctx: KsecContext, definition, target: str, mode):
    """Mode-aware per-step explanations (spec: TOOL EXPLANATION SYSTEM)."""
    explanations = []
    for step in definition.steps:
        explanation = ctx.explain.explain_capability(step.capability, mode)
        if mode.is_expert():
            # Expert mode additionally shows the exact command that would run.
            adapter = ctx.adapters.get(
                step.capability, tool=step.options.get("tool") if step.options else None
            )
            command = None
            if adapter is not None:
                from ksec.adapters.base import CommandRequest

                try:
                    command = adapter.build_command(
                        CommandRequest(
                            capability=step.capability,
                            target=target,
                            options=step.options,
                        )
                    )
                except Exception:
                    command = None
            explanation["command"] = command
        explanations.append(explanation)
    return explanations


def _beginner_summary(run, target: str) -> dict:
    if run.status == "completed":
        happened = f"KSEC finished the {run.workflow} workflow against {target} successfully."
        matters = "The findings and evidence are ready to review."
    else:
        happened = f"KSEC could not complete the {run.workflow} workflow against {target}."
        matters = run.error or "One or more steps were blocked or failed."
    return {
        "what_happened": happened,
        "why_it_matters": matters,
        "what_should_happen_next": [
            "Review findings: ksec finding list",
            "Generate a report: ksec report create --engagement <ID>",
        ],
    }


def cmd_assess(ctx: KsecContext, args) -> int:
    definition = ctx.workflow_store.resolve(args.workflow)
    if definition is None:
        builtin_names = [w.name for w in list_workflows()]
        custom_names = [w.name for w in ctx.workflow_store.list()]
        emit(
            f"unknown workflow {args.workflow!r}; available: {', '.join(builtin_names + custom_names)}",
            args.json,
            args.quiet,
        )
        return 1

    try:
        user = UserRepository(ctx.db).authenticate(args.user, args.password)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1

    session = ctx.sessions.open(user, args.workspace, role_name=args.role)

    mode = _mode(ctx, args)

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
            "operation_mode": mode.value,
            "steps": [
                {
                    "capability": o.capability,
                    "policy": o.policy_decision,
                    "reason": o.policy_reason,
                }
                for o in outcomes
            ],
            "blocked": any(o.policy_decision != "ALLOW" for o in outcomes),
        }
        if args.explain or mode.is_beginner():
            data["explanations"] = _step_explanations(ctx, definition, args.target, mode)
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
        "operation_mode": mode.value,
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
    if args.explain or mode.is_beginner():
        data["explanations"] = _step_explanations(ctx, definition, args.target, mode)
    if mode.is_beginner():
        data["summary"] = _beginner_summary(run, args.target)
    emit(data, args.json, args.quiet)
    return 0 if run.status == "completed" else 1