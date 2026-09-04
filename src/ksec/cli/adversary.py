"""CLI: ``ksec adversary`` — controlled adversary simulation (spec 03#28, 08#12-14).

Surface: profile add/list/show/delete | coverage | exercise new/plan/run |
report. All steps go through the policy engine (authorization + scope).
"""
from __future__ import annotations

import json

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.identity.users import UserRepository

# ATT&CK capability hints used by `profile add` when only a technique is
# given (technique -> default emulation capability).
TECHNIQUE_CAPABILITY = {
    "T1046": "port_scan",      # Network Service Scanning
    "T1595": "port_scan",      # Active Scanning
    "T1590": "dns_lookup",     # Gather Victim Network Information
    "T1005": "http_probe",     # Data from Local System (placeholder probe)
    "T1071": "http_probe",     # Application Layer Protocol
    "T1071.001": "http_probe",
    "T1190": "http_probe",     # Exploit Public-Facing Application
}


def _auth(ctx: KsecContext, args):
    """Authenticate --user; returns user or None (already emitted)."""
    users = UserRepository(ctx.db)
    try:
        return users.authenticate(args.user, args.password)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return None


def _parse_steps(steps_json: str | None, techniques: list[str]) -> list[dict]:
    if steps_json:
        steps = json.loads(steps_json)
        if not isinstance(steps, list):
            raise ValueError("--steps-json must be a JSON list")
        return steps
    steps = []
    for technique in techniques:
        technique = technique.upper()
        steps.append(
            {
                "technique_id": technique,
                "capability": TECHNIQUE_CAPABILITY.get(technique, "dns_lookup"),
            }
        )
    return steps


def cmd_adv_profile_add(ctx: KsecContext, args) -> int:
    try:
        steps = _parse_steps(args.steps_json, args.technique or [])
        profile = ctx.adversary.create_profile(
            args.name,
            description=args.description or "",
            threat_actor=args.threat_actor or "",
            source=args.source or "",
            created_by=args.user,
            steps=steps,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit({"created": True, **profile.to_dict()}, args.json, args.quiet)
    return 0


def cmd_adv_profile_list(ctx: KsecContext, args) -> int:
    profiles = ctx.adversary.list_profiles()
    data = [p.to_dict() for p in profiles]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for p in profiles:
            print(p.name)
    else:
        if not data:
            print("no adversary profiles")
        for p in data:
            print(
                f"{p['id']:>3}  {p['name']:<28} actor={p['threat_actor'] or '-':<20}"
                f" techniques={len(p['techniques'])}"
            )
    return 0


def cmd_adv_profile_show(ctx: KsecContext, args) -> int:
    profile = ctx.adversary.get_profile(args.id)
    if profile is None:
        emit(f"unknown profile: {args.id}", args.json, args.quiet)
        return 1
    emit(profile.to_dict(), args.json, args.quiet)
    return 0


def cmd_adv_profile_delete(ctx: KsecContext, args) -> int:
    profile = ctx.adversary.get_profile(args.id)
    if profile is None:
        emit(f"unknown profile: {args.id}", args.json, args.quiet)
        return 1
    ctx.adversary.delete_profile(args.id)
    emit({"deleted": True, "id": args.id, "name": profile.name}, args.json, args.quiet)
    return 0


def cmd_adv_coverage(ctx: KsecContext, args) -> int:
    coverage = ctx.adversary.coverage(profile_id=args.profile)
    if args.json:
        emit(coverage, True, False)
    elif args.quiet:
        print(coverage["total_techniques"])
    else:
        print(f"ATT&CK coverage ({coverage['scope']}): {coverage['total_techniques']} technique(s)")
        for tactic, techniques in sorted(coverage["by_tactic"].items()):
            print(f"  {tactic:<24} {', '.join(techniques)}")
    return 0


def cmd_adv_exercise_new(ctx: KsecContext, args) -> int:
    user = _auth(ctx, args)
    if user is None:
        return 1
    # Exercises belong to the ADVERSARY_SIMULATION workspace: gate on the
    # authorization record for the engagement if provided.
    try:
        exercise_id = ctx.adversary.create_exercise(
            args.name,
            profile_id=args.profile,
            engagement_id=args.engagement,
            operator_id=user.id,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit({"created": True, "exercise_id": exercise_id}, args.json, args.quiet)
    return 0


def _session_for(ctx: KsecContext, user, args):
    from ksec.sessions.manager import SessionManager

    sessions = SessionManager(ctx.db, ctx.rbac, ctx.audit)
    session = sessions.open(user=user, workspace_name=args.workspace, role_name=args.role)
    return session


def cmd_adv_exercise_run(ctx: KsecContext, args) -> int:
    user = _auth(ctx, args)
    if user is None:
        return 1
    session = _session_for(ctx, user, args)
    try:
        result = ctx.adversary.plan_exercise(
            args.id,
            user=user,
            target=args.target,
            engagement_id=args.engagement,
            policy=ctx.policy,
            dry_run=args.dry_run,
            scheduler=ctx.scheduler if not args.dry_run else None,
            session=session,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(result, args.json, args.quiet)
    return 0 if result["status"] not in ("failed",) else 1


def cmd_adv_chain(ctx: KsecContext, args) -> int:
    """Run an exercise in ATT&CK kill-chain order (phase by phase)."""
    user = _auth(ctx, args)
    if user is None:
        return 1
    session = _session_for(ctx, user, args)
    try:
        result = ctx.adversary.plan_exercise(
            args.id,
            user=user,
            target=args.target,
            engagement_id=args.engagement,
            policy=ctx.policy,
            dry_run=args.dry_run,
            scheduler=ctx.scheduler if not args.dry_run else None,
            session=session,
            chain=True,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    if args.quiet and not args.json:
        for o in result["steps"]:
            print(f"{o['phase']:<18} {o['technique_id'] or '-':<12} {o['policy_decision']:<10} {o['state']}")
        return 0 if result["status"] != "failed" else 1
    emit(result, args.json, args.quiet)
    return 0 if result["status"] not in ("failed",) else 1


def cmd_adv_exercise_list(ctx: KsecContext, args) -> int:
    rows = ctx.adversary.list_exercises()
    data = [dict(r) for r in rows]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in rows:
            print(r["id"])
    else:
        if not data:
            print("no exercises")
        for d in data:
            print(
                f"{d['id']:>3}  {d['name']:<28} profile={d['profile_id'] or '-'}"
                f" status={d['status']:<10} engagement={d['engagement_id'] or '-'}"
            )
    return 0


def cmd_adv_report(ctx: KsecContext, args) -> int:
    try:
        report = ctx.adversary.report(args.id)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(report, args.json, args.quiet)
    return 0