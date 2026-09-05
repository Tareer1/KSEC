"""CLI: ``ksec learn ...`` — curriculum and progress."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.learning.curriculum import LEARNING_LEVELS, find_lesson, phases


def _authenticate(ctx: KsecContext, args):
    return UserRepository(ctx.db).authenticate(args.user, args.password)


def cmd_learn_list(ctx: KsecContext, args) -> int:
    data = [
        {
            "phase": phase.number,
            "title": phase.title,
            "description": phase.description,
            "lessons": [lesson.id for lesson in phase.lessons],
        }
        for phase in phases()
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for phase in phases():
            for lesson in phase.lessons:
                print(f"{phase.number}:{lesson.id}")
    else:
        for phase in phases():
            print(f"Phase {phase.number} — {phase.title}")
            for lesson in phase.lessons:
                print(f"    {lesson.id}: {lesson.title}")
    return 0


def cmd_learn_lesson(ctx: KsecContext, args) -> int:
    found = find_lesson(args.id)
    if found is None:
        emit(f"unknown lesson: {args.id}", args.json, args.quiet)
        return 1
    phase, lesson = found
    if args.user:
        user = _authenticate(ctx, args)
        ctx.learning.start_lesson(user.id, lesson.id)
    emit(
        {
            "lesson_id": lesson.id,
            "phase": phase.number,
            "title": lesson.title,
            "summary": lesson.summary,
            "content": lesson.content,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_learn_complete(ctx: KsecContext, args) -> int:
    try:
        user = _authenticate(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    try:
        ctx.learning.complete_lesson(user.id, args.id)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    ctx.notifications.record(
        event_type="learning.lesson_completed",
        title=f"Lesson completed: {args.id}",
        body=f"user {user.username}",
    )
    emit(
        {"completed": True, "lesson_id": args.id, "user": user.username},
        args.json,
        args.quiet,
    )
    return 0


def cmd_learn_progress(ctx: KsecContext, args) -> int:
    try:
        user = _authenticate(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    data = ctx.learning.progress(user.id)
    data["user"] = user.username
    data["levels"] = {str(k): v for k, v in LEARNING_LEVELS.items()}
    emit(data, args.json, args.quiet)
    return 0


def cmd_learn_practice_list(ctx: KsecContext, args) -> int:
    """List hands-on practice drills (with the user's status when --user)."""
    user = None
    if getattr(args, "user", None):
        try:
            user = _authenticate(ctx, args)
        except KSECError as exc:
            emit(exc.message, args.json, args.quiet)
            return 1
    data = ctx.learning.practice_drills(user.id if user else None)
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for drill in data:
            mark = "[x]" if drill["status"] == "passed" else "[ ]"
            print(f"{mark} {drill['drill_id']}")
    else:
        for drill in data:
            mark = {"passed": "[x]", "pending": "[ ]", "in_progress": "[~]"}.get(
                drill["status"], "[ ]"
            )
            print(f"{mark} {drill['drill_id']} — {drill['title']} (phase {drill['phase']})")
            print(f"    {drill['summary']}")
            print(f"    verify: {drill['verify']}")
    return 0


def cmd_learn_practice_start(ctx: KsecContext, args) -> int:
    try:
        user = _authenticate(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    try:
        ctx.learning.practice_start(user.id, args.id)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {"started": True, "drill_id": args.id, "user": user.username},
        args.json,
        args.quiet,
    )
    return 0


def cmd_learn_practice_pass(ctx: KsecContext, args) -> int:
    try:
        user = _authenticate(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    try:
        ctx.learning.practice_pass(user.id, args.id)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    ctx.notifications.record(
        event_type="learning.practice_passed",
        title=f"Practice drill passed: {args.id}",
        body=f"user {user.username}",
    )
    emit(
        {"passed": True, "drill_id": args.id, "user": user.username},
        args.json,
        args.quiet,
    )
    return 0