"""CLI: ``ksec session ...`` — session lifecycle."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.identity.users import UserRepository


def _authenticate(ctx: KsecContext, args):
    return UserRepository(ctx.db).authenticate(args.user, args.password)


def _session_dict(session) -> dict:
    return {
        "id": session.id,
        "user": session.username,
        "workspace": session.workspace,
        "role": session.role,
        "state": session.state,
        "created_at": session.created_at,
        "closed_at": session.closed_at,
    }


def cmd_session_open(ctx: KsecContext, args) -> int:
    user = _authenticate(ctx, args)
    session = ctx.sessions.open(user, args.workspace, role_name=args.role)
    emit(_session_dict(session), args.json, args.quiet)
    return 0


def cmd_session_list(ctx: KsecContext, args) -> int:
    sessions = ctx.sessions.list()
    data = [_session_dict(s) for s in sessions]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for s in sessions:
            print(s.id)
    else:
        if not data:
            print("no sessions")
        for s in data:
            print(f"{s['id'][:12]:<12} {s['user']:<16} {s['workspace']:<20} {s['role']:<10} {s['state']}")
    return 0


def cmd_session_status(ctx: KsecContext, args) -> int:
    session = ctx.sessions.get(args.id)
    if session is None:
        emit(f"unknown session: {args.id}", args.json, args.quiet)
        return 1
    emit(_session_dict(session), args.json, args.quiet)
    return 0


def cmd_session_close(ctx: KsecContext, args) -> int:
    session = ctx.sessions.close(args.id)
    emit(_session_dict(session), args.json, args.quiet)
    return 0


def cmd_session_pause(ctx: KsecContext, args) -> int:
    session = ctx.sessions.pause(args.id)
    emit(_session_dict(session), args.json, args.quiet)
    return 0


def cmd_session_resume(ctx: KsecContext, args) -> int:
    session = ctx.sessions.resume(args.id)
    emit(_session_dict(session), args.json, args.quiet)
    return 0


def cmd_session_switch(ctx: KsecContext, args) -> int:
    try:
        user = _authenticate(ctx, args)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    try:
        session = ctx.sessions.switch(user, args.id)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(_session_dict(session), args.json, args.quiet)
    return 0


def cmd_session_reconnect(ctx: KsecContext, args) -> int:
    try:
        user = _authenticate(ctx, args)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    try:
        session = ctx.sessions.reconnect(user, args.id)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(_session_dict(session), args.json, args.quiet)
    return 0