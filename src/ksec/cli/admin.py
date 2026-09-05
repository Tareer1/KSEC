"""Admin CLI commands: user creation, role assignment, listing."""
from __future__ import annotations

import getpass
import secrets
import sys

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import AuthorizationError
from ksec.identity.users import UserRepository


def _resolve_user(ctx: KsecContext, username: str):
    users = UserRepository(ctx.db)
    user = users.get_by_username(username.strip().lower())
    if user is None:
        raise AuthorizationError(f"unknown user: {username}")
    return user


def cmd_user_role_add(ctx: KsecContext, args) -> int:
    """Give an existing user an additional role (one person can hold several)."""
    try:
        user = _resolve_user(ctx, args.username)
        if ctx.rbac.role_id(args.role) is None:
            emit(f"unknown role: {args.role}", args.json, args.quiet)
            return 1
        ctx.rbac.assign_role(user.id, args.role)
        ctx.audit.record(
            event_type="admin.user.role_add",
            actor=args.username,
            action="admin.user.role_add",
            target=f"user:{user.username}",
            outcome="success",
            payload={"role": args.role},
        )
    except AuthorizationError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    roles = [r["name"] for r in ctx.rbac.user_roles(user.id)]
    emit(
        {"updated": True, "username": user.username, "added": args.role, "roles": roles},
        args.json,
        args.quiet,
    )
    return 0


def cmd_user_role_remove(ctx: KsecContext, args) -> int:
    """Revoke one role from a user (the last role is kept)."""
    try:
        user = _resolve_user(ctx, args.username)
        removed = ctx.rbac.remove_role(user.id, args.role)
        if not removed:
            emit(
                f"user {user.username} does not have role {args.role}",
                args.json,
                args.quiet,
            )
            return 1
        ctx.audit.record(
            event_type="admin.user.role_remove",
            actor=args.username,
            action="admin.user.role_remove",
            target=f"user:{user.username}",
            outcome="success",
            payload={"role": args.role},
        )
    except AuthorizationError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    roles = [r["name"] for r in ctx.rbac.user_roles(user.id)]
    emit(
        {"updated": True, "username": user.username, "removed": args.role, "roles": roles},
        args.json,
        args.quiet,
    )
    return 0


def cmd_user_roles(ctx: KsecContext, args) -> int:
    """Show every role a user holds (spec: multi-role operators)."""
    try:
        user = _resolve_user(ctx, args.username)
    except AuthorizationError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    roles = [r["name"] for r in ctx.rbac.user_roles(user.id)]
    emit({"username": user.username, "roles": roles}, args.json, args.quiet)
    return 0


def cmd_user_create(ctx: KsecContext, args) -> int:
    users = UserRepository(ctx.db)
    username = (args.username or "").strip().lower()
    if ctx.rbac.role_id(args.role) is None:
        emit(f"unknown role: {args.role}", args.json, args.quiet)
        return 1
    password = args.password
    generated = False
    if password is None:
        if sys.stdin.isatty():
            password = getpass.getpass(f"Password for {username}: ")
        else:
            password = secrets.token_urlsafe(18)
            generated = True
    user = users.create(username, password, display_name=args.display_name or "")
    ctx.rbac.assign_role(user.id, args.role)
    ctx.audit.record(
        event_type="admin.user.create",
        actor=username,
        action="admin.user.create",
        outcome="success",
        payload={"role": args.role},
    )
    if generated:
        print(f"generated password: {password}", file=sys.stderr)
    emit(
        {"created": True, "username": user.username, "id": user.id, "role": args.role},
        args.json,
        args.quiet,
    )
    return 0


def cmd_user_list(ctx: KsecContext, args) -> int:
    users = UserRepository(ctx.db).list()
    data = [
        {
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            "status": u.status,
            "roles": [r["name"] for r in ctx.rbac.user_roles(u.id)],
            "created_at": u.created_at,
        }
        for u in users
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for u in users:
            print(u.username)
    else:
        if not data:
            print("no users")
        for u in data:
            print(f"{u['id']:>3}  {u['username']:<20} {u['display_name']:<24} {u['status']:<9} {','.join(u['roles'])}")
    return 0