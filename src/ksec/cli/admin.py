"""Admin CLI commands: user creation and listing."""
from __future__ import annotations

import getpass
import secrets
import sys

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.identity.users import UserRepository


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