"""CLI: ``ksec api ...`` — REST API tokens + server.

Token management authenticates the acting user (like the audit CLI).
Each token belongs to its creator and can only be revoked by that user.
``ksec api serve`` runs the stdlib JSON API server on a local port.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository


def _require_user(ctx: KsecContext, args):
    if not (args.user and args.password):
        raise KSECError("--user and --password are required for token management")
    return UserRepository(ctx.db).authenticate(args.user, args.password)


def cmd_api_token_create(ctx: KsecContext, args) -> int:
    try:
        user = _require_user(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    token, record = ctx.api_tokens.create(user_id=user.id, name=args.name or "")
    if args.json:
        emit({**record.to_dict(), "token": token}, True, False)
    elif args.quiet:
        print(token)
    else:
        print(f"token created for {user.username}:")
        print(token)
        print("\nStore it somewhere safe — it is shown only once.")
    return 0


def cmd_api_token_list(ctx: KsecContext, args) -> int:
    try:
        user = _require_user(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    records = ctx.api_tokens.list(user_id=user.id)
    data = [r.to_dict() for r in records]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for r in records:
            print(r.id)
    else:
        if not data:
            print("no tokens")
        for r in data:
            flag = "active" if not r["revoked"] else "revoked"
            print(f"{r['id']:>3}  {flag:<8} {r['name']:<20} last_used={r['last_used_at'] or '-'}")
    return 0


def cmd_api_token_revoke(ctx: KsecContext, args) -> int:
    try:
        user = _require_user(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    revoked = ctx.api_tokens.revoke(args.id, user_id=user.id)
    if not revoked:
        emit(f"unknown token: {args.id}", args.json, args.quiet)
        return 1
    emit({"revoked": True, "id": args.id}, args.json, args.quiet)
    return 0


def cmd_api_serve(ctx: KsecContext, args) -> int:
    from ksec.api.server import ApiServer

    server = ApiServer(ctx, host=args.host, port=args.port)
    print(f"KSEC API listening on http://{args.host}:{server.bound_port()}/  (Bearer auth)")
    if args.background:
        server.start()
        print(f"background thread started on port {server.bound_port()}")
        return 0
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0
