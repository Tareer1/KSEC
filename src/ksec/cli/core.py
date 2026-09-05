"""Core CLI commands: ``init``, ``status``, ``doctor``, ``version``, ``config``."""
from __future__ import annotations

import getpass
import os
import secrets
import sys

from ksec import __version__
from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.config.loader import (
    KsecConfig,
    default_config_path,
    render_config_toml,
)
from ksec.core.errors import ConfigurationError, KSECError
from ksec.db.migrations import MigrationRunner
from ksec.identity.users import UserRepository


def cmd_version(ctx: KsecContext, args) -> int:
    emit({"command": "version", "ksec": __version__, "python": sys.version.split()[0]}, args.json, args.quiet)
    return 0


def cmd_init(ctx: KsecContext, args) -> int:
    """Initialize KSEC: write config, create database, seed roles, create admin."""
    config = ctx.config

    # 1. Write a config file if none exists yet.
    cfg_path = default_config_path()
    if ctx.config.source is None:
        try:
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            if not cfg_path.exists():
                cfg_path.write_text(render_config_toml(config), encoding="utf-8")
                emit(f"wrote config: {cfg_path}", args.json, args.quiet)
        except OSError as exc:
            raise ConfigurationError(f"Cannot write config {cfg_path}: {exc}") from exc

    # 2. Database is created and migrated by bootstrap already.

    # 3. Create the admin user (idempotent).
    users = UserRepository(ctx.db)
    username = (args.username or "admin").strip().lower()
    existing = users.get_by_username(username)
    if existing is not None:
        emit(f"user {username} already exists (id={existing.id})", args.json, args.quiet)
    else:
        password = args.password
        generated = False
        if password is None:
            if sys.stdin.isatty():
                password = getpass.getpass(f"Password for {username}: ")
            else:
                password = secrets.token_urlsafe(18)
                generated = True
        user = users.create(username, password, display_name=args.display_name or "KSEC Administrator")
        ctx.rbac.assign_role(user.id, "admin")
        ctx.audit.record(
            event_type="init.admin_user",
            actor=username,
            action="init.admin_user",
            outcome="success",
        )
        if generated:
            print(f"generated admin password: {password}", file=sys.stderr)
        emit(f"created admin user {username} (id={user.id})", args.json, args.quiet)

    emit("KSEC initialized.", args.json, args.quiet)
    return 0


def cmd_status(ctx: KsecContext, args) -> int:
    config = ctx.config
    from ksec.bootstrap import MIGRATIONS_DIR
    migration_runner = MigrationRunner(ctx.db, MIGRATIONS_DIR)
    data = {
        "version": __version__,
        "config_source": str(config.source) if config.source else "built-in defaults",
        "data_dir": str(config.data_dir),
        "db_path": str(config.db_path),
        "db_version": migration_runner.current_version(),
        "pending_migrations": [f.name for f in migration_runner.pending()],
        "users": len(UserRepository(ctx.db).list()),
        "active_sessions": len(ctx.sessions.list()),
        "audit_events": ctx.audit.count(),
        "safety": {
            "require_authorization": config.require_authorization,
            "safe_mode": config.safe_mode,
            "read_only": config.read_only,
            "lab_mode": config.lab_mode,
        },
    }
    emit(data, args.json, args.quiet)
    return 0


def cmd_doctor(ctx: KsecContext, args) -> int:
    config = ctx.config
    from ksec.bootstrap import MIGRATIONS_DIR
    migration_runner = MigrationRunner(ctx.db, MIGRATIONS_DIR)
    checks: list[dict] = []
    ok = True

    def check(name: str, passed: bool, detail: str) -> None:
        nonlocal ok
        checks.append({"check": name, "status": "PASS" if passed else "WARN", "detail": detail})
        if not passed:
            ok = False

    check("python", sys.version_info >= (3, 11), sys.version.split()[0])
    check("config", True, str(config.source) if config.source else "built-in defaults")
    check("data_dir", config.data_dir.is_dir() and os.access(config.data_dir, os.W_OK), str(config.data_dir))
    pending = [f.name for f in migration_runner.pending()]
    check("migrations", not pending, f"version={migration_runner.current_version()}, pending={len(pending)}")
    check("audit", config.audit_enabled, "audit enabled" if config.audit_enabled else "audit disabled")
    emit(checks, args.json, args.quiet)
    return 0 if ok else 1


def cmd_config(ctx: KsecContext, args) -> int:
    if args.action == "show":
        emit(ctx.config.to_dict(), args.json, args.quiet)
        return 0
    emit({"error": f"unknown config action: {args.action}"}, args.json, args.quiet)
    return 1