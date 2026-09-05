"""CLI: ``ksec mode`` — operation modes (beginner/professional/expert) and
safety modes (lab/CTF, safe, read-only).

Safety modes are persisted in the config file's ``[safety]`` table so a
process restart keeps them active. ``ksec mode status`` shows the effective
state; ``ksec mode set <lab|safe|read-only> on|off`` toggles one flag.
"""
from __future__ import annotations

import re
from pathlib import Path

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.config.loader import default_config_path
from ksec.modes import MODE_NAMES

_SAFETY_KEYS = {
    "lab": "lab_mode",
    "safe": "safe_mode",
    "read-only": "read_only",
}


def _config_path(ctx: KsecContext) -> Path:
    if ctx.config.source:
        return ctx.config.source
    return default_config_path()


def _read_config_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []


def _toggle_config(path: Path, key: str, value: bool) -> None:
    """Set ``[safety] <key> = true|false`` in a TOML config file, creating
    the file (and section) if needed. Other keys are preserved verbatim and
    an existing [safety] section is extended in place (no duplicate tables)."""
    lines = _read_config_lines(path)
    target = "true" if value else "false"
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    # Locate the [safety] table span (start..end line indexes).
    safety_start = None
    safety_end = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if safety_start is not None:
                safety_end = i
                break
            if stripped == "[safety]":
                safety_start = i
    if safety_start is not None and safety_end is None:
        safety_end = len(lines)
    out: list[str] = []
    found = False
    for i, line in enumerate(lines):
        if safety_start is not None and safety_start <= i < safety_end and key_re.match(line):
            out.append(re.sub(r"=.*", f"= {target}", line))
            found = True
        else:
            out.append(line)
    if not found:
        if safety_start is not None:
            # Insert just before the next table (or at the end of the file).
            out.insert(safety_end, f"{key} = {target}")
        else:
            if out and out[-1].strip() != "":
                out.append("")
            out.append("[safety]")
            out.append(f"{key} = {target}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def cmd_mode_status(ctx: KsecContext, args) -> int:
    config = ctx.config
    data = {
        "mode": config.mode,
        "modes": list(MODE_NAMES),
        "safety": {
            "lab_mode": config.lab_mode,
            "safe_mode": config.safe_mode,
            "read_only": config.read_only,
        },
        "config_source": str(config.source) if config.source else "built-in defaults",
    }
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        print(config.mode)
    else:
        print(f"operation mode : {config.mode}  (--mode beginner|professional|expert)")
        print(f"lab_mode       : {'ON ' if config.lab_mode else 'off'}  (targets restricted to lab ranges)")
        print(f"safe_mode      : {'ON ' if config.safe_mode else 'off'}  (confirmation required for tool install)")
        print(f"read_only      : {'ON ' if config.read_only else 'off'}  (no mutating actions)")
        print(f"config         : {data['config_source']}")
        print("toggle with: ksec mode set lab|safe|read-only on|off")
    return 0


def cmd_mode_set(ctx: KsecContext, args) -> int:
    key = _SAFETY_KEYS.get(args.name)
    if key is None:
        emit(
            f"unknown safety mode {args.name!r} (choose lab | safe | read-only)",
            args.json,
            args.quiet,
        )
        return 1
    value = args.state == "on"
    path = _config_path(ctx)
    try:
        _toggle_config(path, key, value)
    except OSError as exc:
        emit(f"cannot write config {path}: {exc}", args.json, args.quiet)
        return 1
    if ctx.audit:
        ctx.audit.record(
            event_type="config.mode_set",
            actor="cli",
            action=f"config.mode_set:{key}",
            outcome="success",
            payload={"key": key, "value": value, "config_path": str(path)},
        )
    emit(
        {
            "set": True,
            "key": key,
            "value": value,
            "config_path": str(path),
            "note": "effective on the next `ksec` invocation",
        },
        args.json,
        args.quiet,
    )
    return 0