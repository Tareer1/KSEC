"""KSEC configuration loading.

Precedence (highest wins): command-line override > user config file > built-in
defaults. ``KSEC_HOME`` redirects the data directory; ``KSEC_CONFIG``
redirects the config file location.

Sensitive values are never stored in this module's config; they belong in the
separate secret-management subsystem (not yet implemented).
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ksec.core.errors import ConfigurationError

DEFAULTS: dict[str, dict[str, Any]] = {
    "core": {
        "data_dir": "",  # empty -> XDG default (~/.local/share/ksec)
        "db_name": "ksec.db",
        "log_level": "INFO",
        "log_file": "",  # empty -> <data_dir>/ksec.log
        "mode": "professional",  # beginner | professional | expert
    },
    "scheduler": {
        "max_concurrent_jobs": 2,
        "default_timeout_seconds": 300,
    },
    "safety": {
        "require_authorization": True,
        "safe_mode": False,
        "read_only": False,
    },
    "audit": {
        "enabled": True,
        "retention_days": 365,
    },
    "notifications": {
        # providers.<name> = {type="email|telegram|slack|discord|webhook|log", ...}
        "providers": {},
    },
}


def normalize_mode_value(value: str) -> str:
    if value.lower() in ("beginner", "professional", "expert"):
        return value.lower()
    return "professional"


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def default_home() -> Path:
    env = os.environ.get("KSEC_HOME")
    if env:
        return Path(env)
    return Path.home() / ".local" / "share" / "ksec"


def config_file_candidates() -> list[Path]:
    env = os.environ.get("KSEC_CONFIG")
    if env:
        return [Path(env)]
    return [Path.cwd() / "ksec.toml", Path.home() / ".config" / "ksec" / "config.toml"]


def find_config_file() -> Path | None:
    for path in config_file_candidates():
        if path.is_file():
            return path
    return None


def load_config_dict() -> tuple[dict, Path | None]:
    """Merge defaults with the first found user config file.

    Returns ``(merged_dict, source_path_or_None)``.
    """
    merged = _deep_merge(DEFAULTS, {})
    source = None
    for path in config_file_candidates():
        if path.is_file():
            try:
                with path.open("rb") as fh:
                    user = tomllib.load(fh)
            except (OSError, tomllib.TOMLDecodeError) as exc:
                raise ConfigurationError(f"Failed to read config {path}: {exc}") from exc
            merged = _deep_merge(merged, user)
            source = path
            break
    return merged, source


@dataclass(frozen=True)
class KsecConfig:
    """Resolved, immutable runtime configuration."""

    data_dir: Path
    db_path: Path
    log_level: str
    log_file: Path
    mode: str
    max_concurrent_jobs: int
    default_timeout_seconds: int
    require_authorization: bool
    safe_mode: bool
    read_only: bool
    audit_enabled: bool
    audit_retention_days: int
    notification_providers: dict
    source: Path | None = None

    @classmethod
    def load(cls, overrides: dict | None = None) -> "KsecConfig":
        merged, source = load_config_dict()
        if overrides:
            merged = _deep_merge(merged, overrides)

        core = merged["core"]
        data_dir = Path(
            os.environ.get("KSEC_HOME") or core.get("data_dir") or str(default_home())
        )
        data_dir = data_dir.expanduser().resolve()
        db_path = data_dir / (core.get("db_name") or "ksec.db")
        log_level = str(core.get("log_level") or "INFO").upper()
        log_file_str = core.get("log_file") or ""
        log_file = Path(log_file_str).expanduser() if log_file_str else data_dir / "ksec.log"
        mode = normalize_mode_value(str(core.get("mode") or "professional"))

        scheduler = merged["scheduler"]
        safety = merged["safety"]
        audit = merged["audit"]
        notifications_cfg = merged.get("notifications", {})
        providers = notifications_cfg.get("providers", {}) or {}

        return cls(
            data_dir=data_dir,
            db_path=db_path,
            log_level=log_level,
            log_file=log_file,
            mode=mode,
            max_concurrent_jobs=int(scheduler.get("max_concurrent_jobs", 2)),
            default_timeout_seconds=int(scheduler.get("default_timeout_seconds", 300)),
            require_authorization=bool(safety.get("require_authorization", True)),
            safe_mode=bool(safety.get("safe_mode", False)),
            read_only=bool(safety.get("read_only", False)),
            audit_enabled=bool(audit.get("enabled", True)),
            audit_retention_days=int(audit.get("retention_days", 365)),
            notification_providers=providers if isinstance(providers, dict) else {},
            source=source,
        )

    def to_dict(self) -> dict:
        return {
            "data_dir": str(self.data_dir),
            "db_path": str(self.db_path),
            "log_level": self.log_level,
            "log_file": str(self.log_file),
            "mode": self.mode,
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "default_timeout_seconds": self.default_timeout_seconds,
            "require_authorization": self.require_authorization,
            "safe_mode": self.safe_mode,
            "read_only": self.read_only,
            "audit_enabled": self.audit_enabled,
            "audit_retention_days": self.audit_retention_days,
            "notification_providers": self.notification_providers,
            "source": str(self.source) if self.source else None,
        }


def default_config_path() -> Path:
    env = os.environ.get("KSEC_CONFIG")
    if env:
        return Path(env)
    return Path.home() / ".config" / "ksec" / "config.toml"


def render_config_toml(config: KsecConfig) -> str:
    """Render a config file documenting the effective defaults."""
    return f"""# KSEC configuration
# Written by `ksec init`. Edit freely; comments are ignored.

[core]
data_dir = "{config.data_dir}"
db_name = "ksec.db"
log_level = "{config.log_level}"
log_file = "{config.log_file}"
mode = "{config.mode}"

[scheduler]
max_concurrent_jobs = {config.max_concurrent_jobs}
default_timeout_seconds = {config.default_timeout_seconds}

[safety]
require_authorization = {"true" if config.require_authorization else "false"}
safe_mode = {"true" if config.safe_mode else "false"}
read_only = {"true" if config.read_only else "false"}

[audit]
enabled = {"true" if config.audit_enabled else "false"}
retention_days = {config.audit_retention_days}

[notifications.providers]
# Optional pluggable notification providers. Uncomment and configure to send
# alerts to email / telegram / slack / discord / a generic webhook.
#
# example_log = {{ type = "log" }}
# example_telegram = {{ type = "telegram", url = "https://api.telegram.org/bot<TOKEN>/sendMessage", chat_id = "<CHAT_ID>" }}
# example_slack = {{ type = "slack", url = "https://hooks.slack.com/services/..." }}
# example_email = {{ type = "email", host = "smtp.example.com", port = 587, tls = true, from = "ksec@example.com", to = "soc@example.com", username = "ksec@example.com", password = "..." }}
"""