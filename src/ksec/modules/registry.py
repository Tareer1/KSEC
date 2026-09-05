"""Domain module registry (spec 08).

Each module:
* declares the Kali capabilities its tools provide,
* reports which of those tools are actually installed,
* runs deterministic, offline, read-only posture checks that never need a
  target and never execute anything unsafe — so every module is usable and
  testable in seconds.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from ksec.db.connection import Database
from ksec.identity.users import now_utc


@dataclass(frozen=True)
class ModuleDefinition:
    module_id: str
    title: str
    description: str
    capabilities: tuple[str, ...]
    tools: tuple[str, ...]
    audience: tuple[str, ...] = ("all",)

    def tools_installed(self) -> list[dict]:
        return [
            {"name": t, "binary": shutil.which(t), "ready": shutil.which(t) is not None}
            for t in self.tools
        ]


MODULES: tuple[ModuleDefinition, ...] = (
    ModuleDefinition(
        "api",
        "API Security",
        "Web API posture: methods, auth, headers, TLS, rate limiting and "
        "endpoint exposure. Scans authorized endpoints with web capabilities "
        "and runs offline posture checks (spec 08 #23).",
        ("web_fingerprint", "http_probe", "tls_scan", "web_vuln_scan", "directory_brute"),
        ("curl", "nuclei", "ffuf", "nikto", "jwt_tool"),
        ("red", "blue", "purple"),
    ),
    ModuleDefinition(
        "wireless",
        "Wireless Security",
        "802.11 discovery and audit: interface inventory, monitor-mode "
        "readiness and rogue/evil-twin detection tooling (spec 08 #24).",
        ("wifi_scan", "wifi_crack"),
        ("airmon-ng", "airodump-ng", "aireplay-ng", "wash", "kismet", "iwlist", "aircrack-ng"),
        ("red", "blue"),
    ),
    ModuleDefinition(
        "cloud",
        "Cloud Security",
        "Cloud posture: credential hygiene, exposed config files, metadata "
        "endpoint checks and CSP-specific tooling (spec 08 #25).",
        ("cloud_enum",),
        ("awscli", "az", "gcloud", "s3scanner", "pacu"),
        ("red", "blue", "purple"),
    ),
    ModuleDefinition(
        "container",
        "Container Security",
        "Container image and runtime posture: image inventory, dangerous "
        "privileges and known tooling for image scanning (spec 08 #26).",
        ("container_scan",),
        ("docker", "podman", "trivy", "grype", "dockle"),
        ("blue", "red"),
    ),
    ModuleDefinition(
        "kubernetes",
        "Kubernetes Security",
        "Kubernetes posture: cluster inventory, RBAC exposure and manifest "
        "misconfiguration tooling (spec 08 #27).",
        ("k8s_scan",),
        ("kubectl", "kubeaudit", "kube-hunter", "popeye", "kubesec"),
        ("blue", "red"),
    ),
)

_ID_MAP = {m.module_id: m for m in MODULES}


def modules() -> tuple[ModuleDefinition, ...]:
    return MODULES


def get_module(module_id: str) -> ModuleDefinition | None:
    return _ID_MAP.get(module_id.strip().lower())


def check_ids() -> tuple[str, ...]:
    return (
        "config_present",
        "no_secret_in_cwd",
        "no_world_readable_config",
        "metadata_guard",
    )


def _no_secret_in_cwd() -> dict:
    """Heuristic scan of the current directory for obvious secret patterns in
    files named like keys/tokens/env files. Offline, read-only, shallow."""
    suspicious_names = (
        "aws_credentials", "credentials.json", "id_rsa", "id_ed25519",
        ".env", "service_account.json", "*.pem", "*.key", "kubeconfig",
    )
    found: list[str] = []
    cwd = Path.cwd()
    for child in cwd.rglob("*"):
        if not child.is_file():
            continue
        if child.name.startswith(".git"):
            continue
        try:
            rel = str(child.relative_to(cwd))
        except ValueError:
            continue
        lowered = child.name.lower()
        if lowered in suspicious_names or lowered.endswith((".pem", ".key")):
            # Never print contents; only flag presence of a private-ish name.
            found.append(rel)
        elif child.name == ".env" and child.stat().st_size > 0:
            try:
                text = child.read_text(errors="ignore")
                if "=" in text and any(
                    k in text.upper() for k in ("SECRET", "TOKEN", "PASSWORD", "KEY", "API")
                ):
                    found.append(rel)
            except OSError:
                pass
    return {"status": "PASS" if not found else "FAIL", "detail": ", ".join(found) or "no obvious secrets"}


def _config_present(module: ModuleDefinition) -> dict:
    """Look for each module's typical config/kube/env files on disk."""
    markers: dict[str, tuple[str, ...]] = {
        "api": (".env", "openapi.json", "openapi.yaml", "swagger.json"),
        "wireless": (),
        "cloud": ("~/.aws/credentials", "~/.azure", "~/.config/gcloud", "service_account.json"),
        "container": ("Dockerfile", "docker-compose.yml", "Podfile", "Containerfile"),
        "kubernetes": ("~/.kube/config", "kubeconfig", "deployment.yaml", "values.yaml"),
    }
    hits: list[str] = []
    for marker in markers.get(module.module_id, ()):
        path = Path(marker).expanduser()
        if path.is_file():
            hits.append(marker)
    status = "PASS" if hits else "INFO"
    return {"status": status, "detail": ", ".join(hits) or f"no {module.title.lower()} config files found"}


def _world_readable(module: ModuleDefinition) -> dict:
    markers: dict[str, tuple[str, ...]] = {
        "cloud": ("~/.aws", "~/.azure", "~/.config/gcloud"),
        "kubernetes": ("~/.kube",),
    }
    exposed: list[str] = []
    for marker in markers.get(module.module_id, ()):
        path = Path(marker).expanduser()
        if path.is_dir():
            mode = path.stat().st_mode & 0o777
            if mode & 0o004:  # world-readable bit
                exposed.append(f"{marker} (0o{mode:o})")
    return {"status": "FAIL" if exposed else "PASS", "detail": ", ".join(exposed) or "no world-readable config dirs"}


def _metadata_guard() -> dict:
    """Presence of a metadata-endpoint guard (cloud/kubernetes hardening)."""
    env = os.environ.get("KSEC_METADATA_GUARD", "")
    return {"status": "PASS" if env else "INFO", "detail": "set KSEC_METADATA_GUARD=1 to require metadata guard"}


class ModuleRegistry:
    def __init__(self, db: Database | None = None, audit=None):
        self.db = db
        self.audit = audit

    def list_modules(self) -> list[dict]:
        return [
            {
                "id": m.module_id,
                "title": m.title,
                "description": m.description,
                "capabilities": list(m.capabilities),
                "audience": list(m.audience),
            }
            for m in MODULES
        ]

    def info(self, module_id: str) -> dict | None:
        module = get_module(module_id)
        if module is None:
            return None
        return {
            "id": module.module_id,
            "title": module.title,
            "description": module.description,
            "capabilities": list(module.capabilities),
            "audience": list(module.audience),
            "tools": module.tools_installed(),
        }

    def check(self, module_id: str, *, actor: str = "module") -> dict:
        """Run the offline posture checks for one module and audit the run.

        Checks are deterministic and read-only: they look at local config
        markers, cwd secret hygiene, config-directory permissions and the
        metadata-guard env flag. Nothing is executed against a target.
        """
        module = get_module(module_id)
        if module is None:
            raise ValueError(f"unknown module: {module_id}")
        results: list[dict] = []
        results.append({"check_id": "config_present", **_config_present(module)})
        results.append({"check_id": "no_secret_in_cwd", **_no_secret_in_cwd()})
        results.append({"check_id": "no_world_readable_config", **_world_readable(module)})
        results.append({"check_id": "metadata_guard", **_metadata_guard()})
        payload = {
            "module": module.module_id,
            "generated_at": now_utc(),
            "checks": results,
        }
        if self.audit:
            self.audit.record(
                event_type="module.check",
                actor=actor,
                action=f"module.check:{module.module_id}",
                outcome="success",
                payload={"checks": len(results)},
            )
        return payload

    def record_scan(self, baseline_id: int, status: str, drift: list) -> int | None:
        """Persist a module/drift scan row. Returns the row id (or None when
        the change-scans table is unavailable, e.g. before migration 015)."""
        if self.db is None:
            return None
        try:
            cursor = self.db.execute(
                "INSERT INTO change_scans (baseline_id, status, drift_json, created_at)"
                " VALUES (?, ?, ?, ?)",
                (baseline_id, status, json.dumps(drift), now_utc()),
            )
            return int(cursor.lastrowid)
        except Exception:  # pragma: no cover - table is always migrated
            return None

    @staticmethod
    def check_ids() -> list[str]:
        return list(check_ids())
