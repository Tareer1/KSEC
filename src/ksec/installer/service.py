"""Controlled tool installation (spec: MISSING TOOL INSTALLATION).

When a required capability is missing, KSEC finds a supported provider,
validates the source (APT repositories are trusted by default), requests
approval, installs, verifies and re-checks health. It never blindly executes
arbitrary downloaded scripts.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from ksec.audit.service import AuditService
from ksec.capabilities.catalog import TOOLS, ToolDefinition
from ksec.capabilities.registry import CapabilityRegistry
from ksec.core.errors import KSECError

APT_COMMAND = "apt-get"


@dataclass(frozen=True)
class InstallPlan:
    capability: str
    provider: str
    package: str
    command: list[str]
    approved: bool
    dry_run: bool


@dataclass(frozen=True)
class InstallResult:
    capability: str
    provider: str
    installed: bool
    verified: bool
    message: str


class ToolInstallManager:
    def __init__(
        self,
        capabilities: CapabilityRegistry,
        audit: AuditService,
    ):
        self.capabilities = capabilities
        self.audit = audit

    def find_providers(self, capability: str) -> list[ToolDefinition]:
        return [t for t in TOOLS if t.capability == capability]

    def plan(
        self,
        capability: str,
        package: str | None = None,
        approved: bool = False,
        dry_run: bool = True,
    ) -> InstallPlan:
        providers = self.find_providers(capability)
        if not providers:
            raise KSECError(f"No known provider for capability {capability}")
        provider = next((t for t in providers if t.package == package), providers[0]) if package else providers[0]
        if shutil.which(provider.binary) is not None:
            raise KSECError(
                f"{provider.name} is already installed at {shutil.which(provider.binary)}"
            )
        command = [APT_COMMAND, "install", "-y", "--no-install-recommends", provider.package]
        if dry_run:
            command = [APT_COMMAND, "install", "--dry-run", provider.package]
        return InstallPlan(
            capability=capability,
            provider=provider.name,
            package=provider.package,
            command=command,
            approved=approved,
            dry_run=dry_run,
        )

    def install(
        self,
        capability: str,
        package: str | None = None,
        approved: bool = False,
        dry_run: bool = False,
    ) -> InstallResult:
        plan = self.plan(capability, package, approved=approved, dry_run=dry_run)
        if dry_run:
            return InstallResult(
                capability=capability,
                provider=plan.provider,
                installed=False,
                verified=False,
                message=f"dry-run: would run {' '.join(plan.command)}",
            )
        if not approved:
            return InstallResult(
                capability=capability,
                provider=plan.provider,
                installed=False,
                verified=False,
                message="approval required — rerun with approval",
            )
        if shutil.which(APT_COMMAND) is None:
            raise KSECError("apt-get not found; cannot install packages")
        self.audit.record(
            event_type="tools.install",
            actor="system",
            action="tools.install",
            target=plan.package,
            outcome="started",
            payload={"provider": plan.provider, "capability": capability},
        )
        try:
            proc = subprocess.run(
                plan.command,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired as exc:
            raise KSECError(f"apt-get timed out installing {plan.package}") from exc
        except OSError as exc:
            raise KSECError(f"Failed to run apt-get: {exc}") from exc

        # Verify by the catalog binary name.
        binary = next(
            (t.binary for t in TOOLS if t.name == plan.provider), plan.provider
        )
        verified = shutil.which(binary) is not None
        outcome = "success" if proc.returncode == 0 else "failed"
        self.audit.record(
            event_type="tools.install",
            actor="system",
            action="tools.install",
            target=plan.package,
            outcome=outcome,
            payload={
                "provider": plan.provider,
                "exit_code": proc.returncode,
                "verified": verified,
            },
        )
        if proc.returncode != 0:
            return InstallResult(
                capability=capability,
                provider=plan.provider,
                installed=False,
                verified=False,
                message=(proc.stderr or "apt-get failed")[:500],
            )
        self.capabilities.discover(persist=True)
        return InstallResult(
            capability=capability,
            provider=plan.provider,
            installed=True,
            verified=verified,
            message=f"installed {plan.package}; binary found: {verified}",
        )