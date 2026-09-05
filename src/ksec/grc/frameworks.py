"""GRC framework mappings (spec 08 #36-37).

KSEC maps security-relevant *checks* (TLS, headers, banners, evidence,
configuration, ...) to controls of common frameworks. Mappings are versioned
constants — KSEC never claims legal certification, only that a technical
check passed or failed.

Frameworks: NIST 800-53, CIS, OWASP Top 10 / ASVS, ISO/IEC 27001, SOC 2, PCI DSS.
"""
from __future__ import annotations

from dataclasses import dataclass

GRC_VERSION = "1.0"


@dataclass(frozen=True)
class GrcControl:
    """A framework control mapped to one or more KSEC check ids."""

    framework: str
    control_id: str
    title: str
    description: str
    check_ids: tuple[str, ...]  # KSEC check ids that provide evidence for this control


# Check ids refer to deterministic checks KSEC can actually run:
#   tls_version        — TLS protocol check (ksec vuln check)
#   security_headers   — HTTP security-header check (ksec vuln check)
#   banner_disclosure  — server-banner disclosure check (ksec vuln check)
#   dev_fingerprint    — development-server fingerprint check (ksec vuln check)
#   evidence_integrity — evidence hash verification (ksec evidence verify)
#   scope_enforcement  — out-of-scope target blocked (ksec assess --dry-run)
#   audit_active       — audit log enabled and recording (ksec audit list)
#   authorization      — engagement scope configured (ksec engagement scope list)
#   backup_verified    — backup created and verified (ksec backup verify)

CONTROLS: tuple[GrcControl, ...] = (
    # --- NIST SP 800-53 (moderate baseline excerpts) --------------------
    GrcControl("NIST 800-53", "AC-2", "Account Management",
               "Accounts are managed with authorization and scope controls.",
               ("authorization", "scope_enforcement")),
    GrcControl("NIST 800-53", "AC-3", "Access Enforcement",
               "Access decisions enforce policy (RBAC + scope).",
               ("scope_enforcement", "authorization")),
    GrcControl("NIST 800-53", "AU-2", "Audit Events",
               "Audit logging is enabled and events are recorded.",
               ("audit_active",)),
    GrcControl("NIST 800-53", "AU-6", "Audit Review, Analysis and Reporting",
               "Audit records can be reviewed (ksec audit list).",
               ("audit_active",)),
    GrcControl("NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity",
               "Transmission is protected with current TLS.",
               ("tls_version",)),
    GrcControl("NIST 800-53", "SI-7", "Software, Firmware and Information Integrity",
               "Evidence integrity is preserved and verifiable.",
               ("evidence_integrity",)),
    GrcControl("NIST 800-53", "CP-9", "Information System Backup",
               "Backups are created and verified.",
               ("backup_verified",)),
    # --- CIS (excerpts) --------------------------------------------------
    GrcControl("CIS", "CIS-1.4.1", "Ensure permissions on bootloader config",
               "Configuration hardening baseline (deterministic checks only).",
               ("banner_disclosure", "dev_fingerprint")),
    GrcControl("CIS", "CIS-2.2.1", "Ensure web server software is current",
               "Web server and header configuration is reviewed.",
               ("security_headers", "banner_disclosure")),
    GrcControl("CIS", "CIS-3.1", "Encryption and TLS configuration",
               "TLS configuration is current and secure.",
               ("tls_version",)),
    # --- OWASP Top 10 / ASVS --------------------------------------------
    GrcControl("OWASP", "A05:2021", "Security Misconfiguration",
               "Security headers and server configuration are reviewed.",
               ("security_headers", "banner_disclosure", "dev_fingerprint")),
    GrcControl("OWASP", "A07:2021", "Identification and Authentication Failures",
               "Authentication surfaces are enumerated and reviewed.",
               ("tls_version", "banner_disclosure")),
    GrcControl("OWASP", "ASVS-1.11", "TLS transport security",
               "Transport security uses supported TLS versions.",
               ("tls_version",)),
    # --- ISO/IEC 27001 (excerpts) ---------------------------------------
    GrcControl("ISO 27001", "A.8.8", "Management of technical vulnerabilities",
               "Vulnerability checks run against authorized targets.",
               ("tls_version", "security_headers", "banner_disclosure")),
    GrcControl("ISO 27001", "A.8.15", "Logging",
               "Audit events are captured and reviewable.",
               ("audit_active",)),
    GrcControl("ISO 27001", "A.8.13", "Information backup",
               "Backups are verified for integrity.",
               ("backup_verified",)),
    # --- SOC 2 (trust services categories) ------------------------------
    GrcControl("SOC 2", "CC6.1", "Logical and physical access controls",
               "Access is controlled and scoped.",
               ("authorization", "scope_enforcement")),
    GrcControl("SOC 2", "CC7.2", "Monitor systems for anomalies",
               "Audit and evidence trails support monitoring.",
               ("audit_active", "evidence_integrity")),
    GrcControl("SOC 2", "CC7.3", "Evaluate security incidents",
               "Findings and cases are managed with integrity.",
               ("evidence_integrity",)),
    # --- PCI DSS ---------------------------------------------------------
    GrcControl("PCI DSS", "4.1", "Use strong cryptography for transmission",
               "TLS configuration meets current best practice.",
               ("tls_version",)),
    GrcControl("PCI DSS", "10.2", "Implement automated audit trails",
               "Audit events are recorded and reviewable.",
               ("audit_active",)),
    GrcControl("PCI DSS", "10.5", "Secure audit trails",
               "Evidence integrity is verifiable.",
               ("evidence_integrity",)),
)


def frameworks() -> list[str]:
    """Framework ids in a stable order."""
    return sorted({c.framework for c in CONTROLS})


def controls(framework: str | None = None) -> list[GrcControl]:
    if framework:
        return [c for c in CONTROLS if c.framework == framework]
    return list(CONTROLS)


def check_ids() -> set[str]:
    return {cid for c in CONTROLS for cid in c.check_ids}