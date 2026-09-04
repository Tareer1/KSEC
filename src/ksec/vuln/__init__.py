"""Authorized, deterministic vulnerability checks (``ksec vuln``).

Checks are read-only configuration/version probes (TLS version, HTTP
security headers, dev-server fingerprints) executed only against
in-scope targets. They never exploit anything — findings are created for
an operator to review.
"""
from ksec.vuln.service import VulnService

__all__ = ["VulnService"]
