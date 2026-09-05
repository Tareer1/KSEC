"""Domain modules (spec 08) — API Security, Wireless, Cloud, Container,
Kubernetes. Each module maps to real Kali capabilities and ships
deterministic, offline, read-only checks so a module is usable (and
testable) even before its tools are installed.
"""
from ksec.modules.registry import ModuleRegistry

__all__ = ["ModuleRegistry"]