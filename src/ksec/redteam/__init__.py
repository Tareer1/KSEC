"""Atomic red tests (``ksec atomic``) — detection validation.

Small, repeatable, single-technique emulation steps (like Atomic Red
Team) that exercise your own detections. They only run against
engagement-authorized targets and use the same capability adapters as
normal workflows (dig/nmap/curl), so each run is policy-gated, scheduled,
audited and recorded as a job.
"""
from ksec.redteam.service import AtomicService, Atomic, atomics, get_atomic

__all__ = ["AtomicService", "Atomic", "atomics", "get_atomic"]
