"""Kali environment fingerprinting (spec: KALI ENVIRONMENT FINGERPRINTING).

Detects OS release, kernel, architecture, runtime (bare metal / VM / WSL /
container), privilege state, and network state — all without network calls.
"""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path

_VM_MARKERS = ("virtual", "vmware", "virtualbox", "qemu", "kvm", "xen", "bochs")


def _runtime_detect() -> str:
    if Path("/.dockerenv").exists():
        return "container"
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="ignore")
        if any(marker in cgroup for marker in ("docker", "kubepods", "containerd", "lxc")):
            return "container"
    except OSError:
        pass
    if os.environ.get("WSL_DISTRO_NAME"):
        return "wsl"
    try:
        version = Path("/proc/version").read_text(encoding="utf-8", errors="ignore")
        if "microsoft" in version.lower() and "wsl" in version.lower():
            return "wsl"
    except OSError:
        pass
    try:
        product = Path("/sys/class/dmi/id/product_name").read_text(
            encoding="utf-8", errors="ignore"
        ).strip().lower()
        if any(marker in product for marker in _VM_MARKERS):
            return "vm"
    except OSError:
        pass
    return "bare_metal"


def _os_release_info() -> tuple[str, str]:
    name, version = platform.system(), platform.release()
    try:
        for line in Path("/etc/os-release").read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            if line.startswith("NAME="):
                name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("VERSION="):
                version = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return name, version


def _is_kali() -> bool:
    return "kali" in _os_release_info()[0].lower()


def _apt_available() -> bool:
    return Path("/usr/bin/apt").exists() or Path("/usr/bin/apt-get").exists()


def _network_up() -> bool:
    """Check for a default route without making network calls."""
    try:
        lines = Path("/proc/net/route").read_text(encoding="utf-8", errors="ignore").splitlines()
        return any(parts and parts[1] != "00000000" for parts in (l.split() for l in lines[1:]))
    except OSError:
        return False


@dataclass(frozen=True)
class EnvironmentFingerprint:
    hostname: str
    os_name: str
    os_release: str
    kernel: str
    architecture: str
    runtime: str
    privilege: str
    uid: int
    is_kali: bool
    apt_available: bool
    network_up: bool

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_release": self.os_release,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "runtime": self.runtime,
            "privilege": self.privilege,
            "uid": self.uid,
            "is_kali": self.is_kali,
            "apt_available": self.apt_available,
            "network_up": self.network_up,
        }


def fingerprint_environment() -> EnvironmentFingerprint:
    uname = platform.uname()
    os_name, os_release = _os_release_info()
    uid = os.geteuid() if hasattr(os, "geteuid") else -1
    return EnvironmentFingerprint(
        hostname=platform.node(),
        os_name=os_name,
        os_release=os_release,
        kernel=uname.release,
        architecture=uname.machine,
        runtime=_runtime_detect(),
        privilege="root" if uid == 0 else "user",
        uid=uid,
        is_kali=_is_kali(),
        apt_available=_apt_available(),
        network_up=_network_up(),
    )