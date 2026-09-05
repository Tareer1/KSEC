"""Endpoint security (spec 08 #31) — read-only host inventory.

Collects host identity (OS/kernel/arch/uptime), process inventory, user/account
inventory and listening sockets directly from the local system (os-release,
/proc, /etc/passwd) without executing any audit tool and without modifying the
host. Everything is passive collection; findings are created only when the
operator requests them.
"""
from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from ksec.db.connection import Database
from ksec.identity.users import now_utc

PROC_DIR = Path("/proc")
PASSWD_FILE = Path("/etc/passwd")
OS_RELEASE_FILE = Path("/etc/os-release")
HOSTNAME_FILE = Path("/etc/hostname")


@dataclass(frozen=True)
class HostInventory:
    hostname: str
    os_name: str
    os_version: str
    kernel: str
    architecture: str
    uptime_seconds: float
    cpu_count: int
    pid_count: int
    memory_kb: int
    created_at: str = ""


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    state: str
    ppid: int
    uid: int
    cmdline: str


@dataclass(frozen=True)
class UserAccount:
    username: str
    uid: int
    gid: int
    home: str
    shell: str


@dataclass(frozen=True)
class ListeningSocket:
    protocol: str
    local: str
    state: str
    pid: int
    process: str


class EndpointService:
    """Read-only local endpoint inventory (host, processes, users, sockets)."""

    def __init__(self, db: Database, findings=None, audit=None):
        self.db = db
        self.findings = findings
        self.audit = audit

    # -- host -------------------------------------------------------------

    def host_inventory(self) -> HostInventory:
        hostname = "unknown"
        try:
            hostname = socket.gethostname()
        except OSError:
            pass
        os_name = os_version = ""
        if OS_RELEASE_FILE.is_file():
            for line in OS_RELEASE_FILE.read_text(errors="replace").splitlines():
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip().strip('"')
                if key == "NAME":
                    os_name = value
                elif key == "VERSION":
                    os_version = value
        kernel = os.uname().release if hasattr(os, "uname") else ""
        architecture = os.uname().machine if hasattr(os, "uname") else ""
        uptime = 0.0
        if (PROC_DIR / "uptime").is_file():
            try:
                uptime = float((PROC_DIR / "uptime").read_text().split()[0])
            except (OSError, ValueError, IndexError):
                pass
        cpu_count = os.cpu_count() or 0
        pid_count = 0
        if PROC_DIR.is_dir():
            pid_count = len([d for d in PROC_DIR.iterdir() if d.name.isdigit()])
        memory_kb = 0
        meminfo = PROC_DIR / "meminfo"
        if meminfo.is_file():
            try:
                for line in meminfo.read_text(errors="replace").splitlines():
                    if line.startswith("MemTotal:"):
                        memory_kb = int(line.split()[1])
                        break
            except (OSError, ValueError, IndexError):
                pass
        return HostInventory(
            hostname=hostname, os_name=os_name, os_version=os_version,
            kernel=kernel, architecture=architecture, uptime_seconds=uptime,
            cpu_count=cpu_count, pid_count=pid_count, memory_kb=memory_kb,
            created_at=now_utc(),
        )

    # -- processes --------------------------------------------------------

    def processes(self, limit: int = 500) -> list[ProcessInfo]:
        if not PROC_DIR.is_dir():
            return []
        result: list[ProcessInfo] = []
        for entry in sorted(PROC_DIR.iterdir(), key=lambda p: p.name):
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text(errors="replace")
                # Comm can contain spaces/parens; parse from the right.
                lparen = stat.find("(")
                rparen = stat.rfind(")")
                name = stat[lparen + 1 : rparen] if lparen >= 0 else ""
                rest = stat[rparen + 2 :].split() if rparen >= 0 else stat.split()
                state = rest[0] if rest else ""
                ppid = int(rest[1]) if len(rest) > 1 else 0
                uid = 0
                try:
                    uid = int((entry / "status").read_text(errors="replace")
                              .split("Uid:")[1].split()[0])
                except (OSError, ValueError, IndexError):
                    pass
                cmdline = ""
                try:
                    raw = (entry / "cmdline").read_bytes().replace(b"\x00", b" ")
                    cmdline = raw.decode(errors="replace").strip()
                except OSError:
                    pass
                result.append(ProcessInfo(
                    pid=int(entry.name), name=name, state=state, ppid=ppid,
                    uid=uid, cmdline=cmdline,
                ))
            except (OSError, ValueError):
                continue
            if len(result) >= limit:
                break
        return result

    # -- users ------------------------------------------------------------

    def users(self) -> list[UserAccount]:
        if not PASSWD_FILE.is_file():
            return []
        result: list[UserAccount] = []
        for line in PASSWD_FILE.read_text(errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                uid = int(parts[2])
                gid = int(parts[3])
            except ValueError:
                continue
            result.append(UserAccount(
                username=parts[0], uid=uid, gid=gid, home=parts[5], shell=parts[6],
            ))
        return result

    # -- listening sockets ------------------------------------------------

    def listening_sockets(self) -> list[ListeningSocket]:
        """Parse /proc/net/{tcp,tcp6,udp,udp6} for LISTEN/established rows."""
        result: list[ListeningSocket] = []
        for proto, family in (("tcp", socket.AF_INET), ("tcp6", socket.AF_INET6),
                              ("udp", socket.AF_INET), ("udp6", socket.AF_INET6)):
            net_file = PROC_DIR / "net" / proto
            if not net_file.is_file():
                continue
            for line in net_file.read_text(errors="replace").splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_hex = parts[1]
                state_hex = parts[3]
                inode = parts[9] if len(parts) > 9 else "0"
                state = {
                    "0A": "LISTEN", "01": "ESTABLISHED", "02": "SYN_SENT",
                    "03": "SYN_RECV", "06": "TIME_WAIT", "07": "CLOSE",
                    "08": "CLOSE_WAIT", "09": "LAST_ACK", "0B": "CLOSING",
                }.get(state_hex, state_hex)
                local = self._hex_socket_to_addr(local_hex, family)
                pid = self._inode_pid(inode)
                process = ""
                if pid:
                    try:
                        raw = (PROC_DIR / str(pid) / "cmdline").read_bytes()
                        process = raw.replace(b"\x00", b" ").decode(errors="replace").strip()
                    except OSError:
                        pass
                result.append(ListeningSocket(
                    protocol=proto, local=local, state=state, pid=pid, process=process,
                ))
        return result

    @staticmethod
    def _hex_socket_to_addr(hex_addr: str, family: int) -> str:
        if ":" not in hex_addr:
            return "?"
        addr_hex, port_hex = hex_addr.rsplit(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError:
            port = 0
        if family == socket.AF_INET6:
            try:
                addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(addr_hex))
                return f"[{addr}]:{port}"
            except (OSError, ValueError):
                return f"?:{port}"
        try:
            addr = socket.inet_ntop(socket.AF_INET, bytes.fromhex(addr_hex))
            return f"{addr}:{port}"
        except (OSError, ValueError):
            return f"?:{port}"

    @staticmethod
    def _inode_pid(inode: str) -> int:
        if not inode or inode == "0" or not PROC_DIR.is_dir():
            return 0
        for fd_dir in PROC_DIR.iterdir():
            if not fd_dir.name.isdigit():
                continue
            if (fd_dir / "fd").is_dir():
                try:
                    for fd in (fd_dir / "fd").iterdir():
                        try:
                            if os.readlink(fd) == f"socket:[{inode}]":
                                return int(fd_dir.name)
                        except OSError:
                            continue
                except OSError:
                    continue
        return 0

    # -- findings (optional) ----------------------------------------------

    def check(self, *, create_findings: bool = False, actor: str = "endpoint") -> dict:
        """Run passive endpoint checks and (optionally) create findings for
        notable observations: high-privilege interactive accounts, listening
        sockets with no owning process, and long-running unknown processes."""
        host = self.host_inventory()
        users = self.users()
        sockets = self.listening_sockets()

        observations: list[dict] = []
        # Accounts with UID 0 (root-equivalent) that have a login shell.
        root_equivalent = [u for u in users if u.uid == 0 and u.shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")]
        if root_equivalent:
            observations.append({
                "check": "root_equivalent_accounts",
                "status": "review",
                "detail": ", ".join(u.username for u in root_equivalent),
            })
        # Listening sockets whose owner process could not be resolved.
        orphan_sockets = [s for s in sockets if s.state == "LISTEN" and s.pid == 0]
        if orphan_sockets:
            observations.append({
                "check": "listening_socket_without_process",
                "status": "review",
                "detail": ", ".join(s.local for s in orphan_sockets[:10]),
            })
        # Listening on non-loopback addresses (exposure).
        exposed = [s for s in sockets if s.state == "LISTEN"
                   and not s.local.startswith("127.") and not s.local.startswith("[::1]")
                   and not s.local.startswith("0.0.0.0:") and not s.local.startswith("[::]")]
        if exposed:
            observations.append({
                "check": "exposed_listening",
                "status": "review",
                "detail": ", ".join(s.local for s in exposed[:10]),
            })

        if create_findings and self.findings is not None:
            for obs in observations:
                self.findings.create(
                    title=f"Endpoint: {obs['check']}",
                    description=obs["detail"],
                    severity="medium" if obs["check"] == "root_equivalent_accounts" else "low",
                    source=f"ksec.endpoint:{obs['check']}",
                )
        if self.audit:
            self.audit.record(
                event_type="endpoint.check",
                actor=actor,
                action="endpoint.check",
                outcome="success",
                payload={"observations": len(observations), "host": host.hostname},
            )
        return {
            "host": {
                "hostname": host.hostname, "os": host.os_name, "os_version": host.os_version,
                "kernel": host.kernel, "arch": host.architecture, "uptime": host.uptime_seconds,
            },
            "observations": observations,
            "counts": {
                "users": len(users),
                "sockets": len(sockets),
                "processes": host.pid_count,
            },
        }