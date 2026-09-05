"""nxc adapter — SMB credential/access validation (capability: smb_cred_test).

NetExec (the crackmapexec successor) validates credentials against
authorized hosts: which users/passwords actually work, share access and
admin rights. Only targets inside the engagement scope may be tested; the
policy gate enforces this before any run.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class NxcAdapter(ToolAdapter):
    name = "nxc"
    capability = "smb_cred_test"
    description = "SMB credential/access validation on authorized hosts (nxc)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "nxc"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        target = request.target.strip()
        cmd = ["nxc", "smb", target]
        user = opts.get("user") or opts.get("username")
        if user:
            cmd += ["-u", str(user)]
        if opts.get("password"):
            cmd += ["-p", str(opts["password"])]
        elif opts.get("passwords"):
            cmd += ["-p", str(opts["passwords"])]
        if opts.get("hashes"):
            cmd += ["-H", str(opts["hashes"])]
        if opts.get("share"):
            cmd += ["--shares"]
        if opts.get("users"):
            cmd += ["--users"]
        return cmd