"""hydra adapter — online login/authentication testing (capability: auth_test).

Authorized engagements only: KSEC scope policy is enforced before any job
runs, exactly like every other active capability. Use wordlists you are
licensed to test against (``options.users`` / ``options.passwords`` or a
single ``user`` / ``password`` pair).
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class HydraAdapter(ToolAdapter):
    name = "hydra"
    capability = "auth_test"
    description = "Online login/authentication testing (hydra)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "hydra"

    # Services hydra supports out of the box without extra syntax handling.
    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        target = request.target.strip()
        service = str(opts.get("service") or "ssh").lower()
        cmd = ["hydra", "-t", str(int(opts.get("threads") or 4))]
        # Rate-limit friendly: cap concurrency at a modest default; operators
        # can raise it explicitly through options for fast targets.
        user_opt = opts.get("user")
        users_opt = opts.get("users")
        if user_opt:
            cmd += ["-l", str(user_opt)]
        elif users_opt:
            cmd += ["-L", str(users_opt)]
        pass_opt = opts.get("password")
        passes_opt = opts.get("passwords")
        if pass_opt:
            cmd += ["-p", str(pass_opt)]
        elif passes_opt:
            cmd += ["-P", str(passes_opt)]
        if opts.get("port"):
            cmd += ["-s", str(opts["port"])]
        if opts.get("timeout"):
            cmd += ["-w", str(opts["timeout"])]
        cmd.append(f"{service}://{target}")
        return cmd
