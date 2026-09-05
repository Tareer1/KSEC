"""john adapter — offline password hash cracking (capability: password_crack).

Operates on a local hash file (the job target) the operator owns or is
authorized to test. Wordlist and format come from options; output is parsed
for cracked ``password (user)`` lines.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


class JohnAdapter(ToolAdapter):
    name = "john"
    capability = "password_crack"
    description = "Offline password hash cracking (john the ripper)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "john"

    def build_command(self, request: CommandRequest) -> list[str]:
        hash_file = validate_target(request.target)  # path to the hash file
        opts = request.options or {}
        wordlist = str(opts.get("wordlist") or DEFAULT_WORDLIST)
        cmd = ["john", "--wordlist=" + wordlist, hash_file]
        if opts.get("format"):
            cmd.insert(1, "--format=" + str(opts["format"]))
        return cmd