"""masscan adapter: capability ``port_scan`` (high-speed alternative to nmap).

Selected at dispatch time with ``--options '{"tool": "masscan"}'`` — the
preferred ``port_scan`` adapter stays nmap.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class MasscanAdapter(ToolAdapter):
    name = "masscan"
    capability = "port_scan"
    description = "High-speed port scanning (masscan)."
    safety = "ACTIVE_SAFE"
    default_parser = "masscan_json"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        cmd = ["masscan", "-oJ", "-"]  # JSON result to stdout
        ports = opts.get("ports")
        if ports:
            cmd += ["-p", str(ports)]
        elif opts.get("top_ports"):
            # masscan has no --top-ports; scan the 1..N range as an
            # approximation of a bounded fast scan.
            cmd += ["-p", f"1-{int(opts['top_ports'])}"]
        else:
            cmd += ["-p", "1-1000"]
        if opts.get("rate"):
            cmd += ["--rate", str(int(opts["rate"]))]
        if opts.get("interface"):
            cmd += ["-e", str(opts["interface"])]
        cmd.append(target)
        return cmd