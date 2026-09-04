"""nmap adapter: capability ``port_scan``."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class NmapAdapter(ToolAdapter):
    name = "nmap"
    capability = "port_scan"
    description = "Network exploration and port/service discovery (nmap)."
    safety = "ACTIVE_SAFE"
    default_parser = "nmap_xml"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        cmd = ["nmap", "-oX", "-"]
        opts = request.options or {}
        if opts.get("service_version"):
            cmd.append("-sV")
        if opts.get("fast"):
            cmd.append("-F")
        if opts.get("top_ports"):
            cmd += ["--top-ports", str(int(opts["top_ports"]))]
        elif opts.get("ports"):
            cmd += ["-p", str(opts["ports"])]
        cmd.append(target)
        return cmd