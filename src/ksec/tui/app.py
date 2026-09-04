"""Compact curses-based TUI for KSEC.

Shows a workspace header (the five KSEC workspaces), selectable views
(Status / Jobs / Sessions / Findings / Explain) and a live-updating body.
Built with the standard library only.

Mode-aware (spec: THREE OPERATION MODES):
* beginner  — plain-language explanations for every row; a guided summary view
* professional — technical descriptions with severity/state labels
* expert    — exact adapter commands, raw job output, full findings, config detail
"""
from __future__ import annotations

import curses
import time

from ksec.adapters.base import CommandRequest
from ksec.bootstrap import KsecContext
from ksec.capabilities.catalog import TOOLS
from ksec.capabilities.explain import plain_severity
from ksec.modes import Mode, resolve_mode

WORKSPACES = (
    "RED_TEAM",
    "BLUE_TEAM",
    "RESEARCH_OSINT",
    "ADVERSARY_SIMULATION",
    "LEARN_WORK",
)

VIEWS = ("status", "jobs", "sessions", "findings", "explain")

_HELP_BEGINNER = "q quit | 1-5 view | up/down scroll | r refresh"
_HELP_PRO = "q quit | 1-5 view | arrows navigate | r refresh | (mode from --mode/config)"
_HELP_EXPERT = "q quit | 1-5 view | arrows navigate | r refresh | expert: raw cmds & output"


class KsecTui:
    def __init__(self, ctx: KsecContext, mode: Mode | None = None):
        self.ctx = ctx
        self.mode = mode or resolve_mode(None, ctx.config.mode)
        self.view = 0
        self.offset = 0

    def run(self) -> int:
        try:
            return curses.wrapper(self._main)
        except curses.error:
            print("TUI requires an interactive terminal.")
            return 1

    def _main(self, stdscr) -> int:
        curses.curs_set(0)
        stdscr.nodelay(True)
        last_refresh = 0.0
        while True:
            now = time.monotonic()
            if now - last_refresh > 2.0:
                last_refresh = now
                self._refresh(stdscr)
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                break
            if key in (ord("1"), ord("2"), ord("3"), ord("4"), ord("5")):
                self.view = key - ord("1")
                self.offset = 0
            elif key in (curses.KEY_UP, ord("k")):
                self.offset = max(0, self.offset - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.offset += 1
            elif key in (ord("r"), ord("R")):
                self._refresh(stdscr)
            time.sleep(0.05)
        return 0

    def _refresh(self, stdscr) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        # Header: workspace chips + active mode.
        header = " | ".join(
            (f"[{w}]" if i == 0 else w)
            for i, w in enumerate(WORKSPACES)
        )
        mode_label = f"[MODE: {self.mode.value.upper()}]"
        stdscr.addnstr(0, 0, f" KSEC — {header}  {mode_label}", width, curses.A_BOLD)
        stdscr.hline(1, 0, "-", width)

        # View tabs.
        tabs = "  ".join(
            (f"> {v.upper()} <" if i == self.view else f"  {v.upper()}  ")
            for i, v in enumerate(VIEWS)
        )
        stdscr.addnstr(2, 0, tabs, width)

        rows = self._rows_for_view()
        line = 4
        for row in rows[self.offset : self.offset + max(0, height - 7)]:
            if line >= height - 3:
                break
            stdscr.addnstr(line, 0, row[: width - 1], width - 1)
            line += 1

        stdscr.hline(height - 2, 0, "-", width)
        help_line = {
            Mode.BEGINNER: _HELP_BEGINNER,
            Mode.EXPERT: _HELP_EXPERT,
            Mode.PROFESSIONAL: _HELP_PRO,
        }[self.mode]
        stdscr.addnstr(height - 1, 0, help_line, width)
        stdscr.refresh()

    # -- views ------------------------------------------------------------

    def _rows_for_view(self) -> list[str]:
        view = VIEWS[self.view]
        if view == "status":
            return self._status_rows()
        if view == "jobs":
            return self._job_rows()
        if view == "sessions":
            return self._session_rows()
        if view == "findings":
            return self._finding_rows()
        return self._explain_rows()

    def _status_rows(self) -> list[str]:
        cfg = self.ctx.config
        users = len(self._users())
        sessions = len(self.ctx.sessions.list())
        jobs = len(self.ctx.jobs.list())
        findings = len(self.ctx.findings.list())
        audit = self.ctx.audit.count()

        if self.mode.is_beginner():
            plain: list[str] = []
            if users == 0:
                plain.append("Nothing is set up yet. Run `ksec init` to create your admin account.")
            else:
                plain.append(f"You have {users} user account(s) — these control who can run what.")
            plain.append(f"{sessions} session(s) are open — a session is a signed-in workspace.")
            plain.append(f"{jobs} job(s) exist — jobs are the tasks KSEC runs for you.")
            plain.append(f"{findings} finding(s) exist — findings are problems the scans discovered.")
            plain.append(f"{audit} audit event(s) recorded — a permanent log of what happened.")
            plain.append("Safe mode: " + ("on — nothing active runs" if cfg.safe_mode else "off"))
            if cfg.read_only:
                plain.append("Read-only mode is on — KSEC will not change any data.")
            return plain

        base = [
            f"db_path     : {cfg.db_path}",
            f"config      : {cfg.source or 'built-in defaults'}",
            f"db_version  : {self._db_version()}",
            f"mode        : {self.mode.value}",
            f"users       : {users}",
            f"sessions    : {sessions}",
            f"jobs        : {jobs}",
            f"findings    : {findings}",
            f"audit events: {audit}",
            f"read_only   : {cfg.read_only} | safe_mode: {cfg.safe_mode}",
            f"capabilities: {len(self.ctx.capabilities.definitions())} built-in + {len(self.ctx.plugins.discover())} plugins",
        ]
        if not self.mode.is_expert():
            return base
        base += [
            f"max_concurrent_jobs : {cfg.max_concurrent_jobs}",
            f"default_timeout     : {cfg.default_timeout_seconds}s",
            f"require_authorization: {cfg.require_authorization}",
            f"audit_retention_days: {cfg.audit_retention_days}",
            f"adapters            : {', '.join(self.ctx.adapters.capabilities())}",
        ]
        return base

    def _job_rows(self) -> list[str]:
        jobs = self.ctx.jobs.list(limit=20)
        if not jobs:
            return ["no jobs"]
        rows: list[str] = []
        for job in jobs:
            if self.mode.is_beginner():
                rows.append(
                    f"{job.id[:10]} {job.state:<10} {self._capability_plain(job.capability)}"
                    f"  [{job.target}]"
                )
            elif self.mode.is_expert():
                command = self._command_for(job.capability, job.target, job.options)
                rows.append(
                    f"{job.id[:10]} {job.state:<10} {job.capability:<14} {job.target}"
                    f"  exit={job.exit_code or '-'}"
                )
                rows.append(f"    $ {' '.join(command) if command else '(no adapter)'}")
                result = job.result or {}
                if result:
                    rows.append(
                        f"    entities={result.get('entity_count', 0)}"
                        f" duration={result.get('duration_seconds', '-')}s"
                    )
                    stdout = (result.get("stdout") or "").strip().splitlines()
                    for line in stdout[:2]:
                        rows.append(f"    | {line[:70]}")
            else:
                rows.append(
                    f"{job.id[:10]} {job.state:<10} {job.capability:<14} {job.target}"
                    f"  [{self._capability_technical(job.capability)}]"
                )
        return rows

    def _session_rows(self) -> list[str]:
        sessions = self.ctx.sessions.list()
        if not sessions:
            return ["no sessions"]
        rows: list[str] = []
        for s in sessions:
            if self.mode.is_beginner():
                workspace_plain = {
                    "RED_TEAM": "red team — authorized attack simulation",
                    "BLUE_TEAM": "blue team — defense and monitoring",
                    "RESEARCH_OSINT": "research — open source intelligence",
                    "ADVERSARY_SIMULATION": "adversary simulation — controlled TTPs",
                    "LEARN_WORK": "learn and work — training workspace",
                }.get(s.workspace, s.workspace)
                rows.append(f"{s.id[:10]} {s.workspace:<20} role={s.role:<10} {s.state}")
                rows.append(f"    -> {workspace_plain}")
            else:
                rows.append(f"{s.id[:10]} {s.workspace:<20} {s.role:<10} {s.state}")
                if self.mode.is_expert():
                    rows.append(f"    user={s.user_id} session={s.id}")
        return rows

    def _finding_rows(self) -> list[str]:
        findings = self.ctx.findings.list()[:20]
        if not findings:
            return ["no findings"]
        rows: list[str] = []
        for f in findings:
            if self.mode.is_beginner():
                rows.append(
                    f"[{plain_severity(f.severity)}] {f.title}"
                )
                if f.description:
                    rows.append(f"    {f.description[:80]}")
            elif self.mode.is_expert():
                rows.append(
                    f"[{f.severity.upper():<8}] {f.status:<12} {f.title}  "
                    f"conf={f.confidence} risk={f.risk_level or '-'}/{f.risk_score or '-'}"
                )
                if f.description:
                    rows.append(f"    {f.description[:80]}")
                if f.recommendation:
                    rows.append(f"    fix: {f.recommendation[:80]}")
            else:
                rows.append(
                    f"[{f.severity.upper():<8}] {f.status:<12} {f.title}"
                )
        return rows

    def _explain_rows(self) -> list[str]:
        """Mode-aware tool explanation view (spec: TOOL EXPLANATION SYSTEM)."""
        if self.mode.is_beginner():
            rows = [
                "These are the tools KSEC can use. Scroll to see each one:",
                "",
            ]
            for tool in TOOLS:
                rows.append(f"{tool.name}  ({tool.capability})")
                rows.append(f"    {self._tool_beginner(tool.name)}")
            return rows
        rows = ["Tool explanations (technical):", ""]
        for tool in TOOLS:
            if self.mode.is_expert():
                explanation = self._explanation(tool.name)
                rows.append(f"{tool.name}  [{tool.category}]")
                rows.append(f"    why:     {explanation.why_selected}")
                rows.append(f"    data:    {explanation.data_collected}")
                rows.append(f"    risk:    {explanation.risk}")
                rows.append(f"    priv:    {explanation.privilege}")
                rows.append(f"    inputs:  {explanation.inputs}")
                rows.append(f"    outputs: {explanation.outputs}")
                rows.append(f"    more:    {explanation.learn_more}")
            else:
                rows.append(f"{tool.name}  ({tool.capability})")
                rows.append(f"    {self._explanation(tool.name).technical}")
        return rows

    # -- helpers ----------------------------------------------------------

    def _capability_plain(self, capability: str) -> str:
        from ksec.capabilities.explain import tool_for_capability

        tool = tool_for_capability(capability)
        return self._tool_beginner(tool or "") if tool else capability

    def _capability_technical(self, capability: str) -> str:
        from ksec.capabilities.explain import tool_for_capability

        tool = tool_for_capability(capability)
        return self._explanation(tool or "").technical if tool else capability

    def _tool_beginner(self, name: str) -> str:
        return self._explanation(name).beginner

    def _explanation(self, name: str):
        from ksec.capabilities.explain import explain_tool, _DEFAULT_EXPLANATION

        return explain_tool(name) or _DEFAULT_EXPLANATION

    def _command_for(self, capability: str, target: str, options: dict) -> list[str]:
        adapter = self.ctx.adapters.get(capability)
        if adapter is None:
            return []
        try:
            return adapter.build_command(
                CommandRequest(
                    capability=capability,
                    target=target,
                    options=options or {},
                    timeout=self.ctx.config.default_timeout_seconds,
                )
            )
        except Exception:
            return []

    def _db_version(self) -> int:
        from ksec.bootstrap import MIGRATIONS_DIR
        from ksec.db.migrations import MigrationRunner

        return MigrationRunner(self.ctx.db, MIGRATIONS_DIR).current_version()

    def _users(self):
        from ksec.identity.users import UserRepository

        return UserRepository(self.ctx.db).list()