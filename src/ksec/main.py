"""KSEC CLI entry point.

Primary interface: ``ksec <command>``. Supports ``--json`` machine output and
``--verbose`` diagnostics (spec: CLI Design / CLI Output Levels).
"""
from __future__ import annotations

import argparse
import sys

from ksec import __version__
from ksec.bootstrap import bootstrap
from ksec.cli import admin as admin_commands
from ksec.cli import adversary as adversary_commands
from ksec.cli import audit as audit_commands
from ksec.cli import assess as assess_commands
from ksec.cli import atomic as atomic_commands
from ksec.cli import backup as backup_commands
from ksec.cli import core as core_commands
from ksec.cli import ask as ask_commands
from ksec.cli import data as data_commands
from ksec.cli import dfir as dfir_commands
from ksec.cli import engagement as engagement_commands
from ksec.cli import env as env_commands
from ksec.cli import install as install_commands
from ksec.cli import intel as intel_commands
from ksec.cli import jobs as jobs_commands
from ksec.cli import learn as learn_commands
from ksec.cli import notify as notify_commands
from ksec.cli import plugin as plugin_commands
from ksec.cli import report as report_commands
from ksec.cli import update as update_commands
from ksec.cli import vuln as vuln_commands
from ksec.cli import session as session_commands
from ksec.cli import soc as soc_commands
from ksec.cli import tools as tools_commands
from ksec.cli import ui as ui_commands
from ksec.cli import workflow as workflow_commands
from ksec.core.errors import KSECError


def _common() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="Reduce output")
    common.add_argument("--verbose", action="store_true", help="Verbose diagnostics")
    common.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    common.add_argument(
        "--mode",
        default=None,
        choices=["beginner", "professional", "expert"],
        help="Operation mode (beginner|professional|expert; default from config)",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(
        prog="ksec",
        description="KSEC — All-in-One Kali Linux Security Operations Platform",
        parents=[common],
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # core
    p_init = sub.add_parser("init", help="Initialize KSEC (config, database, roles, admin user)", parents=[common])
    p_init.add_argument("--username", default="admin", help="Admin username (default: admin)")
    p_init.add_argument("--password", default=None, help="Admin password (auto-generated if omitted)")
    p_init.add_argument("--display-name", default="KSEC Administrator")
    p_init.set_defaults(func=core_commands.cmd_init)

    p_status = sub.add_parser("status", help="Show platform status", parents=[common])
    p_status.set_defaults(func=core_commands.cmd_status)

    p_doctor = sub.add_parser("doctor", help="Run health checks", parents=[common])
    p_doctor.set_defaults(func=core_commands.cmd_doctor)

    p_version = sub.add_parser("version", help="Show version", parents=[common])
    p_version.set_defaults(func=core_commands.cmd_version)

    p_config = sub.add_parser("config", help="Configuration commands", parents=[common])
    p_config.add_argument("action", choices=["show"], help="config action")
    p_config.set_defaults(func=core_commands.cmd_config)

    p_env = sub.add_parser("env", help="Show environment fingerprint", parents=[common])
    p_env.set_defaults(func=env_commands.cmd_env)

    # admin
    p_admin = sub.add_parser("admin", help="Administration commands", parents=[common])
    a_sub = p_admin.add_subparsers(dest="admin_command", metavar="ADMIN_COMMAND")
    p_user = a_sub.add_parser("user", help="User management", parents=[common])
    u_sub = p_user.add_subparsers(dest="user_command", metavar="USER_COMMAND")
    p_ucreate = u_sub.add_parser("create", help="Create a user", parents=[common])
    p_ucreate.add_argument("--username", required=True)
    p_ucreate.add_argument("--password", default=None)
    p_ucreate.add_argument("--display-name", default="")
    p_ucreate.add_argument("--role", default="operator", help="Role to assign (default: operator)")
    p_ucreate.set_defaults(func=admin_commands.cmd_user_create)
    p_ulist = u_sub.add_parser("list", help="List users", parents=[common])
    p_ulist.set_defaults(func=admin_commands.cmd_user_list)

    # audit
    p_audit = sub.add_parser("audit", help="Audit log (read-only, requires audit.read)", parents=[common])
    au_sub = p_audit.add_subparsers(dest="audit_command", metavar="AUDIT_COMMAND")
    au_list = au_sub.add_parser("list", help="List audit events (newest first)", parents=[common])
    au_list.add_argument("--limit", type=int, default=50)
    au_list.add_argument("--event-type", default=None)
    au_list.add_argument("--actor", default=None)
    au_list.add_argument("--user", required=True)
    au_list.add_argument("--password", default=None)
    au_list.set_defaults(func=audit_commands.cmd_audit_list)

    # tools
    p_tools = sub.add_parser("tools", help="Kali tool/capability discovery", parents=[common])
    t_sub = p_tools.add_subparsers(dest="tools_command", metavar="TOOLS_COMMAND")
    t_list = t_sub.add_parser("list", help="List discovered tools", parents=[common])
    t_list.set_defaults(func=tools_commands.cmd_tools_list)
    t_info = t_sub.add_parser("info", help="Show tool details", parents=[common])
    t_info.add_argument("tool")
    t_info.set_defaults(func=tools_commands.cmd_tools_info)
    t_health = t_sub.add_parser("health", help="Re-check tool health", parents=[common])
    t_health.set_defaults(func=tools_commands.cmd_tools_health)
    t_explain = t_sub.add_parser("explain", help="Explain a tool (mode-aware)", parents=[common])
    t_explain.add_argument("tool")
    t_explain.set_defaults(func=tools_commands.cmd_tools_explain)
    t_install = t_sub.add_parser("install", help="Install a missing capability's tool", parents=[common])
    t_install.add_argument("--capability", required=True)
    t_install.add_argument("--package", default=None)
    t_install.add_argument("--user", required=True)
    t_install.add_argument("--password", default=None)
    t_install.add_argument("--yes", action="store_true", help="Approve installation")
    t_install.add_argument("--dry-run", action="store_true", help="Show plan without installing")
    t_install.set_defaults(func=install_commands.cmd_tools_install)

    # sessions
    p_session = sub.add_parser("session", help="Session lifecycle", parents=[common])
    s_sub = p_session.add_subparsers(dest="session_command", metavar="SESSION_COMMAND")
    s_open = s_sub.add_parser("open", help="Open a workspace session", parents=[common])
    s_open.add_argument("--user", required=True)
    s_open.add_argument("--password", default=None)
    s_open.add_argument("--workspace", required=True, choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    s_open.add_argument("--role", default=None)
    s_open.set_defaults(func=session_commands.cmd_session_open)
    s_list = s_sub.add_parser("list", help="List sessions", parents=[common])
    s_list.set_defaults(func=session_commands.cmd_session_list)
    for name, func in (
        ("status", session_commands.cmd_session_status),
        ("close", session_commands.cmd_session_close),
        ("pause", session_commands.cmd_session_pause),
        ("resume", session_commands.cmd_session_resume),
    ):
        p = s_sub.add_parser(name, help=f"Session {name}", parents=[common])
        p.add_argument("id")
        p.set_defaults(func=func)

    # engagements
    p_eng = sub.add_parser("engagement", help="Engagements, authorizations and scope", parents=[common])
    e_sub = p_eng.add_subparsers(dest="engagement_command", metavar="ENGAGEMENT_COMMAND")
    e_create = e_sub.add_parser("create", help="Create an engagement", parents=[common])
    e_create.add_argument("--name", required=True)
    e_create.add_argument("--description", default=None)
    e_create.set_defaults(func=engagement_commands.cmd_engagement_create)
    e_list = e_sub.add_parser("list", help="List engagements", parents=[common])
    e_list.set_defaults(func=engagement_commands.cmd_engagement_list)
    e_scope = e_sub.add_parser("scope", help="Scope management", parents=[common])
    sc_sub = e_scope.add_subparsers(dest="scope_command", metavar="SCOPE_COMMAND")
    sc_add = sc_sub.add_parser("add", help="Add a scope rule", parents=[common])
    sc_add.add_argument("--engagement", type=int, required=True)
    sc_add.add_argument("--target", required=True)
    sc_add.add_argument("--action", default="*")
    sc_add.add_argument("--effect", default="allow", choices=["allow", "deny"])
    sc_add.set_defaults(func=engagement_commands.cmd_engagement_scope_add)
    sc_list = sc_sub.add_parser("list", help="List scope rules", parents=[common])
    sc_list.add_argument("--engagement", type=int, required=True)
    sc_list.set_defaults(func=engagement_commands.cmd_engagement_scope_list)

    # assess
    p_assess = sub.add_parser("assess", help="Run a policy-gated assessment workflow", parents=[common])
    p_assess.add_argument("target")
    p_assess.add_argument("--workflow", default="assess", help="Workflow name (default: assess)")
    p_assess.add_argument("--engagement", type=int, default=None, help="Engagement ID (scope)")
    p_assess.add_argument("--user", required=True)
    p_assess.add_argument("--password", default=None)
    p_assess.add_argument("--workspace", default="RED_TEAM", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    p_assess.add_argument("--role", default=None)
    p_assess.add_argument("--dry-run", action="store_true", help="Plan and policy-check without executing")
    p_assess.add_argument("--explain", action="store_true", help="Explain each step in the current mode")
    p_assess.set_defaults(func=assess_commands.cmd_assess)

    # jobs
    p_jobs = sub.add_parser("job", help="Job lifecycle", parents=[common])
    j_sub = p_jobs.add_subparsers(dest="job_command", metavar="JOB_COMMAND")
    j_list = j_sub.add_parser("list", help="List jobs", parents=[common])
    j_list.add_argument("--state", default=None)
    j_list.set_defaults(func=jobs_commands.cmd_job_list)
    for name, func in (
        ("status", jobs_commands.cmd_job_status),
        ("pause", jobs_commands.cmd_job_pause),
        ("resume", jobs_commands.cmd_job_resume),
        ("cancel", jobs_commands.cmd_job_cancel),
    ):
        p = j_sub.add_parser(name, help=f"Job {name}", parents=[common])
        p.add_argument("id")
        p.set_defaults(func=func)
    # recurring schedules (cron-style automation)
    j_sched = j_sub.add_parser("schedule", help="Recurring job schedules", parents=[common])
    s_sub = j_sched.add_subparsers(dest="schedule_command", metavar="SCHEDULE_COMMAND")
    s_add = s_sub.add_parser("add", help="Schedule a recurring job (policy-checked)", parents=[common])
    s_add.add_argument("capability")
    s_add.add_argument("target")
    s_add.add_argument("--cron", required=True, help="5-field cron, e.g. '0 6 * * *' (daily 06:00)")
    s_add.add_argument("--options", default=None, help="JSON object of tool options")
    s_add.add_argument("--engagement", type=int, default=None)
    s_add.add_argument("--user", required=True)
    s_add.add_argument("--password", default=None)
    s_add.add_argument("--role", default=None)
    s_add.add_argument("--workspace", default="RED_TEAM", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    s_add.set_defaults(func=jobs_commands.cmd_job_schedule_add)
    s_list = s_sub.add_parser("list", help="List schedules", parents=[common])
    s_list.set_defaults(func=jobs_commands.cmd_job_schedule_list)
    s_rm = s_sub.add_parser("remove", help="Remove a schedule", parents=[common])
    s_rm.add_argument("id", type=int)
    s_rm.set_defaults(func=jobs_commands.cmd_job_schedule_remove)
    s_run = s_sub.add_parser("run", help="Run a schedule now (re-checks scope)", parents=[common])
    s_run.add_argument("id", type=int)
    s_run.set_defaults(func=jobs_commands.cmd_job_schedule_run)

    # security data
    p_asset = sub.add_parser("asset", help="Assets", parents=[common])
    a1 = p_asset.add_subparsers(dest="asset_command", metavar="ASSET_COMMAND")
    a_list = a1.add_parser("list", help="List assets", parents=[common])
    a_list.add_argument("--engagement", type=int, default=None)
    a_list.set_defaults(func=data_commands.cmd_asset_list)

    p_finding = sub.add_parser("finding", help="Findings", parents=[common])
    f_sub = p_finding.add_subparsers(dest="finding_command", metavar="FINDING_COMMAND")
    f_create = f_sub.add_parser("create", help="Create a finding", parents=[common])
    f_create.add_argument("--title", required=True)
    f_create.add_argument("--description", default=None)
    f_create.add_argument("--severity", default="medium", choices=["info", "low", "medium", "high", "critical"])
    f_create.add_argument("--confidence", default="medium", choices=["low", "medium", "high"])
    f_create.add_argument("--recommendation", default=None)
    f_create.add_argument("--asset", type=int, default=None)
    f_create.add_argument("--engagement", type=int, default=None)
    f_create.add_argument("--source", default=None)
    f_create.add_argument("--risk", action="store_true", help="Calculate deterministic risk")
    f_create.add_argument("--criticality", default=None, choices=["low", "medium", "high", "critical"])
    f_create.add_argument("--exploitability", default=None, choices=["none", "low", "medium", "high"])
    f_create.add_argument("--exposure", default=None, choices=["internal", "limited", "internet"])
    f_create.add_argument("--impact", default=None, choices=["low", "medium", "high", "critical"])
    f_create.add_argument("--evidence", default=None, choices=["none", "partial", "reproducible", "verified"])
    f_create.set_defaults(func=data_commands.cmd_finding_create)
    f_list = f_sub.add_parser("list", help="List findings", parents=[common])
    f_list.add_argument("--engagement", type=int, default=None)
    f_list.add_argument("--status", default=None)
    f_list.add_argument("--severity", default=None)
    f_list.set_defaults(func=data_commands.cmd_finding_list)
    f_explain = f_sub.add_parser("explain", help="Explain a finding (mode-aware)", parents=[common])
    f_explain.add_argument("id", type=int)
    f_explain.set_defaults(func=data_commands.cmd_finding_explain)

    p_evidence = sub.add_parser("evidence", help="Evidence", parents=[common])
    ev_sub = p_evidence.add_subparsers(dest="evidence_command", metavar="EVIDENCE_COMMAND")
    ev_add = ev_sub.add_parser("add", help="Add evidence", parents=[common])
    ev_add.add_argument("--content", default=None)
    ev_add.add_argument("--file", default=None)
    ev_add.add_argument("--tool", default=None)
    ev_add.add_argument("--operator", default=None)
    ev_add.add_argument("--method", default=None)
    ev_add.add_argument("--source", default=None)
    ev_add.add_argument("--engagement", type=int, default=None)
    ev_add.set_defaults(func=data_commands.cmd_evidence_add)
    ev_list = ev_sub.add_parser("list", help="List evidence", parents=[common])
    ev_list.add_argument("--engagement", type=int, default=None)
    ev_list.set_defaults(func=data_commands.cmd_evidence_list)
    ev_verify = ev_sub.add_parser("verify", help="Verify evidence integrity", parents=[common])
    ev_verify.add_argument("id", type=int)
    ev_verify.set_defaults(func=data_commands.cmd_evidence_verify)

    # reporting
    p_report = sub.add_parser("report", help="Reporting", parents=[common])
    r_sub = p_report.add_subparsers(dest="report_command", metavar="REPORT_COMMAND")
    r_create = r_sub.add_parser("create", help="Generate a report", parents=[common])
    r_create.add_argument("--engagement", type=int, default=None)
    r_create.add_argument("--title", default=None)
    r_create.add_argument("--format", default="markdown", choices=["markdown", "html"])
    r_create.add_argument("--out", default=None, help="Write report to a file")
    r_create.add_argument("--user", default="")
    r_create.set_defaults(func=report_commands.cmd_report_create)
    r_list = r_sub.add_parser("list", help="List reports", parents=[common])
    r_list.set_defaults(func=report_commands.cmd_report_list)
    r_show = r_sub.add_parser("show", help="Show a report", parents=[common])
    r_show.add_argument("id", type=int)
    r_show.add_argument("--raw", action="store_true", help="Print full content")
    r_show.set_defaults(func=report_commands.cmd_report_show)

    # learning
    p_learn = sub.add_parser("learn", help="Learning curriculum", parents=[common])
    l_sub = p_learn.add_subparsers(dest="learn_command", metavar="LEARN_COMMAND")
    l_list = l_sub.add_parser("list", help="List curriculum phases and lessons", parents=[common])
    l_list.set_defaults(func=learn_commands.cmd_learn_list)
    l_lesson = l_sub.add_parser("lesson", help="Read a lesson", parents=[common])
    l_lesson.add_argument("--id", required=True)
    l_lesson.add_argument("--user", default=None)
    l_lesson.add_argument("--password", default=None)
    l_lesson.set_defaults(func=learn_commands.cmd_learn_lesson)
    l_complete = l_sub.add_parser("complete", help="Mark a lesson complete", parents=[common])
    l_complete.add_argument("--id", required=True)
    l_complete.add_argument("--user", required=True)
    l_complete.add_argument("--password", default=None)
    l_complete.set_defaults(func=learn_commands.cmd_learn_complete)
    l_progress = l_sub.add_parser("progress", help="Show learning progress", parents=[common])
    l_progress.add_argument("--user", required=True)
    l_progress.add_argument("--password", default=None)
    l_progress.set_defaults(func=learn_commands.cmd_learn_progress)

    # workflows
    p_workflow = sub.add_parser("workflow", help="User-defined workflows", parents=[common])
    w_sub = p_workflow.add_subparsers(dest="workflow_command", metavar="WORKFLOW_COMMAND")
    w_list = w_sub.add_parser("list", help="List workflows (built-in and custom)", parents=[common])
    w_list.set_defaults(func=workflow_commands.cmd_workflow_list)
    w_create = w_sub.add_parser("create", help="Create a custom workflow", parents=[common])
    w_create.add_argument("--name", required=True)
    w_create.add_argument("--description", default=None)
    w_create.add_argument("--user", default="")
    w_create.add_argument("--step", action="append", default=[], help="A capability step (repeatable)")
    w_create.add_argument("--steps-json", default=None, help="JSON list of step objects")
    w_create.set_defaults(func=workflow_commands.cmd_workflow_create)
    w_edit = w_sub.add_parser("edit", help="Edit a custom workflow", parents=[common])
    w_edit.add_argument("--name", required=True)
    w_edit.add_argument("--description", default=None)
    w_edit.add_argument("--step", action="append", default=[], help="A capability step (repeatable)")
    w_edit.add_argument("--steps-json", default=None, help="JSON list of step objects")
    w_edit.add_argument("--enable", action="store_true")
    w_edit.add_argument("--disable", action="store_true")
    w_edit.set_defaults(func=workflow_commands.cmd_workflow_edit)
    w_validate = w_sub.add_parser("validate", help="Validate a custom workflow", parents=[common])
    w_validate.add_argument("--name", required=True)
    w_validate.set_defaults(func=workflow_commands.cmd_workflow_validate)
    w_run = w_sub.add_parser("run", help="Run a workflow against a target", parents=[common])
    w_run.add_argument("name")
    w_run.add_argument("target")
    w_run.add_argument("--engagement", type=int, default=None)
    w_run.add_argument("--user", required=True)
    w_run.add_argument("--password", default=None)
    w_run.add_argument("--workspace", default="RED_TEAM", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    w_run.add_argument("--role", default=None)
    w_run.add_argument("--dry-run", action="store_true")
    w_run.set_defaults(func=workflow_commands.cmd_workflow_run)
    w_history = w_sub.add_parser("history", help="Workflow run history", parents=[common])
    w_history.add_argument("--name", default=None)
    w_history.add_argument("--limit", type=int, default=20)
    w_history.set_defaults(func=workflow_commands.cmd_workflow_history)

    # DFIR
    p_dfir = sub.add_parser("dfir", help="Digital forensics and incident response", parents=[common])
    d_sub = p_dfir.add_subparsers(dest="dfir_command", metavar="DFIR_COMMAND")
    d_art = d_sub.add_parser("artifact", help="Forensic artifacts", parents=[common])
    d_art_sub = d_art.add_subparsers(dest="artifact_command", metavar="ARTIFACT_COMMAND")
    d_add = d_art_sub.add_parser("add", help="Collect an artifact", parents=[common])
    d_add.add_argument("--case", type=int, required=True)
    d_add.add_argument("--type", required=True, help="file|log|process|network|auth|browser|malware|registry|memory|other")
    d_add.add_argument("--name", required=True)
    d_add.add_argument("--host", default=None)
    d_add.add_argument("--details", default=None)
    d_add.add_argument("--tool", default=None)
    d_add.add_argument("--evidence", type=int, default=None)
    d_add.add_argument("--collected-at", default=None)
    d_add.set_defaults(func=dfir_commands.cmd_artifact_add)
    d_list = d_art_sub.add_parser("list", help="List artifacts", parents=[common])
    d_list.add_argument("--case", type=int, default=None)
    d_list.add_argument("--host", default=None)
    d_list.set_defaults(func=dfir_commands.cmd_artifact_list)
    d_ev = d_sub.add_parser("event", help="Timeline events", parents=[common])
    d_ev_sub = d_ev.add_subparsers(dest="event_command", metavar="EVENT_COMMAND")
    d_ev_add = d_ev_sub.add_parser("add", help="Add a timeline event", parents=[common])
    d_ev_add.add_argument("--case", type=int, required=True)
    d_ev_add.add_argument("--time", required=True, help="ISO-8601 event time")
    d_ev_add.add_argument("--type", required=True, help="created|modified|deleted|executed|network|login|auth_failure|privilege|persistence|exfiltration|other")
    d_ev_add.add_argument("--actor", default=None)
    d_ev_add.add_argument("--source", default=None)
    d_ev_add.add_argument("--details", default=None)
    d_ev_add.add_argument("--artifact", type=int, default=None)
    d_ev_add.set_defaults(func=dfir_commands.cmd_event_add)
    d_tl = d_sub.add_parser("timeline", help="Show the incident timeline", parents=[common])
    d_tl.add_argument("--case", type=int, default=None)
    d_tl.add_argument("--event-type", default=None)
    d_tl.set_defaults(func=dfir_commands.cmd_timeline)

    # threat intelligence
    p_intel = sub.add_parser("intel", help="Threat intelligence (IOCs, actors, campaigns, TTPs)", parents=[common])
    i_sub = p_intel.add_subparsers(dest="intel_command", metavar="INTEL_COMMAND")
    i_ioc = i_sub.add_parser("ioc", help="Indicators of compromise", parents=[common])
    i_ioc_sub = i_ioc.add_subparsers(dest="ioc_command", metavar="IOC_COMMAND")
    i_add = i_ioc_sub.add_parser("add", help="Register an IOC", parents=[common])
    i_add.add_argument("--value", required=True)
    i_add.add_argument("--type", required=True, help="IP|DOMAIN|URL|HASH|EMAIL|USERNAME|FILE|PROCESS|CERTIFICATE|OTHER")
    i_add.add_argument("--confidence", default="medium", choices=["low", "medium", "high"])
    i_add.add_argument("--source", default=None)
    i_add.add_argument("--first-seen", default=None)
    i_add.add_argument("--last-seen", default=None)
    i_add.add_argument("--actor", default=None, help="Link to a threat actor by name")
    i_add.add_argument("--campaign", default=None, help="Link to a campaign by name")
    i_add.set_defaults(func=intel_commands.cmd_ioc_add)
    i_list = i_ioc_sub.add_parser("list", help="List IOCs", parents=[common])
    i_list.add_argument("--type", default=None)
    i_list.add_argument("--status", default=None)
    i_list.set_defaults(func=intel_commands.cmd_ioc_list)
    i_corr = i_ioc_sub.add_parser("correlate", help="Correlate an observation against IOCs", parents=[common])
    i_corr.add_argument("--value", required=True)
    i_corr.set_defaults(func=intel_commands.cmd_ioc_correlate)
    i_enrich = i_ioc_sub.add_parser("enrich", help="Enrich an IOC (actor, campaign, TTPs, findings)", parents=[common])
    i_enrich.add_argument("--ioc", type=int, required=True)
    i_enrich.set_defaults(func=intel_commands.cmd_ioc_enrich)
    i_extract = i_ioc_sub.add_parser("extract", help="Extract and auto-register IOCs from evidence", parents=[common])
    i_extract.add_argument("--job", default=None, help="Job id: extract from its stored result")
    i_extract.add_argument("--evidence", type=int, default=None, help="Evidence id: extract from stored content")
    i_extract.add_argument("--text", default=None, help="Raw text to scan")
    i_extract.add_argument("--source", default=None, help="Provenance source for registered IOCs")
    i_extract.add_argument("--confidence", default="medium", choices=["low", "medium", "high"], help="Confidence for text-derived candidates")
    i_extract.set_defaults(func=intel_commands.cmd_ioc_extract)
    i_actor = i_sub.add_parser("actor", help="Threat actors", parents=[common])
    i_actor_sub = i_actor.add_subparsers(dest="actor_command", metavar="ACTOR_COMMAND")
    a_add = i_actor_sub.add_parser("add", help="Add a threat actor", parents=[common])
    a_add.add_argument("--name", required=True)
    a_add.add_argument("--description", default=None)
    a_add.add_argument("--alias", action="append", default=[])
    a_add.add_argument("--source", action="append", default=[])
    a_add.set_defaults(func=intel_commands.cmd_actor_add)
    a_list = i_actor_sub.add_parser("list", help="List threat actors", parents=[common])
    a_list.set_defaults(func=intel_commands.cmd_actor_list)
    i_camp = i_sub.add_parser("campaign", help="Campaigns", parents=[common])
    i_camp_sub = i_camp.add_subparsers(dest="campaign_command", metavar="CAMPAIGN_COMMAND")
    c_add = i_camp_sub.add_parser("add", help="Add a campaign", parents=[common])
    c_add.add_argument("--name", required=True)
    c_add.add_argument("--description", default=None)
    c_add.add_argument("--actor", default=None)
    c_add.add_argument("--confidence", default="medium", choices=["low", "medium", "high"])
    c_add.set_defaults(func=intel_commands.cmd_campaign_add)
    c_list = i_camp_sub.add_parser("list", help="List campaigns", parents=[common])
    c_list.set_defaults(func=intel_commands.cmd_campaign_list)
    i_ttp = i_sub.add_parser("ttp", help="Tactics, techniques and procedures (ATT&CK)", parents=[common])
    i_ttp_sub = i_ttp.add_subparsers(dest="ttp_command", metavar="TTP_COMMAND")
    t_add = i_ttp_sub.add_parser("add", help="Add a TTP", parents=[common])
    t_add.add_argument("--technique-id", required=True)
    t_add.add_argument("--name", required=True)
    t_add.add_argument("--description", default=None)
    t_add.add_argument("--tactic", default=None)
    t_add.add_argument("--source", default=None)
    t_add.set_defaults(func=intel_commands.cmd_ttp_add)
    t_list = i_ttp_sub.add_parser("list", help="List TTPs", parents=[common])
    t_list.set_defaults(func=intel_commands.cmd_ttp_list)
    i_link = i_sub.add_parser("link", help="Link a TTP to a campaign", parents=[common])
    i_link.add_argument("--campaign", type=int, required=True)
    i_link.add_argument("--ttp", type=int, required=True)
    i_link.set_defaults(func=intel_commands.cmd_link_ttp)

    # plugins
    p_plugin = sub.add_parser("plugin", help="Plugin lifecycle (manifest, permissions, trust)", parents=[common])
    pl_sub = p_plugin.add_subparsers(dest="plugin_command", metavar="PLUGIN_COMMAND")
    pl_list = pl_sub.add_parser("list", help="List installed and bundled plugins", parents=[common])
    pl_list.set_defaults(func=plugin_commands.cmd_plugin_list)
    pl_info = pl_sub.add_parser("info", help="Show plugin details", parents=[common])
    pl_info.add_argument("name")
    pl_info.set_defaults(func=plugin_commands.cmd_plugin_info)
    pl_install = pl_sub.add_parser("install", help="Install a plugin from a directory", parents=[common])
    pl_install.add_argument("path", help="Path to the plugin directory (contains manifest.json)")
    pl_install.add_argument("--trust", default="THIRD_PARTY", choices=["CORE_TRUSTED", "VERIFIED", "LOCAL", "THIRD_PARTY", "UNTRUSTED", "BLOCKED"])
    pl_install.add_argument("--user", required=True)
    pl_install.add_argument("--password", default=None)
    pl_install.add_argument("--yes", action="store_true", help="Approve installation")
    pl_install.set_defaults(func=plugin_commands.cmd_plugin_install)
    pl_enable = pl_sub.add_parser("enable", help="Enable a plugin", parents=[common])
    pl_enable.add_argument("name")
    pl_enable.add_argument("--user", required=True)
    pl_enable.add_argument("--password", default=None)
    pl_enable.set_defaults(func=plugin_commands.cmd_plugin_enable)
    pl_disable = pl_sub.add_parser("disable", help="Disable a plugin", parents=[common])
    pl_disable.add_argument("name")
    pl_disable.add_argument("--user", required=True)
    pl_disable.add_argument("--password", default=None)
    pl_disable.set_defaults(func=plugin_commands.cmd_plugin_disable)
    pl_block = pl_sub.add_parser("block", help="Block a plugin", parents=[common])
    pl_block.add_argument("name")
    pl_block.add_argument("--user", required=True)
    pl_block.add_argument("--password", default=None)
    pl_block.set_defaults(func=plugin_commands.cmd_plugin_block)
    pl_uninstall = pl_sub.add_parser("uninstall", help="Uninstall a user plugin", parents=[common])
    pl_uninstall.add_argument("name")
    pl_uninstall.add_argument("--user", required=True)
    pl_uninstall.add_argument("--password", default=None)
    pl_uninstall.add_argument("--yes", action="store_true", help="Approve uninstall")
    pl_uninstall.set_defaults(func=plugin_commands.cmd_plugin_uninstall)
    pl_check = pl_sub.add_parser("check", help="Validate plugins: manifest, hash, health", parents=[common])
    pl_check.set_defaults(func=plugin_commands.cmd_plugin_check)

    # adversary simulation
    p_adv = sub.add_parser("adversary", help="Controlled adversary simulation (profiles, coverage, exercises)", parents=[common])
    adv_sub = p_adv.add_subparsers(dest="adv_command", metavar="ADV_COMMAND")
    adv_prof = adv_sub.add_parser("profile", help="Threat-actor profiles", parents=[common])
    ap_sub = adv_prof.add_subparsers(dest="profile_command", metavar="PROFILE_COMMAND")
    ap_add = ap_sub.add_parser("add", help="Create a profile", parents=[common])
    ap_add.add_argument("--name", required=True)
    ap_add.add_argument("--description", default=None)
    ap_add.add_argument("--threat-actor", default=None)
    ap_add.add_argument("--source", default=None)
    ap_add.add_argument("--technique", action="append", default=[], help="ATT&CK technique id (repeatable)")
    ap_add.add_argument("--steps-json", default=None, help="JSON list of step objects")
    ap_add.add_argument("--user", default="")
    ap_add.set_defaults(func=adversary_commands.cmd_adv_profile_add)
    ap_list = ap_sub.add_parser("list", help="List profiles", parents=[common])
    ap_list.set_defaults(func=adversary_commands.cmd_adv_profile_list)
    ap_show = ap_sub.add_parser("show", help="Show a profile", parents=[common])
    ap_show.add_argument("id", type=int)
    ap_show.set_defaults(func=adversary_commands.cmd_adv_profile_show)
    ap_del = ap_sub.add_parser("delete", help="Delete a profile", parents=[common])
    ap_del.add_argument("id", type=int)
    ap_del.set_defaults(func=adversary_commands.cmd_adv_profile_delete)
    adv_cov = adv_sub.add_parser("coverage", help="ATT&CK coverage analysis", parents=[common])
    adv_cov.add_argument("--profile", type=int, default=None)
    adv_cov.set_defaults(func=adversary_commands.cmd_adv_coverage)
    adv_ex = adv_sub.add_parser("exercise", help="Simulation exercises", parents=[common])
    ex_sub = adv_ex.add_subparsers(dest="exercise_command", metavar="EXERCISE_COMMAND")
    ex_new = ex_sub.add_parser("new", help="Create an exercise from a profile", parents=[common])
    ex_new.add_argument("--name", required=True)
    ex_new.add_argument("--profile", type=int, required=True)
    ex_new.add_argument("--engagement", type=int, default=None)
    ex_new.add_argument("--user", required=True)
    ex_new.add_argument("--password", default=None)
    ex_new.add_argument("--role", default=None)
    ex_new.add_argument("--workspace", default="ADVERSARY_SIMULATION", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    ex_new.set_defaults(func=adversary_commands.cmd_adv_exercise_new)
    ex_list = ex_sub.add_parser("list", help="List exercises", parents=[common])
    ex_list.set_defaults(func=adversary_commands.cmd_adv_exercise_list)
    ex_run = ex_sub.add_parser("run", help="Run an exercise (dry-run or live)", parents=[common])
    ex_run.add_argument("id", type=int)
    ex_run.add_argument("target")
    ex_run.add_argument("--engagement", type=int, default=None)
    ex_run.add_argument("--user", required=True)
    ex_run.add_argument("--password", default=None)
    ex_run.add_argument("--role", default=None)
    ex_run.add_argument("--workspace", default="ADVERSARY_SIMULATION", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    ex_run.add_argument("--dry-run", action="store_true", help="Policy-check without executing")
    ex_run.set_defaults(func=adversary_commands.cmd_adv_exercise_run)
    ex_chain = ex_sub.add_parser("chain", help="Run an exercise in ATT&CK kill-chain order", parents=[common])
    ex_chain.add_argument("id", type=int)
    ex_chain.add_argument("target")
    ex_chain.add_argument("--engagement", type=int, default=None)
    ex_chain.add_argument("--user", required=True)
    ex_chain.add_argument("--password", default=None)
    ex_chain.add_argument("--role", default=None)
    ex_chain.add_argument("--workspace", default="ADVERSARY_SIMULATION", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    ex_chain.add_argument("--dry-run", action="store_true", help="Policy-check without executing")
    ex_chain.set_defaults(func=adversary_commands.cmd_adv_chain)
    adv_rep = adv_sub.add_parser("report", help="Exercise report (technique coverage)", parents=[common])
    adv_rep.add_argument("id", type=int)
    adv_rep.set_defaults(func=adversary_commands.cmd_adv_report)

    # updates
    p_update = sub.add_parser("update", help="Offline update-readiness check (spec 01#36)", parents=[common])
    u_sub = p_update.add_subparsers(dest="update_command", metavar="UPDATE_COMMAND")
    u_check = u_sub.add_parser("check", help="Check version/migrations/rollback readiness", parents=[common])
    u_check.set_defaults(func=update_commands.cmd_update_check)

    # vulnerability checks (authorized, deterministic)
    p_vuln = sub.add_parser("vuln", help="Authorized deterministic vuln checks (TLS, headers, banners)", parents=[common])
    v_sub = p_vuln.add_subparsers(dest="vuln_command", metavar="VULN_COMMAND")
    v_list = v_sub.add_parser("checks", help="List available checks", parents=[common])
    v_list.set_defaults(func=vuln_commands.cmd_vuln_checks)
    v_check = v_sub.add_parser("check", help="Run checks against an in-scope target", parents=[common])
    v_check.add_argument("target")
    v_check.add_argument("--engagement", type=int, default=None)
    v_check.add_argument("--port", type=int, default=None, help="Override port (default: 80/443 by scheme)")
    v_check.add_argument("--user", required=True)
    v_check.add_argument("--password", default=None)
    v_check.set_defaults(func=vuln_commands.cmd_vuln_check)

    # notifications
    p_notify = sub.add_parser("notify", help="Notification store + provider test", parents=[common])
    n_sub = p_notify.add_subparsers(dest="notify_command", metavar="NOTIFY_COMMAND")
    n_list = n_sub.add_parser("list", help="List recorded notifications", parents=[common])
    n_list.add_argument("--limit", type=int, default=50)
    n_list.set_defaults(func=notify_commands.cmd_notify_list)
    n_test = n_sub.add_parser("test", help="Send a test through configured providers", parents=[common])
    n_test.add_argument("--title", default=None)
    n_test.add_argument("--body", default=None)
    n_test.set_defaults(func=notify_commands.cmd_notify_test)

    # soc
    p_soc = sub.add_parser("soc", help="SOC alert pipeline (normalize, enrich, correlate, alert, case)", parents=[common])
    soc_sub = p_soc.add_subparsers(dest="soc_command", metavar="SOC_COMMAND")

    p_ingest = soc_sub.add_parser("ingest", help="Run one event through the alert pipeline", parents=[common])
    p_ingest.add_argument("--event-id", default=None, help="Dedup key for the event")
    p_ingest.add_argument("--source", default="manual", help="firewall|ids|endpoint|siem|job|manual")
    p_ingest.add_argument("--event-type", default=None, help="auth_failure|port_scan|beacon|...")
    p_ingest.add_argument("--severity", default="medium", choices=["info", "low", "medium", "high", "critical"])
    p_ingest.add_argument("--ip", default=None)
    p_ingest.add_argument("--domain", default=None)
    p_ingest.add_argument("--host", default=None)
    p_ingest.add_argument("--username", default=None)
    p_ingest.add_argument("--process", default=None)
    p_ingest.add_argument("--details-json", default=None, help="Extra event fields as JSON")
    p_ingest.add_argument("--event-json", default=None, help="Full raw event as JSON (overrides flags)")
    p_ingest.set_defaults(func=soc_commands.cmd_soc_ingest)

    p_events = soc_sub.add_parser("event", help="Normalized SOC events", parents=[common])
    ev_sub = p_events.add_subparsers(dest="event_command", metavar="EVENT_COMMAND")
    p_ev_list = ev_sub.add_parser("list", help="List normalized events", parents=[common])
    p_ev_list.add_argument("--limit", type=int, default=50)
    p_ev_list.add_argument("--event-type", default=None)
    p_ev_list.add_argument("--entity", default=None, help="Filter by IP/domain/host")
    p_ev_list.set_defaults(func=soc_commands.cmd_soc_event_list)

    p_alerts = soc_sub.add_parser("alert", help="SOC alerts", parents=[common])
    a_sub = p_alerts.add_subparsers(dest="alert_command", metavar="ALERT_COMMAND")
    a_list = a_sub.add_parser("list", help="List alerts", parents=[common])
    a_list.add_argument("--limit", type=int, default=50)
    a_list.add_argument("--status", default=None, choices=["open", "acknowledged", "resolved", "closed"])
    a_list.add_argument("--severity", default=None, choices=["info", "low", "medium", "high", "critical"])
    a_list.set_defaults(func=soc_commands.cmd_soc_alert_list)
    a_show = a_sub.add_parser("show", help="Show an alert", parents=[common])
    a_show.add_argument("id", type=int)
    a_show.set_defaults(func=soc_commands.cmd_soc_alert_show)
    a_act = a_sub.add_parser("action", help="ack|resolve|close an alert", parents=[common])
    a_act.add_argument("action", choices=["ack", "resolve", "close"])
    a_act.add_argument("id", type=int)
    a_act.add_argument("--case", type=int, default=None, help="Link a case on resolve")
    a_act.add_argument("--user", default=None, help="Record this actor in the audit log")
    a_act.add_argument("--password", default=None)
    a_act.set_defaults(func=soc_commands.cmd_soc_alert_action)

    p_rules = soc_sub.add_parser("rule", help="SOC detection rules", parents=[common])
    r_sub = p_rules.add_subparsers(dest="rule_command", metavar="RULE_COMMAND")
    r_add = r_sub.add_parser("add", help="Create a detection rule", parents=[common])
    r_add.add_argument("--name", required=True)
    r_add.add_argument("--description", default=None)
    r_add.add_argument("--event-type", default=None, help="Restrict to one event type")
    r_add.add_argument("--field", default="ip", choices=["ip", "domain", "host", "username", "process", "source", "event_type", "severity", "details"])
    r_add.add_argument("--operator", default="eq", choices=["eq", "ne", "contains", "regex", "min_severity"])
    r_add.add_argument("--value", default=None)
    r_add.add_argument("--severity", default="medium", choices=["info", "low", "medium", "high", "critical"])
    r_add.add_argument("--risk-boost", type=float, default=0.0)
    r_add.add_argument("--no-case", action="store_true", help="Do not auto-open a case")
    r_add.set_defaults(func=soc_commands.cmd_soc_rule_add)
    r_list = r_sub.add_parser("list", help="List detection rules", parents=[common])
    r_list.add_argument("--enabled-only", action="store_true")
    r_list.set_defaults(func=soc_commands.cmd_soc_rule_list)
    for toggle in ("enable", "disable"):
        r_toggle = r_sub.add_parser(toggle, help=f"{toggle} a rule", parents=[common])
        r_toggle.add_argument("id", type=int)
        r_toggle.set_defaults(func=soc_commands.cmd_soc_rule_toggle, enable=toggle == "enable")
    r_del = r_sub.add_parser("delete", help="Delete a rule", parents=[common])
    r_del.add_argument("id", type=int)
    r_del.set_defaults(func=soc_commands.cmd_soc_rule_delete)

    # atomic red tests (detection validation)
    p_atomic = sub.add_parser("atomic", help="Atomic red tests for detection validation", parents=[common])
    at_sub = p_atomic.add_subparsers(dest="atomic_command", metavar="ATOMIC_COMMAND")
    at_list = at_sub.add_parser("list", help="List atomic tests", parents=[common])
    at_list.set_defaults(func=atomic_commands.cmd_atomic_list)
    at_info = at_sub.add_parser("info", help="Show an atomic test", parents=[common])
    at_info.add_argument("id")
    at_info.set_defaults(func=atomic_commands.cmd_atomic_info)
    at_run = at_sub.add_parser("run", help="Run an atomic test against an in-scope target", parents=[common])
    at_run.add_argument("id")
    at_run.add_argument("target")
    at_run.add_argument("--engagement", type=int, default=None)
    at_run.add_argument("--user", required=True)
    at_run.add_argument("--password", default=None)
    at_run.add_argument("--role", default=None)
    at_run.add_argument("--workspace", default="ADVERSARY_SIMULATION", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    at_run.set_defaults(func=atomic_commands.cmd_atomic_run)

    # alias: ksec run NAME TARGET (spec example)
    p_run = sub.add_parser("run", help="Alias for workflow run", parents=[common])
    p_run.add_argument("name")
    p_run.add_argument("target")
    p_run.add_argument("--engagement", type=int, default=None)
    p_run.add_argument("--user", required=True)
    p_run.add_argument("--password", default=None)
    p_run.add_argument("--workspace", default="RED_TEAM", choices=["RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK"])
    p_run.add_argument("--role", default=None)
    p_run.add_argument("--dry-run", action="store_true")
    p_run.set_defaults(func=workflow_commands.cmd_workflow_run)

    # backups
    p_backup = sub.add_parser("backup", help="Backup and recovery", parents=[common])
    b_sub = p_backup.add_subparsers(dest="backup_command", metavar="BACKUP_COMMAND")
    b_create = b_sub.add_parser("create", help="Create a backup", parents=[common])
    b_create.set_defaults(func=backup_commands.cmd_backup_create)
    b_list = b_sub.add_parser("list", help="List backups", parents=[common])
    b_list.set_defaults(func=backup_commands.cmd_backup_list)
    b_verify = b_sub.add_parser("verify", help="Verify backup integrity", parents=[common])
    b_verify.add_argument("id", type=int)
    b_verify.set_defaults(func=backup_commands.cmd_backup_verify)
    b_restore = b_sub.add_parser("restore", help="Restore a backup", parents=[common])
    b_restore.add_argument("id", type=int)
    b_restore.add_argument("--yes", action="store_true", help="Approve restore")
    b_restore.set_defaults(func=backup_commands.cmd_backup_restore)

    # interfaces
    p_tui = sub.add_parser("tui", help="Launch the terminal UI", parents=[common])
    p_tui.set_defaults(func=ui_commands.cmd_tui)
    p_dash = sub.add_parser("dashboard", help="Local web dashboard", parents=[common])
    d_sub = p_dash.add_subparsers(dest="dashboard_command", metavar="DASHBOARD_COMMAND")
    d_start = d_sub.add_parser("start", help="Start the dashboard server", parents=[common])
    d_start.add_argument("--host", default="127.0.0.1")
    d_start.add_argument("--port", type=int, default=8080)
    d_start.add_argument("--background", action="store_true", help="Run in background thread")
    d_start.set_defaults(func=ui_commands.cmd_dashboard_start)

    p_case = sub.add_parser("case", help="Cases", parents=[common])
    c_sub = p_case.add_subparsers(dest="case_command", metavar="CASE_COMMAND")
    c_create = c_sub.add_parser("create", help="Create a case", parents=[common])
    c_create.add_argument("--title", required=True)
    c_create.add_argument("--description", default=None)
    c_create.add_argument("--severity", default="info", choices=["info", "low", "medium", "high", "critical"])
    c_create.add_argument("--owner", default=None)
    c_create.add_argument("--engagement", type=int, default=None)
    c_create.set_defaults(func=data_commands.cmd_case_create)
    c_list = c_sub.add_parser("list", help="List cases", parents=[common])
    c_list.set_defaults(func=data_commands.cmd_case_list)
    c_add = c_sub.add_parser("add-finding", help="Link a finding to a case", parents=[common])
    c_add.add_argument("--case", type=int, required=True)
    c_add.add_argument("--finding", type=int, required=True)
    c_add.set_defaults(func=data_commands.cmd_case_add_finding)
    c_close = c_sub.add_parser("close", help="Close a case", parents=[common])
    c_close.add_argument("id", type=int)
    c_close.add_argument("--user", default=None, help="Record this actor in the audit log")
    c_close.add_argument("--password", default=None)
    c_close.set_defaults(func=data_commands.cmd_case_close)

    # in-tool mentor: ask anything, basics included, never leave the tool
    p_ask = sub.add_parser(
        "ask",
        help="Ask anything in plain language (concepts, tools, role playbooks, modules)",
        parents=[common],
    )
    p_ask.add_argument("question", nargs="*", help="Your question, e.g. 'what is a port' or 'red team kaise shuru karun'")
    p_ask.add_argument("--list", dest="list_topics", action="store_true", help="List every topic in the knowledge base")
    p_ask.set_defaults(func=ask_commands.cmd_ask)

    p_role = sub.add_parser(
        "role",
        help="Show a role playbook: red | blue | purple | learner",
        parents=[common],
    )
    p_role.add_argument("name", help="red | blue | purple | learner")
    p_role.set_defaults(func=ask_commands.cmd_role)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"ksec {__version__}")
        return 0

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0

    try:
        ctx = bootstrap()
        try:
            return func(ctx, args) or 0
        finally:
            ctx.close()
    except KSECError as exc:
        print(
            f"error: {exc.message} (code={exc.info.code}, "
            f"correlation_id={exc.info.correlation_id})",
            file=sys.stderr,
        )
        if getattr(args, "verbose", False):
            import json

            print(json.dumps(exc.to_dict(), indent=2), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())