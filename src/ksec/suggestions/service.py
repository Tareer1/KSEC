"""Role suggestions — deterministic, state-aware "what to do now" steps.

Given a role, inspect the live platform state (users, engagements, scope
rules, sessions, tools, alerts, findings, lessons) and return an ordered
list of concrete next actions. 100% offline and rule-based: no AI, no
network. The same engine powers ``ksec role`` playbook trailers, ``ksec
ask`` role answers and ``ksec suggest``.
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext

# alias -> canonical role id used for topic + suggestions
ROLE_ALIASES: dict[str, str] = {
    "red": "red",
    "blue": "blue",
    "purple": "purple",
    "researcher": "purple",
    "osint": "purple",
    "blackhat": "blackhat",
    "black hat": "blackhat",
    "learner": "learner",
    "learning": "learner",
}

ROLE_LABELS: dict[str, str] = {
    "red": "Red Team (authorized attacker)",
    "blue": "Blue Team / SOC defender",
    "purple": "Purple Team / researcher / OSINT",
    "blackhat": "Black Hat emulation (controlled, authorized)",
    "learner": "Learner",
}


def _suggestions_dataclass():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Suggestion:
        step: str
        command: str
        reason: str
        priority: int = 50  # lower runs first
        state: str = "todo"  # todo | done | info

    return Suggestion


def canonical_role(name: str) -> str | None:
    return ROLE_ALIASES.get((name or "").strip().lower())


def _admin_username(ctx: KsecContext) -> str:
    try:
        row = ctx.db.query_one(
            "SELECT u.username FROM users u ORDER BY u.id LIMIT 1"
        )
        return row["username"] if row else "admin"
    except Exception:  # pragma: no cover
        return "admin"


def _counts(ctx: KsecContext) -> dict:
    counts = {
        "users": 0,
        "engagements": 0,
        "scope_rules": 0,
        "sessions": 0,
        "tools_ready": 0,
        "tools_total": 0,
        "findings": 0,
        "alerts": 0,
        "iocs": 0,
        "cases": 0,
        "completed_lessons": 0,
    }
    try:
        row = ctx.db.query_one("SELECT COUNT(*) AS c FROM users")
        counts["users"] = row["c"] if row else 0
        row = ctx.db.query_one("SELECT COUNT(*) AS c FROM engagements")
        counts["engagements"] = row["c"] if row else 0
        row = ctx.db.query_one("SELECT COUNT(*) AS c FROM authorizations")
        counts["scope_rules"] = row["c"] if row else 0
        row = ctx.db.query_one(
            "SELECT COUNT(*) AS c FROM sessions WHERE state='ACTIVE'"
        )
        counts["sessions"] = row["c"] if row else 0
        # Cheap binary presence check (shutil.which only — no subprocess
        # version probing on every suggestion call).
        import shutil

        definitions = ctx.capabilities.definitions()
        counts["tools_total"] = len(definitions)
        counts["tools_ready"] = sum(
            1 for t in definitions if shutil.which(t.binary) is not None
        )
        counts["findings"] = len(ctx.findings.list())
        counts["alerts"] = ctx.soc_alerts.count()
        counts["iocs"] = len(ctx.intel.list_iocs())
        counts["cases"] = len(ctx.cases.list())
        row = ctx.db.query_one(
            "SELECT COUNT(*) AS c FROM learning_progress WHERE status='completed'"
        )
        counts["completed_lessons"] = row["c"] if row else 0
    except Exception:  # pragma: no cover - read-only best effort
        pass
    return counts


def _first_engagement(ctx: KsecContext) -> int | None:
    row = ctx.db.query_one("SELECT id FROM engagements ORDER BY id LIMIT 1")
    return row["id"] if row else None


def _engagement_has_scope(ctx: KsecContext, engagement_id: int) -> bool:
    row = ctx.db.query_one(
        "SELECT COUNT(*) AS c FROM authorizations WHERE engagement_id=?",
        (engagement_id,),
    )
    return bool(row and row["c"] > 0)


def suggestions(ctx: KsecContext, role: str) -> dict:
    """Return {role, label, items:[...]} — items are the pending next steps,
    lowest priority first, with a short reason for each."""
    role = canonical_role(role) or "red"
    label = ROLE_LABELS.get(role, role)
    c = _counts(ctx)
    user = _admin_username(ctx)
    eng = _first_engagement(ctx)
    eng_scoped = bool(eng and _engagement_has_scope(ctx, eng))
    Suggestion = _suggestions_dataclass()

    items: list = []

    def add(step: str, command: str, reason: str, priority: int = 50,
            state: str = "todo") -> None:
        items.append(Suggestion(step, command, reason, priority, state))

    # ---- universal setup (all roles) ------------------------------------
    if c["users"] == 0:
        add(
            "Initialize KSEC and create your admin user",
            f"python3 -m ksec init --username {user} --password 'change-me'",
            "No users exist yet — KSEC needs an account before anything else.",
            10,
        )
    if c["engagements"] == 0:
        add(
            "Create your first engagement (written authorization scope)",
            "python3 -m ksec engagement create --name first-assessment",
            "Every action against a target requires an authorized engagement — "
            "create one before running anything.",
            20,
        )
    if eng is not None and not eng_scoped:
        add(
            "Add a scope rule to your engagement",
            f"python3 -m ksec engagement scope add --engagement {eng} "
            "--target your-target.example --effect allow",
            "Your engagement has no allow rules yet, so every run would be "
            "blocked by the policy gate.",
            25,
        )

    # ---- per-role next actions -------------------------------------------
    if role in ("red", "blackhat"):
        if eng is not None and eng_scoped:
            add(
                "Run an authorized recon pass on the in-scope target",
                f"python3 -m ksec run recon your-target.example --engagement {eng} "
                f"--user {user} --password ...",
                "Start with passive + light-active recon to see what the target "
                "exposes.",
                30,
            )
            add(
                "Assess the target end-to-end",
                f"python3 -m ksec assess your-target.example --engagement {eng} "
                f"--user {user} --password ...",
                "The assess workflow runs dig + nmap + HTTP probing in one "
                "policy-gated pass.",
                35,
            )
        add(
            "Review which tools are installed",
            "python3 -m ksec tools list --missing",
            f"{c['tools_total'] - c['tools_ready']} of {c['tools_total']} "
            "capabilities have no tool installed — install the ones you need.",
            60,
        )
        if c["findings"] == 0:
            add(
                "Log a finding once you see something",
                "python3 -m ksec finding create --title 'first observation' "
                "--severity medium --risk",
                "Findings are how observations become trackable, risk-scored "
                "work items.",
            70,
        )
    if role == "blackhat":
        add(
            "Model the intruder with an adversary profile",
            "python3 -m ksec adversary profile add --name blackhat-ops "
            "--threat-actor 'Real-World Intruder' --technique T1190",
            "Black-hat emulation means modeling a real intruder inside your "
            "authorized engagement — never outside it.",
            40,
        )
        if eng is not None and eng_scoped:
            add(
                "Run a dry adversary exercise (nothing executes)",
                f"python3 -m ksec adversary exercise new --name bh-ex --profile 1 "
                f"--engagement {eng} --user {user} --password ...",
                "Dry runs validate the kill-chain plan against scope before "
                "anything live.",
            45,
            )

    if role == "blue":
        if c["alerts"] == 0:
            add(
                "Push sample telemetry through the SOC pipeline",
                "python3 -m ksec siem demo --ingest",
                "The SOC pipeline has no alerts yet — ingest the built-in demo "
                "records to see detection in action.",
                30,
            )
        add(
            "List open alerts and triage them",
            "python3 -m ksec soc alert list --status open",
            f"{c['alerts']} alert(s) exist; acknowledge, resolve or close them "
            "with ksec soc alert action.",
            35,
        )
        add(
            "Add a detection rule",
            "python3 -m ksec soc rule add --name brute-force --match "
            "auth_failed --severity high",
            "Rules turn normalized events into alerts; start with one and tune "
            "from real output.",
            40,
        )
        add(
            "Validate your detections with atomic red tests",
            "python3 -m ksec atomic list",
            "Atomics prove whether Blue's rules actually fire.",
            55,
        )

    if role == "purple":
        if c["iocs"] == 0:
            add(
                "Register or harvest threat indicators",
                "python3 -m ksec intel ioc add --value evil.example --type DOMAIN "
                "--confidence medium",
                "IOCs feed the correlation engine; add one manually or extract "
                "from job evidence.",
                30,
            )
        add(
            "Survey OSINT on an in-scope target",
            "python3 -m ksec run osint_harvest your-target.example "
            "--workspace RESEARCH_OSINT",
            "Purple/research starts with passive OSINT collection.",
            35,
        )
        add(
            "Analyze ATT&CK coverage",
            "python3 -m ksec adversary coverage",
            "See which techniques the environment can actually exercise.",
            45,
        )

    if role == "learner":
        if c["completed_lessons"] == 0:
            add(
                "Start the first lesson",
                "python3 -m ksec learn list",
                "The 12-phase curriculum starts at zero — pick lesson 1 and "
                "open it.",
                30,
            )
        add(
            "Mark a lesson complete to level up",
                "python3 -m ksec learn complete --id 1 --user learner",
            f"{c['completed_lessons']} lesson(s) completed so far — finishing "
            "lessons raises your Explorer -> Practitioner level.",
            40,
        )
        add(
            "Ask the mentor anything",
            "python3 -m ksec ask 'what is a port'",
            "The AI-free mentor answers concepts, tools and role questions "
            "instantly.",
            50,
        )

    ordered = sorted(items, key=lambda s: s.priority)
    return {
        "role": role,
        "label": label,
        "items": [vars(s) for s in ordered],
        "state": {
            "users": c["users"],
            "engagements": c["engagements"],
            "scope_rules": c["scope_rules"],
            "active_sessions": c["sessions"],
            "tools_ready": c["tools_ready"],
            "tools_total": c["tools_total"],
            "findings": c["findings"],
            "alerts": c["alerts"],
            "iocs": c["iocs"],
            "completed_lessons": c["completed_lessons"],
        },
    }