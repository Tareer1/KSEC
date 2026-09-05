"""Hands-on practice drills (spec: learn practice / practical labs).

Each drill is a safe, offline, authorized exercise that the learner performs
in KSEC and then marks passed. Completion is recorded per user in
``practice_progress``. No drill requires an unauthorized target.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PracticeDrill:
    drill_id: str
    title: str
    phase: int
    summary: str
    steps: tuple[str, ...]  # suggested commands / actions
    verify: str             # how the learner proves the result


PRACTICE_DRILLS: tuple[PracticeDrill, ...] = (
    PracticeDrill(
        "practice.scope",
        "Create an authorized engagement",
        1,
        "Stand up a written-authorization engagement with an allow-scope rule.",
        (
            "python3 -m ksec engagement create --name lab-scope",
            "python3 -m ksec engagement scope add --engagement 1 --target lab.local --effect allow",
        ),
        "ksec engagement list shows the engagement and its scope rule.",
    ),
    PracticeDrill(
        "practice.recon",
        "Run a recon workflow",
        6,
        "Run the built-in recon workflow against an in-scope target.",
        (
            "python3 -m ksec assess lab.local --workflow recon --engagement 1"
            " --user admin --password <pw>",
        ),
        "Assets are auto-registered from the recon job's output.",
    ),
    PracticeDrill(
        "practice.finding",
        "Document a finding with risk",
        7,
        "Create a finding and let KSEC compute its deterministic risk score.",
        (
            "python3 -m ksec finding create --title 'Open management port'"
            " --severity high --risk --engagement 1",
        ),
        "ksec finding list shows the finding with a risk score and reasoning.",
    ),
    PracticeDrill(
        "practice.detect",
        "Write a SOC detection rule",
        8,
        "Add a detection rule and ingest an event that should fire it.",
        (
            "python3 -m ksec soc rule add --name 'Many auth failures'"
            " --event-type auth_failure --field ip --operator min_severity"
            " --value medium --count 3 --within 5",
            "python3 -m ksec soc ingest --source firewall --event-type auth_failure"
            " --severity high --ip 10.0.0.9",
        ),
        "ksec soc alert list shows an open alert created by the rule.",
    ),
    PracticeDrill(
        "practice.artifact",
        "Collect a forensic artifact",
        9,
        "Open a DFIR case and collect a hashed artifact with chain of custody.",
        (
            "python3 -m ksec case create --title 'Drill case' --severity medium",
            "python3 -m ksec dfir artifact add --case 1 --type process --name sshd",
            "python3 -m ksec evidence verify 1",
        ),
        "ksec dfir artifact list shows the artifact for the case.",
    ),
    PracticeDrill(
        "practice.report",
        "Produce a report",
        11,
        "Generate a markdown report from an engagement.",
        (
            "python3 -m ksec report create --engagement 1 --title 'Lab Report'",
        ),
        "ksec report list shows the stored report.",
    ),
)


def drills() -> list[PracticeDrill]:
    return list(PRACTICE_DRILLS)


def find_drill(drill_id: str) -> PracticeDrill | None:
    for drill in PRACTICE_DRILLS:
        if drill.drill_id == drill_id:
            return drill
    return None
