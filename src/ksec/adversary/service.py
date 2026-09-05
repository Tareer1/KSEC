"""Adversary simulation engine (spec 01#7, 08#12-15).

* Profiles: named threat-actor models with ordered TTP steps.
* Each step maps an ATT&CK technique to a KSEC capability (the emulation).
* Exercises: profile + engagement + operator, run step by step through the
  policy engine (authorization + scope are enforced per step).
* Coverage: which ATT&CK techniques the exercise/profile covered.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.identity.users import now_utc


@dataclass(frozen=True)
class AdversaryStep:
    id: int | None
    position: int
    technique_id: str
    tactic: str
    capability: str
    description: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "position": self.position,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "capability": self.capability,
            "description": self.description,
        }


@dataclass(frozen=True)
class AdversaryProfile:
    id: int
    name: str
    description: str
    threat_actor: str
    source: str
    steps: list[AdversaryStep]
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "threat_actor": self.threat_actor,
            "source": self.source,
            "steps": [s.to_dict() for s in self.steps],
            "techniques": [s.technique_id for s in self.steps],
            "created_at": self.created_at,
        }


# Built-in ATT&CK technique -> tactic map used when a step has no tactic
# recorded (kept in sync with the techniques KSEC can emulate).
TACTIC_MAP = {
    "T1590": "reconnaissance",
    "T1595": "reconnaissance",
    "T1190": "initial-access",
    "T1566": "initial-access",
    "T1059": "execution",
    "T1053": "persistence",
    "T1547": "persistence",
    "T1505.003": "persistence",
    "T1078": "defense-evasion",
    "T1046": "discovery",
    "T1082": "discovery",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1005": "collection",
    "T1213": "collection",
    "T1021": "lateral-movement",
    "T1567": "exfiltration",
    "T1041": "exfiltration",
    "T1055": "defense-evasion",
    "T1485": "impact",
}

# ATT&CK tactic chain (kill-chain order). Steps are executed in this order
# for `adversary chain`; unknown tactics sort last (stable by position).
CHAIN_PHASES = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def _chain_index(tactic: str) -> int:
    t = (tactic or "").strip().lower()
    try:
        return CHAIN_PHASES.index(t)
    except ValueError:
        return len(CHAIN_PHASES)


class AdversaryService:
    def __init__(self, db: Database):
        self.db = db

    # -- profiles ---------------------------------------------------------

    def create_profile(
        self,
        name: str,
        *,
        description: str = "",
        threat_actor: str = "",
        source: str = "",
        created_by: str = "",
        steps: list[dict] | None = None,
    ) -> AdversaryProfile:
        if not name or not name.strip():
            raise ValueError("profile name must not be empty")
        steps = steps or []
        if not steps:
            raise ValueError("profile must contain at least one step")
        for step in steps:
            if not step.get("capability"):
                raise ValueError("each profile step requires a 'capability'")
        now = now_utc()
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO advsim_profiles (name, description, threat_actor, source,"
                    " created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name.strip(), description, threat_actor, source, created_by, now, now),
                )
                profile_id = cursor.lastrowid
                for position, step in enumerate(steps, start=1):
                    conn.execute(
                        "INSERT INTO advsim_profile_steps (profile_id, position, ttp_id,"
                        " technique_id, tactic, capability, description)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            profile_id,
                            position,
                            self._ttp_id(step.get("technique_id", ""), step.get("tactic", "")),
                            step.get("technique_id", ""),
                            self._resolve_tactic(
                                step.get("technique_id", ""), step.get("tactic", "")
                            ),
                            step["capability"],
                            step.get("description", ""),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Profile {name!r} already exists") from exc
        return self.get_profile(cursor.lastrowid)

    def _resolve_tactic(self, technique_id: str, current: str = "") -> str:
        """Tactic for a technique: stored value, built-in map, then ttps table."""
        if (current or "").strip():
            return current.strip()
        key = (technique_id or "").strip().upper()
        if key in TACTIC_MAP:
            return TACTIC_MAP[key]
        row = self.db.query_one(
            "SELECT tactic FROM ttps WHERE technique_id = ? AND tactic != '' LIMIT 1",
            (key,),
        )
        return (row["tactic"] if row else "").strip()

    def _ttp_id(self, technique_id: str, tactic: str = "") -> int | None:
        if not technique_id:
            return None
        row = self.db.query_one(
            "SELECT id FROM ttps WHERE technique_id = ?", (technique_id.upper(),)
        )
        if row is not None:
            return row["id"]
        # Auto-record the technique as a framework record so coverage works.
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO ttps (framework, technique_id, name, description, tactic,"
            " source, created_at) VALUES ('mitre-attack', ?, ?, '', ?, 'adversary profile', ?)",
            (technique_id.upper(), technique_id.upper(), tactic, now_utc()),
        )
        row = self.db.query_one(
            "SELECT id FROM ttps WHERE technique_id = ?", (technique_id.upper(),)
        )
        return row["id"] if row else cursor.lastrowid or None

    def get_profile(self, profile_id: int) -> AdversaryProfile | None:
        row = self.db.query_one(
            "SELECT * FROM advsim_profiles WHERE id = ?", (profile_id,)
        )
        if row is None:
            return None
        steps = [
            AdversaryStep(
                id=step["id"],
                position=step["position"],
                technique_id=step["technique_id"],
                tactic=step["tactic"],
                capability=step["capability"],
                description=step["description"],
            )
            for step in self.db.query_all(
                "SELECT * FROM advsim_profile_steps WHERE profile_id = ? ORDER BY position",
                (profile_id,),
            )
        ]
        return AdversaryProfile(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            threat_actor=row["threat_actor"],
            source=row["source"],
            steps=steps,
            created_at=row["created_at"],
        )

    def list_profiles(self) -> list[AdversaryProfile]:
        rows = self.db.query_all("SELECT id FROM advsim_profiles ORDER BY name")
        return [profile for row in rows if (profile := self.get_profile(row["id"]))]

    def delete_profile(self, profile_id: int) -> None:
        self.db.execute("DELETE FROM advsim_profiles WHERE id = ?", (profile_id,))

    def coverage(self, profile_id: int | None = None) -> dict:
        """ATT&CK coverage: techniques per tactic across profiles/exercises."""
        if profile_id is not None:
            rows = self.db.query_all(
                "SELECT technique_id, tactic, capability FROM advsim_profile_steps"
                " WHERE profile_id = ? ORDER BY tactic, technique_id",
                (profile_id,),
            )
            label = f"profile:{profile_id}"
        else:
            rows = self.db.query_all(
                "SELECT technique_id, tactic, capability FROM advsim_profile_steps"
                " ORDER BY tactic, technique_id"
            )
            label = "all-profiles"
        techniques: dict[str, list[str]] = {}
        capabilities: dict[str, list[str]] = {}
        for row in rows:
            techniques.setdefault(row["tactic"] or "other", []).append(row["technique_id"])
            if row["capability"]:
                capabilities.setdefault(row["capability"], []).append(row["technique_id"])
        return {
            "scope": label,
            "total_techniques": sum(len(v) for v in techniques.values()),
            "by_tactic": {k: sorted(set(v)) for k, v in techniques.items()},
            "capability_map": capabilities,
        }

    # -- exercises --------------------------------------------------------

    def create_exercise(
        self,
        name: str,
        *,
        profile_id: int,
        engagement_id: int | None = None,
        operator_id: int | None = None,
    ) -> int:
        profile = self.get_profile(profile_id)
        if profile is None:
            raise ValueError(f"Unknown profile: {profile_id}")
        cursor = self.db.execute(
            "INSERT INTO advsim_exercises (name, profile_id, engagement_id, workspace,"
            " status, operator_id, created_at) VALUES (?, ?, ?, 'ADVERSARY_SIMULATION',"
            " 'planned', ?, ?)",
            (name.strip(), profile_id, engagement_id, operator_id, now_utc()),
        )
        exercise_id = cursor.lastrowid
        with self.db.transaction() as conn:
            for step in profile.steps:
                conn.execute(
                    "INSERT INTO advsim_exercise_steps (exercise_id, profile_step_id,"
                    " position, technique_id, tactic, capability, state, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, 'planned', ?)",
                    (
                        exercise_id,
                        step.id,
                        step.position,
                        step.technique_id,
                        step.tactic,
                        step.capability,
                        now_utc(),
                    ),
                )
        return exercise_id

    def plan_exercise(
        self,
        exercise_id: int,
        *,
        user,
        target: str,
        engagement_id: int | None,
        policy,
        dry_run: bool = True,
        scheduler=None,
        session=None,
        chain: bool = False,
    ) -> dict:
        """Run a policy check per step (dry-run plan or live exercise).

        With ``chain=True`` steps execute in ATT&CK kill-chain order
        (tactic phases) instead of stored position, and each outcome is
        annotated with its phase.
        """
        exercise = self.db.query_one(
            "SELECT * FROM advsim_exercises WHERE id = ?", (exercise_id,)
        )
        if exercise is None:
            raise ValueError(f"Unknown exercise: {exercise_id}")
        steps = self.db.query_all(
            "SELECT * FROM advsim_exercise_steps WHERE exercise_id = ? ORDER BY position",
            (exercise_id,),
        )
        if not steps:
            raise ValueError("exercise has no steps")
        ordered = sorted(steps, key=lambda s: _chain_index(s["tactic"])) if chain else steps

        self.db.execute(
            "UPDATE advsim_exercises SET status = 'running', started_at = ? WHERE id = ?",
            (now_utc(), exercise_id),
        )
        outcomes = []
        for step in ordered:
            from ksec.capabilities.catalog import capability_permission

            action = capability_permission(step["capability"])
            decision = policy.evaluate(
                user=user,
                action=action,
                session=session,
                target=target,
                engagement_id=engagement_id,
            )
            tactic = self._resolve_tactic(step["technique_id"], step["tactic"])
            step_outcome = {
                "position": step["position"],
                "technique_id": step["technique_id"],
                "tactic": tactic,
                "phase": tactic.strip().lower() if tactic else "unknown",
                "capability": step["capability"],
                "policy_decision": decision.decision.value,
                "policy_reason": decision.reason,
                "state": "planned",
                "job_id": None,
            }
            allowed = decision.decision.value == "ALLOW"
            job = None
            if not dry_run and allowed and scheduler is not None:
                job = scheduler.submit(
                    capability=step["capability"],
                    target=target,
                    session_id=session.id if session else None,
                    user_id=user.id,
                    workspace="ADVERSARY_SIMULATION",
                )
                completed = scheduler.wait_for(job.id)
                step_outcome["job_id"] = job.id
                step_outcome["state"] = completed.state.lower()
            elif not dry_run:
                step_outcome["state"] = "blocked"
            self.db.execute(
                "UPDATE advsim_exercise_steps SET policy_decision = ?, policy_reason = ?,"
                " state = ?, job_id = ?, target = ?, observed_at = ? WHERE id = ?",
                (
                    step_outcome["policy_decision"],
                    step_outcome["policy_reason"],
                    step_outcome["state"],
                    step_outcome["job_id"],
                    target,
                    now_utc(),
                    step["id"],
                ),
            )
            outcomes.append(step_outcome)

        states = [o["state"] for o in outcomes]
        if dry_run:
            status = "planned"
        elif all(s == "completed" for s in states):
            status = "completed"
        elif any(s in ("blocked", "failed") for s in states):
            status = "failed"
        else:
            status = "completed"
        self.db.execute(
            "UPDATE advsim_exercises SET status = ?, completed_at = ? WHERE id = ?",
            (status, now_utc() if status != "planned" else None, exercise_id),
        )
        if not chain:
            for o in outcomes:
                o.pop("phase", None)
        return {
            "exercise_id": exercise_id,
            "name": exercise["name"],
            "target": target,
            "mode": "dry-run" if dry_run else "live",
            "order": "chain" if chain else "position",
            "status": status,
            "steps": outcomes,
        }

    def exercise_steps(self, exercise_id: int) -> list[dict]:
        return [
            dict(row)
            for row in self.db.query_all(
                "SELECT * FROM advsim_exercise_steps WHERE exercise_id = ? ORDER BY position",
                (exercise_id,),
            )
        ]

    def list_exercises(self) -> list[sqlite3.Row]:
        return self.db.query_all("SELECT * FROM advsim_exercises ORDER BY id DESC")

    def report(self, exercise_id: int) -> dict:
        exercise = self.db.query_one(
            "SELECT * FROM advsim_exercises WHERE id = ?", (exercise_id,)
        )
        if exercise is None:
            raise ValueError(f"Unknown exercise: {exercise_id}")
        profile = self.get_profile(exercise["profile_id"]) if exercise["profile_id"] else None
        steps = self.exercise_steps(exercise_id)
        covered = sorted({s["technique_id"] for s in steps if s["technique_id"]})
        allowed = [s for s in steps if s["policy_decision"] == "ALLOW"]
        phase_map: dict[str, set] = {}
        for s in steps:
            tactic = self._resolve_tactic(s.get("technique_id", ""), s.get("tactic", ""))
            tactic = tactic.strip().lower()
            if tactic and s.get("technique_id"):
                phase_map.setdefault(tactic, set()).add(s["technique_id"])
        phases = {p: sorted(ids) for p, ids in phase_map.items()}
        return {
            "exercise_id": exercise_id,
            "name": exercise["name"],
            "status": exercise["status"],
            "profile": profile.name if profile else None,
            "engagement_id": exercise["engagement_id"],
            "techniques_covered": covered,
            "coverage_count": len(covered),
            "phases": phases,
            "phase_count": len(phases),
            "steps_total": len(steps),
            "steps_allowed": len(allowed),
            "steps": steps,
        }