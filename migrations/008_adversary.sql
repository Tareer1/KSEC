-- 008_adversary.sql — Adversary Simulation schema (spec 01#7, 03#28, 08#12-14).
--
-- Profiles model threat actors as ordered TTP chains. Exercises tie a
-- profile to an engagement/scope and record per-step outcomes. Everything is
-- authorization- and scope-controlled (spec: adversary boundary).
--
-- TTPs live in the ttps table (framework/technique_id). Capabilities are the
-- KSEC execution capabilities used to emulate a step.

CREATE TABLE IF NOT EXISTS advsim_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    threat_actor TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',          -- e.g. mitre-attack group ref
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advsim_profile_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES advsim_profiles(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    ttp_id INTEGER REFERENCES ttps(id) ON DELETE SET NULL,
    technique_id TEXT NOT NULL DEFAULT '',   -- snapshot (allows unlisted TTPs)
    tactic TEXT NOT NULL DEFAULT '',
    capability TEXT NOT NULL DEFAULT '',     -- ksec capability that emulates this step
    description TEXT NOT NULL DEFAULT '',
    UNIQUE (profile_id, position)
);

CREATE TABLE IF NOT EXISTS advsim_exercises (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    profile_id INTEGER REFERENCES advsim_profiles(id) ON DELETE SET NULL,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    workspace TEXT NOT NULL DEFAULT 'ADVERSARY_SIMULATION',
    status TEXT NOT NULL DEFAULT 'planned',  -- planned | running | completed | failed | cancelled
    operator_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advsim_exercise_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exercise_id INTEGER NOT NULL REFERENCES advsim_exercises(id) ON DELETE CASCADE,
    profile_step_id INTEGER REFERENCES advsim_profile_steps(id) ON DELETE SET NULL,
    position INTEGER NOT NULL,
    technique_id TEXT NOT NULL DEFAULT '',
    tactic TEXT NOT NULL DEFAULT '',
    capability TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    job_id TEXT,
    policy_decision TEXT NOT NULL DEFAULT '',
    policy_reason TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'planned',   -- planned | allowed | blocked | completed | failed
    observed_at TEXT,
    created_at TEXT NOT NULL
);