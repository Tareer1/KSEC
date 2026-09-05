-- 015_gaps_round.sql — purple team, change detection, practice, workflow triggers
-- Covers the remaining spec gaps: coordinated purple exercises (spec 08),
-- change detection baselines/drift (spec 08 #59), learn practice drills and
-- event-driven workflow triggers (spec 07).

CREATE TABLE IF NOT EXISTS purple_exercises (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    adversary_exercise_id INTEGER,
    status TEXT NOT NULL DEFAULT 'planned',  -- planned | running | completed
    red_findings INTEGER NOT NULL DEFAULT 0,
    blue_alerts INTEGER NOT NULL DEFAULT 0,
    detections_fired INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS change_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'assets',  -- assets | services | config
    target TEXT NOT NULL DEFAULT '*',
    snapshot_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS change_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    baseline_id INTEGER NOT NULL REFERENCES change_baselines(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'clean',   -- clean | drift
    drift_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS practice_progress (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    drill_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | passed
    attempts INTEGER NOT NULL DEFAULT 0,
    passed_at TEXT,
    PRIMARY KEY (user_id, drill_id)
);

CREATE TABLE IF NOT EXISTS workflow_triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    event_type TEXT NOT NULL,       -- e.g. soc.alert.critical | job.failed | schedule
    event_glob TEXT NOT NULL DEFAULT '*',
    workflow TEXT NOT NULL,         -- workflow or capability name
    target_field TEXT NOT NULL DEFAULT 'target',
    workspace TEXT NOT NULL DEFAULT 'RED_TEAM',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_fired_at TEXT
);