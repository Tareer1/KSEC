-- 009_schedules.sql — Recurring job schedules (cron-style automation).
--
-- A schedule defines a capability + target + 5-field cron expression.
-- The scheduler checks due schedules on its loop and submits a regular
-- job (same pipeline, same audit trail) each time one is due. Schedules
-- can only be created for targets that pass the policy/scope check at
-- creation time, keeping automation inside the authorization model.

CREATE TABLE IF NOT EXISTS job_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capability TEXT NOT NULL,
    target TEXT NOT NULL,
    options TEXT NOT NULL DEFAULT '{}',
    cron TEXT NOT NULL,                  -- 5-field cron: minute hour dom month dow
    workspace TEXT NOT NULL DEFAULT 'RED_TEAM',
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,                    -- ISO-8601 of the last fired run
    created_at TEXT NOT NULL
);