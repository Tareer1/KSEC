-- 013_emergency_stop.sql — persistent emergency-stop flag.
-- The emergency stop must survive process restarts (spec 06#32: prevent new
-- jobs). A small key-value table stores system-level flags; the scheduler
-- checks `emergency_stop` on every submission.

CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);