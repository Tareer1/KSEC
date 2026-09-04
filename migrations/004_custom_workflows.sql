-- 004_custom_workflows.sql — user-defined workflow storage (spec: AUTOMATION)

CREATE TABLE IF NOT EXISTS custom_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    steps TEXT NOT NULL DEFAULT '[]',  -- JSON: [{"capability": "...", "options": {...}}]
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);