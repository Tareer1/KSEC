-- 002_security_data.sql — execution + security data schema
-- Covers spec Stage 3-5: tool registry, jobs, assets, findings,
-- evidence (hash-protected), cases and workflow runs.

CREATE TABLE IF NOT EXISTS tool_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL UNIQUE,
    package TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    binary_path TEXT,
    version TEXT,
    capability TEXT NOT NULL,
    ready INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    workspace TEXT NOT NULL DEFAULT '',
    workflow TEXT NOT NULL DEFAULT '',
    capability TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    options TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'QUEUED',
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    exit_code INTEGER,
    error TEXT,
    result TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    target TEXT NOT NULL,
    asset_type TEXT NOT NULL DEFAULT 'host',
    criticality TEXT NOT NULL DEFAULT 'low',
    owner TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (engagement_id, target)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    confidence TEXT NOT NULL DEFAULT 'medium',
    recommendation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    risk_score REAL,
    risk_level TEXT,
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    session_id TEXT,
    tool TEXT NOT NULL DEFAULT '',
    tool_version TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    collection_method TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'open',
    owner TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_findings (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, finding_id)
);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id TEXT PRIMARY KEY,
    workflow TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    engagement_id INTEGER,
    session_id TEXT,
    user_id INTEGER,
    status TEXT NOT NULL DEFAULT 'queued',
    steps_total INTEGER NOT NULL DEFAULT 0,
    steps_completed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT
);