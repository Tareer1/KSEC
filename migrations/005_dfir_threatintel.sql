-- 005_dfir_threatintel.sql — DFIR and Threat Intelligence schema
-- Entity fields follow specs/05 (IOC, THREAT ACTOR, CAMPAIGN, TTP entities)
-- and specs/08 (DFIR module: artifacts, timeline construction).

CREATE TABLE IF NOT EXISTS dfir_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    host TEXT NOT NULL DEFAULT '',
    artifact_type TEXT NOT NULL,      -- file | log | process | network | auth | browser | malware | registry | memory | other
    name TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    tool TEXT NOT NULL DEFAULT '',
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    collected_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dfir_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    artifact_id INTEGER REFERENCES dfir_artifacts(id) ON DELETE SET NULL,
    event_time TEXT NOT NULL,
    event_type TEXT NOT NULL,         -- created | modified | deleted | executed | network | login | auth_failure | privilege | persistence | exfiltration | other
    actor TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    aliases TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    sources TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    threat_actor_id INTEGER REFERENCES threat_actors(id) ON DELETE SET NULL,
    start_date TEXT,
    end_date TEXT,
    confidence TEXT NOT NULL DEFAULT 'medium',
    sources TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ttps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework TEXT NOT NULL DEFAULT 'mitre-attack',
    technique_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    tactic TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (framework, technique_id)
);

CREATE TABLE IF NOT EXISTS campaign_ttps (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ttp_id INTEGER NOT NULL REFERENCES ttps(id) ON DELETE CASCADE,
    PRIMARY KEY (campaign_id, ttp_id)
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,               -- IP | DOMAIN | URL | HASH | EMAIL | USERNAME | FILE | PROCESS | CERTIFICATE | OTHER
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    source TEXT NOT NULL DEFAULT '',
    first_seen TEXT,
    last_seen TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    actor_id INTEGER REFERENCES threat_actors(id) ON DELETE SET NULL,
    campaign_id INTEGER REFERENCES campaigns(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    UNIQUE (type, normalized_value)
);