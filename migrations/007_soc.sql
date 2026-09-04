-- 007_soc.sql — SOC alert pipeline schema (spec 08#16-18 SOC MODULE / ALERT PIPELINE,
--               spec 05#48 ALERT ENTITY).
--
-- Pipeline: Event -> Normalize -> Enrich -> Correlate -> Rule Evaluation
--           -> Risk Score -> Alert -> Case.
--
-- soc_events: canonical normalized events ingested from any source.
-- detection_rules: deterministic field/threshold rules (spec 08#18 DETECTION ENGINE).
-- alerts: spec 05#48 fields (alert_id, source, type, severity, asset_id,
--         finding_id, case_id, status, created_at, acknowledged_at, resolved_at).

CREATE TABLE IF NOT EXISTS soc_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,          -- external dedup key (idempotent intake)
    source TEXT NOT NULL,                   -- firewall | ids | endpoint | siem | job | manual
    event_type TEXT NOT NULL,               -- auth_failure | port_scan | malware | beacon | ...
    severity TEXT NOT NULL DEFAULT 'medium',
    host TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    process TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',     -- raw event fields (JSON)
    normalized TEXT NOT NULL DEFAULT '{}',  -- normalized/canonical fields (JSON)
    occurred_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    event_type TEXT NOT NULL DEFAULT '',    -- filter: empty = any event type
    field TEXT NOT NULL DEFAULT '',         -- normalized field to test: ip|domain|host|username|process|source|event_type|severity
    operator TEXT NOT NULL DEFAULT 'eq',    -- eq | ne | contains | regex | min_severity
    value TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',-- alert severity when the rule fires
    risk_boost REAL NOT NULL DEFAULT 0,     -- added to the base risk score
    open_case INTEGER NOT NULL DEFAULT 1,   -- auto-open a case when it fires
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,                   -- rule:<name> | manual | severity gate
    type TEXT NOT NULL,                     -- alert type (rule name or event type)
    severity TEXT NOT NULL DEFAULT 'medium',
    risk_score REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',    -- open | acknowledged | resolved | closed
    rule_id INTEGER REFERENCES detection_rules(id) ON DELETE SET NULL,
    event_id INTEGER REFERENCES soc_events(id) ON DELETE SET NULL,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    ioc_id INTEGER REFERENCES iocs(id) ON DELETE SET NULL,
    summary TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',     -- enrichment/correlation context (JSON)
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_soc_events_entity ON soc_events (ip, domain, host);
CREATE INDEX IF NOT EXISTS idx_soc_events_type ON soc_events (event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status, created_at);