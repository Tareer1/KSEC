-- 012_custody_notes_remediation.sql — Evidence chain of custody, case notes
-- and timeline events, and the remediation/verification engine.
-- Spec 05 #30 (chain of custody), #36 (case notes), #37-38 (remediation),
-- spec 08 #42/#55-57 (case lifecycle, false-positive handling, remediation).

-- Chain of custody: every evidence state change is recorded append-only.
CREATE TABLE IF NOT EXISTS evidence_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    action TEXT NOT NULL,          -- CAPTURED | VERIFIED | REVIEWED | REFERENCED | EXPORTED | ARCHIVED
    actor TEXT NOT NULL DEFAULT '',
    previous_state TEXT NOT NULL DEFAULT '',
    new_state TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_custody_evidence ON evidence_custody(evidence_id);

-- Case notes (append-only, edit history preserved by adding new records).
CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);

-- Case timeline events (spec 08 #42: cases may contain a timeline).
CREATE TABLE IF NOT EXISTS case_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT 'note',  -- created | finding_linked | status | note | remediation | verification | reopen | other
    details TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events(case_id);

-- Remediation: one or more remediation tasks per finding.
CREATE TABLE IF NOT EXISTS finding_remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    description TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'medium',   -- low | medium | high | critical
    status TEXT NOT NULL DEFAULT 'open',       -- open | in_progress | completed | verified | rejected
    due_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediations_finding ON finding_remediations(finding_id);

-- Verification records: a remediation is only "verified" with a separate
-- verification record (spec 05 #38 — never mark remediated on word alone).
CREATE TABLE IF NOT EXISTS remediation_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    remediation_id INTEGER NOT NULL REFERENCES finding_remediations(id) ON DELETE CASCADE,
    method TEXT NOT NULL DEFAULT '',       -- retest | manual | evidence_review | tool
    result TEXT NOT NULL DEFAULT '',       -- verified | failed | inconclusive
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    verified_by TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verifications_remediation ON remediation_verifications(remediation_id);