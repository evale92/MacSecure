"""
Remediation schema — Phase 48 database additions.

Adds tables for remediation executions, approvals, and playbook runs.
Call init_remediation_schema(conn) during database initialization.
"""

REMEDIATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediation_actions_meta (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    description             TEXT NOT NULL,
    risk_level              TEXT NOT NULL CHECK(risk_level IN ('low', 'medium', 'high')),
    action_type             TEXT NOT NULL,
    verification_type       TEXT,
    first_shipped_in        TEXT NOT NULL,
    examples_json           TEXT DEFAULT '[]',
    references_json         TEXT DEFAULT '[]',
    enabled                 INTEGER NOT NULL DEFAULT 1,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_approval_requests (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id          TEXT NOT NULL UNIQUE,
    action_id           TEXT NOT NULL REFERENCES remediation_actions_meta(id),
    triggered_by        TEXT NOT NULL,
    triggered_by_ref    TEXT NOT NULL,
    risk_level          TEXT NOT NULL CHECK(risk_level IN ('low', 'medium', 'high')),

    created_at          TEXT NOT NULL,
    expires_at          TEXT,

    status              TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'expired', 'auto_approved')),
    approved_at         TEXT,
    approved_by         TEXT,
    approval_reason     TEXT,

    escalation_path     TEXT,
    escalation_sent_at  TEXT,

    change_request_id   TEXT REFERENCES ai_change_requests(cr_id),
    repair_run_id       TEXT REFERENCES agent_repair_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_approval_requests_status
    ON remediation_approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_remediation_approval_requests_action
    ON remediation_approval_requests(action_id);

CREATE TABLE IF NOT EXISTS remediation_executions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id        TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL,
    action_id           TEXT NOT NULL REFERENCES remediation_actions_meta(id),
    triggered_by        TEXT NOT NULL,
    triggered_by_ref    TEXT NOT NULL,

    approval_request_id TEXT REFERENCES remediation_approval_requests(request_id),

    executed_at         TEXT,
    execution_status    TEXT NOT NULL DEFAULT 'pending' CHECK(execution_status IN ('pending', 'approved', 'executed', 'rolled_back', 'failed')),

    change_request_id   TEXT REFERENCES ai_change_requests(cr_id),
    repair_run_id       TEXT REFERENCES agent_repair_runs(run_id),

    outcome             TEXT,
    verification_result TEXT,
    notes               TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_remediation_executions_status
    ON remediation_executions(execution_status);
CREATE INDEX IF NOT EXISTS idx_remediation_executions_action
    ON remediation_executions(action_id);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    completed_at    TEXT,

    playbook_id     TEXT NOT NULL,
    trigger_finding TEXT NOT NULL,
    trigger_anomaly_score REAL NOT NULL DEFAULT 0.0,

    status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'stopped', 'waiting_approval')),
    final_result    TEXT,

    steps_json      TEXT DEFAULT '[]',
    current_step_index INTEGER DEFAULT 0,

    notes           TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_status
    ON playbook_runs(status);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_playbook
    ON playbook_runs(playbook_id);

CREATE TABLE IF NOT EXISTS playbook_step_executions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    step_execution_id TEXT NOT NULL UNIQUE,
    playbook_run_id TEXT NOT NULL REFERENCES playbook_runs(run_id),

    step_id         TEXT NOT NULL,
    remediation_id  TEXT NOT NULL REFERENCES remediation_actions_meta(id),

    status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'skipped', 'failed', 'waiting_approval')),

    started_at      TEXT,
    completed_at    TEXT,

    approval_request_id TEXT REFERENCES remediation_approval_requests(request_id),

    result          TEXT,
    error           TEXT,
    notes           TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_playbook_step_executions_playbook_run
    ON playbook_step_executions(playbook_run_id);
CREATE INDEX IF NOT EXISTS idx_playbook_step_executions_remediation
    ON playbook_step_executions(remediation_id);

CREATE TABLE IF NOT EXISTS remediation_outcomes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    outcome_id          TEXT NOT NULL UNIQUE,
    execution_id        TEXT NOT NULL REFERENCES remediation_executions(execution_id),
    action_id           TEXT NOT NULL REFERENCES remediation_actions_meta(id),

    created_at          TEXT NOT NULL,
    measured_at         TEXT,

    pre_scan_json       TEXT,
    post_scan_json      TEXT,

    status              TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'measuring', 'success', 'partial', 'failed', 'inconclusive')),

    findings_reduced    INTEGER DEFAULT 0,
    anomaly_score_change REAL DEFAULT 0.0,
    services_disabled   INTEGER DEFAULT 0,
    destinations_isolated INTEGER DEFAULT 0,
    time_to_effect      INTEGER DEFAULT 0,
    shadow_scores_json  TEXT DEFAULT '[]',

    effectiveness       TEXT,
    reason              TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_remediation_outcomes_action
    ON remediation_outcomes(action_id);
CREATE INDEX IF NOT EXISTS idx_remediation_outcomes_status
    ON remediation_outcomes(status);
CREATE INDEX IF NOT EXISTS idx_remediation_outcomes_execution
    ON remediation_outcomes(execution_id);

CREATE TABLE IF NOT EXISTS remediation_request_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    log_entry_id        TEXT NOT NULL UNIQUE,

    request_id          TEXT NOT NULL REFERENCES remediation_approval_requests(request_id),
    action_id           TEXT NOT NULL,

    decision_type       TEXT NOT NULL CHECK(decision_type IN ('created', 'approved', 'rejected', 'expired')),
    decision_at         TEXT NOT NULL,
    decided_by          TEXT,                          -- User ID, "system", or device ID

    request_summary     TEXT NOT NULL,                 -- JSON snapshot of request state
    decision_summary    TEXT,                          -- JSON of decision details

    -- Audit trail integrity
    entry_hash          TEXT,                          -- SHA256 of this log entry (for tampering detection)
    prior_hash          TEXT,                          -- SHA256 of previous entry (chain integrity)

    -- Metadata
    created_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remediation_request_log_request
    ON remediation_request_log(request_id);
CREATE INDEX IF NOT EXISTS idx_remediation_request_log_action
    ON remediation_request_log(action_id);
CREATE INDEX IF NOT EXISTS idx_remediation_request_log_decided_by
    ON remediation_request_log(decided_by);
CREATE INDEX IF NOT EXISTS idx_remediation_request_log_created
    ON remediation_request_log(created_at DESC);
"""


def init_remediation_schema(conn) -> None:
    """Create remediation tables if they don't already exist."""
    conn.executescript(REMEDIATION_SCHEMA)
    conn.commit()
