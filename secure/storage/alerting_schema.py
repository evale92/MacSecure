"""
Alerting schema — Phase 53/54 database additions.

Adds tables for alert decisions, reasoning, and audit trail.
Call init_alerting_schema(conn) during database initialization.
"""

ALERTING_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_decisions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Source reference
    source_table            TEXT NOT NULL CHECK(source_table IN ('anomaly_events', 'correlation_alerts', 'correlation_chain_alerts')),
    source_id               INTEGER NOT NULL,

    -- Finding details
    entity_type             TEXT NOT NULL,
    entity_path             TEXT,

    -- Decision outcome
    base_severity           TEXT NOT NULL CHECK(base_severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    verdict                 TEXT NOT NULL CHECK(verdict IN ('ACTIVE', 'SUPPRESSED_EXPECTED', 'DOWNGRADED_EXPECTED')),
    final_severity          TEXT NOT NULL CHECK(final_severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Reasoning audit trail
    reasoning_json          TEXT NOT NULL DEFAULT '[]',  -- JSON array of reasoning steps
    suppression_verdict     TEXT,                         -- from SuppressionVerdict.category
    escalation_factors      TEXT,                         -- JSON array of escalation signal names

    -- Correlation context
    correlation_id          TEXT,                         -- link to Phase 49 correlated finding
    device_count            INTEGER DEFAULT 1,           -- devices with this finding

    -- Metadata
    created_at              TEXT NOT NULL,
    evaluated_at            TEXT NOT NULL,

    -- Audit trail integrity
    decision_hash           TEXT,                         -- SHA256 of decision state (future: for tampering detection)
    prior_hash              TEXT                          -- hash of prior decision (for change tracking)
);

CREATE INDEX IF NOT EXISTS idx_alert_decisions_source
    ON alert_decisions(source_table, source_id);
CREATE INDEX IF NOT EXISTS idx_alert_decisions_entity
    ON alert_decisions(entity_type, entity_path);
CREATE INDEX IF NOT EXISTS idx_alert_decisions_verdict
    ON alert_decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_alert_decisions_severity
    ON alert_decisions(final_severity);
CREATE INDEX IF NOT EXISTS idx_alert_decisions_created
    ON alert_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_decisions_correlation
    ON alert_decisions(correlation_id);
"""


def init_alerting_schema(conn):
    """Initialize alerting schema tables."""
    conn.executescript(ALERTING_SCHEMA)
    conn.commit()
