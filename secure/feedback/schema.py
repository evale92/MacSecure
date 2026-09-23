"""Schema for feedback storage (Phase 55)."""

from __future__ import annotations
import sqlite3


def init_feedback_schema(conn: sqlite3.Connection) -> None:
    """Create feedback table and indexes."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_feedback (
            feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id INTEGER NOT NULL,
            verdict TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'unclear')),
            reason TEXT NOT NULL,
            severity_adjustment INTEGER NOT NULL CHECK (severity_adjustment BETWEEN -2 AND 2),
            feedback_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            feedback_by TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (decision_id) REFERENCES alert_decisions(id)
        )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_decision ON alert_feedback(decision_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON alert_feedback(verdict)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_timestamp ON alert_feedback(created_at DESC)")
    conn.commit()
