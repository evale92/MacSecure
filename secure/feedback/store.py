"""Feedback storage and retrieval (Phase 55)."""

from __future__ import annotations
import sqlite3
from datetime import datetime
from typing import List

from secure.feedback.models import AlertFeedback, FeedbackStats


class FeedbackStore:
    """Store and retrieve user feedback on alert decisions."""

    def __init__(self, db_conn: sqlite3.Connection):
        """Initialize with database connection."""
        self.conn = db_conn
        self.conn.row_factory = sqlite3.Row

    def record_feedback(
        self,
        decision_id: int,
        verdict: str,
        reason: str,
        severity_adjustment: int = 0,
        feedback_by: str = "user",
    ) -> int:
        """Record user feedback on a decision.

        Returns: feedback_id
        """
        cursor = self.conn.execute(
            """
            INSERT INTO alert_feedback (decision_id, verdict, reason, severity_adjustment, feedback_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (decision_id, verdict, reason, severity_adjustment, feedback_by),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_feedback(self, feedback_id: int) -> AlertFeedback | None:
        """Get feedback by ID."""
        row = self.conn.execute(
            "SELECT * FROM alert_feedback WHERE feedback_id = ?",
            (feedback_id,),
        ).fetchone()

        if row is None:
            return None

        return AlertFeedback(
            feedback_id=row["feedback_id"],
            decision_id=row["decision_id"],
            verdict=row["verdict"],
            reason=row["reason"],
            severity_adjustment=row["severity_adjustment"],
            feedback_at=datetime.fromisoformat(row["feedback_at"]),
            feedback_by=row["feedback_by"],
        )

    def get_recent_feedback(self, limit: int = 50) -> List[AlertFeedback]:
        """Get recent feedback."""
        rows = self.conn.execute(
            "SELECT * FROM alert_feedback ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

        return [
            AlertFeedback(
                feedback_id=row["feedback_id"],
                decision_id=row["decision_id"],
                verdict=row["verdict"],
                reason=row["reason"],
                severity_adjustment=row["severity_adjustment"],
                feedback_at=datetime.fromisoformat(row["feedback_at"]),
                feedback_by=row["feedback_by"],
            )
            for row in rows
        ]

    def count_by_verdict(self) -> dict[str, int]:
        """Count feedback by verdict."""
        rows = self.conn.execute(
            "SELECT verdict, COUNT(*) as count FROM alert_feedback GROUP BY verdict"
        ).fetchall()

        return {row["verdict"]: row["count"] for row in rows}

    def get_feedback_stats(self, alert_type: str = None) -> FeedbackStats | None:
        """Get summary stats for feedback."""
        if alert_type:
            rows = self.conn.execute(
                """
                SELECT
                    ad.source_table as alert_type,
                    COUNT(af.feedback_id) as total,
                    SUM(CASE WHEN af.verdict = 'true_positive' THEN 1 ELSE 0 END) as tp,
                    SUM(CASE WHEN af.verdict = 'false_positive' THEN 1 ELSE 0 END) as fp,
                    SUM(CASE WHEN af.verdict = 'unclear' THEN 1 ELSE 0 END) as unc,
                    AVG(af.severity_adjustment) as avg_delta
                FROM alert_feedback af
                JOIN alert_decisions ad ON af.decision_id = ad.id
                WHERE ad.source_table = ?
                """,
                (alert_type,),
            ).fetchone()
        else:
            rows = self.conn.execute(
                """
                SELECT
                    'all' as alert_type,
                    COUNT(af.feedback_id) as total,
                    SUM(CASE WHEN af.verdict = 'true_positive' THEN 1 ELSE 0 END) as tp,
                    SUM(CASE WHEN af.verdict = 'false_positive' THEN 1 ELSE 0 END) as fp,
                    SUM(CASE WHEN af.verdict = 'unclear' THEN 1 ELSE 0 END) as unc,
                    AVG(af.severity_adjustment) as avg_delta
                FROM alert_feedback af
                """
            ).fetchone()

        if rows is None or rows["total"] == 0:
            return None

        total = rows["total"]
        tp = rows["tp"] or 0
        fp = rows["fp"] or 0
        confidence = min(total / 20.0, 1.0)  # Confidence grows with sample size

        return FeedbackStats(
            alert_type=rows["alert_type"] or "unknown",
            total_feedback=total,
            true_positives=tp,
            false_positives=fp,
            unclear=rows["unc"] or 0,
            avg_severity_delta=rows["avg_delta"] or 0.0,
            confidence=confidence,
        )
