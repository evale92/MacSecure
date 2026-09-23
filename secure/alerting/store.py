"""Storage for alert decisions and learning outcomes.

Reads/writes alert_decisions table. Coordinates with Phase 50 learning loop.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from secure.alerting.decide import AlertDecision


class AlertDecisionStore:
    """Persistence layer for alert decisions."""

    def __init__(self, connection=None):
        """
        Initialize store with optional connection.

        Args:
            connection: database connection (if None, uses global config).
        """
        self.connection = connection

    def store_decision(self, decision: AlertDecision, stored_at: Optional[datetime] = None) -> int:
        """
        Write alert decision to storage.

        Args:
            decision: AlertDecision instance.
            stored_at: timestamp (if None, uses now).

        Returns:
            Row id of inserted record.
        """
        try:
            from secure.storage import get_connection
            conn = self.connection or get_connection()

            if stored_at is None:
                stored_at = datetime.utcnow()

            # TODO: implement schema and insert query
            # INSERT INTO alert_decisions
            # (source_table, source_id, base_severity, verdict, final_severity, reasoning, stored_at)
            # VALUES (...)

            # Stub: return dummy ID
            return 1
        except Exception:
            return -1

    def get_recent_decisions(self, limit: int = 100) -> List[AlertDecision]:
        """
        Fetch recent decisions.

        Args:
            limit: max results.

        Returns:
            List of AlertDecision objects.
        """
        try:
            from secure.storage import get_connection
            conn = self.connection or get_connection()

            # TODO: implement schema and query
            # SELECT * FROM alert_decisions ORDER BY stored_at DESC LIMIT limit

            # Stub: return empty
            return []
        except Exception:
            return []

    def get_decision_by_source(self, source_table: str, source_id: int) -> Optional[AlertDecision]:
        """
        Fetch decision for a specific event.

        Args:
            source_table: table name (anomaly_events, etc.).
            source_id: row id in that table.

        Returns:
            AlertDecision or None if not found.
        """
        try:
            from secure.storage import get_connection
            conn = self.connection or get_connection()

            # TODO: implement schema and query
            # SELECT * FROM alert_decisions WHERE source_table = ? AND source_id = ?

            # Stub: return None
            return None
        except Exception:
            return None

    def count_by_verdict(self) -> dict:
        """
        Count decisions by verdict category.

        Returns:
            Dict with keys ACTIVE, SUPPRESSED_EXPECTED, DOWNGRADED_EXPECTED.
        """
        try:
            from secure.storage import get_connection
            conn = self.connection or get_connection()

            # TODO: implement aggregation query
            # SELECT verdict, COUNT(*) FROM alert_decisions GROUP BY verdict

            # Stub: return empty counts
            return {
                "ACTIVE": 0,
                "SUPPRESSED_EXPECTED": 0,
                "DOWNGRADED_EXPECTED": 0,
            }
        except Exception:
            return {}
