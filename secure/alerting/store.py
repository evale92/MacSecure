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

    def store_decision(
        self,
        decision: AlertDecision,
        entity_type: Optional[str] = None,
        entity_path: Optional[str] = None,
        correlation_id: Optional[str] = None,
        device_count: int = 1,
        stored_at: Optional[datetime] = None,
    ) -> int:
        """
        Write alert decision to storage.

        Args:
            decision: AlertDecision instance.
            entity_type: Type of entity affected (process, file, network).
            entity_path: Path to entity (pid, file path, ip:port).
            correlation_id: Link to Phase 49 correlated finding.
            device_count: Number of devices with this finding.
            stored_at: timestamp (if None, uses now).

        Returns:
            Row id of inserted record.
        """
        try:
            conn = self.connection
            if not conn:
                from secure.storage import get_connection
                conn = get_connection()

            if stored_at is None:
                stored_at = datetime.utcnow()

            now_iso = datetime.utcnow().isoformat() + 'Z'
            stored_iso = stored_at.isoformat() + 'Z' if isinstance(stored_at, datetime) else str(stored_at)

            # Convert reasoning list to JSON array
            import json
            reasoning_json = json.dumps(decision.reasoning or [])

            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alert_decisions (
                    source_table,
                    source_id,
                    entity_type,
                    entity_path,
                    base_severity,
                    verdict,
                    final_severity,
                    reasoning_json,
                    correlation_id,
                    device_count,
                    created_at,
                    evaluated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.source_table,
                decision.source_id,
                entity_type or 'unknown',
                entity_path or '',
                decision.base_severity,
                decision.verdict,
                decision.final_severity,
                reasoning_json,
                correlation_id,
                device_count,
                now_iso,
                stored_iso,
            ))
            conn.commit()
            return cursor.lastrowid

        except Exception as e:
            # Log without re-raising; store failures are non-fatal
            print(f"Error storing alert decision: {e}")
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
