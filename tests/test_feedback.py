"""Phase 55: Feedback storage tests."""

import sqlite3
import tempfile
from pathlib import Path

from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema
from secure.feedback.store import FeedbackStore


def test_record_and_retrieve_feedback():
    """Test recording and retrieving feedback."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        conn.execute(
            """INSERT INTO alert_decisions
            (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            ("anomaly_events", 1, "process_key", "MEDIUM", "ACTIVE", "HIGH"),
        )
        conn.commit()

        store = FeedbackStore(conn)
        feedback_id = store.record_feedback(1, "true_positive", "Suspicious", 1)

        assert feedback_id > 0
        feedback = store.get_feedback(feedback_id)
        assert feedback.verdict == "true_positive"


def test_feedback_stats():
    """Test feedback statistics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        for i in range(3):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "MEDIUM", "ACTIVE", "HIGH"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        store.record_feedback(1, "true_positive", "Good")
        store.record_feedback(2, "true_positive", "Good")
        store.record_feedback(3, "false_positive", "Bad")

        stats = store.get_feedback_stats()
        assert stats.true_positives == 2
        assert stats.false_positives == 1


def test_count_by_verdict():
    """Test verdict counts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        conn.execute(
            """INSERT INTO alert_decisions
            (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            ("anomaly_events", 1, "process_key", "MEDIUM", "ACTIVE", "HIGH"),
        )
        conn.commit()

        store = FeedbackStore(conn)
        store.record_feedback(1, "true_positive", "Good")
        store.record_feedback(1, "false_positive", "Bad")

        counts = store.count_by_verdict()
        assert counts["true_positive"] == 1
        assert counts["false_positive"] == 1
