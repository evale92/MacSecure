"""Phase 62: Learning loop feedback integration tests."""

import sqlite3
import tempfile
from pathlib import Path

from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema
from secure.feedback.store import FeedbackStore
from secure.intelligence.learning import LearningEngine
from secure.intelligence.models import EfficacySummary


def test_analyze_feedback_no_data():
    """Test analyzing feedback with no data."""
    engine = LearningEngine()
    result = engine.analyze_feedback()

    assert result["total"] == 0
    assert result["fp_rate"] == 0.0


def test_analyze_feedback_with_data():
    """Test analyzing feedback with user verdicts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create test decisions
        for i in range(15):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "MEDIUM", "ACTIVE", "HIGH"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # 10 true positives, 5 false positives = 33% FP rate
        for i in range(10):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(5):
            store.record_feedback(i+11, "false_positive", "Bad")

        engine = LearningEngine(db_conn=conn)
        feedback = engine.analyze_feedback()

        assert feedback["total"] == 15
        assert feedback["false_positives"] == 5
        assert feedback["true_positives"] == 10
        assert abs(feedback["fp_rate"] - 5/15) < 0.01


def test_feedback_affects_threshold_proposal():
    """Test that high FP rate triggers raise-threshold proposal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create decisions
        for i in range(20):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "anomaly_events", "MEDIUM", "ACTIVE", "HIGH"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # High FP rate: 3 true positives, 17 false positives
        for i in range(3):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(17):
            store.record_feedback(i+4, "false_positive", "Too noisy")

        engine = LearningEngine(db_conn=conn)
        efficacy = EfficacySummary(
            action_id="test",
            measured=0,
            effective=0,
            ineffective=0,
            inconclusive=0,
            success_rate=0.0,
            success_rate_lower=0.0,
            avg_findings_reduced=0.0,
            avg_time_to_effect=0.0,
        )

        proposal = engine.propose_threshold_adjustment(
            playbook_id="test",
            current_threshold=50.0,
            efficacy=efficacy,
            alert_type="anomaly_events",
        )

        # High FP rate should propose raising threshold
        assert proposal.direction == "raise"
        assert proposal.proposed_value > 50.0


def test_feedback_low_fp_rate_holds_threshold():
    """Test that low FP rate doesn't trigger threshold change."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create decisions
        for i in range(15):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "anomaly_events", "MEDIUM", "ACTIVE", "HIGH"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # Low FP rate: 13 true positives, 2 false positives
        for i in range(13):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(2):
            store.record_feedback(i+14, "false_positive", "One-off")

        engine = LearningEngine(db_conn=conn)
        efficacy = EfficacySummary(
            action_id="test",
            measured=0,
            effective=0,
            ineffective=0,
            inconclusive=0,
            success_rate=0.0,
            success_rate_lower=0.0,
            avg_findings_reduced=0.0,
            avg_time_to_effect=0.0,
        )

        proposal = engine.propose_threshold_adjustment(
            playbook_id="test",
            current_threshold=50.0,
            efficacy=efficacy,
            alert_type="anomaly_events",
        )

        # Low FP rate should hold threshold (defer to efficacy)
        # With no efficacy data, should hold
        assert proposal.direction == "hold"
