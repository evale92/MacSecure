"""Phase 64: Automation engine tests."""

import sqlite3
import tempfile
from pathlib import Path

from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema
from secure.feedback.store import FeedbackStore
from secure.automation.engine import AutomationEngine
from secure.remediation.approval import RiskLevel


def test_confidence_high_severity_low_fp():
    """Test high confidence: high severity + low false positive rate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create decisions and feedback
        for i in range(20):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "HIGH", "ACTIVE", "HIGH"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # Low FP rate: 18 true positives, 2 false positives
        for i in range(18):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(2):
            store.record_feedback(i+19, "false_positive", "Bad")

        engine = AutomationEngine(conn)
        should_auto, reason = engine.should_auto_approve(
            alert_id=1,
            severity="HIGH",
            alert_type="anomaly_events",
        )

        assert should_auto is True, \
            f"GATE_AUTOMATION_ENGINE_FEEDBACK: engine should auto-approve high confidence HIGH severity alerts"
        assert "High confidence" in reason


def test_confidence_low_severity_high_fp():
    """Test low confidence: low severity + high false positive rate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create decisions and feedback
        for i in range(15):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "LOW", "ACTIVE", "LOW"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # High FP rate: 3 true positives, 12 false positives
        for i in range(3):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(12):
            store.record_feedback(i+4, "false_positive", "Bad")

        engine = AutomationEngine(conn)
        should_auto, reason = engine.should_auto_approve(
            alert_id=1,
            severity="LOW",
            alert_type="anomaly_events",
        )

        assert should_auto is False
        assert "Insufficient confidence" in reason


def test_confidence_no_feedback():
    """Test confidence calculation with no feedback history."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create alert with no feedback
        conn.execute(
            """INSERT INTO alert_decisions
            (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            ("anomaly_events", 1, "process_key", "MEDIUM", "ACTIVE", "MEDIUM"),
        )
        conn.commit()

        engine = AutomationEngine(conn)
        confidence = engine.calculate_confidence(
            alert_id=1,
            severity="MEDIUM",
            alert_type="anomaly_events",
        )

        # With no feedback, confidence should be neutral (medium)
        assert confidence.confidence_level == "medium"
        assert 0.0 <= confidence.confidence_score <= 1.0


def test_auto_approval_policy_high_confidence():
    """Test approval policy generation for high confidence alerts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create high-confidence scenario
        for i in range(20):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "CRITICAL", "ACTIVE", "CRITICAL"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # Very low FP rate
        for i in range(19):
            store.record_feedback(i+1, "true_positive", "Good")
        store.record_feedback(20, "false_positive", "Bad")

        engine = AutomationEngine(conn)
        policy = engine.get_auto_approval_policy(
            alert_id=1,
            severity="CRITICAL",
            alert_type="anomaly_events",
        )

        # High confidence + critical severity = LOW risk, no approval needed
        assert policy.risk_level == RiskLevel.LOW
        assert policy.approval_required is False
        assert policy.rollback_allowed is True


def test_auto_approval_policy_low_confidence():
    """Test approval policy generation for low confidence alerts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create low-confidence scenario
        for i in range(20):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "LOW", "ACTIVE", "LOW"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # High FP rate
        for i in range(5):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(15):
            store.record_feedback(i+6, "false_positive", "Bad")

        engine = AutomationEngine(conn)
        policy = engine.get_auto_approval_policy(
            alert_id=1,
            severity="LOW",
            alert_type="anomaly_events",
        )

        # Low confidence + low severity = HIGH risk, approval required
        assert policy.risk_level == RiskLevel.HIGH
        assert policy.approval_required is True


def test_engine_handles_siem_failure():
    """Test that automation engine handles SIEM transport failures gracefully."""
    import os
    import sqlite3
    import tempfile
    from pathlib import Path
    from secure.automation.engine import AutomationEngine
    from secure.storage.alerting_schema import init_alerting_schema
    from secure.feedback.schema import init_feedback_schema

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Set SIEM transport stub to simulate failure
        os.environ["SECURE_STUB_SIEM_TRANSPORT_BREAK"] = "true"
        try:
            engine = AutomationEngine(conn)

            # Engine should initialize even if SIEM transport is broken
            assert engine is not None, "GATE_AUTOMATION_ENGINE_SIEM: engine failed to initialize with SIEM transport broken"
        finally:
            del os.environ["SECURE_STUB_SIEM_TRANSPORT_BREAK"]
            conn.close()
