"""Phase 64: Automation dispatcher tests."""

import sqlite3
import tempfile
from pathlib import Path

from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema
from secure.feedback.store import FeedbackStore
from secure.automation.dispatcher import AutomatedAlertDispatcher
from secure.remediation.approval import ApprovalStatus


def test_dispatcher_auto_approves_high_confidence():
    """Test that dispatcher auto-approves high-confidence alerts."""
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
                ("anomaly_events", i+1, "process_key", "HIGH", "ACTIVE", "HIGH"),
            )
        conn.commit()

        store = FeedbackStore(conn)
        # Low FP rate: 18 TP, 2 FP
        for i in range(18):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(2):
            store.record_feedback(i+19, "false_positive", "Bad")

        dispatcher = AutomatedAlertDispatcher(conn)
        status, reason = dispatcher.process_alert_for_automation(
            alert_id=1,
            severity="HIGH",
            verdict="ACTIVE",
            entity_type="anomaly_events",
        )

        assert status == ApprovalStatus.AUTO_APPROVED
        assert "High confidence" in reason


def test_dispatcher_pending_for_low_confidence():
    """Test that dispatcher marks low-confidence alerts as pending."""
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
        # High FP rate: 5 TP, 15 FP
        for i in range(5):
            store.record_feedback(i+1, "true_positive", "Good")
        for i in range(15):
            store.record_feedback(i+6, "false_positive", "Bad")

        dispatcher = AutomatedAlertDispatcher(conn)
        status, reason = dispatcher.process_alert_for_automation(
            alert_id=1,
            severity="LOW",
            verdict="ACTIVE",
            entity_type="anomaly_events",
        )

        assert status == ApprovalStatus.PENDING
        assert "Requires approval" in reason


def test_dispatcher_suppressed_alerts_approved():
    """Test that dispatcher approves suppressed alerts without checking confidence."""
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
            ("anomaly_events", 1, "process_key", "CRITICAL", "SUPPRESSED_EXPECTED", "LOW"),
        )
        conn.commit()

        dispatcher = AutomatedAlertDispatcher(conn)
        status, reason = dispatcher.process_alert_for_automation(
            alert_id=1,
            severity="CRITICAL",
            verdict="SUPPRESSED_EXPECTED",
            entity_type="anomaly_events",
        )

        assert status == ApprovalStatus.APPROVED
        assert "not active" in reason.lower()


def test_dispatcher_auto_escalation_disabled():
    """Test that dispatcher respects auto-escalation disable flag."""
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
        # Low FP rate
        for i in range(19):
            store.record_feedback(i+1, "true_positive", "Good")
        store.record_feedback(20, "false_positive", "Bad")

        dispatcher = AutomatedAlertDispatcher(conn)
        status, reason = dispatcher.process_alert_for_automation(
            alert_id=1,
            severity="CRITICAL",
            verdict="ACTIVE",
            entity_type="anomaly_events",
            allow_auto_escalation=False,
        )

        assert status == ApprovalStatus.PENDING
        assert "disabled" in reason.lower()


def test_dispatcher_creates_automation_request():
    """Test that dispatcher creates audit records for auto-approved alerts."""
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
        for i in range(19):
            store.record_feedback(i+1, "true_positive", "Good")
        store.record_feedback(20, "false_positive", "Bad")

        dispatcher = AutomatedAlertDispatcher(conn)
        request = dispatcher.create_automation_request(
            alert_id=1,
            severity="CRITICAL",
            entity_type="anomaly_events",
        )

        assert request is not None
        assert request["automation_id"]
        assert request["alert_id"] == 1
        assert request["decision"] == "auto_approved"
        assert request["confidence_level"] == "high"
        assert request["confidence_score"] > 0.8


def test_dispatcher_handles_siem_failure():
    """Test that dispatcher handles SIEM transport failures gracefully."""
    import os
    from unittest.mock import patch
    from secure.integrations.siem import SIEMForwarder

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
            ("anomaly_events", 1, "process_key", "HIGH", "ACTIVE", "HIGH"),
        )
        conn.commit()

        # Set SIEM transport stub to simulate failure
        os.environ["SECURE_STUB_SIEM_TRANSPORT_BREAK"] = "true"
        try:
            dispatcher = AutomatedAlertDispatcher(conn)
            status, reason = dispatcher.process_alert_for_automation(
                alert_id=1,
                severity="HIGH",
                verdict="ACTIVE",
                entity_type="anomaly_events",
            )

            # Dispatcher should still work even if SIEM is broken
            assert status is not None, "GATE_AUTOMATION_DISPATCHER_SIEM: dispatcher failed to process alert with SIEM transport broken"
        finally:
            del os.environ["SECURE_STUB_SIEM_TRANSPORT_BREAK"]
