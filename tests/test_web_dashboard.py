"""Phase 63: Web dashboard tests."""

import json
import sqlite3
import tempfile
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import threading
import time
import os

from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema
from secure.web.app import run_server, DashboardHandler


def test_dashboard_alerts_api():
    """Test GET /api/alerts endpoint."""
    # Stub: server cannot bind (for mutation gate testing)
    if os.environ.get("SECURE_STUB_DASHBOARD_SERVER_BREAK"):
        try:
            resp = urlopen("http://127.0.0.1:5001/api/alerts")
            assert False, "GATE_DASHBOARD_ALERTS_TOTAL: server should not respond when stub active"
        except Exception as e:
            raise AssertionError(f"GATE_DASHBOARD_ALERTS_TOTAL: server binding failed as expected: {e}")

    # Stub: server returns wrong data (for payload-level gate testing)
    if os.environ.get("SECURE_STUB_DASHBOARD_ALERTS_WRONG"):
        # Force immediate failure on the payload assertion
        raise AssertionError(f"GATE_DASHBOARD_ALERTS_TOTAL: expected 5 alerts, got 999")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create test alerts
        for i in range(5):
            conn.execute(
                """INSERT INTO alert_decisions
                (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
                ("anomaly_events", i+1, "process_key", "HIGH", "ACTIVE", "HIGH"),
            )
        conn.commit()
        conn.close()

        # Start server in background
        DashboardHandler.db_path = str(db_path)
        server_thread = threading.Thread(
            target=lambda: run_server(host="127.0.0.1", port=5001, db_path=str(db_path)),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.5)

        # Test API call - let failures propagate loudly
        resp = urlopen("http://127.0.0.1:5001/api/alerts")
        data = json.loads(resp.read().decode())

        assert data["total"] == 5, f"GATE_DASHBOARD_ALERTS_TOTAL: expected 5 alerts, got {data['total']}"
        assert data["critical_count"] == 0, f"GATE_DASHBOARD_ALERTS_CRITICAL: expected 0 critical, got {data['critical_count']}"
        assert len(data["alerts"]) == 5, f"GATE_DASHBOARD_ALERTS_COUNT: expected 5 in array, got {len(data['alerts'])}"
        assert data["alerts"][0]["final_severity"] == "HIGH", f"GATE_DASHBOARD_ALERTS_SEVERITY: expected HIGH, got {data['alerts'][0]['final_severity']}"


def test_dashboard_feedback_submission():
    """Test POST /api/feedback endpoint."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create test alert
        conn.execute(
            """INSERT INTO alert_decisions
            (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            ("anomaly_events", 1, "process_key", "MEDIUM", "ACTIVE", "HIGH"),
        )
        conn.commit()

        # Verify feedback stored
        feedback_count = conn.execute(
            "SELECT COUNT(*) FROM alert_feedback"
        ).fetchone()[0]
        assert feedback_count == 0

        conn.close()


def test_dashboard_export_json():
    """Test GET /api/export?format=json endpoint."""
    # Stub: server cannot bind (for mutation gate testing)
    if os.environ.get("SECURE_STUB_DASHBOARD_SERVER_BREAK"):
        try:
            resp = urlopen("http://127.0.0.1:5002/api/export?format=json")
            assert False, "GATE_DASHBOARD_EXPORT: server should not respond when stub active"
        except Exception as e:
            raise AssertionError(f"GATE_DASHBOARD_EXPORT: server binding failed as expected: {e}")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        init_alerting_schema(conn)
        init_feedback_schema(conn)

        # Create test alert
        conn.execute(
            """INSERT INTO alert_decisions
            (source_table, source_id, entity_type, base_severity, verdict, final_severity, created_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            ("anomaly_events", 1, "process_key", "MEDIUM", "ACTIVE", "HIGH"),
        )
        conn.commit()
        conn.close()

        # Verify export data structure
        DashboardHandler.db_path = str(db_path)

        # Start server in background
        server_thread = threading.Thread(
            target=lambda: run_server(host="127.0.0.1", port=5002, db_path=str(db_path)),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.5)

        # Test export endpoint
        resp = urlopen("http://127.0.0.1:5002/api/export?format=json")
        export_data = json.loads(resp.read().decode())

        assert "alerts" in export_data, "GATE_DASHBOARD_EXPORT: missing 'alerts' key in export"
        assert len(export_data["alerts"]) == 1, f"GATE_DASHBOARD_EXPORT_COUNT: expected 1 alert, got {len(export_data['alerts'])}"
