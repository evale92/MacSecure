"""Tests for GUI sensor status view (Phase 61)."""

import sqlite3
import tempfile
from datetime import datetime, timezone

from secure.storage.database import init_schema
from secure_gui.sensor_status_view import SensorStatusController, _format_age


def test_sensor_status_controller_identifies_critical():
    """Controller identifies Tier-1 critical sensors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"
        db_conn = sqlite3.connect(db_path)
        db_conn.row_factory = sqlite3.Row
        init_schema(db_conn)

        controller = SensorStatusController(db_conn)
        sensors = controller.get_all_sensors()

        critical_names = {s.name for s in sensors if s.is_critical}
        expected_critical = {"persistence", "listening", "connections", "fileintegrity", "checks"}

        assert critical_names == expected_critical


def test_sensor_status_identifies_active():
    """Controller marks active sensors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"
        db_conn = sqlite3.connect(db_path)
        db_conn.row_factory = sqlite3.Row
        init_schema(db_conn)

        controller = SensorStatusController(db_conn)
        sensors = controller.get_all_sensors()

        active_names = {s.name for s in sensors if s.is_active}
        expected_active = {"persistence", "listening", "connections", "fileintegrity", "checks", "wifi", "bluetooth"}

        assert active_names == expected_active


def test_sensor_status_test_counts():
    """Controller returns known test counts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"
        db_conn = sqlite3.connect(db_path)
        db_conn.row_factory = sqlite3.Row
        init_schema(db_conn)

        controller = SensorStatusController(db_conn)
        sensors = controller.get_all_sensors()

        sensor_tests = {s.name: s.test_count for s in sensors}

        assert sensor_tests["persistence"] == 97
        assert sensor_tests["listening"] == 47
        assert sensor_tests["wifi"] == 53
        assert sensor_tests["arpwatch"] == 27


def test_format_age_seconds():
    """Format age in seconds."""
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    past = now - timedelta(seconds=30)

    age = _format_age(past)
    assert "30s ago" in age or "29s ago" in age or "31s ago" in age


def test_format_age_minutes():
    """Format age in minutes."""
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    past = now - timedelta(minutes=15)

    age = _format_age(past)
    assert "15m ago" in age or "14m ago" in age


def test_format_age_hours():
    """Format age in hours."""
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    past = now - timedelta(hours=3)

    age = _format_age(past)
    assert "3h ago" in age or "2h ago" in age


def test_format_age_days():
    """Format age in days."""
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    past = now - timedelta(days=5)

    age = _format_age(past)
    assert "5d ago" in age or "4d ago" in age
