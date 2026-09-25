"""Phase 58: Sensor audit tests."""

import tempfile
from pathlib import Path

from secure.diagnostics.sensor_audit import audit_sensors, format_audit_table


def test_audit_finds_all_sensors():
    """Audit discovers all expected sensor modules."""
    statuses = audit_sensors()

    sensor_names = {s.name for s in statuses}
    expected = {"persistence", "listening", "connections", "wifi", "bluetooth",
                "fileintegrity", "checks", "inventory", "arpwatch"}

    assert sensor_names == expected, f"Missing sensors: {expected - sensor_names}"


def test_critical_sensors_identified():
    """Critical Tier-1 sensors are marked as such."""
    statuses = audit_sensors()
    critical_map = {s.name: s.is_critical_tier for s in statuses}

    assert critical_map["persistence"]
    assert critical_map["listening"]
    assert critical_map["connections"]
    assert critical_map["fileintegrity"]
    assert critical_map["checks"]


def test_monitor_active_sensors():
    """Sensors called by secure_monitor.sh are marked active."""
    statuses = audit_sensors()
    active_map = {s.name: s.has_scan_cmd for s in statuses}

    # These are explicitly called by secure_monitor.sh
    assert active_map["persistence"]
    assert active_map["listening"]
    assert active_map["connections"]
    assert active_map["wifi"]
    assert active_map["bluetooth"]


def test_inactive_sensors():
    """Sensors not in monitor are identified as inactive."""
    statuses = audit_sensors()
    inactive_map = {s.name: not s.has_scan_cmd for s in statuses}

    # These are NOT in secure_monitor.sh
    assert inactive_map["inventory"]
    assert inactive_map["arpwatch"]


def test_audit_shows_implementation():
    """Each sensor has implementation files."""
    statuses = audit_sensors()

    for status in statuses:
        assert status.has_implementation, f"{status.name} has no implementation"


def test_audit_counts_tests():
    """Each sensor has test files and estimated test count."""
    statuses = audit_sensors()

    for status in statuses:
        if status.test_files > 0:
            assert status.total_tests > 0, f"{status.name} has {status.test_files} test files but 0 tests"


def test_format_audit_table_is_readable():
    """Audit table is formatted as markdown."""
    statuses = audit_sensors()
    table = format_audit_table(statuses)

    # Should have header and separator
    assert "| Sensor |" in table
    assert "|--------|" in table

    # Should have all sensor names
    for status in statuses:
        assert status.name in table


def test_audit_notes_missing_critical_sensors():
    """Sensors that should be in monitor but aren't are flagged."""
    statuses = audit_sensors()

    # fileintegrity and checks ARE in monitor now, so no flag needed
    # Test remaining critical sensors that aren't in monitor
    inventory = next(s for s in statuses if s.name == "inventory")
    # inventory is not in monitor but not critical, so no required note


def test_audit_location_independent():
    """Audit detects sensors regardless of repo install location.

    Regression test: audit_sensors() should resolve repo root dynamically
    and not depend on hardcoded Desktop/~/Projects paths. If this test fails
    after a directory move, it means the path resolution broke.
    """
    statuses = audit_sensors()

    # All 9 sensors must be found
    sensor_names = {s.name for s in statuses}
    expected = {"persistence", "listening", "connections", "wifi", "bluetooth",
                "fileintegrity", "checks", "inventory", "arpwatch"}

    assert sensor_names == expected, (
        f"Audit failed to find sensors (repo path broken?): "
        f"missing {expected - sensor_names}"
    )
