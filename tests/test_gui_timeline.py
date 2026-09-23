"""Tests for GUI timeline view (Phase 61)."""

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

from secure.storage.database import init_schema
from secure_gui.timeline_view import TimelineController, TimelineEvent


def test_timeline_controller_fetches_events():
    """Timeline controller queries alert_decisions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"
        db_conn = sqlite3.connect(db_path)
        db_conn.row_factory = sqlite3.Row
        init_schema(db_conn)

        controller = TimelineController(db_conn)
        events = controller.fetch_recent_events(hours=24)

        # Should handle empty database gracefully
        assert isinstance(events, list)


def test_timeline_event_grouping_by_sensor():
    """Timeline controller groups events by sensor."""
    now = datetime.now(timezone.utc)
    events = [
        TimelineEvent(
            timestamp=now,
            sensor="persistence",
            severity="HIGH",
            entity_type="launchagent",
            entity_path="/test/path",
            verdict="ACTIVE",
            confidence="HIGH",
            summary="Test event 1",
        ),
        TimelineEvent(
            timestamp=now - timedelta(hours=1),
            sensor="listening",
            severity="MEDIUM",
            entity_type="port",
            entity_path="127.0.0.1:8080",
            verdict="ACTIVE",
            confidence="MEDIUM",
            summary="Test event 2",
        ),
        TimelineEvent(
            timestamp=now - timedelta(hours=2),
            sensor="persistence",
            severity="LOW",
            entity_type="file",
            entity_path="/etc/hosts",
            verdict="SUPPRESSED_EXPECTED",
            confidence="LOW",
            summary="Test event 3",
        ),
    ]

    controller = TimelineController(None)
    grouped = controller.events_by_sensor(events)

    assert "persistence" in grouped
    assert "listening" in grouped
    assert len(grouped["persistence"]) == 2
    assert len(grouped["listening"]) == 1


def test_timeline_event_grouping_by_hour():
    """Timeline controller groups events by hour."""
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    events = [
        TimelineEvent(
            timestamp=now,
            sensor="persistence",
            severity="HIGH",
            entity_type="launchagent",
            entity_path="/test",
            verdict="ACTIVE",
            confidence="HIGH",
            summary="Recent event",
        ),
        TimelineEvent(
            timestamp=one_hour_ago,
            sensor="listening",
            severity="MEDIUM",
            entity_type="port",
            entity_path="127.0.0.1:8080",
            verdict="ACTIVE",
            confidence="MEDIUM",
            summary="Older event",
        ),
    ]

    controller = TimelineController(None)
    grouped = controller.events_by_hour(events)

    # Should have 2 groups (1 per hour)
    assert len(grouped) == 2


def test_severity_color_mapping():
    """Severity maps to color codes."""
    from secure_gui.timeline_view import severity_color

    assert severity_color("CRITICAL") == "#d91e18"  # Red
    assert severity_color("HIGH") == "#ff8000"      # Orange
    assert severity_color("MEDIUM") == "#f9a603"    # Yellow-orange
    assert severity_color("LOW") == "#0055cc"       # Blue
    assert severity_color("UNKNOWN") == "#cccccc"   # Gray default
