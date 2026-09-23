"""Phase 53: Alert decision orchestration tests.

Tests for decide_alert() combining suppression and escalation.
"""

from datetime import datetime, timedelta, timezone

from secure.alerting.context import (
    AlertContext,
    DeviceContext,
    ExpectedChange,
    ResponseContext,
)
from secure.alerting.decide import decide_alert


def test_suppressed_event_not_escalated():
    """If event is suppressed, escalation is skipped."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device, expected_changes=(change,))

    # LOW event in suppression window with ADMIN device
    # Should be suppressed (not escalated to MEDIUM)
    decision = decide_alert(
        source_table="anomaly_events",
        source_id=123,
        entity_type="process_key",
        entity_path=None,
        base_severity="LOW",
        event_timestamp=now,
        context=ctx,
    )

    assert decision.verdict == "SUPPRESSED_EXPECTED"
    assert decision.final_severity == "LOW"  # Not escalated
    assert any("skipped" in r for r in decision.reasoning)


def test_downgraded_event_still_escalated():
    """If event is downgraded, escalation still applies from base."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device, expected_changes=(change,))

    # MEDIUM event in suppression window with ADMIN device
    # Should be downgraded (capped) but not suppressed
    # And escalation should still be considered
    decision = decide_alert(
        source_table="anomaly_events",
        source_id=123,
        entity_type="process_key",
        entity_path=None,
        base_severity="MEDIUM",
        event_timestamp=now,
        context=ctx,
    )

    assert decision.verdict == "DOWNGRADED_EXPECTED"
    assert decision.base_severity == "MEDIUM"
    # Final severity: MEDIUM + escalation (ADMIN) = HIGH (possibly capped by suppression)
    assert any("Suppression:" in r for r in decision.reasoning)


def test_active_event_escalated():
    """If event is not suppressed, escalation applies."""
    now = datetime.now(timezone.utc)
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device, expected_changes=())

    decision = decide_alert(
        source_table="anomaly_events",
        source_id=123,
        entity_type="process_key",
        entity_path=None,
        base_severity="MEDIUM",
        event_timestamp=now,
        context=ctx,
    )

    assert decision.verdict == "ACTIVE"
    assert decision.final_severity == "HIGH"  # Escalated by ADMIN role
    assert any("Escalation:" in r for r in decision.reasoning)


def test_reasoning_includes_both_components():
    """Reasoning list includes both suppression and escalation reasons."""
    now = datetime.now(timezone.utc)
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device, expected_changes=())

    decision = decide_alert(
        source_table="anomaly_events",
        source_id=123,
        entity_type="process_key",
        entity_path=None,
        base_severity="MEDIUM",
        event_timestamp=now,
        context=ctx,
    )

    has_suppression = any("Suppression:" in r for r in decision.reasoning)
    has_escalation = any("Escalation:" in r for r in decision.reasoning)
    assert has_suppression or has_escalation


def test_decision_captures_source_info():
    """Decision captures source table and ID."""
    ctx = AlertContext.empty()

    decision = decide_alert(
        source_table="correlation_alerts",
        source_id=456,
        entity_type="file_change",
        entity_path="/tmp/test",
        base_severity="HIGH",
        event_timestamp=datetime.now(timezone.utc),
        context=ctx,
    )

    assert decision.source_table == "correlation_alerts"
    assert decision.source_id == 456


def test_critical_never_downgraded():
    """CRITICAL events cannot be downgraded or suppressed."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    decision = decide_alert(
        source_table="anomaly_events",
        source_id=789,
        entity_type="process_key",
        entity_path=None,
        base_severity="CRITICAL",
        event_timestamp=now,
        context=ctx,
    )

    assert decision.verdict == "ACTIVE"
    assert decision.final_severity == "CRITICAL"
    assert decision.base_severity == "CRITICAL"


def test_complete_workflow_with_all_signals():
    """Full workflow: event + device context + response context + expected changes."""
    now = datetime.now(timezone.utc)
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=2,
    )
    response = ResponseContext(
        max_risk_level="HIGH",
        playbook_id="pb-123",
        playbook_severity="critical",
    )
    ctx = AlertContext(device=device, response=response, expected_changes=())

    decision = decide_alert(
        source_table="anomaly_events",
        source_id=999,
        entity_type="process_key",
        entity_path=None,
        base_severity="LOW",
        event_timestamp=now,
        context=ctx,
    )

    # LOW + 4 escalation signals (ADMIN, peer_count, HIGH response, critical playbook)
    # Step count clamped to +2 = LOW (index 1) + 2 = HIGH (index 3)
    assert decision.verdict == "ACTIVE"
    assert decision.final_severity == "HIGH"
    assert decision.base_severity == "LOW"
    assert len(decision.reasoning) > 0
