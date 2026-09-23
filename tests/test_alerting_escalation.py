"""Phase 53: Escalation logic tests.

Tests for context-aware severity weighting and tier stepping.
"""

from secure.alerting.context import AlertContext, DeviceContext, ResponseContext
from secure.alerting.escalation import weigh


def test_base_severity_with_no_context():
    """With empty context, severity unchanged."""
    ctx = AlertContext.empty()
    final, reasons = weigh("MEDIUM", ctx)
    assert final == "MEDIUM"
    assert len(reasons) == 0


def test_admin_device_escalates():
    """Device role ADMIN adds +1 step."""
    device = DeviceContext(
        device_id="admin-machine",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device)

    final, reasons = weigh("MEDIUM", ctx)
    assert final == "HIGH"
    assert any("ADMIN" in r for r in reasons)


def test_shared_device_escalates():
    """Device role SHARED adds +1 step."""
    device = DeviceContext(
        device_id="shared-machine",
        role="SHARED",
        health="healthy",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device)

    final, reasons = weigh("MEDIUM", ctx)
    assert final == "HIGH"
    assert any("SHARED" in r for r in reasons)


def test_peer_device_count_escalates():
    """peer_device_count >= 2 adds +1 step (supply-chain indicator)."""
    device = DeviceContext(
        device_id="device-1",
        role="PRIMARY",
        health="healthy",
        sync_state="synced",
        peer_device_count=3,  # 3 peers
    )
    ctx = AlertContext(device=device)

    final, reasons = weigh("MEDIUM", ctx)
    assert final == "HIGH"
    assert any("peer" in r.lower() for r in reasons)


def test_high_risk_remediation_escalates():
    """response.max_risk_level == HIGH adds +1 step."""
    response = ResponseContext(
        max_risk_level="HIGH",
        playbook_id=None,
        playbook_severity=None,
    )
    ctx = AlertContext(response=response)

    final, reasons = weigh("MEDIUM", ctx)
    assert final == "HIGH"
    assert any("HIGH-risk" in r for r in reasons)


def test_critical_playbook_escalates():
    """response.playbook_severity == critical adds +1 step."""
    response = ResponseContext(
        max_risk_level="LOW",
        playbook_id="pb-123",
        playbook_severity="critical",
    )
    ctx = AlertContext(response=response)

    final, reasons = weigh("MEDIUM", ctx)
    assert final == "HIGH"
    assert any("critical-severity playbook" in r for r in reasons)


def test_multiple_escalation_signals():
    """Multiple signals stack with ±2 tier clamp applied to step count."""
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=3,
    )
    response = ResponseContext(
        max_risk_level="HIGH",
        playbook_id="pb-123",
        playbook_severity="critical",
    )
    ctx = AlertContext(device=device, response=response)

    # LOW + 4 signals (ADMIN, peer_count, HIGH response, critical playbook)
    # Steps clamped to +2 = LOW (index 1) + 2 = HIGH (index 3)
    final, reasons = weigh("LOW", ctx)
    assert final == "HIGH"  # Clamped to +2
    assert any("clamped" in r for r in reasons)


def test_escalation_clamped_at_plus_two():
    """Escalation clamped to +2 tiers maximum (enforced on step count)."""
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=3,
    )
    response = ResponseContext(
        max_risk_level="HIGH",
        playbook_id="pb-123",
        playbook_severity="critical",
    )
    ctx = AlertContext(device=device, response=response)

    # LOW with 4 signals: steps clamped to +2 = LOW (index 1) + 2 = HIGH (index 3)
    final, reasons = weigh("LOW", ctx)
    assert final == "HIGH"
    # Should note the clamping
    assert any("clamped" in r.lower() for r in reasons)


def test_escalation_clamped_at_critical():
    """Cannot escalate above CRITICAL."""
    device = DeviceContext(
        device_id="device",
        role="ADMIN",
        health="healthy",
        sync_state="synced",
        peer_device_count=3,
    )
    response = ResponseContext(
        max_risk_level="HIGH",
        playbook_id="pb-123",
        playbook_severity="critical",
    )
    ctx = AlertContext(device=device, response=response)

    # CRITICAL + signals = stays CRITICAL (can't go higher)
    final, reasons = weigh("CRITICAL", ctx)
    assert final == "CRITICAL"


def test_device_health_annotated_not_escalated():
    """Device health degraded/stale is annotated but never escalates."""
    device = DeviceContext(
        device_id="device",
        role="PRIMARY",
        health="degraded",
        sync_state="synced",
        peer_device_count=0,
    )
    ctx = AlertContext(device=device)

    final, reasons = weigh("MEDIUM", ctx)
    # No escalation, but health should be annotated
    assert final == "MEDIUM"
    assert any("degraded" in r for r in reasons)


def test_unknown_base_severity_passthrough():
    """Unknown base severity passes through unchanged with warning."""
    ctx = AlertContext.empty()
    final, reasons = weigh("UNKNOWN_TIER", ctx)
    assert final == "UNKNOWN_TIER"
    assert any("unknown" in r for r in reasons)
