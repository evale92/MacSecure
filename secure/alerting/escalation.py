"""Escalation logic — context-aware severity weighting.

PURE function. No I/O, no imports from remediation/multi_device/intelligence.
Additive tier steps with ±2 tier clamp.
"""

from __future__ import annotations

from typing import List, Tuple

from secure.alerting.context import AlertContext

# Severity tier ladder (ordinal: INFORMATIONAL < LOW < MEDIUM < HIGH < CRITICAL)
_TIERS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_TIER_TO_INDEX = {t: i for i, t in enumerate(_TIERS)}


def weigh(base_severity: str, context: AlertContext) -> Tuple[str, List[str]]:
    """
    Escalate (or cap) base severity based on context signals.

    Signals (each +1 step, max ±2 total):
    - device.role == ADMIN: +1 (blast radius)
    - device.role == SHARED: +1 (multi-user exposure)
    - peer_device_count >= 2 with same finding: +1 (supply-chain indicator)
    - response.max_risk_level == HIGH: +1 (matching HIGH-risk remediation exists)
    - playbook_severity == critical: +1 (Phase 51 judgment)
    - device.health == degraded/stale: 0, annotate only (reduced visibility ≠ reduced severity)

    Returns:
        (final_severity, list of reason strings)
    """
    if base_severity not in _TIER_TO_INDEX:
        return (base_severity, ["unknown base severity"])

    base_idx = _TIER_TO_INDEX[base_severity]
    steps = 0
    reasons = []

    if context.device:
        if context.device.role == "ADMIN":
            steps += 1
            reasons.append("device role is ADMIN (blast radius)")

        if context.device.role == "SHARED":
            steps += 1
            reasons.append("device role is SHARED (multi-user exposure)")

        if context.device.peer_device_count >= 2:
            steps += 1
            reasons.append(f"same finding across {context.device.peer_device_count} peer devices (supply-chain indicator)")

        if context.device.health in ("degraded", "stale"):
            reasons.append(f"device health is {context.device.health} (reduced visibility — annotated only)")

    if context.response:
        if context.response.max_risk_level == "HIGH":
            steps += 1
            reasons.append("matching HIGH-risk remediation action exists")

        if context.response.playbook_severity == "critical":
            steps += 1
            reasons.append("matching critical-severity playbook (Phase 51)")

    # Clamp step count to ±2 tiers per design spec
    original_steps = steps
    steps = max(-2, min(2, steps))
    if steps != original_steps:
        reasons.append("step count clamped to ±2 tiers")

    final_idx = max(0, min(len(_TIERS) - 1, base_idx + steps))

    final_severity = _TIERS[final_idx]
    return (final_severity, reasons)
