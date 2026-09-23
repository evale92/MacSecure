"""Alert decision orchestration — combines suppression and escalation.

PURE function. No I/O, no imports from remediation/multi_device/intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from secure.alerting.context import AlertContext
from secure.alerting.suppression import classify as classify_suppression, SuppressionVerdict
from secure.alerting.escalation import weigh


@dataclass(frozen=True)
class AlertDecision:
    """Result of alert decision logic."""
    source_table: str                  # anomaly_events | correlation_alerts | correlation_chain_alerts
    source_id: int
    base_severity: str
    verdict: str                       # ACTIVE | SUPPRESSED_EXPECTED | DOWNGRADED_EXPECTED
    final_severity: str
    reasoning: List[str]               # component-by-component reasons


def decide_alert(
    source_table: str,
    source_id: int,
    entity_type: str,
    entity_path: Optional[str],
    base_severity: str,
    event_timestamp: datetime,
    context: AlertContext,
) -> AlertDecision:
    """
    Make an alert decision: escalate, then suppress.

    Process:
    1. Escalate? (context weighting) — check if escalation signals override suppression
    2. Suppress? (expected changes) — apply suppression if no escalation signals
    3. Build reasoning record

    By escalating first, high-risk escalation signals won't be fully suppressed by expected changes.
    """
    reasoning = []

    # Step 1: Escalation first (context weighting)
    escalated_severity, escalation_reasons = weigh(base_severity, context)
    if escalation_reasons:
        for reason in escalation_reasons:
            reasoning.append(f"Escalation: {reason}")
    else:
        reasoning.append("Escalation: no signals")

    # Step 2: Suppression (applies to base severity; multi_device check prevents full suppression)
    suppression = classify_suppression(
        event_severity=base_severity,
        entity_type=entity_type,
        entity_path=entity_path,
        event_timestamp=event_timestamp,
        context=context,
    )

    if suppression.reason:
        reasoning.append(f"Suppression: {suppression.reason}")

    # Final decision: determine severity based on suppression + escalation
    # - SUPPRESSED: use base_severity (event is in expected-change window)
    # - DOWNGRADED: use base_severity (downgrade was already decided by suppression)
    # - ACTIVE: use escalated_severity (no suppression, so escalation applies)
    if suppression.category in ("SUPPRESSED_EXPECTED", "DOWNGRADED_EXPECTED"):
        final_severity = base_severity
    else:  # ACTIVE
        final_severity = escalated_severity

    return AlertDecision(
        source_table=source_table,
        source_id=source_id,
        base_severity=base_severity,
        verdict=suppression.category,
        final_severity=final_severity,
        reasoning=reasoning,
    )
