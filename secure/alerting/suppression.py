"""Suppression logic — expected-change rules for false-positive reduction.

PURE function. No I/O, no imports from remediation/multi_device/intelligence.
Takes an event and AlertContext as values.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from secure.alerting.context import AlertContext, ExpectedChange


@dataclass(frozen=True)
class SuppressionVerdict:
    """Result of suppression classification."""
    category: str                      # ACTIVE | SUPPRESSED_EXPECTED | DOWNGRADED_EXPECTED
    matching_expected_change: Optional[ExpectedChange] = None
    reason: str = ""


def classify(
    event_severity: str,
    entity_type: str,
    entity_path: Optional[str],
    event_timestamp: datetime,
    context: AlertContext,
) -> SuppressionVerdict:
    """
    Classify an event against expected-change windows.

    Rules:
    1. CRITICAL events are never suppressed (cap only, never full suppression).
    2. Match requires entity-type AND path-prefix agreement, plus timestamp inside window.
    3. Record the matching ExpectedChange.source (audit trail).

    Returns:
        SuppressionVerdict with category and optionally matching source.
    """
    if event_severity == "CRITICAL":
        return SuppressionVerdict(
            category="ACTIVE",
            reason="CRITICAL severity never suppressed per policy"
        )

    if not context.expected_changes:
        return SuppressionVerdict(category="ACTIVE")

    # Check each expected change window
    for change in context.expected_changes:
        if event_timestamp < change.started_at or event_timestamp > change.ends_at:
            continue  # Outside window

        if entity_type not in change.entity_types:
            continue  # Entity type mismatch

        # Path matching: requires at least one prefix to match (or no prefixes specified = match any path)
        if change.path_prefixes and entity_path:
            if not any(entity_path.startswith(p) for p in change.path_prefixes):
                continue  # Path mismatch
        elif change.path_prefixes and not entity_path:
            continue  # Window requires path but event has none

        # Match! Apply suppression rules based on severity
        if event_severity in ("HIGH", "MEDIUM"):
            # Cap only — downgrade one tier, never full suppression
            return SuppressionVerdict(
                category="DOWNGRADED_EXPECTED",
                matching_expected_change=change,
                reason=f"Expected change '{change.kind}' from {change.source} — capped severity"
            )
        else:
            # LOW / INFORMATIONAL — full suppression allowed
            return SuppressionVerdict(
                category="SUPPRESSED_EXPECTED",
                matching_expected_change=change,
                reason=f"Expected change '{change.kind}' from {change.source} — suppressed"
            )

    return SuppressionVerdict(category="ACTIVE")
