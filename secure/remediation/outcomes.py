"""
Outcomes — learning loop for remediation efficacy measurement.

Phase 48.4 tracks pre/post-remediation state changes to measure whether
actions actually worked, building efficacy data for future recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any


class OutcomeStatus(str, Enum):
    """Status of outcome measurement."""
    PENDING = "pending"
    MEASURING = "measuring"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


@dataclass
class PreScanSnapshot:
    """State of system before remediation."""
    scan_id: str
    timestamp: datetime
    finding_count: int
    anomaly_score: float
    active_services: list = field(default_factory=list)
    network_destinations: list = field(default_factory=list)
    file_changes: int = 0
    process_count: int = 0
    persistence_entries: int = 0


@dataclass
class PostScanSnapshot:
    """State of system after remediation."""
    scan_id: str
    timestamp: datetime
    elapsed_seconds: int
    finding_count: int
    anomaly_score: float
    active_services: list = field(default_factory=list)
    network_destinations: list = field(default_factory=list)
    file_changes: int = 0
    process_count: int = 0
    persistence_entries: int = 0


@dataclass
class RemediationOutcome:
    """Outcome record for a remediation action."""
    outcome_id: str
    execution_id: str
    action_id: str

    created_at: datetime = field(default_factory=datetime.utcnow)
    measured_at: Optional[datetime] = None

    pre_scan: Optional[PreScanSnapshot] = None
    post_scan: Optional[PostScanSnapshot] = None

    status: OutcomeStatus = OutcomeStatus.PENDING

    # Efficacy metrics
    findings_reduced: int = 0  # Pre - Post
    anomaly_score_change: float = 0.0  # Post - Pre
    services_disabled: int = 0
    destinations_isolated: int = 0
    time_to_effect: int = 0  # Seconds from execution to effect observed

    # Classification
    effectiveness: Optional[str] = None  # "high", "medium", "low", "none"
    reason: str = ""


class OutcomeEngine:
    """Measures remediation efficacy and learns from outcomes."""

    def __init__(self, conn: Optional[Any] = None):
        """Initialize outcome tracker with optional database connection for persistence."""
        self.outcomes: dict[str, RemediationOutcome] = {}
        self.conn = conn

    def create_outcome(
        self,
        execution_id: str,
        action_id: str,
        pre_scan: PreScanSnapshot,
        outcome_id: str = "",
    ) -> RemediationOutcome:
        """Create an outcome record with pre-remediation scan."""
        outcome_id = outcome_id or f"oc_{execution_id}_{action_id}"
        outcome = RemediationOutcome(
            outcome_id=outcome_id,
            execution_id=execution_id,
            action_id=action_id,
            pre_scan=pre_scan,
            status=OutcomeStatus.MEASURING,
        )
        self.outcomes[outcome_id] = outcome
        return outcome

    def record_post_scan(
        self,
        outcome_id: str,
        post_scan: PostScanSnapshot,
    ) -> RemediationOutcome | None:
        """Record post-remediation scan and calculate changes. Persists to DB if connected."""
        outcome = self.outcomes.get(outcome_id)
        if outcome is None or outcome.pre_scan is None:
            return None

        outcome.post_scan = post_scan
        outcome.measured_at = datetime.utcnow()

        # Calculate efficacy metrics
        outcome.findings_reduced = outcome.pre_scan.finding_count - post_scan.finding_count
        outcome.anomaly_score_change = post_scan.anomaly_score - outcome.pre_scan.anomaly_score
        outcome.time_to_effect = int(
            (post_scan.timestamp - outcome.pre_scan.timestamp).total_seconds()
        )

        # Determine effectiveness
        outcome = self._classify_effectiveness(outcome)
        outcome.status = OutcomeStatus.SUCCESS if outcome.findings_reduced > 0 else OutcomeStatus.PARTIAL

        # Persist to database if connected
        if self.conn:
            from secure.storage.models.remediation import insert_outcome
            insert_outcome(self.conn, outcome, outcome.execution_id)

        return outcome

    @staticmethod
    def _classify_effectiveness(outcome: RemediationOutcome) -> RemediationOutcome:
        """Classify effectiveness based on metrics."""
        if outcome.findings_reduced <= 0 and outcome.anomaly_score_change >= 0:
            outcome.effectiveness = "none"
            outcome.reason = "Finding count unchanged or increased"
        elif outcome.findings_reduced >= 3:
            outcome.effectiveness = "high"
            outcome.reason = f"Eliminated {outcome.findings_reduced} findings"
        elif outcome.findings_reduced >= 1:
            outcome.effectiveness = "medium"
            outcome.reason = f"Reduced findings by {outcome.findings_reduced}"
        else:
            outcome.effectiveness = "low"
            outcome.reason = "Minimal measurable improvement"

        return outcome

    def get_action_efficacy(self, action_id: str) -> dict:
        """Calculate cumulative efficacy stats for an action. Denominator is ALL measured outcomes, not just successes."""
        measured_outcomes = [
            o for o in self.outcomes.values()
            if o.action_id == action_id and o.post_scan is not None
        ]

        if not measured_outcomes:
            return {"action_id": action_id, "samples": 0, "success_rate": 0.0}

        effective = sum(
            1 for o in measured_outcomes if o.effectiveness in ("high", "medium")
        )
        ineffective = sum(
            1 for o in measured_outcomes if o.effectiveness == "none"
        )
        inconclusive = sum(
            1 for o in measured_outcomes if o.effectiveness == "low"
        )

        success_rate = effective / len(measured_outcomes)
        avg_reduced = sum(o.findings_reduced for o in measured_outcomes) / len(measured_outcomes)
        avg_time = sum(o.time_to_effect for o in measured_outcomes) / len(measured_outcomes)

        return {
            "action_id": action_id,
            "samples": len(measured_outcomes),
            "success_rate": success_rate,
            "effective": effective,
            "ineffective": ineffective,
            "inconclusive": inconclusive,
            "avg_findings_reduced": avg_reduced,
            "avg_time_to_effect": avg_time,
        }

    def get_outcome(self, outcome_id: str) -> RemediationOutcome | None:
        """Get outcome by ID."""
        return self.outcomes.get(outcome_id)

    def list_outcomes(self, action_id: str = "") -> list[RemediationOutcome]:
        """List outcomes, optionally filtered by action."""
        result = list(self.outcomes.values())
        if action_id:
            result = [o for o in result if o.action_id == action_id]
        return sorted(result, key=lambda o: o.created_at, reverse=True)
