"""Automation engine — Phase 64. Auto-escalate high-confidence threats without approval."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional

from secure.feedback.store import FeedbackStore
from secure.remediation.approval import ApprovalPolicy, RiskLevel


@dataclass
class ConfidenceScore:
    """Confidence metrics for an alert."""

    alert_id: int
    feedback_rate: float  # false_positive_rate from Phase 62
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    confidence_level: str  # "high", "medium", "low"
    confidence_score: float  # 0.0 to 1.0


class AutomationEngine:
    """Decide which alerts should auto-escalate without manual approval."""

    def __init__(self, db_conn: sqlite3.Connection):
        """Initialize automation engine.

        Args:
            db_conn: Database connection for feedback lookup
        """
        self.db_conn = db_conn
        self.feedback_store = FeedbackStore(db_conn)

    def calculate_confidence(
        self,
        alert_id: int,
        alert_type: Optional[str] = None,
        severity: str = "MEDIUM",
    ) -> ConfidenceScore:
        """Calculate confidence score for an alert based on feedback history.

        High confidence = low false positive rate + high severity.
        Confidence ranges: high (>0.8), medium (0.5-0.8), low (<0.5).

        Args:
            alert_id: Alert decision ID
            alert_type: Alert type for feedback filtering (e.g., 'anomaly_events')
            severity: Alert severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)

        Returns:
            ConfidenceScore with computed metrics
        """
        # Get feedback stats for this alert type
        stats = self.feedback_store.get_feedback_stats(alert_type=alert_type)

        # Start with severity-based baseline
        severity_weight = {"CRITICAL": 1.0, "HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5, "NONE": 0.0}.get(
            severity, 0.5
        )

        # Adjust for false positive rate: high FP rate lowers confidence
        fp_rate = 0.0
        if stats and stats.total_feedback > 0:
            fp_rate = stats.false_positives / stats.total_feedback
        else:
            # No feedback yet: neutral confidence
            fp_rate = 0.5

        # Confidence = high severity AND low false positive rate
        fp_penalty = fp_rate * 0.5  # FP rate can reduce confidence by 50%
        confidence_score = severity_weight * (1.0 - fp_penalty)
        confidence_score = max(0.0, min(1.0, confidence_score))

        # Classify confidence level
        if confidence_score > 0.8:
            confidence_level = "high"
        elif confidence_score > 0.5:
            confidence_level = "medium"
        else:
            confidence_level = "low"

        return ConfidenceScore(
            alert_id=alert_id,
            feedback_rate=fp_rate,
            severity=severity,
            confidence_level=confidence_level,
            confidence_score=confidence_score,
        )

    def should_auto_approve(
        self,
        alert_id: int,
        severity: str = "MEDIUM",
        alert_type: Optional[str] = None,
        allow_high_confidence_escalation: bool = True,
    ) -> tuple[bool, str]:
        """Decide if alert should auto-approve without manual review.

        Auto-approve if:
        - Confidence is HIGH (>0.8)
        - Allow high confidence escalation is enabled
        - Severity supports auto-action

        Args:
            alert_id: Alert decision ID
            severity: Alert severity
            alert_type: Alert type for feedback filtering
            allow_high_confidence_escalation: Whether to auto-approve high confidence

        Returns:
            (should_auto_approve: bool, reason: str)
        """
        if not allow_high_confidence_escalation:
            return False, "Auto-escalation disabled by policy"

        confidence = self.calculate_confidence(alert_id, alert_type, severity)

        if confidence.confidence_level == "high":
            return True, f"High confidence ({confidence.confidence_score:.1%}): low FP rate ({confidence.feedback_rate:.1%})"

        return False, f"Insufficient confidence ({confidence.confidence_level}): score {confidence.confidence_score:.1%}"

    def get_auto_approval_policy(
        self,
        alert_id: int,
        severity: str = "MEDIUM",
        alert_type: Optional[str] = None,
    ) -> ApprovalPolicy:
        """Generate an approval policy for an alert based on confidence.

        High confidence alerts get LOW risk level (auto-approve).
        Medium confidence gets MEDIUM risk (needs approval).
        Low confidence gets HIGH risk (full review).

        Args:
            alert_id: Alert decision ID
            severity: Alert severity
            alert_type: Alert type for feedback filtering

        Returns:
            ApprovalPolicy for this alert
        """
        confidence = self.calculate_confidence(alert_id, alert_type, severity)

        if confidence.confidence_level == "high":
            risk_level = RiskLevel.LOW
            approval_required = False
        elif confidence.confidence_level == "medium":
            risk_level = RiskLevel.MEDIUM
            approval_required = True
        else:
            risk_level = RiskLevel.HIGH
            approval_required = True

        return ApprovalPolicy(
            action_id=f"alert_{alert_id}",
            risk_level=risk_level,
            approval_required=approval_required,
            post_action_notification=True,
            rollback_allowed=True,
            rollback_window_hours=24,
        )
