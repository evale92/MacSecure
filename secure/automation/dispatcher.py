"""Alert dispatcher with automation — Phase 64. Routes high-confidence alerts for auto-escalation."""

from __future__ import annotations

import sqlite3
from typing import Optional

from secure.automation.engine import AutomationEngine
from secure.remediation.approval import ApprovalStatus, ApprovalRequest, ApprovalEngine
from secure.remediation.models import RiskLevel
from datetime import datetime, timedelta
import uuid


class AutomatedAlertDispatcher:
    """Routes alerts to approval system with confidence-based auto-approval."""

    def __init__(self, db_conn: sqlite3.Connection):
        """Initialize dispatcher.

        Args:
            db_conn: Database connection
        """
        self.db_conn = db_conn
        self.automation_engine = AutomationEngine(db_conn)
        self.approval_engine = ApprovalEngine(db_conn)

    def process_alert_for_automation(
        self,
        alert_id: int,
        severity: str,
        verdict: str,
        entity_type: Optional[str] = None,
        allow_auto_escalation: bool = True,
    ) -> tuple[ApprovalStatus, str]:
        """Process an alert and determine approval status using automation.

        High confidence + appropriate severity = auto-approve.
        Everything else goes to standard approval flow.

        Args:
            alert_id: Alert decision ID
            severity: Alert severity (CRITICAL, HIGH, MEDIUM, LOW)
            verdict: Alert verdict (ACTIVE, SUPPRESSED_EXPECTED, etc.)
            entity_type: Entity type for feedback filtering
            allow_auto_escalation: Whether to allow auto-approval

        Returns:
            (approval_status: ApprovalStatus, reason: str)
        """
        if verdict != "ACTIVE":
            # Suppressed or downgraded alerts don't need approval
            return ApprovalStatus.APPROVED, "Alert not active (suppressed/downgraded)"

        if not allow_auto_escalation:
            return ApprovalStatus.PENDING, "Auto-escalation disabled"

        # Check if this alert should auto-approve
        should_auto, confidence_reason = self.automation_engine.should_auto_approve(
            alert_id=alert_id,
            severity=severity,
            alert_type=entity_type,
            allow_high_confidence_escalation=True,
        )

        if should_auto:
            return (
                ApprovalStatus.AUTO_APPROVED,
                f"Auto-approved: {confidence_reason}",
            )

        # Not auto-approvable; needs manual review
        policy = self.automation_engine.get_auto_approval_policy(
            alert_id=alert_id,
            severity=severity,
            alert_type=entity_type,
        )

        if policy.risk_level == RiskLevel.LOW:
            # Low risk but didn't meet auto-approval criteria (shouldn't happen)
            return ApprovalStatus.APPROVED, "Low-risk alert approved"

        # MEDIUM or HIGH risk: needs approval
        return ApprovalStatus.PENDING, f"Requires approval ({policy.risk_level.value} risk)"

    def create_automation_request(
        self,
        alert_id: int,
        severity: str,
        entity_type: Optional[str] = None,
    ) -> Optional[dict]:
        """Create an automation request record for auditing.

        Args:
            alert_id: Alert decision ID
            severity: Alert severity
            entity_type: Entity type for feedback

        Returns:
            Dict with automation decision details, or None if not auto-approved
        """
        should_auto, reason = self.automation_engine.should_auto_approve(
            alert_id=alert_id,
            severity=severity,
            alert_type=entity_type,
        )

        if not should_auto:
            return None

        confidence = self.automation_engine.calculate_confidence(
            alert_id=alert_id,
            severity=severity,
            alert_type=entity_type,
        )

        return {
            "automation_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "decision": "auto_approved",
            "confidence_level": confidence.confidence_level,
            "confidence_score": confidence.confidence_score,
            "feedback_rate": confidence.feedback_rate,
            "severity": severity,
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
        }
