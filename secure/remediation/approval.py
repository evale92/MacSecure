"""
Approval — remediation action approval workflows.

Phase 48.2 implements risk-stratified approval flows:
- LOW: Auto-execute immediately, user notified after
- MEDIUM: Require human approval (1-hour timeout)
- HIGH: Full Phase 47 review workflow (24-hour timeout)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Literal, Optional

from secure.remediation.models import RiskLevel, RemediationAction


class ApprovalStatus(str, Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


class EscalationPath(str, Enum):
    """Where to escalate approval requests."""
    HUMAN_REVIEW = "human_review"
    MDM_SUPERVISOR = "mdm_supervisor"
    SECURITY_TEAM = "security_team"


@dataclass
class ApprovalRequest:
    """A request for approval to execute a remediation action."""
    request_id: str
    action_id: str
    triggered_by: str                           # Finding ID, playbook run, user request
    triggered_by_ref: str                       # Reference to the trigger
    risk_level: RiskLevel

    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    # Approval tracking
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None           # User ID, "system", "auto"
    approval_reason: Optional[str] = None

    # Escalation
    escalation_path: Optional[EscalationPath] = None
    escalation_sent_at: Optional[datetime] = None


@dataclass
class ApprovalPolicy:
    """Policy determining how an action should be approved."""
    action_id: str
    risk_level: RiskLevel
    approval_required: bool

    # If approval is required:
    escalation_path: Optional[EscalationPath] = None
    escalation_timeout: timedelta = field(default_factory=lambda: timedelta(hours=1))

    # If low-risk and auto-executable:
    post_action_notification: bool = True
    rollback_allowed: bool = True
    rollback_window_hours: int = 24

    # User configurable overrides
    always_require_approval: bool = False       # User can force human review
    never_auto_approve: bool = False            # Even LOW actions need approval


class ApprovalEngine:
    """Routes remediation actions to appropriate approval workflows."""

    def __init__(self, policies: dict[str, ApprovalPolicy] | None = None):
        """Initialize approval engine with optional custom policies."""
        self.policies = policies or self._default_policies()

    @staticmethod
    def _default_policies() -> dict[str, ApprovalPolicy]:
        """Return default approval policies for all actions."""
        return {
            # LOW-risk: auto-execute with notification
            "firewall.enable": ApprovalPolicy(
                action_id="firewall.enable",
                risk_level=RiskLevel.LOW,
                approval_required=False,
                post_action_notification=True,
                rollback_allowed=True,
            ),

            "ssh.disable-root-login": ApprovalPolicy(
                action_id="ssh.disable-root-login",
                risk_level=RiskLevel.LOW,
                approval_required=False,
                post_action_notification=True,
                rollback_allowed=True,
            ),

            "config.harden-umask": ApprovalPolicy(
                action_id="config.harden-umask",
                risk_level=RiskLevel.LOW,
                approval_required=False,
                post_action_notification=True,
                rollback_allowed=True,
            ),

            # MEDIUM-risk: human approval required, 1-hour timeout
            "firewall.block-inbound": ApprovalPolicy(
                action_id="firewall.block-inbound",
                risk_level=RiskLevel.MEDIUM,
                approval_required=True,
                escalation_path=EscalationPath.HUMAN_REVIEW,
                escalation_timeout=timedelta(hours=1),
                post_action_notification=True,
                rollback_allowed=True,
            ),

            "service.disable-launchagent": ApprovalPolicy(
                action_id="service.disable-launchagent",
                risk_level=RiskLevel.MEDIUM,
                approval_required=True,
                escalation_path=EscalationPath.HUMAN_REVIEW,
                escalation_timeout=timedelta(hours=1),
                post_action_notification=True,
                rollback_allowed=True,
            ),

            "endpoint.mdm-notify": ApprovalPolicy(
                action_id="endpoint.mdm-notify",
                risk_level=RiskLevel.MEDIUM,
                approval_required=True,
                escalation_path=EscalationPath.MDM_SUPERVISOR,
                escalation_timeout=timedelta(hours=2),
            ),

            # HIGH-risk: full Phase 47 review, 24-hour timeout
            "network.isolate-destination": ApprovalPolicy(
                action_id="network.isolate-destination",
                risk_level=RiskLevel.HIGH,
                approval_required=True,
                escalation_path=EscalationPath.SECURITY_TEAM,
                escalation_timeout=timedelta(hours=24),
                post_action_notification=True,
                rollback_allowed=False,  # Network isolation not user-reversible
            ),
        }

    def get_policy(self, action_id: str) -> ApprovalPolicy | None:
        """Get the approval policy for an action."""
        return self.policies.get(action_id)

    def create_approval_request(
        self,
        action_id: str,
        triggered_by: str,
        triggered_by_ref: str,
        request_id: str | None = None,
    ) -> ApprovalRequest | None:
        """Create an approval request for an action.

        Returns None if action is not in policy (unknown action).
        Returns an ApprovalRequest with appropriate status and expiration.
        """
        policy = self.get_policy(action_id)
        if policy is None:
            return None

        request_id = request_id or f"ar_{action_id}_{triggered_by_ref}"
        now = datetime.utcnow()

        # Low-risk actions auto-approve immediately
        if not policy.approval_required and not policy.always_require_approval:
            return ApprovalRequest(
                request_id=request_id,
                action_id=action_id,
                triggered_by=triggered_by,
                triggered_by_ref=triggered_by_ref,
                risk_level=policy.risk_level,
                created_at=now,
                expires_at=None,  # No timeout for auto-approved
                status=ApprovalStatus.AUTO_APPROVED,
                approved_at=now,
                approved_by="system",
            )

        # Medium/high-risk require approval
        return ApprovalRequest(
            request_id=request_id,
            action_id=action_id,
            triggered_by=triggered_by,
            triggered_by_ref=triggered_by_ref,
            risk_level=policy.risk_level,
            created_at=now,
            expires_at=now + policy.escalation_timeout,
            status=ApprovalStatus.PENDING,
            escalation_path=policy.escalation_path,
        )

    def approve_request(
        self,
        request: ApprovalRequest,
        approved_by: str,
        reason: str = "",
    ) -> ApprovalRequest:
        """Approve a pending approval request."""
        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot approve {request.status} request")

        request.status = ApprovalStatus.APPROVED
        request.approved_at = datetime.utcnow()
        request.approved_by = approved_by
        request.approval_reason = reason
        return request

    def reject_request(
        self,
        request: ApprovalRequest,
        rejected_by: str,
        reason: str = "",
    ) -> ApprovalRequest:
        """Reject a pending approval request."""
        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot reject {request.status} request")

        request.status = ApprovalStatus.REJECTED
        request.approved_by = rejected_by
        request.approval_reason = reason
        return request

    def check_expiration(self, request: ApprovalRequest) -> ApprovalRequest:
        """Check if a request has expired; update status if so."""
        if request.status != ApprovalStatus.PENDING or request.expires_at is None:
            return request

        if datetime.utcnow() > request.expires_at:
            request.status = ApprovalStatus.EXPIRED

        return request

    def is_approved(self, request: ApprovalRequest) -> bool:
        """Check if a request is approved (either auto or human)."""
        return request.status in [
            ApprovalStatus.APPROVED,
            ApprovalStatus.AUTO_APPROVED,
        ]

    def can_execute(self, request: ApprovalRequest) -> bool:
        """Check if an action can execute (approved and not expired)."""
        request = self.check_expiration(request)
        return self.is_approved(request)
