"""
Tests for Phase 48.2 remediation approval workflows.
"""

import pytest
from datetime import datetime, timedelta

from secure.remediation.approval import (
    ApprovalEngine,
    ApprovalRequest,
    ApprovalPolicy,
    ApprovalStatus,
    EscalationPath,
)
from secure.remediation.models import RiskLevel


class TestApprovalEngine:
    """Test the approval engine."""

    def test_engine_creates_with_defaults(self):
        """ApprovalEngine initializes with default policies."""
        engine = ApprovalEngine()
        assert engine.policies is not None
        assert len(engine.policies) >= 12

    def test_get_policy_for_action(self):
        """Can retrieve policy for a known action."""
        engine = ApprovalEngine()
        policy = engine.get_policy("firewall.enable")
        assert policy is not None
        assert policy.action_id == "firewall.enable"
        assert policy.risk_level == RiskLevel.LOW

    def test_get_policy_nonexistent_returns_none(self):
        """get_policy returns None for unknown action."""
        engine = ApprovalEngine()
        policy = engine.get_policy("unknown.action")
        assert policy is None


class TestLowRiskApproval:
    """Test LOW-risk auto-approval workflow."""

    def test_low_risk_auto_approved(self):
        """LOW-risk actions are auto-approved."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.enable",
            triggered_by="finding",
            triggered_by_ref="finding_123",
        )
        assert request is not None
        assert request.status == ApprovalStatus.AUTO_APPROVED
        assert request.approved_by == "system"
        assert request.approved_at is not None

    def test_low_risk_no_expiration(self):
        """AUTO_APPROVED requests don't expire."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="ssh.disable-root-login",
            triggered_by="playbook",
            triggered_by_ref="playbook_1",
        )
        assert request.expires_at is None

    def test_low_risk_can_execute_immediately(self):
        """LOW-risk approved requests can execute immediately."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="config.harden-umask",
            triggered_by="user",
            triggered_by_ref="user_initiated",
        )
        assert engine.can_execute(request)


class TestMediumRiskApproval:
    """Test MEDIUM-risk human-review workflow."""

    def test_medium_risk_pending(self):
        """MEDIUM-risk actions start PENDING."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.block-inbound",
            triggered_by="finding",
            triggered_by_ref="finding_456",
        )
        assert request is not None
        assert request.status == ApprovalStatus.PENDING
        assert request.approved_by is None

    def test_medium_risk_has_escalation(self):
        """MEDIUM-risk requests have escalation path."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="service.disable-launchagent",
            triggered_by="detection",
            triggered_by_ref="detection_789",
        )
        assert request.escalation_path == EscalationPath.HUMAN_REVIEW
        assert request.escalation_sent_at is None

    def test_medium_risk_has_timeout(self):
        """MEDIUM-risk requests have 1-hour timeout."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.block-inbound",
            triggered_by="finding",
            triggered_by_ref="finding_999",
        )
        assert request.expires_at is not None
        # Expiration should be roughly 1 hour from now
        delta = (request.expires_at - request.created_at).total_seconds()
        assert 3500 < delta < 3700  # ~1 hour (3600 seconds), allow small variance

    def test_cannot_execute_medium_risk_pending(self):
        """MEDIUM-risk PENDING requests cannot execute."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="endpoint.mdm-notify",
            triggered_by="incident",
            triggered_by_ref="incident_1",
        )
        assert not engine.can_execute(request)

    def test_approve_pending_request(self):
        """Can approve a PENDING request."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.block-inbound",
            triggered_by="finding",
            triggered_by_ref="finding_555",
        )

        approved = engine.approve_request(
            request,
            approved_by="user_admin",
            reason="Verified finding is legitimate",
        )

        assert approved.status == ApprovalStatus.APPROVED
        assert approved.approved_by == "user_admin"
        assert approved.approved_at is not None
        assert approved.approval_reason == "Verified finding is legitimate"

    def test_execute_after_approval(self):
        """Can execute after approval."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="service.disable-launchagent",
            triggered_by="finding",
            triggered_by_ref="finding_777",
        )

        approved = engine.approve_request(
            request,
            approved_by="security_team",
        )

        assert engine.can_execute(approved)


class TestHighRiskApproval:
    """Test HIGH-risk full-review workflow."""

    def test_high_risk_pending_24h_timeout(self):
        """HIGH-risk requests have 24-hour timeout."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="network.isolate-destination",
            triggered_by="anomaly",
            triggered_by_ref="anomaly_score_95",
        )
        assert request.status == ApprovalStatus.PENDING
        assert request.escalation_path == EscalationPath.SECURITY_TEAM

        delta = (request.expires_at - request.created_at).total_seconds()
        # 24 hours = 86400 seconds
        assert 85000 < delta < 87000  # Allow variance

    def test_high_risk_no_auto_rollback(self):
        """HIGH-risk actions don't support user rollback."""
        engine = ApprovalEngine()
        policy = engine.get_policy("network.isolate-destination")
        assert policy is not None
        assert policy.rollback_allowed is False


class TestApprovalExpiration:
    """Test approval request expiration."""

    def test_pending_request_checks_expiration(self):
        """Expired PENDING requests update status."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.block-inbound",
            triggered_by="finding",
            triggered_by_ref="finding_exp1",
        )

        # Manually set expiration to past
        request.expires_at = datetime.utcnow() - timedelta(seconds=1)

        checked = engine.check_expiration(request)
        assert checked.status == ApprovalStatus.EXPIRED
        assert not engine.can_execute(checked)

    def test_auto_approved_never_expires(self):
        """AUTO_APPROVED requests never expire."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.enable",
            triggered_by="playbook",
            triggered_by_ref="pb_1",
        )
        # Manually set to past to test
        request.created_at = datetime.utcnow() - timedelta(days=1)

        # Should still be executable
        assert engine.can_execute(request)


class TestApprovalRejection:
    """Test rejection workflow."""

    def test_reject_pending_request(self):
        """Can reject a PENDING request."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.block-inbound",
            triggered_by="finding",
            triggered_by_ref="finding_rej1",
        )

        rejected = engine.reject_request(
            request,
            rejected_by="user_security",
            reason="Potential false positive, needs more investigation",
        )

        assert rejected.status == ApprovalStatus.REJECTED
        assert rejected.approved_by == "user_security"
        assert "false positive" in rejected.approval_reason.lower()
        assert not engine.can_execute(rejected)

    def test_cannot_reject_approved(self):
        """Cannot reject an already-approved request."""
        engine = ApprovalEngine()
        request = engine.create_approval_request(
            action_id="firewall.block-inbound",
            triggered_by="finding",
            triggered_by_ref="finding_rej2",
        )
        approved = engine.approve_request(request, "admin")

        with pytest.raises(ValueError):
            engine.reject_request(approved, "user", "Too late")


class TestApprovalPolicies:
    """Test approval policy configurations."""

    def test_default_low_risk_policies(self):
        """Default policies mark LOW-risk as no approval required."""
        engine = ApprovalEngine()
        low_risk_ids = [
            "firewall.enable",
            "ssh.disable-root-login",
            "ssh.disable-password-auth",
            "config.harden-umask",
            "process.alert-on-relaunch",
            "credential.recommend-rotation",
            "threat-hunt.priority-flag",
        ]
        for action_id in low_risk_ids:
            policy = engine.get_policy(action_id)
            assert policy is not None
            assert policy.approval_required is False

    def test_default_medium_risk_policies(self):
        """Default policies mark MEDIUM-risk as approval required."""
        engine = ApprovalEngine()
        human_review_ids = [
            "firewall.block-inbound",
            "service.disable-launchagent",
            "service.disable-launchdaemon",
        ]
        for action_id in human_review_ids:
            policy = engine.get_policy(action_id)
            assert policy is not None
            assert policy.approval_required is True
            assert policy.escalation_path == EscalationPath.HUMAN_REVIEW

        # MDM notify has its own escalation path
        mdm_policy = engine.get_policy("endpoint.mdm-notify")
        assert mdm_policy is not None
        assert mdm_policy.approval_required is True
        assert mdm_policy.escalation_path == EscalationPath.MDM_SUPERVISOR

    def test_default_high_risk_policies(self):
        """Default policies mark HIGH-risk with full review."""
        engine = ApprovalEngine()
        high_risk_ids = ["network.isolate-destination"]
        for action_id in high_risk_ids:
            policy = engine.get_policy(action_id)
            assert policy is not None
            assert policy.approval_required is True
            assert policy.escalation_path == EscalationPath.SECURITY_TEAM


class TestCustomPolicies:
    """Test custom approval policies."""

    def test_custom_policy_override(self):
        """Can override default policies."""
        custom_policies = {
            "firewall.enable": ApprovalPolicy(
                action_id="firewall.enable",
                risk_level=RiskLevel.LOW,
                approval_required=True,  # Override default
                escalation_path=EscalationPath.HUMAN_REVIEW,
            ),
        }
        engine = ApprovalEngine(policies=custom_policies)
        request = engine.create_approval_request(
            action_id="firewall.enable",
            triggered_by="finding",
            triggered_by_ref="finding_custom",
        )
        # Now requires approval, not auto-approved
        assert request.status == ApprovalStatus.PENDING


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
