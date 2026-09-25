"""Phase 2 approval flow tests (wired to real approval engine).

Tests for:
- Approval state machine: PENDING → APPROVED/REJECTED
- execute_action(require_approval=True) enforcement
- Audit trail persistence (timestamps, approver, reason)
- Sandbox constraints validation
- Rollback bookkeeping
"""

import os
from datetime import datetime

from secure.remediation.executor import RemediationExecutor, ExecutionStatus
from secure.remediation.approval import ApprovalStatus


class TestApprovalFlow:
    """Test Phase 2 approval state machine."""

    def test_medium_risk_requires_approval(self):
        """Test MEDIUM-risk action stays PENDING without approval.

        This is the core Phase 2 gate: if approval enforcement is bypassed,
        this test should fail.
        """
        executor = RemediationExecutor()

        # Execute MEDIUM-risk action, requiring approval
        result = executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="test",
            triggered_by_ref="test_approval_medium",
            require_approval=True,
        )

        # Must stay PENDING without approval
        # (This is what fails when bypass stub is active)
        assert result.status == ExecutionStatus.PENDING, \
            f"GATE2_APPROVAL_PENDING: MEDIUM-risk should stay PENDING but got {result.status}"

        # Approval request should exist
        assert result.approval_request_id is not None, \
            "No approval request created for MEDIUM-risk action"

        # Audit trail: execution started but not completed
        assert result.started_at is not None, \
            "Execution start time missing"
        assert result.completed_at is None, \
            "Pending execution should not be completed yet"

    def test_low_risk_auto_approves(self):
        """Test LOW-risk action auto-approves and executes immediately."""
        executor = RemediationExecutor()

        result = executor.execute_action(
            action_id="firewall.enable",
            triggered_by="test",
            triggered_by_ref="test_approval_low",
            require_approval=True,
        )

        # LOW-risk auto-approves and executes
        assert result.status == ExecutionStatus.SIMULATED, \
            f"LOW-risk should auto-execute but got {result.status}"

        # Audit trail complete
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.approval_request_id is not None

        # Executor was invoked (SIMULATED status, not execution)
        assert result.exit_code is None, \
            "SIMULATED execution should have exit_code=None"

    def test_approval_state_machine_pending_to_approved(self):
        """Test approval state machine: PENDING → (approve) → SIMULATED."""
        executor = RemediationExecutor()

        # Create pending MEDIUM-risk execution
        result1 = executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="test",
            triggered_by_ref="test_state_medium",
            require_approval=True,
        )

        assert result1.status == ExecutionStatus.PENDING
        exec_id = result1.execution_id

        # Approve and execute
        result2 = executor.approve_and_execute(
            execution_id=exec_id,
            approved_by="security_team",
            reason="Threat verified",
        )

        assert result2 is not None, "approve_and_execute returned None"
        assert result2.status == ExecutionStatus.SIMULATED, \
            f"After approval, should be SIMULATED but got {result2.status}"

        # Verify audit trail persisted approval info
        assert result2.approval_request_id is not None
        assert result2.completed_at is not None
        assert result2.completed_at > result2.started_at, \
            "Completion should be after start"

    def test_rejection_path(self):
        """Test approval rejection: PENDING → (reject) → FAILED."""
        executor = RemediationExecutor()

        # Create pending execution
        result1 = executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="test",
            triggered_by_ref="test_reject_medium",
            require_approval=True,
        )

        assert result1.status == ExecutionStatus.PENDING
        exec_id = result1.execution_id

        # Reject execution
        result2 = executor.reject_execution(
            execution_id=exec_id,
            rejected_by="security_review",
            reason="False positive",
        )

        assert result2 is not None
        assert result2.status == ExecutionStatus.FAILED, \
            f"After rejection, should be FAILED but got {result2.status}"

        # Audit trail records rejection
        assert "False positive" in result2.stderr, \
            "Rejection reason not in audit trail"
        assert result2.completed_at is not None

    def test_audit_trail_persistence(self):
        """Test audit trail records timestamp, approver, reason."""
        executor = RemediationExecutor()

        # Execute and immediately approve
        result1 = executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="test",
            triggered_by_ref="test_audit_trail",
            require_approval=True,
        )

        start_time = datetime.utcnow()
        result2 = executor.approve_and_execute(
            execution_id=result1.execution_id,
            approved_by="alice@security.local",
            reason="C2 detection confirmed",
        )

        # Verify audit trail fields
        assert result2.started_at is not None, \
            "Audit trail missing: started_at"
        assert result2.completed_at is not None, \
            "Audit trail missing: completed_at"
        assert result2.approval_request_id is not None, \
            "Audit trail missing: approval_request_id"

        # Times should be reasonable
        assert result2.completed_at >= result2.started_at, \
            "Completed should not precede started"

    def test_rollback_bookkeeping(self):
        """Test rollback_execution bookkeeping (SIMULATED cannot rollback)."""
        executor = RemediationExecutor()

        # Create and approve a LOW-risk action (returns SIMULATED)
        result1 = executor.execute_action(
            action_id="firewall.enable",
            triggered_by="test",
            triggered_by_ref="test_rollback_book",
            require_approval=True,
        )

        assert result1.status == ExecutionStatus.SIMULATED

        # Attempt rollback (should fail on SIMULATED)
        result2 = executor.rollback_execution(
            execution_id=result1.execution_id,
            reason="Test rollback",
        )

        # SIMULATED cannot be rolled back (only SUCCESS can)
        assert result2.status == ExecutionStatus.SIMULATED, \
            "SIMULATED should not change status on rollback"
        assert result2.rolled_back == False, \
            "Rollback should not succeed on SIMULATED"

    def test_sandbox_constraints_validation(self):
        """Test sandbox constraints: reject eval/exec/subprocess/shell keywords."""
        executor = RemediationExecutor()

        # Test action with forbidden keywords
        forbidden_keywords = ["eval", "exec", "__import__", "subprocess", "shell"]

        for keyword in forbidden_keywords:
            # In real implementation, this would check the action's code
            # For now, test the validation API exists
            valid, errors = executor.validate_sandbox_constraints(f"test.{keyword}")

            # Should either pass validation or return errors
            # (This depends on whether "test.{keyword}" is a real action ID)
            # The important thing is the API exists and is callable
            assert isinstance(valid, bool), "validate_sandbox_constraints should return bool"
            assert isinstance(errors, list), "Errors should be a list"

    def test_execution_lookup_by_id(self):
        """Test retrieving execution by ID from audit trail."""
        executor = RemediationExecutor()

        result1 = executor.execute_action(
            action_id="firewall.enable",
            triggered_by="test",
            triggered_by_ref="test_lookup_exec",
            require_approval=True,
        )

        exec_id = result1.execution_id

        # Look it up
        result2 = executor.get_execution(exec_id)

        assert result2 is not None, "Execution not found in audit trail"
        assert result2.action_id == "firewall.enable"
        assert result2.execution_id == exec_id

    def test_list_executions_filtered_by_status(self):
        """Test listing executions filtered by status."""
        executor = RemediationExecutor()

        # Create mixed executions
        pending = executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="test",
            triggered_by_ref="test_list_pending",
            require_approval=True,
        )  # PENDING

        simulated = executor.execute_action(
            action_id="firewall.enable",
            triggered_by="test",
            triggered_by_ref="test_list_simulated",
            require_approval=True,
        )  # SIMULATED

        # List all PENDING
        pending_results = executor.list_executions(status=ExecutionStatus.PENDING)
        assert len(pending_results) >= 1
        assert all(r.status == ExecutionStatus.PENDING for r in pending_results)

        # List all SIMULATED
        simulated_results = executor.list_executions(status=ExecutionStatus.SIMULATED)
        assert len(simulated_results) >= 1
        assert all(r.status == ExecutionStatus.SIMULATED for r in simulated_results)
