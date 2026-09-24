"""
Tests for remediation executor and action execution workflow.

Phase 48.5 executor tests covering:
- Executor initialization and action loading
- Execution workflow (approve → execute → persist)
- Status tracking and result persistence
- History and filtering
"""

import unittest
from datetime import datetime, timedelta

from secure.remediation.executor import (
    RemediationExecutor,
    ExecutionResult,
    ExecutionStatus,
)
from secure.remediation.approval import ApprovalEngine, ApprovalStatus
from secure.remediation.playbooks import PlaybookEngine
from secure.remediation.catalog import get_action


class TestRemediationExecutor(unittest.TestCase):
    """Test RemediationExecutor functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.executor = RemediationExecutor()
        self.approval_engine = self.executor.approval_engine

    def test_executor_init(self):
        """Test executor initialization."""
        self.assertIsNotNone(self.executor.approval_engine)
        self.assertIsNotNone(self.executor.playbook_engine)
        self.assertEqual(len(self.executor.executions), 0)

    def test_execute_low_risk_action(self):
        """Test executing a LOW-risk action (auto-approves)."""
        result = self.executor.execute_action(
            action_id="firewall.enable",
            triggered_by="detection",
            triggered_by_ref="find_123",
            require_approval=True,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.action_id, "firewall.enable")
        self.assertEqual(result.status, ExecutionStatus.SIMULATED)
        self.assertIsNone(result.exit_code)  # SIMULATED: no execution attempted

    def test_execute_medium_risk_action_pending(self):
        """Test executing MEDIUM-risk action without approval (stays pending)."""
        result = self.executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="detection",
            triggered_by_ref="find_456",
            require_approval=True,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.action_id, "firewall.block-inbound")
        self.assertEqual(result.status, ExecutionStatus.PENDING)
        self.assertIsNotNone(result.approval_request_id)

    def test_execute_high_risk_action(self):
        """Test executing HIGH-risk action (network isolation)."""
        result = self.executor.execute_action(
            action_id="network.isolate-destination",
            triggered_by="detection",
            triggered_by_ref="find_789",
            require_approval=True,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.action_id, "network.isolate-destination")
        self.assertEqual(result.status, ExecutionStatus.PENDING)

    def test_execute_unknown_action(self):
        """Test executing unknown action returns failure."""
        result = self.executor.execute_action(
            action_id="unknown.action",
            triggered_by="detection",
            triggered_by_ref="find_999",
        )

        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("not found", result.stderr)

    def test_approve_and_execute(self):
        """Test approval flow: PENDING → execute."""
        # First, create pending execution
        result1 = self.executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="detection",
            triggered_by_ref="find_111",
            require_approval=True,
        )

        self.assertEqual(result1.status, ExecutionStatus.PENDING)
        execution_id = result1.execution_id

        # Then approve and execute
        result2 = self.executor.approve_and_execute(
            execution_id=execution_id,
            approved_by="security_team",
            reason="Verified threat",
        )

        self.assertIsNotNone(result2)
        self.assertEqual(result2.status, ExecutionStatus.SIMULATED)
        self.assertEqual(result2.execution_id, execution_id)

    def test_approve_nonexistent_execution(self):
        """Test approving non-existent execution returns None."""
        result = self.executor.approve_and_execute(
            execution_id="exec_fake_id",
            approved_by="user",
        )

        self.assertIsNone(result)

    def test_rollback_execution(self):
        """Test rollback of successful execution.

        Note: SIMULATED executions cannot be rolled back (nothing was executed).
        Only SUCCESS status can be rolled back.
        """
        result1 = self.executor.execute_action(
            action_id="firewall.enable",
            triggered_by="detection",
            triggered_by_ref="find_222",
        )

        self.assertEqual(result1.status, ExecutionStatus.SIMULATED)

        result2 = self.executor.rollback_execution(
            execution_id=result1.execution_id,
            reason="False positive",
        )

        # SIMULATED cannot be rolled back; returns unchanged
        self.assertEqual(result2.status, ExecutionStatus.SIMULATED)
        self.assertFalse(result2.rolled_back)

    def test_execution_persistence(self):
        """Test executions are stored in memory."""
        result = self.executor.execute_action(
            action_id="ssh.disable-root-login",
            triggered_by="detection",
            triggered_by_ref="find_333",
        )

        execution_id = result.execution_id

        # Verify stored
        stored = self.executor.get_execution(execution_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.action_id, "ssh.disable-root-login")
        self.assertEqual(stored.status, ExecutionStatus.SIMULATED)

    def test_get_execution_not_found(self):
        """Test getting non-existent execution returns None."""
        result = self.executor.get_execution("exec_fake_id")
        self.assertIsNone(result)

    def test_list_executions_all(self):
        """Test listing all executions."""
        self.executor.execute_action("firewall.enable", "det", "f1")
        self.executor.execute_action("firewall.enable", "det", "f2")
        self.executor.execute_action("ssh.disable-root-login", "det", "f3")

        results = self.executor.list_executions()
        self.assertEqual(len(results), 3)

    def test_list_executions_by_action(self):
        """Test filtering executions by action ID."""
        self.executor.execute_action("firewall.enable", "det", "f1")
        self.executor.execute_action("firewall.enable", "det", "f2")
        self.executor.execute_action("ssh.disable-root-login", "det", "f3")

        results = self.executor.list_executions(action_id="firewall.enable")
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.action_id == "firewall.enable" for r in results))

    def test_list_executions_by_status(self):
        """Test filtering executions by status."""
        self.executor.execute_action("firewall.enable", "det", "f1")  # SUCCESS
        self.executor.execute_action("firewall.block-inbound", "det", "f2")  # PENDING

        results = self.executor.list_executions(status=ExecutionStatus.SIMULATED)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ExecutionStatus.SIMULATED)

    def test_list_executions_limit(self):
        """Test limit parameter in list_executions."""
        for i in range(10):
            self.executor.execute_action("firewall.enable", "det", f"f{i}")

        results = self.executor.list_executions(limit=5)
        self.assertEqual(len(results), 5)

    def test_list_executions_ordered(self):
        """Test executions are ordered by timestamp (newest first)."""
        exec1 = self.executor.execute_action("firewall.enable", "det", "f1")
        exec2 = self.executor.execute_action("firewall.enable", "det", "f2")
        exec3 = self.executor.execute_action("firewall.enable", "det", "f3")

        results = self.executor.list_executions()
        # Should be newest first
        self.assertEqual(results[0].execution_id, exec3.execution_id)
        self.assertEqual(results[1].execution_id, exec2.execution_id)
        self.assertEqual(results[2].execution_id, exec1.execution_id)


class TestExecutionResult(unittest.TestCase):
    """Test ExecutionResult dataclass."""

    def test_execution_result_creation(self):
        """Test creating an ExecutionResult."""
        result = ExecutionResult(
            execution_id="exec_test",
            action_id="firewall.enable",
            status=ExecutionStatus.SIMULATED,
            started_at=datetime.utcnow(),
        )

        self.assertEqual(result.execution_id, "exec_test")
        self.assertEqual(result.action_id, "firewall.enable")
        self.assertEqual(result.status, ExecutionStatus.SIMULATED)
        self.assertIsNotNone(result.started_at)

    def test_execution_result_with_stderr(self):
        """Test ExecutionResult with error output."""
        result = ExecutionResult(
            execution_id="exec_error",
            action_id="unknown.action",
            status=ExecutionStatus.FAILED,
            started_at=datetime.utcnow(),
            stderr="Action not found",
            exit_code=1,
        )

        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assertIn("not found", result.stderr)
        self.assertEqual(result.exit_code, 1)

    def test_execution_result_timestamps(self):
        """Test execution result timing."""
        started = datetime.utcnow()
        result = ExecutionResult(
            execution_id="exec_timed",
            action_id="firewall.enable",
            status=ExecutionStatus.SIMULATED,
            started_at=started,
            completed_at=started + timedelta(seconds=2),
        )

        elapsed = (result.completed_at - result.started_at).total_seconds()
        self.assertAlmostEqual(elapsed, 2.0, places=0)


class TestExecutorWithPlaybooks(unittest.TestCase):
    """Test executor integration with playbooks."""

    def setUp(self):
        """Set up test fixtures."""
        self.executor = RemediationExecutor()

    def test_execution_with_playbook_ref(self):
        """Test execution triggered from playbook."""
        result = self.executor.execute_action(
            action_id="firewall.enable",
            triggered_by="playbook",
            triggered_by_ref="pb_incident_unsigned_process",
        )

        self.assertEqual(result.status, ExecutionStatus.SIMULATED)
        self.assertIn("pb_incident_unsigned_process", result.execution_id)


if __name__ == "__main__":
    unittest.main()
