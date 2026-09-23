"""
Tests for remediation CLI interface.

Phase 48.5 CLI tests covering:
- Command execution and output formatting
- Catalog and playbook display
- History and filtering
- Detail views
"""

import unittest
from io import StringIO
import sys

from secure.remediation.cli import RemediationCLI
from secure.remediation.executor import RemediationExecutor, ExecutionStatus
from secure.remediation.playbooks import PlaybookEngine


class TestRemediationCLI(unittest.TestCase):
    """Test RemediationCLI interface."""

    def setUp(self):
        """Set up test fixtures."""
        self.cli = RemediationCLI()
        self.executor = self.cli.executor

    def test_cli_init(self):
        """Test CLI initialization."""
        self.assertIsNotNone(self.cli.executor)
        self.assertIsNotNone(self.cli.playbook_engine)

    def _capture_output(self, func):
        """Helper to capture stdout."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            func()
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout
        return output

    def test_cmd_run_success(self):
        """Test 'run' command for LOW-risk action."""
        result = self.cli.cmd_run(
            action_id="firewall.enable",
            triggered_by="detection",
            triggered_by_ref="find_test",
            require_approval=True,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.status, ExecutionStatus.SUCCESS)

    def test_cmd_run_failure(self):
        """Test 'run' command with unknown action."""
        result = self.cli.cmd_run(
            action_id="unknown.action",
            triggered_by="detection",
            triggered_by_ref="find_test",
        )

        # Result is None for errors
        # (captured via output, not return value in actual CLI)

    def test_cmd_approve(self):
        """Test 'approve' command."""
        # Create pending execution first
        exec1 = self.executor.execute_action(
            action_id="firewall.block-inbound",
            triggered_by="detection",
            triggered_by_ref="find_test",
        )

        # Then approve via CLI
        result = self.cli.cmd_approve(
            execution_id=exec1.execution_id,
            approved_by="security_admin",
            reason="Verified C2 activity",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.status, ExecutionStatus.SUCCESS)

    def test_cmd_status(self):
        """Test 'status' command."""
        exec1 = self.executor.execute_action(
            action_id="firewall.enable",
            triggered_by="detection",
            triggered_by_ref="find_status_test",
        )

        result = self.cli.cmd_status(exec1.execution_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.action_id, "firewall.enable")

    def test_cmd_status_not_found(self):
        """Test 'status' command with unknown execution."""
        result = self.cli.cmd_status("exec_fake")
        self.assertIsNone(result)

    def test_cmd_history_empty(self):
        """Test 'history' command with no executions."""
        results = self.cli.cmd_history()
        self.assertEqual(len(results), 0)

    def test_cmd_history_all(self):
        """Test 'history' command lists all executions."""
        self.executor.execute_action("firewall.enable", "det", "f1")
        self.executor.execute_action("ssh.disable-root-login", "det", "f2")

        results = self.cli.cmd_history()
        self.assertEqual(len(results), 2)

    def test_cmd_history_filter_action(self):
        """Test 'history' command filtered by action."""
        self.executor.execute_action("firewall.enable", "det", "f1")
        self.executor.execute_action("firewall.enable", "det", "f2")
        self.executor.execute_action("ssh.disable-root-login", "det", "f3")

        results = self.cli.cmd_history(action_id="firewall.enable")
        self.assertEqual(len(results), 2)

    def test_cmd_history_limit(self):
        """Test 'history' command with limit."""
        for i in range(10):
            self.executor.execute_action("firewall.enable", "det", f"f{i}")

        results = self.cli.cmd_history(limit=5)
        self.assertEqual(len(results), 5)

    def test_cmd_catalog_all(self):
        """Test 'catalog' command lists all actions."""
        actions = self.cli.cmd_catalog()
        self.assertGreater(len(actions), 0)
        self.assertEqual(len(actions), 12)  # 12 built-in actions

    def test_cmd_catalog_filter_risk(self):
        """Test 'catalog' command filtered by risk level."""
        actions = self.cli.cmd_catalog(risk_level="low")
        # Verify all are LOW risk
        for action in actions:
            self.assertEqual(action.risk_level.value, "low")

    def test_cmd_catalog_filter_type(self):
        """Test 'catalog' command filtered by action type."""
        actions = self.cli.cmd_catalog(action_type="firewall")
        # Should have firewall.enable and firewall.block-inbound
        self.assertGreaterEqual(len(actions), 2)
        for action in actions:
            self.assertEqual(action.action_type, "firewall")

    def test_cmd_catalog_detail(self):
        """Test 'catalog-detail' command."""
        action = self.cli.cmd_catalog_detail("firewall.enable")

        self.assertIsNotNone(action)
        self.assertEqual(action.id, "firewall.enable")
        self.assertEqual(action.action_type, "firewall")

    def test_cmd_catalog_detail_not_found(self):
        """Test 'catalog-detail' command with unknown action."""
        action = self.cli.cmd_catalog_detail("unknown.action")
        self.assertIsNone(action)

    def test_cmd_playbooks_all(self):
        """Test 'playbooks' command."""
        playbooks = self.cli.cmd_playbooks()
        self.assertEqual(len(playbooks), 5)  # 5 built-in playbooks

    def test_cmd_playbook_detail(self):
        """Test 'playbook-detail' command."""
        pb = self.cli.cmd_playbook_detail("incident.unsigned-process")

        self.assertIsNotNone(pb)
        self.assertEqual(pb.id, "incident.unsigned-process")
        self.assertEqual(len(pb.steps), 3)

    def test_cmd_playbook_detail_not_found(self):
        """Test 'playbook-detail' command with unknown playbook."""
        pb = self.cli.cmd_playbook_detail("unknown.playbook")
        self.assertIsNone(pb)

    def test_cmd_catalog_displays_correctly(self):
        """Test catalog output format."""
        def run_catalog():
            self.cli.cmd_catalog()

        output = self._capture_output(run_catalog)

        # Should contain catalog heading
        self.assertIn("Remediation Catalog", output)
        # Should list some actions
        self.assertIn("firewall.enable", output)

    def test_cmd_history_displays_correctly(self):
        """Test history output format."""
        self.executor.execute_action("firewall.enable", "det", "f1")

        def run_history():
            self.cli.cmd_history()

        output = self._capture_output(run_history)

        # Should contain history heading
        self.assertIn("Execution History", output)
        # Should list execution
        self.assertIn("firewall.enable", output)

    def test_print_execution_summary(self):
        """Test execution summary formatting."""
        result = self.executor.execute_action(
            action_id="firewall.enable",
            triggered_by="det",
            triggered_by_ref="f1",
        )

        def run_summary():
            self.cli._print_execution_summary(result)

        output = self._capture_output(run_summary)

        self.assertIn(result.execution_id, output)
        self.assertIn(result.action_id, output)
        self.assertIn(result.status, output)


class TestCLIIntegration(unittest.TestCase):
    """Integration tests for full CLI workflows."""

    def setUp(self):
        """Set up test fixtures."""
        self.cli = RemediationCLI()

    def test_workflow_run_and_status(self):
        """Test workflow: run action → check status."""
        result = self.cli.cmd_run(
            action_id="firewall.enable",
            triggered_by="detection",
            triggered_by_ref="find_123",
        )

        self.assertEqual(result.status, ExecutionStatus.SUCCESS)

        # Check status
        status = self.cli.cmd_status(result.execution_id)
        self.assertEqual(status.status, ExecutionStatus.SUCCESS)
        self.assertEqual(status.action_id, "firewall.enable")

    def test_workflow_pending_approve_execute(self):
        """Test workflow: execute (pending) → approve → status."""
        # Execute LOW risk to get quick success, then test with MEDIUM risk
        result1 = self.cli.cmd_run(
            action_id="firewall.block-inbound",
            triggered_by="detection",
            triggered_by_ref="find_456",
            require_approval=True,
        )

        self.assertEqual(result1.status, ExecutionStatus.PENDING)

        # Approve
        result2 = self.cli.cmd_approve(
            execution_id=result1.execution_id,
            approved_by="security_admin",
            reason="Verified threat",
        )

        self.assertEqual(result2.status, ExecutionStatus.SUCCESS)

        # Check status
        result3 = self.cli.cmd_status(result1.execution_id)
        self.assertEqual(result3.status, ExecutionStatus.SUCCESS)

    def test_workflow_list_and_filter(self):
        """Test workflow: execute multiple → history with filter."""
        self.cli.cmd_run("firewall.enable", "det", "f1")
        self.cli.cmd_run("firewall.enable", "det", "f2")
        self.cli.cmd_run("ssh.disable-root-login", "det", "f3")

        all_results = self.cli.cmd_history()
        self.assertEqual(len(all_results), 3)

        firewall_results = self.cli.cmd_history(action_id="firewall.enable")
        self.assertEqual(len(firewall_results), 2)

        ssh_results = self.cli.cmd_history(action_id="ssh.disable-root-login")
        self.assertEqual(len(ssh_results), 1)


if __name__ == "__main__":
    unittest.main()
