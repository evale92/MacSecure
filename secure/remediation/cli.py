"""
CLI — command-line interface for remediation management.

Phase 48.5 CLI commands:
  secure remediation run <action-id> --triggered-by <ref>
  secure remediation approve <execution-id> --approved-by <user>
  secure remediation status <execution-id>
  secure remediation history [--action-id <id>] [--limit 20]
  secure remediation catalog [--risk-level <low|medium|high>]
  secure remediation playbooks [--enabled-only]
"""

from datetime import datetime

from secure.remediation.executor import RemediationExecutor, ExecutionStatus
from secure.remediation.approval import ApprovalStatus
from secure.remediation.catalog import list_actions, get_action, load_catalog
from secure.remediation.playbooks import PlaybookEngine
from secure.remediation.models import RiskLevel


class RemediationCLI:
    """Command-line interface for remediation management."""

    def __init__(self, executor=None, playbook_engine=None):
        """Initialize CLI with executor and playbook engine."""
        self.executor = executor or RemediationExecutor()
        self.playbook_engine = playbook_engine or PlaybookEngine()

    def cmd_run(
        self,
        action_id: str,
        triggered_by: str,
        triggered_by_ref: str,
        require_approval: bool = True,
    ):
        """Run remediation action: secure remediation run <action-id> --triggered-by <ref>

        Returns execution result and prints status.
        """
        result = self.executor.execute_action(
            action_id=action_id,
            triggered_by=triggered_by,
            triggered_by_ref=triggered_by_ref,
            require_approval=require_approval,
        )

        if result.status == ExecutionStatus.FAILED:
            return self._print_error(f"Failed to execute: {result.stderr}")

        self._print_execution_summary(result)
        return result

    def cmd_approve(
        self,
        execution_id: str,
        approved_by: str,
        reason: str = "",
    ):
        """Approve and execute pending remediation: secure remediation approve <execution-id>

        Approves a PENDING execution and runs it.
        """
        result = self.executor.approve_and_execute(
            execution_id=execution_id,
            approved_by=approved_by,
            reason=reason,
        )

        if result is None:
            return self._print_error(f"Execution {execution_id} not found")

        self._print_execution_summary(result)
        return result

    def cmd_status(self, execution_id: str):
        """Get execution status: secure remediation status <execution-id>"""
        result = self.executor.get_execution(execution_id)

        if result is None:
            return self._print_error(f"Execution {execution_id} not found")

        self._print_execution_detail(result)
        return result

    def cmd_history(
        self,
        action_id: str = "",
        status: str = "",
        limit: int = 20,
    ):
        """List execution history: secure remediation history [--action-id <id>] [--limit 20]"""
        results = self.executor.list_executions(
            action_id=action_id,
            status=status,
            limit=limit,
        )

        if not results:
            print("No executions found")
            return []

        print(f"\nExecution History ({len(results)} total):\n")
        print(f"{'Execution ID':<30} {'Action':<20} {'Status':<12} {'Time':<20}")
        print("-" * 82)

        for result in results:
            time_str = result.completed_at.strftime("%Y-%m-%d %H:%M:%S") if result.completed_at else "running"
            print(
                f"{result.execution_id:<30} "
                f"{result.action_id:<20} "
                f"{result.status:<12} "
                f"{time_str:<20}"
            )

        return results

    def cmd_catalog(
        self,
        risk_level: str = "",
        action_type: str = "",
    ):
        """List remediation catalog: secure remediation catalog [--risk-level <low|medium|high>]"""
        actions = list_actions(
            risk_level=risk_level,
            action_type=action_type,
            enabled_only=True,
        )

        if not actions:
            print("No actions found")
            return []

        print(f"\nRemediation Catalog ({len(actions)} actions):\n")
        print(f"{'ID':<30} {'Name':<30} {'Risk':<8} {'Type':<12}")
        print("-" * 80)

        for action in actions:
            print(
                f"{action.id:<30} "
                f"{action.name:<30} "
                f"{action.risk_level.value:<8} "
                f"{action.action_type:<12}"
            )

        return actions

    def cmd_catalog_detail(self, action_id: str):
        """Show detailed action info: secure remediation catalog-detail <action-id>"""
        action = get_action(action_id)

        if action is None:
            return self._print_error(f"Action {action_id} not found")

        print(f"\n=== {action.name} ===\n")
        print(f"ID:          {action.id}")
        print(f"Risk Level:  {action.risk_level.value.upper()}")
        print(f"Type:        {action.action_type}")
        print(f"Description: {action.description}\n")

        if action.examples:
            print("Examples:")
            for ex in action.examples:
                print(f"  - {ex}")
            print()

        if action.references:
            print("References:")
            for ref in action.references:
                print(f"  - {ref}")
            print()

        return action

    def cmd_playbooks(self, enabled_only: bool = True):
        """List playbooks: secure remediation playbooks [--enabled-only]"""
        playbooks = self.playbook_engine.list_playbooks(enabled_only=enabled_only)

        if not playbooks:
            print("No playbooks found")
            return []

        print(f"\nIncident Response Playbooks ({len(playbooks)} total):\n")
        print(f"{'ID':<40} {'Name':<30} {'Risk':<8}")
        print("-" * 78)

        for pb in playbooks:
            print(
                f"{pb.id:<40} "
                f"{pb.name:<30} "
                f"{pb.severity.value:<8}"
            )

        return playbooks

    def cmd_playbook_detail(self, playbook_id: str):
        """Show detailed playbook info: secure remediation playbook-detail <id>"""
        pb = self.playbook_engine.get_playbook(playbook_id)

        if pb is None:
            return self._print_error(f"Playbook {playbook_id} not found")

        print(f"\n=== {pb.name} ===\n")
        print(f"ID:          {pb.id}")
        print(f"Severity:    {pb.severity.value.upper()}")
        print(f"Description: {pb.description}\n")

        print("Trigger:")
        print(f"  Type:      {pb.trigger.trigger_type}")
        print(f"  Condition: {pb.trigger.condition}")
        print(f"  Findings:  {', '.join(pb.trigger.finding_types)}\n")

        print("Steps:")
        for i, step in enumerate(pb.steps, 1):
            print(f"  {i}. {step.remediation_id}")
            if step.condition:
                print(f"     Condition: {step.condition}")
            if step.on_success:
                print(f"     On success: → {step.on_success}")
            if step.on_failure:
                print(f"     On failure: → {step.on_failure}")

        return pb

    def _print_execution_summary(self, result):
        """Pretty-print execution summary."""
        status_icon = "✓" if result.status == ExecutionStatus.SUCCESS else "✗" if result.status == ExecutionStatus.FAILED else "⏳"

        print(f"\n{status_icon} Execution {result.execution_id}")
        print(f"  Action:  {result.action_id}")
        print(f"  Status:  {result.status}")
        print(f"  Started: {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}")

        if result.completed_at:
            elapsed = (result.completed_at - result.started_at).total_seconds()
            print(f"  Time:    {elapsed:.1f}s")

        if result.exit_code != 0:
            print(f"  Exit:    {result.exit_code}")

        if result.stdout:
            print(f"\n  Output:\n  {result.stdout}")

    def _print_execution_detail(self, result):
        """Pretty-print full execution details."""
        print(f"\n=== Execution {result.execution_id} ===\n")
        print(f"Action:     {result.action_id}")
        print(f"Status:     {result.status}")
        print(f"Started:    {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}")

        if result.completed_at:
            elapsed = (result.completed_at - result.started_at).total_seconds()
            print(f"Completed:  {result.completed_at.strftime('%Y-%m-%d %H:%M:%S')} ({elapsed:.1f}s)")

        if result.approval_request_id:
            print(f"Approval:   {result.approval_request_id}")

        if result.playbook_run_id:
            print(f"Playbook:   {result.playbook_run_id}")

        if result.exit_code != 0:
            print(f"\nExit Code:  {result.exit_code}")

        if result.stdout:
            print(f"\nOutput:\n{result.stdout}")

        if result.stderr:
            print(f"\nError:\n{result.stderr}")

        if result.rolled_back:
            print(f"\nRolled Back: {result.rollback_reason}")

    def _print_error(self, message: str):
        """Print error message and return None."""
        print(f"❌ Error: {message}")
        return None
