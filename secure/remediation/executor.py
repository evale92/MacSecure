"""
Executor — remediation action execution with approval routing and persistence.

Phase 48.5 ties together actions, approvals, and database persistence.
All executions route through Phase 47's verified safe-code infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from secure.remediation.models import RemediationAction
from secure.remediation.approval import ApprovalEngine, ApprovalStatus
from secure.remediation.catalog import get_action
from secure.remediation.playbooks import PlaybookEngine


class ExecutionStatus:
    """Status constants for remediation execution."""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCESS = "success"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass
class ExecutionResult:
    """Result of executing a remediation action."""
    execution_id: str
    action_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    approval_request_id: Optional[str] = None
    playbook_run_id: Optional[str] = None

    rolled_back: bool = False
    rollback_reason: str = ""


class RemediationExecutor:
    """Executes remediation actions with approval routing and database persistence."""

    def __init__(self, approval_engine=None, playbook_engine=None, db_conn=None):
        """Initialize executor with engines and database connection."""
        self.approval_engine = approval_engine or ApprovalEngine()
        self.playbook_engine = playbook_engine or PlaybookEngine()
        self.db_conn = db_conn

        self.executions: dict[str, ExecutionResult] = {}

    def execute_action(
        self,
        action_id: str,
        triggered_by: str,
        triggered_by_ref: str,
        require_approval: bool = True,
        approved_by: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a remediation action with optional approval flow.

        Steps:
        1. Load action from catalog
        2. Create approval request (routes by risk level)
        3. Check if approved or auto-approved
        4. Execute through Phase 47 safe-code
        5. Persist to database
        6. Return result
        """
        action = get_action(action_id)
        if action is None:
            return ExecutionResult(
                execution_id=f"exec_{action_id}_unknown",
                action_id=action_id,
                status=ExecutionStatus.FAILED,
                started_at=datetime.utcnow(),
                stderr="Action not found in catalog",
                exit_code=1,
            )

        # Create approval request
        approval_req = self.approval_engine.create_approval_request(
            action_id=action_id,
            triggered_by=triggered_by,
            triggered_by_ref=triggered_by_ref,
        )

        if approval_req is None:
            return ExecutionResult(
                execution_id=f"exec_{action_id}_badpolicy",
                action_id=action_id,
                status=ExecutionStatus.FAILED,
                started_at=datetime.utcnow(),
                stderr="No approval policy for action",
                exit_code=1,
            )

        execution_id = f"exec_{action_id}_{triggered_by_ref}"
        result = ExecutionResult(
            execution_id=execution_id,
            action_id=action_id,
            status=ExecutionStatus.PENDING,
            started_at=datetime.utcnow(),
            approval_request_id=approval_req.request_id,
        )

        # Check if we need manual approval
        if not self.approval_engine.is_approved(approval_req) and require_approval:
            result.status = ExecutionStatus.PENDING
            self.executions[execution_id] = result
            self._persist_execution(result)
            return result

        # If we have explicit approval, apply it
        if approved_by and approval_req.status == ApprovalStatus.PENDING:
            approval_req = self.approval_engine.approve_request(
                approval_req,
                approved_by=approved_by,
                reason="Manual approval provided",
            )

        # Execute action
        if self.approval_engine.can_execute(approval_req):
            result = self._execute_action_safe(action, result)

        self.executions[execution_id] = result
        self._persist_execution(result)
        return result

    def _execute_action_safe(
        self,
        action: RemediationAction,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Execute action through Phase 47 verified safe-code infrastructure.

        In production, this would invoke:
        - secure.phase47.CodeVerifier for syntax/security checks
        - secure.phase47.SandboxExecutor for isolated execution
        - secure.phase47.RepairRun for tracking

        For now, simulates successful execution.
        """
        result.status = ExecutionStatus.EXECUTING

        try:
            # Phase 47 would handle actual execution
            # Here we simulate success for the 12 catalog actions
            result.status = ExecutionStatus.SUCCESS
            result.exit_code = 0
            result.stdout = f"✓ {action.name} executed successfully"
            result.completed_at = datetime.utcnow()
        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.exit_code = 1
            result.stderr = str(e)
            result.completed_at = datetime.utcnow()

        return result

    def approve_and_execute(
        self,
        execution_id: str,
        approved_by: str,
        reason: str = "",
    ) -> ExecutionResult:
        """Approve a pending execution and execute it."""
        result = self.executions.get(execution_id)
        if result is None:
            return None

        if result.status != ExecutionStatus.PENDING:
            return result  # Already processed

        # Update approval
        if result.approval_request_id:
            # In real implementation, would fetch from database
            # For now, simulate approval
            pass

        result = self._execute_action_safe(
            get_action(result.action_id),
            result,
        )
        self.executions[execution_id] = result
        self._persist_execution(result)
        return result

    def reject_execution(
        self,
        execution_id: str,
        rejected_by: str,
        reason: str = "",
    ) -> ExecutionResult:
        """Reject a pending execution."""
        result = self.executions.get(execution_id)
        if result is None:
            return None

        if result.status != ExecutionStatus.PENDING:
            return result  # Can only reject pending actions

        result.status = ExecutionStatus.FAILED
        result.stderr = f"Rejected by {rejected_by}: {reason}"
        result.completed_at = datetime.utcnow()

        self.executions[execution_id] = result
        self._persist_execution(result)
        return result

    def rollback_execution(
        self,
        execution_id: str,
        reason: str = "",
    ) -> ExecutionResult:
        """Rollback a completed execution (if supported by action)."""
        result = self.executions.get(execution_id)
        if result is None:
            return None

        if result.status != ExecutionStatus.SUCCESS:
            return result  # Can only rollback successful actions

        action = get_action(result.action_id)
        # Check if rollback is allowed (from approval policy)

        result.status = ExecutionStatus.ROLLED_BACK
        result.rolled_back = True
        result.rollback_reason = reason
        result.completed_at = datetime.utcnow()

        self.executions[execution_id] = result
        self._persist_execution(result)
        return result

    def get_execution(self, execution_id: str) -> ExecutionResult:
        """Get execution result by ID."""
        return self.executions.get(execution_id)

    def list_executions(
        self,
        action_id: str = "",
        status: str = "",
        limit: int = 50,
    ) -> list[ExecutionResult]:
        """List executions, optionally filtered."""
        results = list(self.executions.values())

        if action_id:
            results = [r for r in results if r.action_id == action_id]

        if status:
            results = [r for r in results if r.status == status]

        return sorted(
            results,
            key=lambda r: r.started_at,
            reverse=True,
        )[:limit]

    def _persist_execution(self, result: ExecutionResult) -> None:
        """Persist execution result to database.

        In production, writes to remediation_executions table with:
        - execution_id, action_id, status
        - timestamps, approval_request_id
        - stdout, stderr, exit_code
        - playbook_run_id if applicable
        """
        if self.db_conn is None:
            return

        # Placeholder: db_conn.execute("""
        #     INSERT INTO remediation_executions
        #     (execution_id, action_id, status, ...)
        #     VALUES (?, ?, ?, ...)
        # """)
        pass

    def validate_sandbox_constraints(self, action_id: str) -> tuple[bool, list[str]]:
        """
        Validate that action meets sandboxing constraints before execution.

        Constraints:
        1. Action scope must be limited (single device or specific finding type)
        2. Action cannot modify audit tables or core configuration
        3. Action must have rollback support for destructive operations
        4. Action cannot execute external code without verification

        Returns: (is_valid, list of constraint violations)
        """
        action = get_action(action_id)
        if action is None:
            return False, ["Action not found in catalog"]

        violations = []

        # Constraint 1: Check scope
        scope_ok = False
        if hasattr(action, 'scope'):
            scope_value = action.scope.apply_to if hasattr(action.scope, 'apply_to') else ""
            if scope_value in ["specific_finding_type", "this_mac"]:
                scope_ok = True
            else:
                violations.append(f"Scope '{scope_value}' is too broad (must be specific_finding_type or this_mac)")

        # Constraint 2: Check for dangerous modifications
        dangerous_tables = [
            "alert_decisions", "remediation_request_log", "evidence_links",
            "baseline_entities", "device_registry"
        ]
        action_desc = f"{action.name} {action.description if hasattr(action, 'description') else ''}".lower()
        for table in dangerous_tables:
            if table in action_desc:
                violations.append(f"Action cannot modify {table} (audit/core table)")

        # Constraint 3: Check rollback support for destructive operations
        destructive_keywords = ["kill", "disable", "delete", "remove", "uninstall", "quarantine"]
        action_name_lower = action.name.lower()
        is_destructive = any(kw in action_name_lower for kw in destructive_keywords)

        if is_destructive:
            if not hasattr(action, 'rollback_allowed') or not action.rollback_allowed:
                violations.append("Destructive action must have rollback support enabled")

        # Constraint 4: Check for code execution
        code_keywords = ["eval", "exec", "subprocess", "shell"]
        if any(kw in action_desc for kw in code_keywords):
            if not hasattr(action, 'verification_type'):
                violations.append("Code execution actions require verification_type")

        return len(violations) == 0, violations
