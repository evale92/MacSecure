"""
Remediation — automated response orchestration for Secure findings.

Phase 48 adds safe, auditable remediation actions for common security findings.
Every action is defined as an immutable specification, executed through Phase 47's
verified safe-code infrastructure (never directly), and tracked in the database.
"""

from secure.remediation.models import (
    RemediationAction,
    ApprovalPolicy,
    RemediationScope,
    RemediationVerification,
    PlaybookStep,
    Playbook,
    PlaybookTrigger,
)
from secure.remediation.catalog import (
    load_catalog,
    get_action,
    list_actions,
)
from secure.remediation.executor import (
    RemediationExecutor,
    ExecutionResult,
    ExecutionStatus,
)
from secure.remediation.cli import RemediationCLI
from secure.remediation.api import RemediationAPIServer

__all__ = [
    "RemediationAction",
    "ApprovalPolicy",
    "RemediationScope",
    "RemediationVerification",
    "PlaybookStep",
    "Playbook",
    "PlaybookTrigger",
    "load_catalog",
    "get_action",
    "list_actions",
    "RemediationExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    "RemediationCLI",
    "RemediationAPIServer",
]
