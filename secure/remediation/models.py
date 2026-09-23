"""
Models — dataclasses for remediation actions, approvals, and playbooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Callable, Literal, Optional


class RiskLevel(str, Enum):
    """Risk classification for a remediation action."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationType(str, Enum):
    """How to verify if a remediation action actually worked."""
    SCAN_COMPARISON = "scan_comparison"  # Compare pre/post security scan
    CONFIG_CHECK = "config_check"        # Read config file and verify setting
    PROCESS_CHECK = "process_check"      # Check running process state
    FILE_CHECK = "file_check"            # Check file exists/deleted/modified
    MANUAL = "manual"                    # User must manually verify


@dataclass
class RemediationScope:
    """Who/what this action applies to."""
    apply_to: Literal["all_macs", "this_mac", "specific_finding_type"]
    finding_type_filter: Optional[str] = None  # e.g., "persistence.unsigned_executable"
    exclude_patterns: list[str] = field(default_factory=list)  # e.g., ["system_", "com.apple"]


@dataclass
class RemediationVerification:
    """How to verify a remediation action succeeded."""
    type: VerificationType
    check_function: Optional[Callable] = None  # For programmatic verification
    description: str = ""                       # Human-readable check description
    timeout_seconds: int = 30
    retry_count: int = 1


@dataclass
class RemediationAction:
    """A named, versioned remediation recipe."""
    id: str                                     # e.g., "firewall.enable"
    name: str                                   # "Enable firewall"
    description: str                            # What this does
    risk_level: RiskLevel
    action_type: str                            # Category: 'firewall', 'ssh', 'service', etc.

    # Prerequisites: actions that must run first
    prerequisites: list[str] = field(default_factory=list)

    # Who/what this applies to
    applicability: RemediationScope = field(default_factory=lambda: RemediationScope("this_mac"))

    # Change request generation
    change_request_template: str = ""           # Path or Jinja2 template

    # Outcome verification
    verification: RemediationVerification = field(
        default_factory=lambda: RemediationVerification(VerificationType.MANUAL)
    )

    # Metadata
    first_shipped_in: str = "48"
    examples: list[str] = field(default_factory=list)  # Attack patterns
    references: list[str] = field(default_factory=list)  # MITRE ATT&CK links, docs

    # Operational
    enabled: bool = True


@dataclass
class ApprovalPolicy:
    """Approval workflow configuration for an action."""
    action_id: str
    risk_level: RiskLevel

    # Whether approval is required before execution
    approval_required: bool

    # If approval_required is True:
    escalation_path: Optional[str] = None       # "human_review", "mdm_supervisor", "security_team"
    escalation_timeout: Optional[timedelta] = None

    # If low-risk (auto-executable):
    post_action_notification: bool = True
    rollback_allowed: bool = True
    rollback_window_hours: int = 24


@dataclass
class PlaybookTrigger:
    """What causes a playbook to execute."""
    trigger_type: Literal["finding_pattern", "anomaly_score", "correlation_match"]
    condition: str                              # e.g., "anomaly_score > 80"
    finding_types: list[str] = field(default_factory=list)  # Specific finding types


@dataclass
class PlaybookStep:
    """One step in a remediation playbook."""
    remediation_id: str
    condition: Optional[str] = None             # e.g., "if anomaly_score > 80"
    on_success: Optional[str] = None            # Step ID to execute next
    on_failure: Optional[str] = None            # Alternate remediation
    on_timeout: Optional[str] = None            # If approval times out


@dataclass
class Playbook:
    """A sequence of remediation actions for incident response."""
    id: str                                     # e.g., "incident.lateral_movement"
    name: str                                   # "Suspected Lateral Movement Response"
    description: str = ""
    trigger: PlaybookTrigger = field(default_factory=lambda: PlaybookTrigger("anomaly_score", ""))
    steps: list[PlaybookStep] = field(default_factory=list)

    # Metadata
    severity: RiskLevel = RiskLevel.HIGH
    first_shipped_in: str = "48"
    references: list[str] = field(default_factory=list)
    enabled: bool = True
