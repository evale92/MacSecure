"""
Playbooks — incident response orchestration sequences.

Phase 48.3 implements incident playbooks: sequences of remediation actions
chained together with condition evaluation and branching logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable

from secure.remediation.models import (
    PlaybookStep,
    Playbook,
    PlaybookTrigger,
    RiskLevel,
)
from secure.remediation.approval import ApprovalRequest


class PlaybookRunStatus(str, Enum):
    """Status of a playbook execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    WAITING_APPROVAL = "waiting_approval"


class StepStatus(str, Enum):
    """Status of a single step."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    WAITING_APPROVAL = "waiting_approval"


@dataclass
class StepExecution:
    """Record of executing a single playbook step."""
    step_id: str
    remediation_id: str
    status: StepStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    approval_request: Optional[ApprovalRequest] = None
    result: Optional[str] = None  # "success", "partial", "failed"
    error: Optional[str] = None
    notes: str = ""


@dataclass
class PlaybookRun:
    """Execution record for a complete playbook."""
    run_id: str
    playbook_id: str
    trigger_finding: str
    trigger_anomaly_score: float

    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    status: PlaybookRunStatus = PlaybookRunStatus.PENDING
    steps: list[StepExecution] = field(default_factory=list)

    current_step_index: int = 0
    final_result: Optional[str] = None  # "success", "partial_remediation", "failed"


class PlaybookEngine:
    """Orchestrates playbook execution with condition evaluation and branching."""

    def __init__(self, playbooks=None):
        """Initialize with playbooks (use defaults if None)."""
        self.playbooks = playbooks or self._default_playbooks()
        self.runs: dict[str, PlaybookRun] = {}

    @staticmethod
    def _default_playbooks() -> dict[str, Playbook]:
        """Return 5 built-in incident playbooks."""
        return {
            "incident.unsigned-process": Playbook(
                id="incident.unsigned-process",
                name="Unsigned Process Execution Response",
                description="Respond to unsigned executable spawning from suspicious location.",
                trigger=PlaybookTrigger(
                    trigger_type="finding_pattern",
                    condition="persistence.unsigned_executable",
                    finding_types=["persistence.unsigned_executable"],
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="process.alert-on-relaunch",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="service.disable-launchagent",
                        condition="if_unsigned",
                        on_success="step_3",
                        on_failure=None,
                    ),
                    PlaybookStep(
                        remediation_id="threat-hunt.priority-flag",
                        condition=None,
                        on_success=None,
                    ),
                ],
                severity=RiskLevel.MEDIUM,
            ),

            "incident.persistence-change": Playbook(
                id="incident.persistence-change",
                name="Unexpected Persistence Modification Response",
                description="Respond to unexpected changes in LaunchAgent/LaunchDaemon.",
                trigger=PlaybookTrigger(
                    trigger_type="correlation_match",
                    condition="persistence AND file_integrity AND new_connection",
                    finding_types=["persistence.modified_agent", "file_change.launchagent"],
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="firewall.enable",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="service.disable-launchagent",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="threat-hunt.priority-flag",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
            ),

            "incident.network-anomaly": Playbook(
                id="incident.network-anomaly",
                name="Network Anomaly Response (Process + Connection + File)",
                description="Respond to correlated process, network, and file changes within 60s.",
                trigger=PlaybookTrigger(
                    trigger_type="anomaly_score",
                    condition="anomaly_score > 80 AND span < 60s",
                    finding_types=["process.new", "connection.new_destination", "file.modified"],
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="firewall.block-inbound",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="service.disable-launchagent",
                        condition=None,
                        on_success="step_3",
                        on_failure="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="network.isolate-destination",
                        condition="if_remote_ip",
                        on_success=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
            ),

            "incident.privilege-escalation": Playbook(
                id="incident.privilege-escalation",
                name="Privilege Escalation Attempt Response",
                description="Respond to process with elevated uid/gid.",
                trigger=PlaybookTrigger(
                    trigger_type="finding_pattern",
                    condition="process.privilege_escalation",
                    finding_types=["process.uid_mismatch", "process.gid_escalation"],
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="firewall.enable",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="credential.recommend-rotation",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="endpoint.mdm-notify",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
            ),

            "incident.lateral-movement": Playbook(
                id="incident.lateral-movement",
                name="Suspected Lateral Movement Response",
                description="Respond to SSH key modification + new network destination.",
                trigger=PlaybookTrigger(
                    trigger_type="correlation_match",
                    condition="file_change(ssh_authorized_keys) AND connection.new_destination",
                    finding_types=["file.ssh_keys_modified", "connection.new_remote"],
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="ssh.disable-root-login",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="ssh.disable-password-auth",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="network.isolate-destination",
                        condition="if_suspicious_ip",
                        on_success="step_4",
                    ),
                    PlaybookStep(
                        remediation_id="credential.recommend-rotation",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
            ),

            # Phase 51: Extended Playbooks (5 new incident types)
            "incident.persistence-registry": Playbook(
                id="incident.persistence-registry",
                name="Windows Registry Persistence Response",
                description="Respond to suspicious registry modifications used for persistence (Run, RunOnce, etc).",
                trigger=PlaybookTrigger(
                    trigger_type="finding_pattern",
                    condition="persistence AND registry",
                    finding_types=["persistence.registry-run-key", "persistence.registry-runonce", "file_change.registry"],
                    anomaly_threshold=65.0,
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="registry.clear-persistence",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="process.alert-on-relaunch",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="threat-hunt.priority-flag",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
                first_shipped_in="51",
            ),

            "incident.lsass-dump": Playbook(
                id="incident.lsass-dump",
                name="LSASS Memory Dump Attack Response",
                description="Respond to attempts to access LSASS process for credential extraction.",
                trigger=PlaybookTrigger(
                    trigger_type="finding_pattern",
                    condition="process AND lsass_access",
                    finding_types=["process.suspicious-lsass-access", "process.credential-dump-attempt"],
                    anomaly_threshold=75.0,
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="process.kill-suspicious",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="firewall.enable",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="credential.recommend-rotation",
                        condition=None,
                        on_success="step_4",
                    ),
                    PlaybookStep(
                        remediation_id="threat-hunt.priority-flag",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
                first_shipped_in="51",
            ),

            "incident.dcom-lateral-movement": Playbook(
                id="incident.dcom-lateral-movement",
                name="DCOM Lateral Movement Response",
                description="Respond to DCOM or WMI exploitation for lateral movement.",
                trigger=PlaybookTrigger(
                    trigger_type="correlation_match",
                    condition="network AND dcom OR wmi",
                    finding_types=["network.dcom-lateral-movement", "network.wmi-lateral-movement", "connection.new_remote"],
                    anomaly_threshold=70.0,
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="process.block-dcom",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="ssh.disable-password-auth",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="network.isolate-destination",
                        condition="if_remote_lateral_movement",
                        on_success="step_4",
                    ),
                    PlaybookStep(
                        remediation_id="endpoint.mdm-notify",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
                first_shipped_in="51",
            ),

            "incident.webshell-execution": Playbook(
                id="incident.webshell-execution",
                name="Webshell Execution Response",
                description="Respond to suspected webshell upload and execution on web server.",
                trigger=PlaybookTrigger(
                    trigger_type="finding_pattern",
                    condition="web AND execution",
                    finding_types=["file.webshell-execution", "web.suspicious-upload-executed"],
                    anomaly_threshold=80.0,
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="file.quarantine-webshell",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="firewall.block-inbound",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="threat-hunt.priority-flag",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
                first_shipped_in="51",
            ),

            "incident.data-staging": Playbook(
                id="incident.data-staging",
                name="Data Staging and Exfiltration Response",
                description="Respond to suspicious file gathering and staging for data exfiltration.",
                trigger=PlaybookTrigger(
                    trigger_type="correlation_match",
                    condition="file_activity AND network_connection",
                    finding_types=["network.data-staging", "file.bulk-archive-creation", "connection.exfiltration-destination"],
                    anomaly_threshold=75.0,
                ),
                steps=[
                    PlaybookStep(
                        remediation_id="network.block-exfil-destinations",
                        condition=None,
                        on_success="step_2",
                    ),
                    PlaybookStep(
                        remediation_id="firewall.block-inbound",
                        condition=None,
                        on_success="step_3",
                    ),
                    PlaybookStep(
                        remediation_id="endpoint.mdm-notify",
                        condition=None,
                        on_success="step_4",
                    ),
                    PlaybookStep(
                        remediation_id="threat-hunt.priority-flag",
                        condition=None,
                    ),
                ],
                severity=RiskLevel.HIGH,
                first_shipped_in="51",
            ),
        }

    def get_playbook(self, playbook_id: str):
        """Get a playbook by ID."""
        return self.playbooks.get(playbook_id)

    def list_playbooks(self, enabled_only=True):
        """List all playbooks."""
        result = list(self.playbooks.values())
        if enabled_only:
            result = [p for p in result if p.enabled]
        return sorted(result, key=lambda p: p.id)

    def find_applicable_playbooks(
        self,
        finding_types,
        anomaly_score=0.0,
    ):
        """Find playbooks that match the given findings and anomaly score."""
        applicable = []

        for playbook in self.list_playbooks():
            # Check if any finding type matches
            finding_match = any(
                ft in playbook.trigger.finding_types
                for ft in finding_types
            )

            # Check anomaly score threshold if applicable
            score_match = True
            if playbook.trigger.anomaly_threshold is not None:
                score_match = anomaly_score >= playbook.trigger.anomaly_threshold
            elif "anomaly_score" in playbook.trigger.condition:
                try:
                    parts = playbook.trigger.condition.split(">")[1].split()[0]
                    threshold = int(parts)
                    score_match = anomaly_score >= threshold
                except (IndexError, ValueError):
                    score_match = False

            if finding_match and score_match:
                applicable.append(playbook)

        return applicable

    def create_run(
        self,
        playbook_id: str,
        trigger_finding: str,
        trigger_anomaly_score: float,
        run_id=None,
    ):
        """Create a new playbook run."""
        playbook = self.get_playbook(playbook_id)
        if playbook is None:
            return None

        run_id = run_id or f"pb_{playbook_id}_{trigger_finding}"
        run = PlaybookRun(
            run_id=run_id,
            playbook_id=playbook_id,
            trigger_finding=trigger_finding,
            trigger_anomaly_score=trigger_anomaly_score,
        )
        self.runs[run_id] = run
        return run

    def get_run(self, run_id: str):
        """Get a playbook run by ID."""
        return self.runs.get(run_id)

    def start_run(self, run: PlaybookRun) -> PlaybookRun:
        """Start executing a playbook run."""
        run.status = PlaybookRunStatus.RUNNING
        run.current_step_index = 0
        return run

    def execute_step(
        self,
        run: PlaybookRun,
        step_index: int,
        approval_request: Optional[ApprovalRequest] = None,
    ):
        """Execute a single step in a playbook run."""
        playbook = self.get_playbook(run.playbook_id)
        if playbook is None or step_index >= len(playbook.steps):
            return None

        step = playbook.steps[step_index]
        execution = StepExecution(
            step_id=f"step_{step_index}",
            remediation_id=step.remediation_id,
            status=StepStatus.RUNNING,
            started_at=datetime.utcnow(),
            approval_request=approval_request,
        )

        run.steps.append(execution)
        run.current_step_index = step_index

        return execution

    def complete_step(
        self,
        run: PlaybookRun,
        step_execution: StepExecution,
        result: str = "success",
        error: str = "",
    ) -> StepExecution:
        """Mark a step as complete."""
        step_execution.status = StepStatus.COMPLETED if not error else StepStatus.FAILED
        step_execution.result = result
        step_execution.error = error
        step_execution.completed_at = datetime.utcnow()
        return step_execution

    def get_next_step(
        self,
        run: PlaybookRun,
        current_result: str = "success",
    ):
        """Get the next step to execute based on current result."""
        playbook = self.get_playbook(run.playbook_id)
        if playbook is None or run.current_step_index >= len(playbook.steps):
            return None

        step = playbook.steps[run.current_step_index]

        # Determine next step based on result
        if current_result == "success" and step.on_success:
            # Extract step index from step ID (e.g., "step_2" → 2)
            next_id = step.on_success
            if next_id.startswith("step_"):
                return int(next_id.split("_")[1])
        elif current_result == "failed" and step.on_failure:
            next_id = step.on_failure
            if next_id.startswith("step_"):
                return int(next_id.split("_")[1])
        elif current_result == "timeout" and step.on_timeout:
            next_id = step.on_timeout
            if next_id.startswith("step_"):
                return int(next_id.split("_")[1])

        # Default: no next step (end of playbook)
        return None

    def complete_run(
        self,
        run: PlaybookRun,
        final_result: str = "success",
    ) -> PlaybookRun:
        """Mark a playbook run as complete."""
        run.status = PlaybookRunStatus.COMPLETED
        run.completed_at = datetime.utcnow()
        run.final_result = final_result
        return run

    def fail_run(
        self,
        run: PlaybookRun,
        reason: str = "",
    ) -> PlaybookRun:
        """Mark a playbook run as failed."""
        run.status = PlaybookRunStatus.FAILED
        run.completed_at = datetime.utcnow()
        run.final_result = f"failed: {reason}"
        return run

    def stop_run(self, run: PlaybookRun) -> PlaybookRun:
        """Stop a running playbook."""
        run.status = PlaybookRunStatus.STOPPED
        run.completed_at = datetime.utcnow()
        return run
