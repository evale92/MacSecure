"""Compose AlertContext from Phase 48-51 data sources.

This is the ONLY impure file in secure/alerting/. It imports from
remediation, multi_device, intelligence, and storage to assemble
the frozen AlertContext dataclass that pure decision functions use.

If Phase 48-51 are unavailable, this returns AlertContext.empty() with safe defaults.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from secure.alerting.context import (
    AlertContext,
    DeviceContext,
    ExpectedChange,
    LearningContext,
    ResponseContext,
)


def compose_device_context() -> Optional[DeviceContext]:
    """
    Read Phase 49 multi-device state.

    Returns:
        DeviceContext or None if multi_device is unavailable.
    """
    try:
        from secure.multi_device.device_registry import get_device_info
        from secure.config import load_config

        cfg = load_config()
        device_info = get_device_info(cfg)

        if device_info is None:
            return None

        # Map internal device structure to DeviceContext
        return DeviceContext(
            device_id=device_info.device_id,
            role=device_info.role.value if hasattr(device_info.role, 'value') else str(device_info.role),
            health=device_info.health if hasattr(device_info, 'health') else "unknown",
            sync_state=device_info.sync_state if hasattr(device_info, 'sync_state') else "unknown",
            peer_device_count=0,  # TODO: query cross_device.py
        )
    except (ImportError, Exception):
        return None


def compose_response_context() -> Optional[ResponseContext]:
    """
    Read Phase 48/51 remediation and playbook state.

    Returns:
        ResponseContext or None if remediation is unavailable.
    """
    try:
        from secure.remediation.executor import RemediationExecutor, ExecutionStatus

        executor = RemediationExecutor()
        recent_executions = executor.list_executions(limit=100)

        if not recent_executions:
            return None

        # Find max risk level from recent actions
        max_risk = "LOW"
        max_playbook_id = None
        max_playbook_severity = None

        for execution in recent_executions:
            if execution.status == ExecutionStatus.PENDING:
                # Get action risk level
                try:
                    from secure.remediation.catalog import get_action
                    action = get_action(execution.action_id)
                    if action and action.risk_level.value > max_risk:
                        max_risk = action.risk_level.value
                except (ImportError, Exception):
                    pass

                # Get playbook info if available
                if execution.playbook_run_id:
                    try:
                        from secure.remediation.playbooks import PlaybookEngine
                        engine = PlaybookEngine()
                        pb = engine.get_playbook(execution.playbook_run_id)
                        if pb:
                            max_playbook_id = pb.id
                            max_playbook_severity = pb.severity.value
                    except (ImportError, Exception):
                        pass

        return ResponseContext(
            max_risk_level=max_risk,
            playbook_id=max_playbook_id,
            playbook_severity=max_playbook_severity,
        )
    except (ImportError, Exception):
        return None


def compose_learning_context() -> LearningContext:
    """
    Read Phase 50 learning outcomes and threshold overrides.

    Returns:
        LearningContext (always valid, defaults to empty if unavailable).
    """
    try:
        from secure.intelligence.learning import get_threshold_proposals
        from secure.config import load_config

        cfg = load_config()
        proposals = get_threshold_proposals(cfg)

        # Convert proposals to override dict
        overrides = {}
        if proposals:
            for proposal in proposals:
                if hasattr(proposal, 'feature_name') and hasattr(proposal, 'proposed_threshold'):
                    overrides[proposal.feature_name] = proposal.proposed_threshold

        return LearningContext(
            threshold_overrides=overrides,
            fp_rate_by_feature={},  # TODO: compute from anomaly_events.known=1
            sample_counts={},  # TODO: compute from baseline history
        )
    except (ImportError, Exception):
        return LearningContext()


def compose_expected_changes() -> tuple:
    """
    Read expected-change windows (OS updates, app installs, user declarations).

    Returns:
        Tuple of ExpectedChange objects.
    """
    try:
        from secure.checks.software_update import get_update_window
        from secure.config import load_config

        cfg = load_config()
        update_window = get_update_window(cfg)

        changes = []
        if update_window:
            changes.append(
                ExpectedChange(
                    kind="os_update",
                    started_at=update_window.started_at,
                    ends_at=update_window.ends_at,
                    entity_types=frozenset(["process_key", "file_change", "persistence_key"]),
                    path_prefixes=("/Library/Updates", "/System/Library/Updates"),
                    source="system:software_update",
                )
            )

        # TODO: read user-declared expected changes from storage

        return tuple(changes)
    except (ImportError, Exception):
        return ()


def compose(use_defaults: bool = True) -> AlertContext:
    """
    Assemble a complete AlertContext from all Phase 48-51 sources.

    Args:
        use_defaults: if True, missing sources return None/empty (safe defaults).
                     if False, raises on missing sources.

    Returns:
        AlertContext ready for decision functions.
    """
    try:
        device = compose_device_context()
        response = compose_response_context()
        learning = compose_learning_context()
        expected_changes = compose_expected_changes()

        return AlertContext(
            device=device,
            response=response,
            learning=learning,
            expected_changes=expected_changes,
        )
    except Exception:
        if use_defaults:
            return AlertContext.empty()
        raise
