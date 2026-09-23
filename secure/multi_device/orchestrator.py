"""
Multi-device orchestrator — coordinate incident response across devices.

Phase 49 orchestrates remediation actions across enrolled devices
with approval routing, isolation constraints, and team workflows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from secure.multi_device.device_registry import DeviceRegistry, DeviceStatus
from secure.multi_device.cross_device import (
    CrossDeviceFindingCorrelator,
    CorrelatedFinding,
)


@dataclass
class CrossDeviceIncident:
    """An incident involving multiple devices."""
    incident_id: str
    incident_type: str                # "coordinated_attack", "supply_chain", etc.

    correlation_ids: list = field(default_factory=list)
    device_ids: list = field(default_factory=list)
    device_count: int = 0

    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    status: str = "open"              # open, investigating, remediating, resolved, closed
    severity: str = "high"            # low, medium, high, critical

    # Remediation tracking
    remediation_playbooks: list = field(default_factory=list)
    devices_remediated: list = field(default_factory=list)
    devices_pending: list = field(default_factory=list)

    # Team coordination
    assigned_to: Optional[str] = None  # Team member ID
    approval_status: str = "pending"   # pending, approved, approved_partial, rejected
    approved_by: Optional[str] = None

    notes: str = ""
    tags: list = field(default_factory=list)


class MultiDeviceOrchestrator:
    """Orchestrates incident response across multiple devices."""

    def __init__(self, device_registry=None, correlator=None):
        """Initialize orchestrator."""
        self.device_registry = device_registry or DeviceRegistry()
        self.correlator = correlator or CrossDeviceFindingCorrelator()

        self.incidents: dict[str, CrossDeviceIncident] = {}
        self.device_isolation_map: dict[str, list[str]] = {}  # device_id -> [isolated_devices]

    def detect_cross_device_incident(
        self,
        correlation_ids: list[str],
        incident_type: str,
    ) -> CrossDeviceIncident:
        """Detect and create an incident from correlated findings."""
        device_ids = set()
        correlated_findings = []

        for corr_id in correlation_ids:
            finding = self.correlator.get_correlated_finding(corr_id)
            if finding:
                correlated_findings.append(finding)
                device_ids.update(finding.device_ids)

        incident_id = f"cdi_{incident_type}_{len(device_ids)}d"

        incident = CrossDeviceIncident(
            incident_id=incident_id,
            incident_type=incident_type,
            correlation_ids=correlation_ids,
            device_ids=list(device_ids),
            device_count=len(device_ids),
            severity=self._calculate_incident_severity(
                correlated_findings, len(device_ids)
            ),
        )

        self.incidents[incident_id] = incident
        return incident

    def coordinate_remediation(
        self,
        incident_id: str,
        playbook_ids: list[str],
    ) -> CrossDeviceIncident:
        """Coordinate remediation playbooks across incident devices."""
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None

        incident.remediation_playbooks = playbook_ids
        incident.status = "remediating"
        incident.devices_pending = list(incident.device_ids)

        return incident

    def execute_on_device(
        self,
        incident_id: str,
        device_id: str,
        playbook_id: str,
        approved_by: Optional[str] = None,
    ) -> bool:
        """Execute a remediation playbook on a specific device."""
        incident = self.incidents.get(incident_id)
        device = self.device_registry.get_device(device_id)

        if incident is None or device is None:
            return False

        # Check device health
        if not self.device_registry.is_device_healthy(device_id):
            return False

        # Check device permissions
        if not device.allow_cross_device_actions and approved_by is None:
            return False

        # Execute playbook (simulated)
        if device_id in incident.devices_pending:
            incident.devices_pending.remove(device_id)
            incident.devices_remediated.append(device_id)

        return True

    def isolate_device_network(
        self,
        incident_id: str,
        device_id: str,
        isolated_from_ids: list[str],
    ) -> bool:
        """Isolate a device from other specific devices."""
        incident = self.incidents.get(incident_id)
        device = self.device_registry.get_device(device_id)

        if incident is None or device is None:
            return False

        # Record isolation
        self.device_isolation_map[device_id] = isolated_from_ids

        return True

    def sync_incident_status(self, incident_id: str) -> CrossDeviceIncident:
        """Sync incident status across all devices."""
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None

        # Check if all devices are remediated
        if not incident.devices_pending:
            incident.status = "resolved"
            incident.resolved_at = datetime.utcnow()

        # Create sync requests for all devices
        for device_id in incident.device_ids:
            self.device_registry.create_sync_request(
                device_id,
                request_type="incident_status",
                ttl_seconds=300,  # 5-minute TTL
            )

        return incident

    def request_team_approval(
        self,
        incident_id: str,
        approver_id: str,
        reason: str = "",
    ) -> CrossDeviceIncident:
        """Request team approval for incident remediation."""
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None

        incident.approval_status = "pending"
        incident.assigned_to = approver_id

        return incident

    def approve_incident_remediation(
        self,
        incident_id: str,
        approved_by: str,
        reason: str = "",
    ) -> CrossDeviceIncident:
        """Approve remediation for an incident."""
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None

        incident.approval_status = "approved"
        incident.approved_by = approved_by
        incident.notes = reason or incident.notes

        return incident

    def reject_incident_remediation(
        self,
        incident_id: str,
        rejected_by: str,
        reason: str = "",
    ) -> CrossDeviceIncident:
        """Reject remediation for an incident."""
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None

        incident.approval_status = "rejected"
        incident.assigned_to = rejected_by
        incident.notes = reason or incident.notes
        incident.status = "investigating"

        return incident

    def get_incident(self, incident_id: str) -> CrossDeviceIncident:
        """Get an incident by ID."""
        return self.incidents.get(incident_id)

    def list_incidents(
        self,
        status: str = None,
        severity: str = None,
    ) -> list[CrossDeviceIncident]:
        """List incidents, optionally filtered."""
        result = list(self.incidents.values())

        if status:
            result = [i for i in result if i.status == status]

        if severity:
            result = [i for i in result if i.severity == severity]

        return sorted(result, key=lambda i: i.created_at, reverse=True)

    def get_device_incidents(self, device_id: str) -> list[CrossDeviceIncident]:
        """Get all incidents affecting a specific device."""
        return [i for i in self.incidents.values() if device_id in i.device_ids]

    def get_isolated_devices(self, device_id: str) -> list[str]:
        """Get list of devices isolated from a specific device."""
        return self.device_isolation_map.get(device_id, [])

    def close_incident(
        self,
        incident_id: str,
        closed_by: str,
        reason: str = "",
    ) -> CrossDeviceIncident:
        """Close an incident after remediation is complete."""
        incident = self.incidents.get(incident_id)
        if incident is None:
            return None

        incident.status = "closed"
        incident.resolved_at = datetime.utcnow()
        incident.notes = reason or incident.notes

        return incident

    @staticmethod
    def _calculate_incident_severity(
        correlated_findings: list[CorrelatedFinding],
        device_count: int,
    ) -> str:
        """Calculate incident severity from findings."""
        if device_count >= 5:
            return "critical"

        max_strength = max(
            (f.correlation_strength for f in correlated_findings),
            default=0.0
        )

        if max_strength >= 80 or device_count >= 3:
            return "high"
        elif max_strength >= 60:
            return "medium"
        else:
            return "low"
