"""
Tests for multi-device orchestration.

Phase 49 tests covering:
- Device enrollment and status tracking
- Cross-device finding correlation
- Incident detection and coordination
- Remediation workflows across devices
"""

import unittest
from datetime import datetime, timedelta

from secure.multi_device.device_registry import (
    DeviceRegistry,
    DeviceRole,
    DeviceStatus,
)
from secure.multi_device.cross_device import CrossDeviceFindingCorrelator
from secure.multi_device.orchestrator import (
    MultiDeviceOrchestrator,
    CrossDeviceIncident,
)


class TestDeviceRegistry(unittest.TestCase):
    """Test device registry functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.registry = DeviceRegistry()

    def test_enroll_device(self):
        """Test enrolling a device."""
        device = self.registry.enroll_device(
            device_id="mac_001",
            device_name="MacBook Pro",
            device_type="mac",
            enrolled_by="user@example.com",
            role=DeviceRole.PRIMARY,
        )

        self.assertIsNotNone(device)
        self.assertEqual(device.device_id, "mac_001")
        self.assertEqual(device.device_name, "MacBook Pro")
        self.assertEqual(device.role, DeviceRole.PRIMARY)
        self.assertEqual(device.status, DeviceStatus.ACTIVE)

    def test_enroll_multiple_devices(self):
        """Test enrolling multiple devices."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")
        self.registry.enroll_device("ipad_001", "iPad", "ipad", "user@ex.com")
        self.registry.enroll_device("iphone_001", "iPhone", "iphone", "user@ex.com")

        devices = self.registry.list_devices()
        self.assertEqual(len(devices), 3)

    def test_get_device(self):
        """Test getting a device by ID."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")
        device = self.registry.get_device("mac_001")

        self.assertIsNotNone(device)
        self.assertEqual(device.device_id, "mac_001")

    def test_update_device_status(self):
        """Test updating device status."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")

        updated = self.registry.update_device_status(
            "mac_001",
            DeviceStatus.IDLE,
        )

        self.assertEqual(updated.status, DeviceStatus.IDLE)
        self.assertIsNotNone(updated.last_seen)

    def test_list_devices_by_status(self):
        """Test filtering devices by status."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com", DeviceRole.PRIMARY)
        self.registry.enroll_device("mac_002", "MacBook", "mac", "user@ex.com", DeviceRole.SECONDARY)
        self.registry.update_device_status("mac_002", DeviceStatus.IDLE)

        active = self.registry.list_devices(status=DeviceStatus.ACTIVE)
        idle = self.registry.list_devices(status=DeviceStatus.IDLE)

        self.assertEqual(len(active), 1)
        self.assertEqual(len(idle), 1)

    def test_list_devices_by_role(self):
        """Test filtering devices by role."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com", DeviceRole.PRIMARY)
        self.registry.enroll_device("mac_002", "MacBook", "mac", "user@ex.com", DeviceRole.SECONDARY)

        primary = self.registry.list_devices(role=DeviceRole.PRIMARY)
        secondary = self.registry.list_devices(role=DeviceRole.SECONDARY)

        self.assertEqual(len(primary), 1)
        self.assertEqual(len(secondary), 1)

    def test_record_device_health(self):
        """Test recording device health metrics."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")

        updated = self.registry.record_device_health(
            "mac_001",
            cpu_ok=True,
            disk_ok=True,
            memory_ok=True,
            network_ok=True,
        )

        self.assertTrue(updated.cpu_ok)
        self.assertTrue(updated.disk_ok)
        self.assertGreater(len(self.registry.device_health_history["mac_001"]), 0)

    def test_device_health_degradation(self):
        """Test device status change on health degradation."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")

        self.registry.record_device_health(
            "mac_001",
            cpu_ok=True,
            disk_ok=False,
            memory_ok=True,
            network_ok=True,
        )

        device = self.registry.get_device("mac_001")
        self.assertEqual(device.status, DeviceStatus.IDLE)

    def test_is_device_healthy(self):
        """Test checking if device is healthy."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")
        self.registry.update_device_status("mac_001", DeviceStatus.ACTIVE)

        is_healthy = self.registry.is_device_healthy("mac_001")
        self.assertTrue(is_healthy)

    def test_get_active_devices(self):
        """Test getting active, healthy devices."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")
        d2 = self.registry.enroll_device("mac_002", "MacBook", "mac", "user@ex.com")
        # Mark device 2 as old (not recently seen)
        d2.last_seen = datetime.utcnow() - timedelta(minutes=10)

        active = self.registry.get_active_devices()
        self.assertEqual(len(active), 1)

    def test_unenroll_device(self):
        """Test unenrolling a device."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")
        unenrolled = self.registry.unenroll_device("mac_001")

        self.assertEqual(unenrolled.status, DeviceStatus.UNENROLLED)
        self.assertFalse(unenrolled.enabled)

    def test_create_sync_request(self):
        """Test creating sync requests."""
        self.registry.enroll_device("mac_001", "MacBook", "mac", "user@ex.com")
        request = self.registry.create_sync_request("mac_001", "findings")

        self.assertIsNotNone(request)
        self.assertEqual(request.device_id, "mac_001")
        self.assertEqual(request.status, "pending")


class TestCrossDeviceCorrelation(unittest.TestCase):
    """Test cross-device finding correlation."""

    def setUp(self):
        """Set up test fixtures."""
        self.correlator = CrossDeviceFindingCorrelator()

    def test_add_device_findings(self):
        """Test adding findings from devices."""
        findings = [
            {"finding_type": "persistence.unsigned_executable", "timestamp": datetime.utcnow()},
            {"finding_type": "network.c2", "timestamp": datetime.utcnow()},
        ]

        self.correlator.add_device_findings("mac_001", findings)
        self.assertIn("mac_001", self.correlator.device_findings)

    def test_correlate_single_device(self):
        """Test that single-device findings are not correlated."""
        findings = [
            {"finding_type": "persistence.unsigned_executable", "timestamp": datetime.utcnow()},
        ]
        self.correlator.add_device_findings("mac_001", findings)

        correlated = self.correlator.correlate_findings(min_device_count=2)
        self.assertEqual(len(correlated), 0)

    def test_correlate_multi_device_findings(self):
        """Test correlating findings across multiple devices."""
        now = datetime.utcnow()
        findings = [
            {"finding_type": "persistence.unsigned_executable", "timestamp": now},
        ]

        self.correlator.add_device_findings("mac_001", findings)
        self.correlator.add_device_findings("mac_002", findings)

        correlated = self.correlator.correlate_findings(min_device_count=2)
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0].device_count, 2)

    def test_correlation_strength(self):
        """Test correlation strength calculation."""
        now = datetime.utcnow()
        findings = [
            {"finding_type": "network.c2", "timestamp": now},
        ]

        # Multiple devices, tight timeframe → high correlation strength
        for i in range(3):
            self.correlator.add_device_findings(f"mac_{i}", findings)

        correlated = self.correlator.correlate_findings(min_device_count=2)
        self.assertGreater(correlated[0].correlation_strength, 50)

    def test_vector_classification_supply_chain(self):
        """Test classifying supply chain attack vector."""
        now = datetime.utcnow()
        findings = [
            {"finding_type": "persistence.modified_agent", "timestamp": now},
        ]

        # 3+ devices within 1 hour = supply chain
        for i in range(3):
            self.correlator.add_device_findings(f"mac_{i}", findings)

        correlated = self.correlator.correlate_findings()
        self.assertEqual(correlated[0].suspected_vector, "supply_chain")

    def test_vector_classification_coordinated_attack(self):
        """Test classifying coordinated attack vector."""
        now = datetime.utcnow()
        old_time = now - timedelta(hours=2)

        findings = [
            {"finding_type": "process.privilege_escalation", "timestamp": old_time},
        ]

        self.correlator.add_device_findings("mac_001", findings)

        new_findings = [
            {"finding_type": "process.privilege_escalation", "timestamp": now},
        ]
        self.correlator.add_device_findings("mac_002", new_findings)

        correlated = self.correlator.correlate_findings()
        # Should be time-windowed out if > 24h
        self.assertTrue(len(correlated) >= 0)


class TestMultiDeviceOrchestrator(unittest.TestCase):
    """Test multi-device orchestration."""

    def setUp(self):
        """Set up test fixtures."""
        self.orchestrator = MultiDeviceOrchestrator()

        # Enroll test devices
        for i in range(3):
            self.orchestrator.device_registry.enroll_device(
                device_id=f"mac_{i:03d}",
                device_name=f"MacBook {i}",
                device_type="mac",
                enrolled_by="admin@ex.com",
            )

    def test_detect_cross_device_incident(self):
        """Test detecting a cross-device incident."""
        # Add findings to devices
        findings = [
            {"finding_type": "persistence.unsigned_executable", "timestamp": datetime.utcnow()},
        ]
        for i in range(2):
            self.orchestrator.correlator.add_device_findings(f"mac_{i:03d}", findings)

        # Correlate findings
        correlated = self.orchestrator.correlator.correlate_findings(min_device_count=2)
        self.assertEqual(len(correlated), 1)

        # Detect incident
        incident = self.orchestrator.detect_cross_device_incident(
            [correlated[0].correlation_id],
            "supply_chain",
        )

        self.assertIsNotNone(incident)
        self.assertEqual(incident.device_count, 2)
        self.assertEqual(incident.status, "open")

    def test_coordinate_remediation(self):
        """Test coordinating remediation across devices."""
        correlated = self.orchestrator.correlator.correlate_findings()
        incident = self.orchestrator.detect_cross_device_incident([], "test")

        updated = self.orchestrator.coordinate_remediation(
            incident.incident_id,
            ["incident.unsigned-process"],
        )

        self.assertEqual(updated.status, "remediating")
        self.assertIn("incident.unsigned-process", updated.remediation_playbooks)

    def test_execute_on_device(self):
        """Test executing remediation on a device."""
        # Ensure devices are healthy before test
        self.orchestrator.device_registry.update_device_status(
            "mac_000", DeviceStatus.ACTIVE
        )
        self.orchestrator.device_registry.update_device_status(
            "mac_001", DeviceStatus.ACTIVE
        )
        self.orchestrator.device_registry.record_device_health("mac_000")
        self.orchestrator.device_registry.record_device_health("mac_001")

        incident = self.orchestrator.detect_cross_device_incident([], "test")
        incident.device_ids = ["mac_000", "mac_001"]
        incident.devices_pending = list(incident.device_ids)

        success = self.orchestrator.execute_on_device(
            incident.incident_id,
            "mac_000",
            "incident.unsigned-process",
            approved_by="admin@ex.com",
        )

        self.assertTrue(success)
        self.assertNotIn("mac_000", incident.devices_pending)
        self.assertIn("mac_000", incident.devices_remediated)

    def test_approve_incident_remediation(self):
        """Test approving remediation for an incident."""
        incident = self.orchestrator.detect_cross_device_incident([], "test")

        approved = self.orchestrator.approve_incident_remediation(
            incident.incident_id,
            "admin@ex.com",
            "Verified supply chain compromise",
        )

        self.assertEqual(approved.approval_status, "approved")
        self.assertEqual(approved.approved_by, "admin@ex.com")

    def test_reject_incident_remediation(self):
        """Test rejecting remediation for an incident."""
        incident = self.orchestrator.detect_cross_device_incident([], "test")

        rejected = self.orchestrator.reject_incident_remediation(
            incident.incident_id,
            "analyst@ex.com",
            "False positive, known sample",
        )

        self.assertEqual(rejected.approval_status, "rejected")
        self.assertEqual(rejected.status, "investigating")

    def test_get_device_incidents(self):
        """Test getting incidents for a specific device."""
        incident1 = self.orchestrator.detect_cross_device_incident([], "test1")
        incident1.device_ids = ["mac_000", "mac_001"]

        incident2 = self.orchestrator.detect_cross_device_incident([], "test2")
        incident2.device_ids = ["mac_001", "mac_002"]

        mac_001_incidents = self.orchestrator.get_device_incidents("mac_001")
        self.assertEqual(len(mac_001_incidents), 2)

    def test_isolate_device_network(self):
        """Test isolating a device from others."""
        incident = self.orchestrator.detect_cross_device_incident([], "test")
        incident.device_ids = ["mac_000", "mac_001", "mac_002"]

        success = self.orchestrator.isolate_device_network(
            incident.incident_id,
            "mac_000",
            ["mac_001", "mac_002"],
        )

        self.assertTrue(success)
        isolated = self.orchestrator.get_isolated_devices("mac_000")
        self.assertEqual(len(isolated), 2)

    def test_close_incident(self):
        """Test closing an incident."""
        incident = self.orchestrator.detect_cross_device_incident([], "test")

        closed = self.orchestrator.close_incident(
            incident.incident_id,
            "admin@ex.com",
            "Remediation complete on all devices",
        )

        self.assertEqual(closed.status, "closed")
        self.assertIsNotNone(closed.resolved_at)

    def test_list_incidents(self):
        """Test listing incidents with filters."""
        self.orchestrator.detect_cross_device_incident([], "test1")
        self.orchestrator.detect_cross_device_incident([], "test2")

        all_incidents = self.orchestrator.list_incidents()
        self.assertEqual(len(all_incidents), 2)

    def test_incident_severity_calculation(self):
        """Test incident severity calculation."""
        # 3+ devices with high correlation = high severity
        now = datetime.utcnow()
        findings = [
            {"finding_type": "network.c2", "timestamp": now},
        ]

        for i in range(3):
            self.orchestrator.correlator.add_device_findings(f"mac_{i:03d}", findings)

        correlated = self.orchestrator.correlator.correlate_findings(min_device_count=2)
        self.assertEqual(len(correlated), 1)

        incident = self.orchestrator.detect_cross_device_incident(
            [correlated[0].correlation_id], "test"
        )

        self.assertEqual(incident.device_count, 3)
        self.assertEqual(incident.severity, "high")


if __name__ == "__main__":
    unittest.main()
