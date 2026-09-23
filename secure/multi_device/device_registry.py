"""
Device registry — manage enrolled devices in a family/team.

Phase 49 tracks which devices are enrolled, their last seen time,
health status, and whether they're active in multi-device coordination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


class DeviceStatus(str, Enum):
    """Status of an enrolled device."""
    ACTIVE = "active"
    IDLE = "idle"
    UNREACHABLE = "unreachable"
    SUSPENDED = "suspended"
    UNENROLLED = "unenrolled"


class DeviceRole(str, Enum):
    """Role of device in family/team."""
    PRIMARY = "primary"          # User's main device
    SECONDARY = "secondary"       # Additional personal devices
    SHARED = "shared"             # Family/team shared device
    ADMIN = "admin"              # Admin/supervisor device


@dataclass
class EnrolledDevice:
    """Record of a device enrolled in multi-device coordination."""
    device_id: str
    device_name: str
    device_type: str              # "mac", "ipad", "iphone"

    enrolled_by: str              # User ID or email
    enrolled_at: datetime = field(default_factory=datetime.utcnow)

    status: DeviceStatus = DeviceStatus.ACTIVE
    role: DeviceRole = DeviceRole.PRIMARY

    last_seen: Optional[datetime] = None
    last_sync: Optional[datetime] = None

    # Health metrics
    cpu_ok: bool = True
    disk_ok: bool = True
    memory_ok: bool = True
    network_ok: bool = True

    # Configuration
    sync_findings: bool = True        # Share findings with team
    sync_remediations: bool = True    # Sync remediation actions
    allow_cross_device_actions: bool = False  # Allow actions on this device from others

    # Metadata
    os_version: str = ""
    secure_version: str = ""
    notes: str = ""
    tags: list = field(default_factory=list)

    enabled: bool = True


@dataclass
class DeviceSyncRequest:
    """Request to sync data with a device."""
    request_id: str
    device_id: str
    request_type: str              # "findings", "remediations", "status", "full"

    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    status: str = "pending"        # pending, sent, received, failed
    last_attempt: Optional[datetime] = None
    attempt_count: int = 0


class DeviceRegistry:
    """Manages enrolled devices in a family/team."""

    def __init__(self):
        """Initialize device registry."""
        self.devices: dict[str, EnrolledDevice] = {}
        self.sync_requests: dict[str, DeviceSyncRequest] = {}
        self.device_health_history: dict[str, list] = {}  # device_id -> [health records]

    def enroll_device(
        self,
        device_id: str,
        device_name: str,
        device_type: str,
        enrolled_by: str,
        role: DeviceRole = DeviceRole.PRIMARY,
    ) -> EnrolledDevice:
        """Enroll a new device in the registry."""
        device = EnrolledDevice(
            device_id=device_id,
            device_name=device_name,
            device_type=device_type,
            enrolled_by=enrolled_by,
            role=role,
        )
        self.devices[device_id] = device
        self.device_health_history[device_id] = []
        return device

    def get_device(self, device_id: str) -> EnrolledDevice:
        """Get a device by ID."""
        return self.devices.get(device_id)

    def list_devices(
        self,
        status: DeviceStatus = None,
        role: DeviceRole = None,
        enabled_only: bool = True,
    ) -> list[EnrolledDevice]:
        """List devices, optionally filtered."""
        result = list(self.devices.values())

        if enabled_only:
            result = [d for d in result if d.enabled]

        if status:
            result = [d for d in result if d.status == status]

        if role:
            result = [d for d in result if d.role == role]

        return sorted(result, key=lambda d: d.enrolled_at)

    def update_device_status(
        self,
        device_id: str,
        status: DeviceStatus,
        last_seen: Optional[datetime] = None,
    ) -> EnrolledDevice:
        """Update device status and last seen time."""
        device = self.get_device(device_id)
        if device is None:
            return None

        device.status = status
        if last_seen:
            device.last_seen = last_seen
        else:
            device.last_seen = datetime.utcnow()

        return device

    def update_device_sync(
        self,
        device_id: str,
        sync_time: Optional[datetime] = None,
    ) -> EnrolledDevice:
        """Update device last sync time."""
        device = self.get_device(device_id)
        if device is None:
            return None

        device.last_sync = sync_time or datetime.utcnow()
        return device

    def record_device_health(
        self,
        device_id: str,
        cpu_ok: bool = True,
        disk_ok: bool = True,
        memory_ok: bool = True,
        network_ok: bool = True,
    ) -> EnrolledDevice:
        """Record health metrics for a device."""
        device = self.get_device(device_id)
        if device is None:
            return None

        device.cpu_ok = cpu_ok
        device.disk_ok = disk_ok
        device.memory_ok = memory_ok
        device.network_ok = network_ok

        # Record in history
        health_record = {
            "timestamp": datetime.utcnow(),
            "cpu_ok": cpu_ok,
            "disk_ok": disk_ok,
            "memory_ok": memory_ok,
            "network_ok": network_ok,
        }
        self.device_health_history[device_id].append(health_record)

        # Update device status based on health
        all_ok = cpu_ok and disk_ok and memory_ok and network_ok
        if not all_ok and device.status == DeviceStatus.ACTIVE:
            device.status = DeviceStatus.IDLE

        return device

    def unenroll_device(self, device_id: str) -> EnrolledDevice:
        """Unenroll a device from the registry."""
        device = self.get_device(device_id)
        if device is None:
            return None

        device.status = DeviceStatus.UNENROLLED
        device.enabled = False
        return device

    def create_sync_request(
        self,
        device_id: str,
        request_type: str,
        ttl_seconds: int = 3600,
        request_id: str = "",
    ) -> DeviceSyncRequest:
        """Create a sync request to a device."""
        device = self.get_device(device_id)
        if device is None:
            return None

        request_id = request_id or f"sync_{device_id}_{request_type}"
        now = datetime.utcnow()

        request = DeviceSyncRequest(
            request_id=request_id,
            device_id=device_id,
            request_type=request_type,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

        self.sync_requests[request_id] = request
        return request

    def get_sync_request(self, request_id: str) -> DeviceSyncRequest:
        """Get a sync request by ID."""
        return self.sync_requests.get(request_id)

    def mark_sync_sent(self, request_id: str) -> DeviceSyncRequest:
        """Mark a sync request as sent."""
        request = self.get_sync_request(request_id)
        if request is None:
            return None

        request.status = "sent"
        request.last_attempt = datetime.utcnow()
        request.attempt_count += 1
        return request

    def mark_sync_received(self, request_id: str) -> DeviceSyncRequest:
        """Mark a sync request as received."""
        request = self.get_sync_request(request_id)
        if request is None:
            return None

        request.status = "received"
        request.last_attempt = datetime.utcnow()
        return request

    def is_device_healthy(self, device_id: str) -> bool:
        """Check if device is healthy and active."""
        device = self.get_device(device_id)
        if device is None or not device.enabled:
            return False

        # Check if recently seen (within 5 minutes)
        if device.last_seen:
            elapsed = (datetime.utcnow() - device.last_seen).total_seconds()
            if elapsed > 300:
                return False

        return device.cpu_ok and device.disk_ok and device.memory_ok and device.network_ok

    def get_active_devices(self) -> list[EnrolledDevice]:
        """Get all active, healthy devices."""
        return [d for d in self.list_devices() if self.is_device_healthy(d.device_id)]

    def get_inactive_devices(self, idle_seconds: int = 300) -> list[EnrolledDevice]:
        """Get devices that haven't synced recently."""
        result = []
        cutoff = datetime.utcnow() - timedelta(seconds=idle_seconds)

        for device in self.list_devices():
            if device.last_seen and device.last_seen < cutoff:
                result.append(device)

        return result
