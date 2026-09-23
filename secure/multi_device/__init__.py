"""
Multi-device coordination — family/team incident response orchestration.

Phase 49 extends Phase 48 remediation to coordinate across multiple devices
with local data isolation, cross-device correlation, and team workflows.
"""

from secure.multi_device.orchestrator import (
    MultiDeviceOrchestrator,
    CrossDeviceIncident,
)
from secure.multi_device.device_registry import (
    DeviceRegistry,
    EnrolledDevice,
    DeviceStatus,
)
from secure.multi_device.cross_device import (
    CrossDeviceFindingCorrelator,
    CorrelatedFinding,
)

__all__ = [
    "MultiDeviceOrchestrator",
    "CrossDeviceIncident",
    "DeviceRegistry",
    "EnrolledDevice",
    "DeviceStatus",
    "CrossDeviceFindingCorrelator",
    "CorrelatedFinding",
]
