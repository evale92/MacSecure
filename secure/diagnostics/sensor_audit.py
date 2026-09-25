"""Phase 58: Sensor coverage audit — map which sensors are active and tested.

Produces a CSV/table report of all sensors, their implementation status,
test coverage, and integration into the detection pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class SensorStatus:
    """Status of one sensor module."""
    name: str
    module_path: str
    has_scan_cmd: bool  # Called by secure_monitor.sh
    has_implementation: bool  # Has main scan/collect function
    test_files: int  # Count of test_*.py files
    total_tests: int  # Approximate count of test functions
    is_critical_tier: bool  # Persistence, listening, connections, file integrity, baseline, checks
    notes: str = ""


def audit_sensors(repo_root: str | None = None) -> List[SensorStatus]:
    """
    Audit all sensors in the codebase.

    Returns:
        List of SensorStatus for each sensor module
    """
    if repo_root is None:
        # Infer repo root from this module's location
        # secure/diagnostics/sensor_audit.py -> walk up 2 levels to repo root
        repo_root = str(Path(__file__).resolve().parents[2])

    repo_path = Path(repo_root)

    # Sensors we expect
    sensors = [
        ("persistence", True),   # Called by monitor, critical
        ("listening", True),     # Called by monitor, critical
        ("connections", True),   # Called by monitor, critical
        ("wifi", True),          # Called by monitor
        ("bluetooth", True),     # Called by monitor
        ("fileintegrity", False),  # Not called by monitor currently, critical
        ("checks", False),       # Not called by monitor (posture checks), critical
        ("inventory", False),    # Not called by monitor
        ("arpwatch", False),     # Not called by monitor
    ]

    # Read monitor script to verify
    monitor_script = repo_path / "secure_monitor.sh"
    monitor_text = monitor_script.read_text() if monitor_script.exists() else ""

    statuses = []

    for sensor_name, assumed_in_monitor in sensors:
        module_path = f"secure/{sensor_name}"
        module_dir = repo_path / module_path

        # Check if module exists
        if not module_dir.exists():
            continue

        # Check for scan function in monitor
        has_scan_cmd = f"{sensor_name}" in monitor_text and "scan" in monitor_text

        # Check for implementation (look for .py files with scan or collect)
        impl_files = list(module_dir.glob("*.py"))
        has_implementation = len([f for f in impl_files if f.name not in ["__init__.py", "__pycache__"]]) > 0

        # Count test files
        test_files = list(repo_path.glob(f"tests/test_{sensor_name}*.py"))
        test_count = len(test_files)

        # Estimate test function count
        total_tests = 0
        for test_file in test_files:
            content = test_file.read_text()
            total_tests += content.count("def test_")

        # Critical tier
        critical = sensor_name in ["persistence", "listening", "connections", "fileintegrity", "checks"]

        # Notes
        notes = ""
        if not has_scan_cmd and assumed_in_monitor:
            notes = "⚠️ Expected in monitor but not found"
        elif has_scan_cmd:
            notes = "✓ Active in monitor.sh"
        elif sensor_name in ["fileintegrity", "checks"]:
            notes = "Not in monitor (should be)"

        statuses.append(SensorStatus(
            name=sensor_name,
            module_path=module_path,
            has_scan_cmd=has_scan_cmd,
            has_implementation=has_implementation,
            test_files=test_count,
            total_tests=total_tests,
            is_critical_tier=critical,
            notes=notes,
        ))

    return sorted(statuses, key=lambda s: (not s.is_critical_tier, s.name))


def format_audit_table(statuses: List[SensorStatus]) -> str:
    """Format audit as markdown table."""
    lines = [
        "| Sensor | In Monitor | Tests | Impl | Critical | Notes |",
        "|--------|-----------|-------|------|----------|-------|",
    ]

    for s in statuses:
        in_monitor = "✓" if s.has_scan_cmd else "✗"
        impl = "✓" if s.has_implementation else "✗"
        tier = "✓ CRITICAL" if s.is_critical_tier else ""
        test_col = f"{s.test_files} files, {s.total_tests} tests"

        lines.append(f"| {s.name} | {in_monitor} | {test_col} | {impl} | {tier} | {s.notes} |")

    return "\n".join(lines)
