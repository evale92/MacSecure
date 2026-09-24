"""Test fixtures wired to real scanners."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

# Import real scanners
from secure.persistence.scanner import scan_persistence
from secure.listening.scanner import scan_listening_services
from secure.connections.scanner import scan_connections
from secure.fileintegrity.scanner import scan_file_integrity
from secure.wifi.scanner import scan_wifi
from secure.bluetooth.scanner import scan_bluetooth
from secure.storage.database import init_schema


@dataclass
class DetectionResult:
    """Result of a ground-truth injection test."""

    test_name: str
    sensor_type: str
    artifact_injected: str
    detected: bool
    detection_latency_ms: float
    artifact_identified: str
    false_positives: int
    confidence_score: float
    timestamp: datetime


@dataclass
class RemediationResult:
    """Result of a remediation safety test."""

    test_name: str
    action: str
    pre_state: Dict
    remediation_executed: bool
    post_state: Dict
    state_verified: bool
    rollback_successful: bool
    error: Optional[str] = None


class GroundTruthInjector:
    """Inject controlled, reproducible anomaly scenarios for real scanner testing."""

    def __init__(self, temp_dir: str = None, db_conn: sqlite3.Connection = None):
        """Initialize injector.

        Args:
            temp_dir: Temporary directory for artifacts. If None, creates one.
            db_conn: Database connection for scanners. If None, creates test DB.
        """
        self.temp_dir = Path(temp_dir or tempfile.mkdtemp())
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.injected_artifacts: List[Path] = []

        # Create test database if not provided
        if db_conn is None:
            self.db_path = self.temp_dir / "test.db"
            self.db_conn = sqlite3.connect(str(self.db_path))
            self.db_conn.row_factory = sqlite3.Row  # Enable named access
            init_schema(self.db_conn)
        else:
            self.db_conn = db_conn
            self.db_path = None

    def inject_persistence_mechanism(
        self,
        mechanism_type: str = "launchagent",
        name: str = "com.test.scanner.plist",
    ) -> Path:
        """Inject a test persistence mechanism (LaunchAgent/Daemon).

        Args:
            mechanism_type: "launchagent" or "launchdaemon"
            name: Plist filename

        Returns:
            Path to injected artifact
        """
        if mechanism_type == "launchagent":
            base_path = self.temp_dir / "LaunchAgents"
        else:
            base_path = self.temp_dir / "LaunchDaemons"

        base_path.mkdir(parents=True, exist_ok=True)
        plist_path = base_path / name

        # Valid plist for real scanner testing
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.test.scanner</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/touch</string>
        <string>/tmp/test_marker_{name}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""

        plist_path.write_text(plist_content)
        self.injected_artifacts.append(plist_path)
        return plist_path

    def inject_listening_port(
        self,
        port: int = 9999,
        protocol: str = "tcp",
    ) -> Dict:
        """Record a test listening port (simulator; actual port binding not required).

        Args:
            port: Port number
            protocol: "tcp" or "udp"

        Returns:
            Dict with port info for verification
        """
        return {
            "port": port,
            "protocol": protocol,
            "process": "test_process",
            "pid": 99999,
            "local_address": "127.0.0.1",
            "exposed": False,
        }

    def inject_file_modification(
        self,
        target_file: str = "/etc/hosts.test",
        modification: str = "127.0.0.1 test.local",
    ) -> Path:
        """Inject a modified file (uses temp directory).

        Args:
            target_file: Filename to simulate
            modification: Content to write

        Returns:
            Path to modified file
        """
        file_path = self.temp_dir / Path(target_file).name
        file_path.write_text(modification)
        self.injected_artifacts.append(file_path)
        return file_path

    def inject_network_connection(
        self,
        remote_ip: str = "192.0.2.1",
        remote_port: int = 443,
        local_port: int = 54321,
    ) -> Dict:
        """Record a test network connection (simulator).

        Args:
            remote_ip: Remote IP address
            remote_port: Remote port
            local_port: Local port

        Returns:
            Dict with connection info for verification
        """
        return {
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": "tcp",
            "state": "ESTABLISHED",
            "process": "test_process",
            "pid": 99999,
        }

    def scan_persistence(self) -> tuple[bool, float, Optional[str]]:
        """Run persistence scanner and measure latency.

        Returns:
            (detected, latency_ms, artifact_id) or (False, latency_ms, None)
        """
        start_time = time.time()
        try:
            result = scan_persistence(self.db_conn)
            latency_ms = (time.time() - start_time) * 1000

            # Check if any new persistence items detected
            detected = len(result.alerts) > 0 or len(result.new_entries) > 0
            artifact_id = None
            if result.new_entries:
                artifact_id = f"persistence:{result.new_entries[0].label if hasattr(result.new_entries[0], 'label') else result.new_entries[0]}"

            return detected, latency_ms, artifact_id
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, None

    def scan_listening(self) -> tuple[bool, float, Optional[str]]:
        """Run listening services scanner and measure latency."""
        start_time = time.time()
        try:
            result = scan_listening_services(self.db_conn)
            latency_ms = (time.time() - start_time) * 1000

            detected = len(result.new_listening_services) > 0
            artifact_id = None
            if result.new_listening_services:
                first = result.new_listening_services[0]
                artifact_id = f"listening:{first.port if hasattr(first, 'port') else first}"

            return detected, latency_ms, artifact_id
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, None

    def scan_connections(self) -> tuple[bool, float, Optional[str]]:
        """Run connections scanner and measure latency."""
        start_time = time.time()
        try:
            result = scan_connections(self.db_conn)
            latency_ms = (time.time() - start_time) * 1000

            detected = len(result.new_connections) > 0
            artifact_id = None
            if result.new_connections:
                first = result.new_connections[0]
                artifact_id = f"connection:{first.remote_ip if hasattr(first, 'remote_ip') else first}:{first.remote_port if hasattr(first, 'remote_port') else ''}"

            return detected, latency_ms, artifact_id
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, None

    def cleanup(self) -> None:
        """Clean up all injected artifacts."""
        for artifact in self.injected_artifacts:
            if artifact.exists():
                artifact.unlink()

        # Clean up empty directories
        for directory in self.injected_artifacts:
            try:
                directory.parent.rmdir()
            except (OSError, FileNotFoundError):
                pass

        # Close database connection
        if self.db_path and self.db_conn:
            self.db_conn.close()


class MetricsCollector:
    """Collect and aggregate test metrics."""

    def __init__(self):
        """Initialize metrics collector."""
        self.detections: List[DetectionResult] = []
        self.remediations: List[RemediationResult] = []
        self.start_time = datetime.now()

    def record_detection(
        self,
        test_name: str,
        sensor_type: str,
        artifact: str,
        detected: bool,
        latency_ms: float,
        identified: str = "",
        false_positives: int = 0,
        confidence: float = 0.0,
    ) -> None:
        """Record a detection result.

        Args:
            test_name: Test identifier
            sensor_type: Which sensor (persistence, listening, etc.)
            artifact: What was injected
            detected: Was it detected?
            latency_ms: Time to detect in milliseconds
            identified: Exact identification string
            false_positives: Number of FPs in time window
            confidence: Confidence score (0.0-1.0)
        """
        result = DetectionResult(
            test_name=test_name,
            sensor_type=sensor_type,
            artifact_injected=artifact,
            detected=detected,
            detection_latency_ms=latency_ms,
            artifact_identified=identified,
            false_positives=false_positives,
            confidence_score=confidence,
            timestamp=datetime.now(),
        )
        self.detections.append(result)

    def record_remediation(
        self,
        test_name: str,
        action: str,
        pre_state: Dict,
        post_state: Dict,
        executed: bool,
        verified: bool,
        rollback_ok: bool,
        error: Optional[str] = None,
    ) -> None:
        """Record a remediation result.

        Args:
            test_name: Test identifier
            action: What remediation action
            pre_state: State before remediation
            post_state: State after remediation
            executed: Did remediation run?
            verified: Was post-state correct?
            rollback_ok: Did rollback work?
            error: Error message if any
        """
        result = RemediationResult(
            test_name=test_name,
            action=action,
            pre_state=pre_state,
            remediation_executed=executed,
            post_state=post_state,
            state_verified=verified,
            rollback_successful=rollback_ok,
            error=error,
        )
        self.remediations.append(result)

    def detection_summary(self) -> Dict:
        """Summarize detection metrics.

        Returns:
            Dict with detection rate, latency stats, FP stats
        """
        if not self.detections:
            return {"error": "No detection data"}

        by_sensor = {}
        for detection in self.detections:
            sensor = detection.sensor_type
            if sensor not in by_sensor:
                by_sensor[sensor] = {
                    "total": 0,
                    "detected": 0,
                    "latencies": [],
                    "false_positives": [],
                    "confidence_scores": [],
                }

            by_sensor[sensor]["total"] += 1
            by_sensor[sensor]["detected"] += int(detection.detected)
            by_sensor[sensor]["latencies"].append(detection.detection_latency_ms)
            by_sensor[sensor]["false_positives"].append(detection.false_positives)
            by_sensor[sensor]["confidence_scores"].append(detection.confidence_score)

        summary = {}
        for sensor, data in by_sensor.items():
            latencies = data["latencies"]
            fps = data["false_positives"]
            confidences = data["confidence_scores"]

            summary[sensor] = {
                "total_tests": data["total"],
                "detection_rate": data["detected"] / data["total"] if data["total"] > 0 else 0.0,
                "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
                "median_latency_ms": sorted(latencies)[len(latencies) // 2] if latencies else 0.0,
                "avg_false_positives": sum(fps) / len(fps) if fps else 0.0,
                "avg_confidence": sum(confidences) / len(confidences) if confidences else 0.0,
            }

        return summary

    def remediation_summary(self) -> Dict:
        """Summarize remediation metrics.

        Returns:
            Dict with execution, verification, rollback rates
        """
        if not self.remediations:
            return {"error": "No remediation data"}

        by_action = {}
        for remediation in self.remediations:
            action = remediation.action
            if action not in by_action:
                by_action[action] = {
                    "total": 0,
                    "executed": 0,
                    "verified": 0,
                    "rollback_ok": 0,
                    "errors": [],
                }

            by_action[action]["total"] += 1
            by_action[action]["executed"] += int(remediation.remediation_executed)
            by_action[action]["verified"] += int(remediation.state_verified)
            by_action[action]["rollback_ok"] += int(remediation.rollback_successful)
            if remediation.error:
                by_action[action]["errors"].append(remediation.error)

        summary = {}
        for action, data in by_action.items():
            summary[action] = {
                "total_tests": data["total"],
                "execution_rate": data["executed"] / data["total"] if data["total"] > 0 else 0.0,
                "verification_rate": data["verified"] / data["total"] if data["total"] > 0 else 0.0,
                "rollback_rate": data["rollback_ok"] / data["total"] if data["total"] > 0 else 0.0,
                "error_count": len(data["errors"]),
            }

        return summary

    def to_json(self) -> str:
        """Export metrics as JSON.

        Returns:
            JSON string with all metrics
        """
        return json.dumps(
            {
                "detection_summary": self.detection_summary(),
                "remediation_summary": self.remediation_summary(),
                "total_detection_tests": len(self.detections),
                "total_remediation_tests": len(self.remediations),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            },
            indent=2,
            default=str,
        )
