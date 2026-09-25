"""SIEM integration — Phase 65. Forward alerts to external systems."""

from __future__ import annotations

import json
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from urllib.parse import urljoin


class SIEMFormat(str, Enum):
    """Supported SIEM output formats."""
    JSON = "json"
    SYSLOG = "syslog"
    CEF = "cef"
    SPLUNK_HEC = "splunk_hec"


@dataclass
class SIEMEndpoint:
    """Configuration for a SIEM endpoint."""
    endpoint_id: str
    name: str
    format: SIEMFormat
    url: Optional[str] = None  # For HTTP endpoints
    host: Optional[str] = None  # For Syslog
    port: Optional[int] = None  # For Syslog/HTTP
    api_key: Optional[str] = None  # For Splunk HEC, etc.
    enabled: bool = True
    timeout_seconds: int = 10


class SIEMForwarder:
    """Forward alerts to SIEM systems in multiple formats."""

    def __init__(self):
        """Initialize SIEM forwarder."""
        pass

    def format_cef(
        self,
        alert_id: int,
        severity: str,
        entity_type: str,
        entity_path: str,
        verdict: str,
        timestamp: datetime,
    ) -> str:
        """Format alert as CEF (Common Event Format).

        CEF Header format:
        CEF:0|vendor|product|version|signature|name|severity|extension

        Args:
            alert_id: Alert ID
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            entity_type: Type of entity (process_key, file_path, etc.)
            entity_path: Path or identifier of entity
            verdict: Alert verdict (ACTIVE, SUPPRESSED_EXPECTED, etc.)
            timestamp: Alert timestamp

        Returns:
            CEF formatted string
        """
        severity_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "NONE": 0}
        cef_severity = severity_map.get(severity, 5)

        cef_header = f"CEF:0|Secure|Monitor|1.0|{alert_id}|Threat Alert|{cef_severity}"

        extensions = {
            "rt": int(timestamp.timestamp() * 1000),  # Receipt timestamp (milliseconds)
            "cn1": alert_id,
            "cn1Label": "AlertID",
            "cs1": entity_type,
            "cs1Label": "EntityType",
            "cs2": verdict,
            "cs2Label": "Verdict",
            "cs3": entity_path,
            "cs3Label": "EntityPath",
            "sev": severity,
        }

        ext_str = " ".join(f"{k}={v}" for k, v in extensions.items())
        return f"{cef_header}|{ext_str}"

    def format_syslog(
        self,
        alert_id: int,
        severity: str,
        entity_type: str,
        entity_path: str,
        verdict: str,
        timestamp: datetime,
    ) -> str:
        """Format alert as Syslog message (RFC 3164).

        Format: <PRI>HEADER TAG MSG

        Args:
            alert_id: Alert ID
            severity: Severity level
            entity_type: Type of entity
            entity_path: Path or identifier
            verdict: Alert verdict
            timestamp: Alert timestamp

        Returns:
            Syslog formatted string
        """
        # Priority: facility 16 (local0), severity 3-8
        severity_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5, "NONE": 7}
        syslog_severity = severity_map.get(severity, 4)
        facility = 16
        priority = (facility * 8) + syslog_severity

        # Timestamp in syslog format
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")

        # Message
        msg = f"alert_id={alert_id} entity_type={entity_type} entity_path={entity_path} verdict={verdict} severity={severity}"

        return f"<{priority}>{timestamp_str} secure-monitor: {msg}"

    def format_splunk_hec(
        self,
        alert_id: int,
        severity: str,
        entity_type: str,
        entity_path: str,
        verdict: str,
        timestamp: datetime,
        source: str = "secure-monitor",
        sourcetype: str = "alert",
    ) -> str:
        """Format alert for Splunk HTTP Event Collector (HEC).

        Args:
            alert_id: Alert ID
            severity: Severity level
            entity_type: Type of entity
            entity_path: Path or identifier
            verdict: Alert verdict
            timestamp: Alert timestamp
            source: Source field
            sourcetype: Sourcetype field

        Returns:
            JSON formatted for Splunk HEC
        """
        event = {
            "event": {
                "alert_id": alert_id,
                "severity": severity,
                "entity_type": entity_type,
                "entity_path": entity_path,
                "verdict": verdict,
            },
            "source": source,
            "sourcetype": sourcetype,
            "time": int(timestamp.timestamp()),
        }
        return json.dumps(event)

    def format_json(
        self,
        alert_id: int,
        severity: str,
        entity_type: str,
        entity_path: str,
        verdict: str,
        timestamp: datetime,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Format alert as generic JSON.

        Args:
            alert_id: Alert ID
            severity: Severity level
            entity_type: Type of entity
            entity_path: Path or identifier
            verdict: Alert verdict
            timestamp: Alert timestamp
            extra_fields: Additional fields to include

        Returns:
            JSON formatted string
        """
        data = {
            "alert_id": alert_id,
            "severity": severity,
            "entity_type": entity_type,
            "entity_path": entity_path,
            "verdict": verdict,
            "timestamp": timestamp.isoformat(),
        }
        if extra_fields:
            data.update(extra_fields)

        return json.dumps(data)

    def format_alert(
        self,
        format: SIEMFormat,
        alert_id: int,
        severity: str,
        entity_type: str,
        entity_path: str,
        verdict: str,
        timestamp: datetime,
    ) -> str:
        """Format alert in the specified format.

        Args:
            format: Output format
            alert_id: Alert ID
            severity: Severity level
            entity_type: Type of entity
            entity_path: Path or identifier
            verdict: Alert verdict
            timestamp: Alert timestamp

        Returns:
            Formatted alert string
        """
        if format == SIEMFormat.CEF:
            return self.format_cef(alert_id, severity, entity_type, entity_path, verdict, timestamp)
        elif format == SIEMFormat.SYSLOG:
            return self.format_syslog(alert_id, severity, entity_type, entity_path, verdict, timestamp)
        elif format == SIEMFormat.SPLUNK_HEC:
            return self.format_splunk_hec(alert_id, severity, entity_type, entity_path, verdict, timestamp)
        elif format == SIEMFormat.JSON:
            return self.format_json(alert_id, severity, entity_type, entity_path, verdict, timestamp)
        else:
            raise ValueError(f"Unknown format: {format}")

    def send_syslog(
        self,
        host: str,
        port: int,
        message: str,
        timeout_seconds: int = 10,
    ) -> bool:
        """Send message to Syslog endpoint.

        Args:
            host: Syslog host
            port: Syslog port (usually 514)
            message: Formatted message
            timeout_seconds: Send timeout

        Returns:
            True if sent successfully
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout_seconds)
            sock.sendto(message.encode(), (host, port))
            sock.close()
            return True
        except Exception:
            return False

    def send_http(
        self,
        url: str,
        message: str,
        api_key: Optional[str] = None,
        timeout_seconds: int = 10,
    ) -> bool:
        """Send message to HTTP endpoint.

        Args:
            url: HTTP endpoint URL
            message: Message to send (JSON or formatted string)
            api_key: Optional API key for authentication
            timeout_seconds: Request timeout

        Returns:
            True if sent successfully
        """
        try:
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            req = urllib.request.Request(
                url,
                data=message.encode() if isinstance(message, str) else message,
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                return response.status in (200, 201, 202, 204)
        except urllib.error.URLError:
            return False
        except Exception:
            return False

    def send_alert(
        self,
        endpoint: SIEMEndpoint,
        alert_id: int,
        severity: str,
        entity_type: str,
        entity_path: str,
        verdict: str,
        timestamp: datetime,
    ) -> bool:
        """Send alert to a SIEM endpoint.

        Args:
            endpoint: SIEM endpoint configuration
            alert_id: Alert ID
            severity: Severity level
            entity_type: Type of entity
            entity_path: Path or identifier
            verdict: Alert verdict
            timestamp: Alert timestamp

        Returns:
            True if sent successfully
        """
        import os

        # Stub: transport broken (for mutation gate testing)
        if os.environ.get("SECURE_STUB_SIEM_TRANSPORT_BREAK"):
            return False

        if not endpoint.enabled:
            return False

        # Format the alert
        formatted = self.format_alert(
            endpoint.format,
            alert_id,
            severity,
            entity_type,
            entity_path,
            verdict,
            timestamp,
        )

        # Send to appropriate endpoint
        if endpoint.url:
            return self.send_http(endpoint.url, formatted, endpoint.api_key, endpoint.timeout_seconds)
        elif endpoint.host and endpoint.port:
            return self.send_syslog(endpoint.host, endpoint.port, formatted, endpoint.timeout_seconds)

        return False
