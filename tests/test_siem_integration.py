"""Phase 65: SIEM integration tests."""

import json
from datetime import datetime

from secure.integrations.siem import SIEMForwarder, SIEMFormat, SIEMEndpoint


def test_format_cef():
    """Test CEF format output."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    cef = forwarder.format_cef(
        alert_id=123,
        severity="HIGH",
        entity_type="process_key",
        entity_path="/usr/bin/malware",
        verdict="ACTIVE",
        timestamp=timestamp,
    )

    assert "CEF:0" in cef
    assert "Secure" in cef
    assert "Threat Alert" in cef
    assert "cn1=123" in cef
    assert "cs1=process_key" in cef
    assert "cs3=/usr/bin/malware" in cef
    assert "sev=HIGH" in cef


def test_format_syslog():
    """Test Syslog format output."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    syslog = forwarder.format_syslog(
        alert_id=123,
        severity="CRITICAL",
        entity_type="file_path",
        entity_path="/etc/shadow",
        verdict="ACTIVE",
        timestamp=timestamp,
    )

    # Syslog format: <PRI>TIMESTAMP HOSTNAME TAG: MSG
    assert "<" in syslog
    assert ">" in syslog
    assert "alert_id=123" in syslog
    assert "entity_type=file_path" in syslog
    assert "severity=CRITICAL" in syslog


def test_format_splunk_hec():
    """Test Splunk HEC format output."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    splunk = forwarder.format_splunk_hec(
        alert_id=456,
        severity="MEDIUM",
        entity_type="listening_port",
        entity_path="127.0.0.1:8080",
        verdict="SUPPRESSED_EXPECTED",
        timestamp=timestamp,
    )

    data = json.loads(splunk)
    assert data["event"]["alert_id"] == 456
    assert data["event"]["severity"] == "MEDIUM"
    assert data["sourcetype"] == "alert"
    assert data["source"] == "secure-monitor"


def test_format_json():
    """Test generic JSON format output."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    json_alert = forwarder.format_json(
        alert_id=789,
        severity="LOW",
        entity_type="wifi_network",
        entity_path="FakeWiFi",
        verdict="ACTIVE",
        timestamp=timestamp,
        extra_fields={"correlation_id": "abc123"},
    )

    data = json.loads(json_alert)
    assert data["alert_id"] == 789
    assert data["severity"] == "LOW"
    assert data["correlation_id"] == "abc123"
    assert "timestamp" in data


def test_format_alert_dispatcher():
    """Test format_alert dispatcher method."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    # Test each format
    for fmt in [SIEMFormat.CEF, SIEMFormat.SYSLOG, SIEMFormat.JSON, SIEMFormat.SPLUNK_HEC]:
        result = forwarder.format_alert(
            format=fmt,
            alert_id=100,
            severity="HIGH",
            entity_type="persistence_mechanism",
            entity_path="/Library/LaunchAgents/com.malware.plist",
            verdict="ACTIVE",
            timestamp=timestamp,
        )
        assert result is not None
        assert len(result) > 0


def test_siem_endpoint_config():
    """Test SIEM endpoint configuration."""
    endpoint = SIEMEndpoint(
        endpoint_id="splunk1",
        name="Splunk Enterprise",
        format=SIEMFormat.SPLUNK_HEC,
        url="https://splunk.company.com:8088/services/collector",
        api_key="Splunk 12345-abcde-67890",
        enabled=True,
        timeout_seconds=15,
    )

    assert endpoint.endpoint_id == "splunk1"
    assert endpoint.format == SIEMFormat.SPLUNK_HEC
    assert endpoint.enabled is True


def test_severity_mapping():
    """Test severity level mapping across formats."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

    for severity in severities:
        # CEF should handle all severities
        cef = forwarder.format_cef(1, severity, "type", "path", "ACTIVE", timestamp)
        assert f"sev={severity}" in cef

        # Syslog should handle all severities
        syslog = forwarder.format_syslog(1, severity, "type", "path", "ACTIVE", timestamp)
        assert f"severity={severity}" in syslog

        # JSON should handle all severities
        json_alert = forwarder.format_json(1, severity, "type", "path", "ACTIVE", timestamp)
        data = json.loads(json_alert)
        assert data["severity"] == severity


def test_http_endpoint_construction():
    """Test HTTP endpoint construction."""
    endpoint = SIEMEndpoint(
        endpoint_id="http1",
        name="Webhook Receiver",
        format=SIEMFormat.JSON,
        url="https://api.example.com/alerts",
        api_key="bearer_token_xyz",
        enabled=True,
    )

    assert endpoint.url == "https://api.example.com/alerts"
    assert endpoint.host is None
    assert endpoint.port is None


def test_syslog_endpoint_construction():
    """Test Syslog endpoint construction."""
    endpoint = SIEMEndpoint(
        endpoint_id="syslog1",
        name="Syslog Server",
        format=SIEMFormat.SYSLOG,
        host="syslog.company.com",
        port=514,
        enabled=True,
    )

    assert endpoint.host == "syslog.company.com"
    assert endpoint.port == 514
    assert endpoint.url is None


def test_disabled_endpoint():
    """Test that disabled endpoints are not processed."""
    endpoint = SIEMEndpoint(
        endpoint_id="disabled",
        name="Disabled Endpoint",
        format=SIEMFormat.JSON,
        url="https://example.com",
        enabled=False,
    )

    forwarder = SIEMForwarder()
    result = forwarder.send_alert(
        endpoint,
        alert_id=1,
        severity="HIGH",
        entity_type="test",
        entity_path="path",
        verdict="ACTIVE",
        timestamp=datetime.now(),
    )

    assert result is False


def test_format_alert_with_special_characters():
    """Test formatting alerts with special characters in paths."""
    forwarder = SIEMForwarder()
    timestamp = datetime(2026, 9, 24, 12, 0, 0)

    # Path with spaces and special characters
    entity_path = "/Users/My User/My Documents/file (1).txt"

    cef = forwarder.format_cef(
        1, "HIGH", "file_path", entity_path, "ACTIVE", timestamp
    )
    assert entity_path in cef

    syslog = forwarder.format_syslog(
        1, "HIGH", "file_path", entity_path, "ACTIVE", timestamp
    )
    assert entity_path in syslog

    json_alert = forwarder.format_json(
        1, "HIGH", "file_path", entity_path, "ACTIVE", timestamp
    )
    data = json.loads(json_alert)
    assert data["entity_path"] == entity_path
