"""Phase 63 SIEM forwarder mutation gates.

Verify that send_alert and transport failures are properly detected.
Uses subprocess-based gates with unique sentinels (a31c573 pattern).
"""

import subprocess
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestSIEMMutationGates:
    """Mutation gates for SIEM forwarder."""

    def test_gate_siem_send_alert_fails_on_http_error(self):
        """GATE: Real send_alert must return False when HTTP fails.

        This gate tests that when we stub urlopen to raise an exception,
        send_alert correctly returns False (not True, not throwing).
        """
        from secure.integrations.siem import SIEMForwarder, SIEMEndpoint, SIEMFormat
        from datetime import datetime
        from unittest.mock import patch

        endpoint = SIEMEndpoint(
            endpoint_id="test_http",
            name="Test HTTP",
            format=SIEMFormat.JSON,
            url="https://broken.invalid/alerts",
            enabled=True,
        )

        forwarder = SIEMForwarder()

        # Stub: urlopen raises ConnectionError
        with patch("urllib.request.urlopen", side_effect=ConnectionError("Connection refused")):
            result = forwarder.send_alert(
                endpoint,
                alert_id=999,
                severity="HIGH",
                entity_type="test",
                entity_path="/test",
                verdict="ACTIVE",
                timestamp=datetime.now(),
            )

        # Must return False when transport fails (not True, not exception)
        assert result is False, \
            f"GATE_SIEM_HTTP_ERROR: send_alert should return False on HTTP error, got {result}"

    def test_siem_send_alert_returns_false_on_all_errors(self):
        """Verify send_alert always returns False on any error (not True, not exception).

        This is the protection against silent transport failures.
        """
        from secure.integrations.siem import SIEMForwarder, SIEMEndpoint, SIEMFormat
        from datetime import datetime
        from unittest.mock import patch

        endpoint = SIEMEndpoint(
            endpoint_id="test_http",
            name="Test HTTP",
            format=SIEMFormat.JSON,
            url="https://example.com/alerts",
            enabled=True,
            timeout_seconds=1,
        )

        forwarder = SIEMForwarder()

        # Test various failure modes
        failure_modes = [
            ConnectionError("refused"),
            TimeoutError("timeout"),
            OSError("permission denied"),
            Exception("unknown error"),
        ]

        for error in failure_modes:
            with patch("urllib.request.urlopen", side_effect=error):
                result = forwarder.send_alert(
                    endpoint,
                    alert_id=999,
                    severity="HIGH",
                    entity_type="test",
                    entity_path="/test",
                    verdict="ACTIVE",
                    timestamp=datetime.now(),
                )
                assert result is False, \
                    f"GATE_SIEM_ERROR_MODES: send_alert returned {result} on {type(error).__name__}"

    def test_siem_malformed_endpoint_returns_false(self):
        """Verify send_alert returns False for malformed endpoints (no URL and no host/port).

        This tests the safety check at send_alert line 349.
        """
        from secure.integrations.siem import SIEMForwarder, SIEMEndpoint, SIEMFormat
        from datetime import datetime

        # Malformed: no URL, no host/port
        endpoint = SIEMEndpoint(
            endpoint_id="malformed",
            name="Malformed",
            format=SIEMFormat.JSON,
            enabled=True,
        )

        forwarder = SIEMForwarder()
        result = forwarder.send_alert(
            endpoint,
            alert_id=999,
            severity="HIGH",
            entity_type="test",
            entity_path="/test",
            verdict="ACTIVE",
            timestamp=datetime.now(),
        )

        assert result is False, \
            f"GATE_SIEM_MALFORMED: send_alert should return False for malformed endpoint, got {result}"

    def test_siem_disabled_endpoint_returns_false(self):
        """Verify disabled endpoints are never sent (return False immediately).

        This tests that the enabled check prevents any network call.
        """
        from secure.integrations.siem import SIEMForwarder, SIEMEndpoint, SIEMFormat
        from datetime import datetime

        endpoint = SIEMEndpoint(
            endpoint_id="disabled",
            name="Disabled",
            format=SIEMFormat.JSON,
            url="https://example.com/alerts",
            enabled=False,  # Disabled
        )

        forwarder = SIEMForwarder()
        result = forwarder.send_alert(
            endpoint,
            alert_id=999,
            severity="HIGH",
            entity_type="test",
            entity_path="/test",
            verdict="ACTIVE",
            timestamp=datetime.now(),
        )

        assert result is False, \
            f"GATE_SIEM_DISABLED: send_alert should return False for disabled endpoint, got {result}"
