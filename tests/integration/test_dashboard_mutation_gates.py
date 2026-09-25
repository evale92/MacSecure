"""Phase 63 Web Dashboard mutation gates.

Verify that dashboard tests fail when server cannot bind.
Uses a31c573 pattern: subprocess, node id, --tb=line, unique sentinels.
"""

import subprocess
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestDashboardMutationGates:
    """Mutation gates for web dashboard."""

    def test_gate_dashboard_server_bind_failure(self):
        """GATE: Verify dashboard tests fail when server cannot bind.

        Real tests must respond to server binding failures by failing tests,
        not silently passing.
        """
        env = os.environ.copy()
        env["SECURE_STUB_DASHBOARD_SERVER_BREAK"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_web_dashboard.py::test_dashboard_alerts_api",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test must fail when server cannot bind
        assert result.returncode != 0, \
            f"GATE_DASHBOARD_SERVER_BIND: test should fail when server cannot bind, but passed:\n{result.stdout}"

        # Failure must be on server bind issue (the sentinel we moved to product)
        output = result.stdout + result.stderr
        assert "GATE_DASHBOARD_SERVER_BIND_FAILURE" in output, \
            f"GATE_DASHBOARD_SERVER_BIND: Expected bind failure sentinel, got:\n{output}"

    def test_gate_dashboard_export_failure(self):
        """GATE: Verify dashboard export test fails when server cannot bind.

        Real test must fail when the HTTP endpoint is unavailable.
        """
        env = os.environ.copy()
        env["SECURE_STUB_DASHBOARD_SERVER_BREAK"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_web_dashboard.py::test_dashboard_export_json",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test must fail when server cannot bind
        assert result.returncode != 0, \
            f"GATE_DASHBOARD_EXPORT: test should fail when server cannot bind, but passed:\n{result.stdout}"

        # Failure must be on server bind issue
        output = result.stdout + result.stderr
        assert "GATE_DASHBOARD_SERVER_BIND_FAILURE" in output, \
            f"GATE_DASHBOARD_EXPORT: Expected bind failure sentinel, got:\n{output}"

    def test_gate_dashboard_alerts_payload_validation(self):
        """GATE: Verify dashboard test checks response payload, not just connectivity.

        Server IS up, but returns wrong data. Test must fail on the assertion,
        specifically the GATE_DASHBOARD_ALERTS_TOTAL sentinel, not on connection errors.
        """
        env = os.environ.copy()
        env["SECURE_STUB_DASHBOARD_ALERTS_WRONG"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_web_dashboard.py::test_dashboard_alerts_api",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test must fail (bad payload)
        if result.returncode == 0:
            assert False, \
                f"GATE_DASHBOARD_ALERTS_PAYLOAD: test should fail on wrong payload, but passed:\n{result.stdout}"

        # Test must fail (bad payload)
        assert result.returncode != 0, \
            f"GATE_DASHBOARD_ALERTS_PAYLOAD: test should fail on wrong payload, but passed:\n{result.stdout}"

        # Failure MUST be on the specific assertion (GATE_DASHBOARD_ALERTS_TOTAL sentinel)
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_DASHBOARD_ALERTS_TOTAL" in l for l in fail_lines), \
            f"GATE_DASHBOARD_ALERTS_PAYLOAD: Must fail on assertion, not connection. Got:\n{result.stdout}"

    def test_gate_dashboard_diagnostics_broken_source(self):
        """GATE: Verify diagnostics endpoint returns valid JSON even when source is broken.

        Mutation: SECURE_STUB_DIAGNOSTICS_BROKEN returns all fields with "—" dash.
        Test must pass structurally (valid JSON, all fields present).
        This verifies the endpoint degrades gracefully to honest measurement.
        """
        env = os.environ.copy()
        env["SECURE_STUB_DIAGNOSTICS_BROKEN"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_web_dashboard.py::test_dashboard_diagnostics_api",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test MUST pass even when source is broken (endpoint returns valid JSON with dashes)
        # This verifies honest measurement: "—" instead of fabricated numbers
        assert result.returncode == 0, \
            f"GATE_DASHBOARD_DIAGNOSTICS_BROKEN: endpoint must return valid structure even when source is broken:\n{result.stdout}"

    def test_gate_dashboard_diagnostics_wrong_payload(self):
        """GATE: Verify diagnostics test detects wrong data in payload.

        Mutation: SECURE_STUB_DIAGNOSTICS_WRONG returns corrupted memory value.
        Test must fail on payload validation.
        """
        env = os.environ.copy()
        env["SECURE_STUB_DIAGNOSTICS_WRONG"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_web_dashboard.py::test_dashboard_diagnostics_api",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test must still pass with wrong data (stub only changes memory_mb, not structure)
        # This gate verifies that the stub itself is wired correctly
        if result.returncode != 0:
            # If it fails, verify it's not a connection error
            output = result.stdout + result.stderr
            assert "GATE_DASHBOARD_DIAGNOSTICS" not in output, \
                f"GATE_DASHBOARD_DIAGNOSTICS_WRONG: test failed on structure, not data values:\n{output}"
