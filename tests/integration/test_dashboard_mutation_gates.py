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

        # With server bind stub, test must fail (return code != 0)
        # and fail on the specific HTTP call, not somewhere else
        if result.returncode == 0:
            assert False, \
                f"GATE_DASHBOARD_SERVER_BIND: test should fail when server cannot bind, but passed:\n{result.stdout}"

        # Check that failure is on the HTTP call (GATE_DASHBOARD_ALERTS_TOTAL sentinel)
        # not on setup or unrelated assertion
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_DASHBOARD_ALERTS_TOTAL" in l or "URLError" in l or "Connection" in l
                   for l in fail_lines), \
            f"GATE_DASHBOARD_SERVER_BIND: Expected HTTP/connection error, got:\n{result.stdout}"

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
        if result.returncode == 0:
            assert False, \
                f"GATE_DASHBOARD_EXPORT: test should fail when server cannot bind, but passed:\n{result.stdout}"

        # Failure should be on HTTP call, not unrelated assertion
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_DASHBOARD_EXPORT" in l or "URLError" in l or "Connection" in l
                   for l in fail_lines), \
            f"GATE_DASHBOARD_EXPORT: Expected HTTP/connection error, got:\n{result.stdout}"

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

        # Failure MUST be on the specific assertion (GATE_DASHBOARD_ALERTS_TOTAL sentinel)
        # NOT on a connection error — we're testing the payload check, not connectivity
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_DASHBOARD_ALERTS_TOTAL" in l for l in fail_lines), \
            f"GATE_DASHBOARD_ALERTS_PAYLOAD: Must fail on assertion, not connection. Got:\n{result.stdout}"
        # Ensure it's NOT a connection error (that would mean no payload check)
        assert not any("URLError" in l or "Connection" in l for l in fail_lines), \
            f"GATE_DASHBOARD_ALERTS_PAYLOAD: Should not fail on connection when server is up:\n{result.stdout}"
