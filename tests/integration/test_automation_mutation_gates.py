"""Phase 64-65 automation and SIEM mutation gates.

Verify that automation dispatcher and SIEM forwarder failures are properly detected.
Uses a31c573 pattern: subprocess, node id, --tb=line, unique sentinels.
"""

import subprocess
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestAutomationMutationGates:
    """Mutation gates for automation dispatcher and SIEM integration."""

    def test_gate_automation_dispatcher_with_siem_stub(self):
        """GATE: Verify automation dispatcher tests fail when SIEM transport breaks.

        Real tests must respond to SIEM transport stub by failing (exit code != 0)
        with a specific failure sentinel.
        """
        env = os.environ.copy()
        env["SECURE_STUB_SIEM_TRANSPORT_BREAK"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_automation_dispatcher.py",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test must fail when SIEM transport is broken
        if result.returncode == 0:
            assert False, \
                f"GATE_AUTOMATION_DISPATCHER_SIEM: test should fail when SIEM transport is broken, but passed:\n{result.stdout}"

        # Failure must be on SIEM transport issue, not unrelated
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_AUTOMATION_DISPATCHER_SIEM" in l for l in fail_lines), \
            f"GATE_AUTOMATION_DISPATCHER_SIEM: Expected specific failure sentinel, got:\n{result.stdout}"

    def test_gate_automation_engine_with_siem_stub(self):
        """GATE: Verify automation engine tests fail when SIEM fails.

        Real tests must respond to SIEM transport stub by failing (exit code != 0)
        with a specific failure sentinel.
        """
        env = os.environ.copy()
        env["SECURE_STUB_SIEM_TRANSPORT_BREAK"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_automation_engine.py",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Test must fail when SIEM transport is broken
        if result.returncode == 0:
            assert False, \
                f"GATE_AUTOMATION_ENGINE_SIEM: test should fail when SIEM transport is broken, but passed:\n{result.stdout}"

        # Failure must be on SIEM transport issue, not unrelated
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_AUTOMATION_ENGINE_SIEM" in l for l in fail_lines), \
            f"GATE_AUTOMATION_ENGINE_SIEM: Expected specific failure sentinel, got:\n{result.stdout}"
