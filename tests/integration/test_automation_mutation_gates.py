"""Mutation gates: Phase 64 automation engine with feedback stub.

Real gate invokes test_automation_engine via subprocess, verifies it fails
when feedback store is stubbed empty. Pattern: a31c573 (subprocess, node id,
--tb=line, unique sentinel, no or fallback).
"""

import subprocess
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestAutomationMutationGates:
    """Mutation gates for Phase 64 automation engine."""

    def test_gate_automation_engine_feedback_store(self):
        """GATE: Verify automation engine requires real feedback stats.

        Real test must FAIL (exit code != 0) when feedback store returns empty.
        Engine should surface PENDING approval, not auto-approval, with no stats.
        """
        env = os.environ.copy()
        env["SECURE_STUB_FEEDBACK_STORE_EMPTY"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/test_automation_engine.py::test_confidence_high_severity_low_fp",
             "--tb=line", "-q", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )

        # Real test must FAIL under feedback stub
        assert result.returncode != 0, \
            f"GATE_AUTOMATION_ENGINE_FEEDBACK: test should fail with empty feedback store, but passed:\n{result.stdout}"

        # Check for the specific sentinel in failure lines
        fail_lines = [l for l in result.stdout.splitlines() if "AssertionError" in l]
        assert any("GATE_AUTOMATION_ENGINE_FEEDBACK" in l for l in fail_lines), \
            f"GATE_AUTOMATION_ENGINE_FEEDBACK: Expected specific failure sentinel, got:\n{result.stdout}"
