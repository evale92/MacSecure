"""Mutation gates: run ACTUAL tests via subprocess, verify they fail under stubs.

A real gate invokes the test by node ID and checks non-zero exit code.
"""

import subprocess
import sys
import os


class TestMutationGates:
    """Mutation gates: real tests fail under stubs."""

    def test_gate1_real_phase1_fails_when_persistence_latency_stubbed_high(self):
        """GATE 1: Run actual test_persistence_mechanism_detection with stubbed high latency.

        Real test must FAIL (exit code != 0) when persistence scanner returns 30000ms.
        Phase 1 asserts: latency_ms < 25000
        """
        env = os.environ.copy()
        env["SECURE_STUB_PERSISTENCE_LATENCY"] = "30000"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/integration/test_sensor_ground_truth.py::TestSensorAccuracy::test_persistence_mechanism_detection",
             "-v", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd="/Users/erickvale/Projects/secure-resource",
        )

        # Real test must FAIL under stub
        assert result.returncode != 0, \
            f"Phase 1 passed under latency stub (30000ms) — it does not test the scanner:\n{result.stdout}\n{result.stderr}"
        assert "Scanner latency too high" in result.stdout, \
            f"Expected 'Scanner latency too high' in output:\n{result.stdout}"

    def test_gate1_real_phase1_passes_with_real_scanner(self):
        """GATE 1 control: Actual test_persistence_mechanism_detection passes without stub."""
        env = os.environ.copy()
        # Ensure no stub
        env.pop("SECURE_STUB_PERSISTENCE_LATENCY", None)

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/integration/test_sensor_ground_truth.py::TestSensorAccuracy::test_persistence_mechanism_detection",
             "-v", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd="/Users/erickvale/Projects/secure-resource",
        )

        # Real test must PASS without stub
        assert result.returncode == 0, \
            f"Phase 1 failed with real scanner:\n{result.stdout}\n{result.stderr}"
        assert "PASSED" in result.stdout, \
            f"Expected PASSED in output:\n{result.stdout}"

    def test_gate2_real_phase2_approval_flow_enforced(self):
        """GATE 2: Run actual Phase 2 approval-flow test with approval stubbed (removed).

        Real test must FAIL (exit code != 0) when approval enforcement is bypassed.
        Phase 2 asserts: MEDIUM-risk stays PENDING without approval.
        """
        env = os.environ.copy()
        env["SECURE_STUB_APPROVAL_BYPASS"] = "true"

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/integration/test_phase2_approval.py::TestApprovalFlow::test_medium_risk_requires_approval",
             "-v", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd="/Users/erickvale/Projects/secure-resource",
        )

        # Real test must FAIL under approval stub
        assert result.returncode != 0, \
            f"Phase 2 passed without approval enforcement — it is not testing the flow:\n{result.stdout}\n{result.stderr}"
        assert "PENDING" in result.stdout or "AssertionError" in result.stdout, \
            f"Expected approval assertion in output:\n{result.stdout}"

    def test_gate2_real_phase2_approval_flow_passes_with_enforcement(self):
        """GATE 2 control: Actual Phase 2 approval test passes when enforcement works."""
        env = os.environ.copy()
        env.pop("SECURE_STUB_APPROVAL_BYPASS", None)

        result = subprocess.run(
            [sys.executable, "-m", "pytest",
             "tests/integration/test_phase2_approval.py::TestApprovalFlow::test_medium_risk_requires_approval",
             "-v", "-p", "no:cacheprovider"],
            env=env,
            capture_output=True,
            text=True,
            cwd="/Users/erickvale/Projects/secure-resource",
        )

        # Real test must PASS with enforcement
        assert result.returncode == 0, \
            f"Phase 2 failed with real enforcement:\n{result.stdout}\n{result.stderr}"
        assert "PASSED" in result.stdout, \
            f"Expected PASSED in output:\n{result.stdout}"
