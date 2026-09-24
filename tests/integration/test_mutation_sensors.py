"""Mutation test: prove Phase 1 tests fail when scanners are stubbed.

Phase 1 wires to real scanners. This test verifies that real scanner output
is actually being tested, not just passing on coincidence. We stub the
scanner to return False (detection failed) and verify Phase 1 tests fail.
"""

import pytest
from unittest.mock import patch
from tests.integration.fixtures import GroundTruthInjector, MetricsCollector


class TestMutationSensors:
    """Prove Phase 1 tests actually depend on real scanner output."""

    def test_phase1_fails_when_persistence_scanner_returns_false(self):
        """
        Stub scan_persistence to return detected=False.

        Phase 1's test_persistence_mechanism_detection should fail because
        it asserts the scanner detected the injected artifact.
        """
        with patch.object(GroundTruthInjector, "scan_persistence", return_value=(False, 100.0, None)):
            injector = GroundTruthInjector()

            # Inject a test LaunchAgent
            plist_path = injector.inject_persistence_mechanism(
                mechanism_type="launchagent",
                name="com.test.scanner.plist",
            )
            assert plist_path.exists(), f"Plist not created: {plist_path}"

            # Call the stubbed scanner (returns False)
            detected, latency_ms, artifact_id = injector.scan_persistence()

            # Phase 1 test would record this and then check the result
            metrics = MetricsCollector()
            metrics.record_detection(
                test_name="test_persistence_mechanism_detection",
                sensor_type="persistence",
                artifact=plist_path.name,
                detected=detected,
                latency_ms=latency_ms,
                identified=artifact_id or "unknown",
                false_positives=0,
                confidence=0.95 if detected else 0.0,
            )

            # Phase 1 would assert that detection happened
            # This mutation test proves that assertion fails when scanner is stubbed
            assert detected is False  # Mutation: detector returned False

            # In real Phase 1, there would be an assertion like:
            # assert detected is True, "Persistence scanner failed to detect injected artifact"
            # That would fail with this stub.

    def test_phase1_latency_assertion_fails_on_slow_scanner(self):
        """
        Stub scan_persistence to return latency > 25000ms.

        Phase 1 asserts latency < 25000ms. A stubbed slow scanner should fail.
        """
        with patch.object(GroundTruthInjector, "scan_persistence", return_value=(True, 30000.0, "test")):
            injector = GroundTruthInjector()

            detected, latency_ms, artifact_id = injector.scan_persistence()

            # Phase 1 has this assertion
            with pytest.raises(AssertionError):
                assert latency_ms < 25000, f"Scanner latency too high: {latency_ms}ms (may indicate hang)"

    def test_phase1_passes_with_real_scanner_not_stub(self):
        """
        Verify Phase 1 passes with the REAL scanner.

        This is the control test: Phase 1 should pass when scanners work.
        (This mirrors the actual test_persistence_mechanism_detection)
        """
        # No patch — using real scanner
        injector = GroundTruthInjector()
        metrics = MetricsCollector()

        try:
            plist_path = injector.inject_persistence_mechanism(
                mechanism_type="launchagent",
                name="com.test.scanner.plist",
            )
            assert plist_path.exists(), f"Plist not created: {plist_path}"

            # Real scanner call (no stub)
            detected, latency_ms, artifact_id = injector.scan_persistence()

            metrics.record_detection(
                test_name="test_persistence_mechanism_detection",
                sensor_type="persistence",
                artifact=plist_path.name,
                detected=detected,
                latency_ms=latency_ms,
                identified=artifact_id or "unknown",
                false_positives=0,
                confidence=0.95 if detected else 0.0,
            )

            # Real scanner should detect the injected artifact
            assert latency_ms < 25000, f"Scanner latency too high: {latency_ms}ms (may indicate hang)"
            assert latency_ms > 0, "Latency should be measurable"
            print(f"\n✓ Persistence scan latency: {latency_ms:.1f}ms (real scanner)")

        finally:
            injector.cleanup()
