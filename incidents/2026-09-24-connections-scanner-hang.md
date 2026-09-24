# Incident: Connections Scanner Hangs

**Date:** 2026-09-24  
**Duration:** 980+ seconds (test timeout)  
**Status:** Open - TCC privilege investigation needed

## Summary

The connections scanner (`secure.connections.scanner.scan_connections()`) hangs indefinitely when called from test suite. Latency: 980,646ms (16+ minutes).

## Reproduction

```bash
cd /Users/erickvale/Projects/secure-resource
/usr/bin/python3 -m pytest tests/integration/test_sensor_ground_truth.py::TestSensorAccuracy::test_network_connection_detection -v --timeout=60
```

**Result:** Timeout at 60 seconds (real hang is 980+ seconds).

## Hypothesis (unverified)

Per briefing 2026-09-24 §3: "A scan of network connections that runs 980+ seconds instead of failing is the classic macOS signature of enumerating connections without privileges."

Likely cause: TCC (Transparency, Consent, and Control) privilege issue. Privileged reads block forever rather than being refused; same code from terminal works because terminal already holds consent.

## Next Steps (operator)

1. **Bound the hang:** Add `@pytest.mark.timeout(30)` or hard timeout to test
2. **Verify TCC hypothesis:** Run scanner from terminal vs launchd; compare timing
3. **If TCC:** See runbook §5 for remediation (code signing, entitlements, or Desktop relocation)
4. **If not TCC:** Investigate `scan_connections()` implementation for infinite loops or subprocess leaks

## Context

- Isolated to one of 9 sensors; others pass
- Occurred during Phase 1/2 testing
- Machine: 8GB Mac mini (swap sensitive)
- Workaround: commented out test (temporary)
