"""
secure/validate/scenarios/ — one module per category from the
governing instruction's own "representative behaviors" list: native
sensors (persistence, fileintegrity, connections, listening),
detection rules (Sigma/YARA-X/Suricata, wrapping Phase 25's own
fixtures), and cross-sensor concerns (correlation, deduplication,
sensor failure).

Every scenario function has the same shape: `run(sandbox) ->
ScenarioResult`. `sandbox` is a secure.validate.sandbox.Sandbox — a
real, throwaway AppConfig + Database connection, never the operator's
own. Each function is responsible for injecting its own synthetic
fixture data at the real scanner's own shell/filesystem/DB boundary
(via unittest.mock.patch, the exact same boundary
tests/test_*.py already patches with pytest's `monkeypatch` fixture),
then calling the REAL scan/correlate/explain function and inspecting
what it actually did.

`REGISTRY` (built up by runner.py from each category module's own
`SCENARIOS` list) is the full catalog `secure validate run` executes.
"""

from __future__ import annotations
