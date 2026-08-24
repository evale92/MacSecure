"""
secure/validate/ — Phase 27 Security Validation: a controlled,
repeatable framework that measures whether Secure's own detection,
correlation, and explanation layers actually work, without ever
touching the operator's real Mac or real ~/.secure database.

Governing instruction's own words, and the two hard rules they imply:

    "Use safe, established defensive testing resources such as
    applicable Atomic Red Team techniques and purpose-built local
    fixtures... Do not optimize tests to make Secure look good. Record
    missed detections and limitations."

1. **Sandbox-only, always.** Every scenario runs against a throwaway,
   temp-file SQLite database and an isolated AppConfig
   (secure/validate/sandbox.py) — never the operator's real database,
   never real system locations like ~/Library/LaunchAgents. Atomic
   Red Team / MITRE ATT&CK supply CONTENT here (real technique IDs,
   realistic artifact shapes — secure/validate/attck.py) not an
   EXECUTION MECHANISM — this framework never creates a real
   LaunchAgent, opens a real listening socket, or touches a real file
   outside its own sandbox. Explicitly and deliberately narrower than
   literal Atomic Red Team usage (which normally does act on the real
   host) — approved this way by the user specifically because Phase 26
   (real, confirmed actions on the live Mac) is still deferred.
2. **Never filter a failure out of the report.** A scenario's outcome
   is always exactly one of the five OUTCOME_* constants below, decided
   by comparing what actually happened to `expected_result` — nothing
   in this package or in secure/validate/report.py is able to omit a
   MISS/NOT_EVALUABLE/SENSOR_UNAVAILABLE row. The scenario catalog
   deliberately includes cases Secure is known, going in, to only
   partially handle (see secure/validate/scenarios/ for exactly which).

Every scenario function reuses Secure's own real scanner/correlate/
explain code paths unchanged — this package adds zero new detection
logic of its own, only synthetic input data and measurement.
"""

from __future__ import annotations

OUTCOME_PASS = "PASS"
OUTCOME_PARTIAL = "PARTIAL"
OUTCOME_MISS = "MISS"
OUTCOME_NOT_EVALUABLE = "NOT_EVALUABLE"
OUTCOME_SENSOR_UNAVAILABLE = "SENSOR_UNAVAILABLE"

VALID_OUTCOMES = (
    OUTCOME_PASS,
    OUTCOME_PARTIAL,
    OUTCOME_MISS,
    OUTCOME_NOT_EVALUABLE,
    OUTCOME_SENSOR_UNAVAILABLE,
)

CATEGORY_PERSISTENCE = "persistence_creation"
CATEGORY_FILE_CHANGE = "suspicious_file_change"
CATEGORY_PROCESS_EXECUTION = "unusual_process_execution"
CATEGORY_LISTENER = "new_listener"
CATEGORY_OUTBOUND_CONNECTION = "unusual_outbound_connection"
CATEGORY_DETECTION_RULE = "detection_rule"
CATEGORY_CORRELATION = "correlation"
CATEGORY_DEDUPLICATION = "deduplication"
CATEGORY_SENSOR_FAILURE = "sensor_failure"
