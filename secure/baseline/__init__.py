"""
secure/baseline/ — Product Phase 14: Behavioral Baselining and Anomaly
Detection.

Learns what's "normal" for THIS Mac (network/LAN presence, processes,
remote destinations, listening services, Wi-Fi, Bluetooth/BLE,
file/persistence activity, and coarse time-of-day patterns) from
history already sitting in this database, and flags meaningful
deviations — never every uncommon event. Deliberately built from
simple, inspectable statistics (counts, frequencies, distinct-day
counts, rolling windows) rather than opaque machine learning; every
anomaly score must be explainable component-by-component, and no
component may rely on subjective prose.

Hard rules, carried through every module in this package (see
PROJECT_NOTES.md's Phase 14 entry and docs/BASELINING.md for the full
design discussion and the approval this package was built against):

    1. Anomaly/deviation is a SEPARATE axis from security severity,
       Phase 13 confidence, and trust/review state. A baseline finding
       never overrides or replaces the severity of an existing alert —
       see secure/explain/baseline_explainer.py.
    2. Frequency alone never makes something "trusted" or "known".
       Common, trusted, known, normal, and safe are not synonyms — see
       eligibility.py and maturity.py.
    3. No strong anomaly claim (HIGH/CRITICAL tier) is made while an
       entity's baseline is still LEARNING, or is STALE and hasn't
       been refreshed.
    4. Unresolved HIGH/CRITICAL findings must never silently train the
       baseline into treating themselves as normal — see
       eligibility.py's poisoning-protection rules, which are
       forward-only (a later review only affects future observations).
    5. This package never becomes a second detection engine and never
       duplicates secure/correlate's clustering/scoring logic or
       secure/explain's explanation model — it extends them.
    6. Every module here is pure logic with no I/O except
       secure/baseline/_shell.py, which is the one place allowed to
       call into secure.storage.models (matching the shell/pure-logic
       split used by every other monitoring package in this project).
"""
