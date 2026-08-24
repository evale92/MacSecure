"""secure/explain/ — Explainable Security UX (Product Phase 13).

A frontend-independent explanation layer sitting on top of the
existing detection/correlation modules. Nothing in this package
detects anything, scores anything, or writes to the database — it
only reads already-computed alert/correlation records and derives a
structured, presentation-ready `Explanation` (see explanation.py) from
fields already stored on them.

Hard rules that keep this from becoming a second detection engine:

    1. Severity is always a passthrough from the existing record.
       Nothing here ever computes or overrides severity — that stays
       authoritative in secure/arpwatch, secure/wifi,
       secure/bluetooth, secure/persistence, secure/fileintegrity,
       secure/correlate.
    2. Confidence is a SEPARATE axis: how strongly the evidence
       already stored in the finding supports Secure's interpretation
       of it. See vocab.py's CONFIDENCE_LEVELS — CONFIRMED never means
       "confirmed malicious," only that the observed fact itself
       isn't in doubt.
    3. Every confidence/action/uncertainty rule in this package is
       deterministic and documented, and traceable to fields already
       present on the stored record — no learned/opaque logic, no new
       detection.
    4. This package does no I/O. It takes a record in and returns an
       Explanation out. That's what makes it consumable by anything —
       the GUI today, and later the CLI, forensics exports, an API, or
       a local AI analyst — without re-deriving anything or opening a
       second path to the database.
    5. Explanation generation must never hide the original finding.
       See explanation.py's `generic_explanation()` and dispatch.py's
       failure handling — any explainer that can't produce a specific
       explanation (an unrecognized kind, a future module, malformed
       input) still returns the record's real severity and message,
       with confidence explicitly INSUFFICIENT_EVIDENCE, never a blank
       or broken result.

See docs/EXPLAINABILITY.md for the full model and docs/DESIGN_SYSTEM.md
for how the GUI presents it.
"""

from __future__ import annotations
