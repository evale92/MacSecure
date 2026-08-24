"""
secure/validate/rubric.py — a deterministic, checklist-based measure of
"explanation quality" (one of the instruction's own named metrics).
Never a fuzzy 1-10 score: every item is a plain boolean, computed the
same way from the same Explanation every time a scenario re-runs, same
"deterministic" discipline as everything else in this app.

Deliberately small and honest about what it can check. It cannot judge
whether an explanation's PROSE is well-written or its recommended
action is the objectively right one — only whether the Explanation
object secure/explain/dispatch.explain() produced meets the structural
bar that module's own docstring already commits to: real severity, at
least one piece of evidence, valid provenance tags on that evidence,
and a summary that isn't empty or a generic degraded-fallback message.
"""

from __future__ import annotations

from secure.explain import vocab
from secure.explain.explanation import Explanation

CHECK_HAS_SEVERITY = "has_severity"
CHECK_HAS_EVIDENCE = "has_evidence"
CHECK_EVIDENCE_PROVENANCE_VALID = "evidence_provenance_valid"
CHECK_SUMMARY_NON_GENERIC = "summary_non_generic"
CHECK_NOT_DEGRADED = "not_degraded"

ALL_CHECKS = (
    CHECK_HAS_SEVERITY,
    CHECK_HAS_EVIDENCE,
    CHECK_EVIDENCE_PROVENANCE_VALID,
    CHECK_SUMMARY_NON_GENERIC,
    CHECK_NOT_DEGRADED,
)


def score_explanation(explanation: "Explanation | None") -> "dict[str, bool]":
    """Returns one bool per ALL_CHECKS item. `explanation=None` (no
    finding to explain at all — e.g. a MISS scenario where nothing
    fired) fails every check, honestly, rather than being skipped.
    """
    if explanation is None:
        return {check: False for check in ALL_CHECKS}

    has_severity = bool(explanation.severity) and explanation.severity != "unknown"
    has_evidence = len(explanation.evidence) >= 1
    evidence_provenance_valid = has_evidence and all(
        item.provenance in vocab.EVIDENCE_PROVENANCE for item in explanation.evidence
    )
    summary_non_generic = bool(explanation.summary) and len(explanation.summary.strip()) > 10
    not_degraded = not explanation.degraded

    return {
        CHECK_HAS_SEVERITY: has_severity,
        CHECK_HAS_EVIDENCE: has_evidence,
        CHECK_EVIDENCE_PROVENANCE_VALID: evidence_provenance_valid,
        CHECK_SUMMARY_NON_GENERIC: summary_non_generic,
        CHECK_NOT_DEGRADED: not_degraded,
    }
