"""Pure vocabulary for secure/explain/ — no I/O, no detection logic.

Every dict here follows the same discipline established in Phase 12's
secure_gui/tokens.py: a fixed, documented set of values, never
extended dynamically, always with clear meaning attached to each
entry. Unlike tokens.py (presentation — glyphs/colors), everything in
this module is MEANING, owned by the backend. secure_gui/tokens.py
adds a small presentation-only mapping on top of the CONFIDENCE keys
defined here; it never redefines what they mean.
"""

from __future__ import annotations

# ---------- confidence ----------
# How strongly the evidence ALREADY STORED on a finding supports
# Secure's interpretation of it. This is a SEPARATE axis from
# severity — severity says how bad it would be if the concerning
# interpretation is correct; confidence says how sure Secure is about
# the interpretation itself. A high-severity finding can have low
# confidence (e.g. a correlation cluster that coincides with a known
# update window); a low-severity finding can have high confidence
# (e.g. "this file's hash changed" is not in doubt, it's just not very
# severe).
#
# CONFIRMED never means "confirmed malicious" — only that the observed
# fact is directly established, not that Secure has determined intent
# or cause. "File hash changed" can be CONFIRMED while the reason for
# the change remains completely unknown.

CONFIRMED = "confirmed"
LIKELY = "likely"
UNCERTAIN = "uncertain"
INSUFFICIENT_EVIDENCE = "insufficient_evidence"

CONFIDENCE_LEVELS = {
    CONFIRMED: (
        "The observation itself is directly established by the sensor. "
        "This does not mean the underlying cause is malicious — only "
        "that the fact reported (e.g. 'this file's hash changed') is "
        "not in doubt."
    ),
    LIKELY: (
        "Multiple, or a particularly strong, stored observation(s) "
        "support Secure's interpretation of what this finding means."
    ),
    UNCERTAIN: (
        "The observation is real, but both benign and concerning "
        "interpretations remain plausible given what's stored."
    ),
    INSUFFICIENT_EVIDENCE: (
        "The stored record does not contain enough evidence for Secure "
        "to assess confidence either way."
    ),
}

# Weakest -> strongest. For tests/sorting/display only — never used to
# derive severity, and never averaged/combined into a number.
CONFIDENCE_ORDER = [INSUFFICIENT_EVIDENCE, UNCERTAIN, LIKELY, CONFIRMED]


# ---------- evidence provenance ----------
# Keeps "what a sensor directly reported" separate from "what Secure
# computed from that" separate from "what Secure thinks it might
# mean" — three different kinds of claim, so a reader can tell which
# is which at a glance rather than have to infer it from wording.

DIRECT_OBSERVATION = "direct_observation"
DERIVED_FACT = "derived_fact"
SECURE_INTERPRETATION = "secure_interpretation"

EVIDENCE_PROVENANCE = {
    DIRECT_OBSERVATION: "A fact reported directly by a sensor/scanner.",
    DERIVED_FACT: (
        "A deterministic computation over stored/direct facts (e.g. a "
        "count, a comparison) — not a subjective judgment."
    ),
    SECURE_INTERPRETATION: (
        "Secure's own interpretation or hypothesis about what the "
        "observed facts might mean."
    ),
}


# ---------- uncertainty status ----------
# Whether a finding's uncertainty list is populated, and why. Prevents
# generic filler text from being forced onto every finding just to
# make a list non-empty — see explanation.py's Explanation docstring.

UNCERTAINTY_KNOWN = "known"  # meaningful benign/alternative explanations exist and are listed
UNCERTAINTY_NONE_MATERIAL = "none_material"  # genuinely no material uncertainty for this observation
UNCERTAINTY_INSUFFICIENT_INFORMATION = "insufficient_information"  # not enough to assess either way

UNCERTAINTY_STATUSES = {
    UNCERTAINTY_KNOWN: "Meaningful benign or alternative explanations exist and are listed below.",
    UNCERTAINTY_NONE_MATERIAL: "No material uncertainty is known for this specific observation.",
    UNCERTAINTY_INSUFFICIENT_INFORMATION: "Secure does not have enough information to identify likely alternative explanations.",
}


# ---------- recommended action ----------
# A constrained vocabulary, not free text — kept small deliberately so
# every explainer picks from the same small set instead of authoring
# ad hoc instructions. Finding KIND drives which of these is chosen,
# not severity/confidence alone (severity/confidence inform urgency
# within that choice — see docs/EXPLAINABILITY.md). This layer only
# ever RECOMMENDS; nothing in secure/explain/ executes an action.

NO_ACTION = "NO_ACTION"
MONITOR = "MONITOR"
CLASSIFY = "CLASSIFY"
RESCAN = "RESCAN"
VERIFY_APPLICATION = "VERIFY_APPLICATION"
VERIFY_DEVICE = "VERIFY_DEVICE"
INSPECT_PROCESS = "INSPECT_PROCESS"
INSPECT_FILE = "INSPECT_FILE"
REVIEW_PERSISTENCE = "REVIEW_PERSISTENCE"
REVIEW_NETWORK_DESTINATION = "REVIEW_NETWORK_DESTINATION"
CHECK_MACOS_SETTING = "CHECK_MACOS_SETTING"
INVESTIGATE_NOW = "INVESTIGATE_NOW"

RECOMMENDED_ACTIONS = {
    NO_ACTION: "No action needed.",
    MONITOR: "No action needed now; keep an eye on this if the pattern recurs.",
    CLASSIFY: "Review it, then mark it known or unknown once you recognize (or don't) what this is.",
    RESCAN: "Re-run a scan to confirm this is still current before acting on it.",
    VERIFY_APPLICATION: "Verify this application or process is one you installed and trust.",
    VERIFY_DEVICE: "Verify this device is one you recognize on your network.",
    INSPECT_PROCESS: "Inspect the running process directly (Activity Monitor or equivalent) before deciding.",
    INSPECT_FILE: "Inspect the file directly — what changed, and why — before deciding.",
    REVIEW_PERSISTENCE: "Review this startup item (LaunchAgent/LaunchDaemon/login item) directly.",
    REVIEW_NETWORK_DESTINATION: "Review this network destination or connection directly.",
    CHECK_MACOS_SETTING: "Check the relevant macOS setting directly.",
    INVESTIGATE_NOW: "Investigate promptly — this severity/evidence combination warrants prompt review.",
}
