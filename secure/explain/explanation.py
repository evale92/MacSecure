"""The Explanation model — a structured, frontend-independent
description of one finding, produced once and meant to be consumed by
any surface (GUI today; later the CLI, historical forensics, exports,
an API, or a local AI analyst) without re-deriving anything.

Discipline (see secure/explain/__init__.py for the full rule set):
  - `severity` on an Explanation is always copied verbatim from the
    source record. Nothing in this module computes it.
  - `confidence` is a separate axis — see vocab.py.
  - Nothing here does I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from secure.explain import vocab


@dataclass(frozen=True)
class EvidenceItem:
    text: str
    provenance: str  # one of vocab.DIRECT_OBSERVATION / DERIVED_FACT / SECURE_INTERPRETATION


@dataclass(frozen=True)
class Explanation:
    """Progressive-disclosure-ready explanation of one finding.

    Field groups map directly onto the three disclosure levels used
    by secure_gui/alerts_view.py (see docs/DESIGN_SYSTEM.md):

        Summary:   summary, severity, confidence, significance,
                   recommended_action(_text)
        Evidence:  evidence, correlated_events, uncertainty_status,
                   uncertainty
        Technical: (not duplicated here — Level 3 in the GUI shows the
                   original record's own raw fields; this object is
                   the derived Summary/Evidence layer, not a second
                   copy of the raw data)
    """

    summary: str
    severity: str  # passthrough from the source record, never recomputed here
    confidence: str  # vocab.py CONFIDENCE_* constant
    confidence_reason: str
    significance: str
    recommended_action: str  # vocab.py action constant
    recommended_action_text: str  # resolved human-readable text

    evidence: Tuple[EvidenceItem, ...]
    correlated_events: Tuple[str, ...]

    uncertainty_status: str  # vocab.py UNCERTAINTY_* constant
    uncertainty: Tuple[str, ...]

    # Set only when this Explanation is a fallback produced because a
    # specific explainer couldn't run (see dispatch.py) — never set
    # merely because a finding's `kind` isn't individually documented
    # yet (see generic_explanation()'s `degraded` parameter).
    degraded: bool = False
    degraded_reason: Optional[str] = None


def resolve_action(key: str) -> Tuple[str, str]:
    """Look up a vocab.py action constant's human-readable text
    alongside itself, so callers get both in one call:
    `action, action_text = resolve_action(vocab.INSPECT_FILE)`.
    """
    return key, vocab.RECOMMENDED_ACTIONS[key]


def generic_summary(severity: str, subject: Optional[str] = None) -> str:
    """The placeholder summary generic_explanation() uses when a record
    has no message — kept beside is_generic_summary() so the two can't
    drift apart."""
    subject_text = f" ({subject})" if subject else ""
    return f"A {severity} finding was recorded{subject_text}."


def is_generic_summary(summary: str, severity: str) -> bool:
    """True when `summary` is generic_summary()'s placeholder for this
    severity, with or without a subject."""
    text = summary.strip()
    base = f"A {severity} finding was recorded"
    return text == base + "." or (text.startswith(base + " (") and text.endswith(")."))


def generic_explanation(
    *,
    source_table: str,
    severity: str,
    message: str,
    subject: Optional[str] = None,
    degraded: bool = False,
    degraded_reason: Optional[str] = None,
) -> Explanation:
    """A safe, honest Explanation built only from a record's original
    severity/message.

    Used in two situations:
      1. A specific per-kind rule doesn't exist yet for this finding
         (an alert_explainers.py function fell through to its default
         branch) — `degraded=False`. This is an expected, documented
         gap, not a failure.
      2. Explanation generation itself failed (dispatch.py caught an
         exception, or the source table isn't recognized at all) —
         `degraded=True`, with `degraded_reason` explaining why.

    Either way, this NEVER hides the original finding: severity and
    message are always exactly what the detection module stored, and
    confidence is honestly INSUFFICIENT_EVIDENCE rather than guessed.
    """
    summary = message or generic_summary(severity, subject)
    evidence = (EvidenceItem(message, vocab.DIRECT_OBSERVATION),) if message else ()

    if degraded:
        significance = (
            "This finding could not be explained in more detail than what was "
            "originally recorded. It is shown exactly as the detection module "
            "reported it."
        )
        reason = degraded_reason or "A detailed explanation was unavailable."
    else:
        significance = (
            "Secure does not yet have specific explanatory guidance for this "
            "kind of finding. It is shown exactly as the detection module "
            "reported it."
        )
        reason = "No documented confidence rule exists yet for this specific finding kind."

    action, action_text = resolve_action(vocab.CLASSIFY)
    return Explanation(
        summary=summary,
        severity=severity,
        confidence=vocab.INSUFFICIENT_EVIDENCE,
        confidence_reason=reason,
        significance=significance,
        recommended_action=action,
        recommended_action_text=action_text,
        evidence=evidence,
        correlated_events=(),
        uncertainty_status=vocab.UNCERTAINTY_INSUFFICIENT_INFORMATION,
        uncertainty=(
            "Secure does not have enough documented interpretation for this "
            "specific finding kind to identify likely benign explanations.",
        ),
        degraded=degraded,
        degraded_reason=(degraded_reason if degraded else None),
    )
