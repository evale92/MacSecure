"""
Tests for secure/validate/rubric.py — the explanation-quality checklist.

The scenario tests only assert that a checklist is a non-empty dict of
bools, so every check hard-wired to False survived all of them (J-0564).
Each check here is flipped by exactly one input, next to a clean
explanation that passes all five, so a check that stops reading its
input fails one of these tests whichever way it breaks.

Run with:  pytest
"""

from __future__ import annotations

import dataclasses

from secure.explain import vocab
from secure.explain.explanation import EvidenceItem, generic_explanation, generic_summary, is_generic_summary
from secure.validate.rubric import (
    ALL_CHECKS,
    CHECK_EVIDENCE_PROVENANCE_VALID,
    CHECK_HAS_EVIDENCE,
    CHECK_HAS_SEVERITY,
    CHECK_NOT_DEGRADED,
    CHECK_SUMMARY_NON_GENERIC,
    score_explanation,
)


def _clean():
    return generic_explanation(source_table="t", severity="high", message="A new LaunchDaemon appeared.")


def _failing(explanation) -> "set[str]":
    return {check for check, ok in score_explanation(explanation).items() if not ok}


def test_clean_explanation_passes_every_check():
    # Positive control: without it, each single-failure test below would
    # also pass against a rubric that fails everything.
    assert score_explanation(_clean()) == {check: True for check in ALL_CHECKS}


def test_none_fails_every_check():
    assert score_explanation(None) == {check: False for check in ALL_CHECKS}


def test_missing_or_unknown_severity_fails_only_has_severity():
    for severity in ("", "unknown"):
        assert _failing(dataclasses.replace(_clean(), severity=severity)) == {CHECK_HAS_SEVERITY}


def test_no_evidence_fails_evidence_and_provenance():
    assert _failing(dataclasses.replace(_clean(), evidence=())) == {
        CHECK_HAS_EVIDENCE,
        CHECK_EVIDENCE_PROVENANCE_VALID,
    }


def test_one_invalid_provenance_fails_only_provenance():
    evidence = (EvidenceItem("seen", vocab.DIRECT_OBSERVATION), EvidenceItem("guess", "made_up"))
    assert _failing(dataclasses.replace(_clean(), evidence=evidence)) == {CHECK_EVIDENCE_PROVENANCE_VALID}


def test_degraded_fails_only_not_degraded():
    assert _failing(dataclasses.replace(_clean(), degraded=True)) == {CHECK_NOT_DEGRADED}


def test_short_summary_fails_only_summary_check():
    assert _failing(dataclasses.replace(_clean(), summary="  alert   ")) == {CHECK_SUMMARY_NON_GENERIC}


def test_generic_placeholder_summary_fails_summary_check():
    # The docstring's promise that was not kept before J-0564: the
    # placeholder is 28 characters, so the length test alone passed it.
    for subject in (None, "com.example.agent"):
        placeholder = generic_summary("high", subject)
        assert len(placeholder.strip()) > 10
        assert _failing(dataclasses.replace(_clean(), summary=placeholder)) == {CHECK_SUMMARY_NON_GENERIC}


def test_generic_explanation_without_message_is_scored_generic():
    explanation = generic_explanation(source_table="t", severity="high", message="", subject="x")
    assert score_explanation(explanation)[CHECK_SUMMARY_NON_GENERIC] is False


def test_is_generic_summary_matches_only_its_own_severity_and_shape():
    assert is_generic_summary(generic_summary("low"), "low")
    assert is_generic_summary(generic_summary("low", "subj"), "low")
    assert not is_generic_summary(generic_summary("low"), "high")
    assert not is_generic_summary("A high finding was recorded on the boot volume.", "high")
