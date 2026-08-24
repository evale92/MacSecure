"""
Tests for Phase 28 Stage 4: secure/ai/vocab.py, secure/ai/response.py
(parse_answer / validate_citations), and secure/ai/prompt.py's prompt
builders. Pure logic, no I/O.

Run with:  pytest
"""

from __future__ import annotations

import json

from secure.ai import prompt as prompt_module
from secure.ai import vocab
from secure.ai.context import AnalystContext, MODE_FREEFORM
from secure.ai.response import Claim, StructuredAnswer, parse_answer, validate_citations


# ---------- parse_answer() ----------


def test_parse_answer_empty_text_is_unparsed():
    answer = parse_answer("")
    assert answer.parse_ok is False
    assert answer.parse_error == "empty response"
    assert answer.claims == []


def test_parse_answer_none_is_unparsed():
    answer = parse_answer(None)
    assert answer.parse_ok is False


def test_parse_answer_garbage_text_is_unparsed_and_raw_text_preserved():
    answer = parse_answer("I refuse to answer in JSON today, sorry!")
    assert answer.parse_ok is False
    assert answer.raw_text == "I refuse to answer in JSON today, sorry!"


def test_parse_answer_plain_json():
    raw = json.dumps({
        "summary": "s", "claims": [{"kind": "ai_assessment", "text": "t", "citation": None}],
        "suggested_next_steps": ["step 1"],
    })
    answer = parse_answer(raw)
    assert answer.parse_ok is True
    assert answer.summary == "s"
    assert len(answer.claims) == 1
    assert answer.claims[0].kind == vocab.AI_ASSESSMENT
    assert answer.suggested_next_steps == ["step 1"]


def test_parse_answer_extracts_json_from_markdown_fence():
    payload = {"summary": "fenced", "claims": [], "suggested_next_steps": []}
    raw = f"Sure, here you go:\n```json\n{json.dumps(payload)}\n```\nHope that helps!"
    answer = parse_answer(raw)
    assert answer.parse_ok is True
    assert answer.summary == "fenced"


def test_parse_answer_extracts_first_brace_span_as_last_resort():
    payload = {"summary": "brace-span", "claims": [], "suggested_next_steps": []}
    raw = f"prose before {json.dumps(payload)} prose after"
    answer = parse_answer(raw)
    assert answer.parse_ok is True
    assert answer.summary == "brace-span"


def test_parse_answer_unrecognized_claim_kind_downgrades_to_unverified_hypothesis():
    raw = json.dumps({
        "summary": "s", "claims": [{"kind": "totally_made_up_kind", "text": "t", "citation": None}],
        "suggested_next_steps": [],
    })
    answer = parse_answer(raw)
    assert answer.claims[0].kind == vocab.UNVERIFIED_HYPOTHESIS


def test_parse_answer_claim_without_text_is_dropped():
    raw = json.dumps({
        "summary": "s", "claims": [{"kind": "ai_assessment", "citation": None}, {"kind": "ai_assessment", "text": "", "citation": None}],
        "suggested_next_steps": [],
    })
    answer = parse_answer(raw)
    assert answer.claims == []


def test_parse_answer_verifier_fields_parsed_when_requested():
    raw = json.dumps({
        "summary": "s", "claims": [], "suggested_next_steps": [],
        "agreement": "disagrees", "contradictions_found": ["x contradicts y"],
        "unsupported_assumptions": ["assumed z"], "citation_check_notes": ["note"],
    })
    answer = parse_answer(raw, verifier_fields=True)
    assert answer.agreement == vocab.AGREEMENT_DISAGREES
    assert answer.contradictions_found == ["x contradicts y"]
    assert answer.unsupported_assumptions == ["assumed z"]


def test_parse_answer_invalid_agreement_value_becomes_unknown():
    raw = json.dumps({"summary": "s", "claims": [], "suggested_next_steps": [], "agreement": "sort of maybe"})
    answer = parse_answer(raw, verifier_fields=True)
    assert answer.agreement == vocab.AGREEMENT_UNKNOWN


def test_parse_answer_non_verifier_call_never_sets_verifier_fields():
    raw = json.dumps({"summary": "s", "claims": [], "suggested_next_steps": [], "agreement": "agrees"})
    answer = parse_answer(raw, verifier_fields=False)
    assert answer.agreement is None


# ---------- validate_citations() ----------


def _manifest():
    return [{"source_table": "persistence_alerts", "source_id": 42}, {"source_table": "process_events", "source_id": 7}]


def test_validate_citations_valid_stored_fact():
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[Claim(kind=vocab.STORED_FACT, text="t", citation="persistence_alerts#42")],
    )
    validate_citations(answer, _manifest())
    assert answer.claims[0].citation_valid is True


def test_validate_citations_invalid_stored_fact_stays_in_the_answer_flagged():
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[Claim(kind=vocab.STORED_FACT, text="t", citation="persistence_alerts#999")],
    )
    validate_citations(answer, _manifest())
    assert answer.claims[0].citation_valid is False
    assert answer.claims[0] in answer.claims  # never removed


def test_validate_citations_missing_citation_on_required_kind_is_invalid():
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[Claim(kind=vocab.SECURE_INTERPRETATION, text="t", citation=None)],
    )
    validate_citations(answer, _manifest())
    assert answer.claims[0].citation_valid is False


def test_validate_citations_malformed_citation_string_is_invalid():
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[Claim(kind=vocab.STORED_FACT, text="t", citation="not-a-valid-citation-format")],
    )
    validate_citations(answer, _manifest())
    assert answer.claims[0].citation_valid is False


def test_validate_citations_ai_assessment_is_not_applicable_not_invalid():
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[Claim(kind=vocab.AI_ASSESSMENT, text="t", citation=None)],
    )
    validate_citations(answer, _manifest())
    assert answer.claims[0].citation_valid is None


def test_validate_citations_unverified_hypothesis_with_a_fabricated_citation_is_not_checked():
    # A hypothesis is citation-exempt by definition — even if the model
    # invented a citation string on one, it's not checked (and doesn't
    # need to be — a hypothesis was never claiming to be a stored fact).
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[Claim(kind=vocab.UNVERIFIED_HYPOTHESIS, text="t", citation="made_up_table#1")],
    )
    validate_citations(answer, _manifest())
    assert answer.claims[0].citation_valid is None


def test_citation_counts_only_counts_applicable_kinds():
    answer = StructuredAnswer(
        raw_text="", parse_ok=True, parse_error=None,
        claims=[
            Claim(kind=vocab.STORED_FACT, text="t1", citation="persistence_alerts#42"),
            Claim(kind=vocab.STORED_FACT, text="t2", citation="persistence_alerts#999"),
            Claim(kind=vocab.AI_ASSESSMENT, text="t3", citation=None),
        ],
    )
    validate_citations(answer, _manifest())
    valid, invalid = answer.citation_counts()
    assert valid == 1
    assert invalid == 1


# ---------- prompt.py ----------


def _empty_freeform_context() -> AnalystContext:
    return AnalystContext(
        generated_at="t", mode=MODE_FREEFORM, entity=None, exists=True, summary={},
        findings=[], timeline=[], related_evidence=[], pivots=[], threat_intel=[], tool_health=[],
        truncated=False, notes=[],
    )


def test_analyst_prompt_embeds_hard_rules_and_forbids_autonomous_action():
    system, user = prompt_module.build_analyst_prompt(_empty_freeform_context(), "why?")
    assert "NOT a detection authority" in system
    assert "never recommend or imply" in system.lower() or "NEVER recommend" in system
    assert "why?" in user


def test_analyst_prompt_embeds_all_four_claim_kinds():
    system, _ = prompt_module.build_analyst_prompt(_empty_freeform_context(), "q")
    for kind in vocab.VALID_CLAIM_KINDS:
        assert kind in system


def test_verifier_independent_prompt_does_not_mention_model_a_answer():
    system, user = prompt_module.build_verifier_independent_prompt(_empty_freeform_context(), "q")
    assert "MODEL A" not in user
    assert "INDEPENDENT" in system


def test_verifier_review_prompt_shows_both_answers_and_asks_for_contradictions():
    context = _empty_freeform_context()
    independent = parse_answer(json.dumps({"summary": "my own take", "claims": [], "suggested_next_steps": []}))
    analyst = parse_answer(json.dumps({"summary": "model a's take", "claims": [], "suggested_next_steps": []}))
    system, user = prompt_module.build_verifier_review_prompt(context, "q", analyst, independent)
    assert "CONTRADICTS" in system
    assert "my own take" in user
    assert "model a's take" in user


def test_context_block_embeds_the_context_as_json():
    context = _empty_freeform_context()
    system, user = prompt_module.build_analyst_prompt(context, "q")
    assert '"mode"' in user
    assert MODE_FREEFORM in user
