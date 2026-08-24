"""
secure/ai/vocab.py — the four-way claim vocabulary every AI answer in
this package is required to sort its own statements into. Governing
instruction, verbatim:

    "Require AI responses to distinguish: stored facts, deterministic
    Secure interpretations, AI assessments, unverified hypotheses."

Two of these four are NOT new — they're Phase 23's own
`secure.explain.vocab.DIRECT_OBSERVATION`/`DERIVED_FACT` (collapsed
here into one "stored fact" bucket: both are things Secure itself
already recorded, as opposed to something the AI is newly asserting)
and the deterministic severity/confidence/significance a
secure/explain/ Explanation already computed ("Secure interpretation").
The other two are new to this phase, because they describe the MODEL's
own new reasoning, which nothing in this codebase has ever needed a
vocabulary for before:

    AI_ASSESSMENT         — the model's own reasoning, grounded in the
        facts it was given, presented with some confidence.
    UNVERIFIED_HYPOTHESIS — a plausible but unconfirmed theory the
        model is proposing, explicitly flagged as weaker than an
        assessment — a guess offered for the operator to investigate,
        not a conclusion.

Only STORED_FACT and SECURE_INTERPRETATION claims require (and are
checked for) a cited Secure evidence id — an AI_ASSESSMENT or
UNVERIFIED_HYPOTHESIS is, by definition, not something already sitting
in Secure's database to cite.
"""

from __future__ import annotations

STORED_FACT = "stored_fact"
SECURE_INTERPRETATION = "secure_interpretation"
AI_ASSESSMENT = "ai_assessment"
UNVERIFIED_HYPOTHESIS = "unverified_hypothesis"

VALID_CLAIM_KINDS = (STORED_FACT, SECURE_INTERPRETATION, AI_ASSESSMENT, UNVERIFIED_HYPOTHESIS)

# Only these two kinds are checked for a citation at all — see this
# module's own docstring for why the other two are citation-exempt by
# definition, not by oversight.
CITATION_REQUIRED_KINDS = (STORED_FACT, SECURE_INTERPRETATION)

AGREEMENT_AGREES = "agrees"
AGREEMENT_DISAGREES = "disagrees"
AGREEMENT_PARTIAL = "partially_agrees"
AGREEMENT_UNKNOWN = "unknown"  # the model's own review pass didn't yield a clear verdict — never guessed

VALID_AGREEMENT_VALUES = (AGREEMENT_AGREES, AGREEMENT_DISAGREES, AGREEMENT_PARTIAL, AGREEMENT_UNKNOWN)
