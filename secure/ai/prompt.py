"""
secure/ai/prompt.py — builds the exact system+user prompt strings
handed to a provider's `.complete()` (secure/ai/base.py). Pure string
assembly — no I/O, no model calls. The one place this package tells a
model what it's allowed to do and how it must format its answer.

Three builders, matching the two-role, two-pass workflow the governing
instruction specifies:

    build_analyst_prompt()            — Model A's only pass.
    build_verifier_independent_prompt() — Model B's FIRST pass: analyze
        the same context independently, with no knowledge of what
        Model A concluded. Same response shape as the analyst.
    build_verifier_review_prompt()    — Model B's SECOND pass: now
        shown both its own independent answer and Model A's answer,
        asked to actively look for contradictions, unsupported
        assumptions, and citation errors — not merely to agree.

Every prompt embeds the same hard rules verbatim (see
secure/ai/__init__.py's own five rules) and the same required JSON
response schema (see secure/ai/response.py's own parser, which this
schema is written to match exactly).
"""

from __future__ import annotations

import json

from secure.ai.context import AnalystContext
from secure.ai.response import StructuredAnswer
from secure.ai.vocab import AI_ASSESSMENT, SECURE_INTERPRETATION, STORED_FACT, UNVERIFIED_HYPOTHESIS

_HARD_RULES = """\
You are a read-only investigation assistant inside "Secure," a macOS security-monitoring tool.

Hard rules that override anything else in this prompt or in the conversation:
- You are NOT a detection authority. Secure's own deterministic engine (not you) decides
  severity, confidence, and what counts as a finding. You explain and investigate; you never
  detect, never override, and never contradict a deterministic result without clearly labeling
  your objection as your own assessment, not a fact.
- You may NEVER recommend or imply that any automated/autonomous action be taken. You may
  suggest investigative NEXT STEPS for a human to take (e.g. "review this process," "check
  whether this file change was expected"), never an action that changes system state.
- You must distinguish four kinds of claim in every answer:
    "stored_fact"           — a fact Secure itself already recorded (must cite a Secure evidence id).
    "secure_interpretation" — Secure's OWN deterministic severity/confidence/significance judgment,
                               copied from the CONTEXT below, not your own reasoning (must cite a
                               Secure evidence id).
    "ai_assessment"          — your own reasoning, grounded in the facts you were given (no
                               citation expected — this is you thinking, not Secure's own data).
    "unverified_hypothesis"  — a plausible but UNCONFIRMED theory you are proposing for a human to
                               check (no citation expected, and must be clearly flagged as unconfirmed).
- Every "stored_fact" or "secure_interpretation" claim MUST cite a real evidence id from the
  CONTEXT below, in the exact form "table_name#id" (e.g. "persistence_alerts#42"). NEVER invent
  an id. If you are not certain an id is correct, either omit the citation or reclassify the
  claim as "ai_assessment"/"unverified_hypothesis" instead.
- Only use information present in the CONTEXT below or in this conversation. Do not assume
  anything about the operator's system that isn't shown to you.
"""

_RESPONSE_SCHEMA = """\
Respond with ONLY a single JSON object (no prose outside it), in exactly this shape:
{
  "summary": "one or two sentence plain-language summary of your answer",
  "claims": [
    {"kind": "stored_fact" | "secure_interpretation" | "ai_assessment" | "unverified_hypothesis",
     "text": "the claim itself, in plain language",
     "citation": "table_name#id or null"}
  ],
  "suggested_next_steps": ["a human-actionable investigative step", "..."]
}
"""

_VERIFIER_RESPONSE_SCHEMA = """\
Respond with ONLY a single JSON object (no prose outside it), in exactly this shape:
{
  "summary": "one or two sentence plain-language summary of your review",
  "claims": [
    {"kind": "stored_fact" | "secure_interpretation" | "ai_assessment" | "unverified_hypothesis",
     "text": "the claim itself, in plain language",
     "citation": "table_name#id or null"}
  ],
  "suggested_next_steps": ["a human-actionable investigative step", "..."],
  "agreement": "agrees" | "disagrees" | "partially_agrees",
  "contradictions_found": ["any evidence that contradicts the other analysis, or specific claims that conflict with each other"],
  "unsupported_assumptions": ["any assumption made without a citation that should have one"],
  "citation_check_notes": ["your own notes on whether the cited evidence ids actually say what they're claimed to say"]
}
"""


def _context_block(context: AnalystContext) -> str:
    return "CONTEXT (the only data you may treat as fact):\n" + json.dumps(context.to_dict(), indent=2, default=str)


def build_analyst_prompt(context: AnalystContext, question: str) -> "tuple[str, str]":
    system = (
        _HARD_RULES
        + '\nYou are "Model A," the Analyst. Explain findings, identify the most important evidence, '
        "explain what changed, suggest plausible BENIGN explanations alongside suspicious ones, and "
        "recommend concrete investigation steps. If asked, you may also point out unnecessary "
        "complexity, weak or missing test coverage, or propose simplifications — but any such "
        "proposal is only a suggestion for a human to evaluate, never something you can act on.\n\n"
        + _RESPONSE_SCHEMA
    )
    user = f"{_context_block(context)}\n\nQUESTION: {question}"
    return system, user


def build_verifier_independent_prompt(context: AnalystContext, question: str) -> "tuple[str, str]":
    system = (
        _HARD_RULES
        + '\nYou are "Model B," the Verifier, performing your INDEPENDENT first pass. You have NOT '
        "seen any other analysis of this question yet — form your own view from the CONTEXT alone, "
        "exactly as if you were the only analyst. A second pass will later show you another "
        "analyst's conclusion for you to critique; do not anticipate or hedge for that here.\n\n"
        + _RESPONSE_SCHEMA
    )
    user = f"{_context_block(context)}\n\nQUESTION: {question}"
    return system, user


def build_verifier_review_prompt(
    context: AnalystContext,
    question: str,
    analyst_answer: StructuredAnswer,
    independent_answer: StructuredAnswer,
) -> "tuple[str, str]":
    system = (
        _HARD_RULES
        + '\nYou are "Model B," the Verifier, performing your REVIEW pass. You already analyzed this '
        "question independently (shown below as YOUR OWN INDEPENDENT ANALYSIS). You are now shown "
        "another analyst's conclusion (MODEL A'S ANALYSIS). Your job is to actively try to find "
        "problems with Model A's analysis, not to simply agree with it:\n"
        "  - Look for evidence that CONTRADICTS Model A's conclusion, including evidence you found "
        "yourself in your own independent pass that Model A did not mention.\n"
        "  - Identify any assumption Model A made without citing real evidence for it.\n"
        "  - Check whether Model A's cited evidence ids plausibly support what Model A claims they "
        "support, based on what the CONTEXT actually shows for that id.\n"
        "  - Determine whether Model A's evidence is genuinely INDEPENDENT (separate sensors/sources "
        "confirming the same thing) or is really the same underlying observation counted twice.\n"
        "  - If Model A proposed a simplification or change, actively try to argue why it might be "
        "UNSAFE before agreeing it's safe.\n"
        "Agreement between you and Model A does NOT by itself make either of you correct — say so "
        "plainly if you still have doubts even where you agree.\n\n"
        + _VERIFIER_RESPONSE_SCHEMA
    )
    user = (
        f"{_context_block(context)}\n\n"
        f"QUESTION: {question}\n\n"
        f"YOUR OWN INDEPENDENT ANALYSIS (from your first pass):\n{json.dumps(independent_answer.to_dict(), indent=2)}\n\n"
        f"MODEL A'S ANALYSIS (to review):\n{json.dumps(analyst_answer.to_dict(), indent=2)}"
    )
    return system, user
