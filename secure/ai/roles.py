"""
secure/ai/roles.py — the two-role, two-pass orchestration the
governing instruction requires: Model A (Analyst) answers once; Model
B (Verifier) answers TWICE — an INDEPENDENT pass with no knowledge of
Model A's conclusion, then a REVIEW pass shown both its own
independent answer and Model A's answer, explicitly asked to look for
contradictions rather than simply agree.

    "Do not simply let the models agree with each other. Model B
    should independently analyze the issue before reviewing Model A's
    conclusion."

This module owns exactly two things: which provider plays which role
(`resolve_role_providers()`), and running the actual completion+parse+
citation-validate sequence for each pass. It has no idea how a query
gets persisted (secure/ai/analyst.py) or how a context gets built
(secure/ai/context.py) — pure orchestration glue.
"""

from __future__ import annotations

from dataclasses import dataclass

from secure.ai.base import ProviderCompletionResult
from secure.ai.context import AnalystContext
from secure.ai.prompt import build_analyst_prompt, build_verifier_independent_prompt, build_verifier_review_prompt
from secure.ai.response import StructuredAnswer, parse_answer, validate_citations


def resolve_role_providers(providers: dict) -> "tuple[object, object]":
    """Picks which provider plays Model A (Analyst) and which plays
    Model B (Verifier). Prefers two DIFFERENT backends when both are
    configured — reduces correlated bias/failure between the analyst
    and its own verifier, which is the whole point of having a second
    backend "for good measure." Falls back to one provider playing
    both roles (still two genuinely independent completion calls, just
    from the same model) when only one backend is configured. Returns
    (None, None) when neither is configured — the caller decides how
    to report that.
    """
    ollama = providers.get("ollama")
    compat = providers.get("openai_compatible")
    ollama_ok = ollama is not None and ollama.configured
    compat_ok = compat is not None and compat.configured

    if ollama_ok and compat_ok:
        return ollama, compat
    if ollama_ok:
        return ollama, ollama
    if compat_ok:
        return compat, compat
    return None, None


@dataclass
class AnalystRunResult:
    completion: ProviderCompletionResult
    answer: StructuredAnswer


@dataclass
class VerifierRunResult:
    independent_completion: ProviderCompletionResult
    independent_answer: StructuredAnswer
    review_completion: ProviderCompletionResult
    review_answer: StructuredAnswer


def run_analyst(provider, context: AnalystContext, question: str) -> AnalystRunResult:
    system, user = build_analyst_prompt(context, question)
    completion = provider.complete(system, user)
    answer = validate_citations(parse_answer(completion.text), context.evidence_manifest())
    return AnalystRunResult(completion=completion, answer=answer)


def run_verifier(
    provider, context: AnalystContext, question: str, analyst_answer: StructuredAnswer
) -> VerifierRunResult:
    independent_system, independent_user = build_verifier_independent_prompt(context, question)
    independent_completion = provider.complete(independent_system, independent_user)
    independent_answer = validate_citations(
        parse_answer(independent_completion.text), context.evidence_manifest()
    )

    review_system, review_user = build_verifier_review_prompt(
        context, question, analyst_answer, independent_answer
    )
    review_completion = provider.complete(review_system, review_user)
    review_answer = validate_citations(
        parse_answer(review_completion.text, verifier_fields=True), context.evidence_manifest()
    )

    return VerifierRunResult(
        independent_completion=independent_completion, independent_answer=independent_answer,
        review_completion=review_completion, review_answer=review_answer,
    )
