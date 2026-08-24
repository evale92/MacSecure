"""
secure/ai/response.py — parses a model's raw completion text into a
structured, machine-checkable StructuredAnswer, and validates every
citation it contains against the exact context manifest the model was
given (secure/ai/context.py's own AnalystContext.evidence_manifest()).

Two separate honesty guarantees this module enforces:

1. **Never fabricate structure.** If the model's raw text can't be
   parsed as the requested JSON shape at all, `parse_answer()` returns
   `parse_ok=False` with the raw text preserved verbatim and an empty
   claim list — never a best-effort guess dressed up as a real parse.
2. **Never silently accept or silently drop a citation.**
   `validate_citations()` checks every STORED_FACT/SECURE_INTERPRETATION
   claim's citation against the manifest and marks it
   `citation_valid=True/False` — an invalid citation is kept in the
   answer, visibly flagged, never removed. A STORED_FACT/
   SECURE_INTERPRETATION claim with NO citation at all is itself
   treated as invalid (a stored fact with nothing to point at isn't a
   stored fact).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from secure.ai.vocab import (
    AGREEMENT_UNKNOWN,
    CITATION_REQUIRED_KINDS,
    UNVERIFIED_HYPOTHESIS,
    VALID_AGREEMENT_VALUES,
    VALID_CLAIM_KINDS,
)

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


@dataclass
class Claim:
    kind: str
    text: str
    citation: "Optional[str]"  # the model's own claimed "table#id" string, verbatim
    citation_valid: "Optional[bool]" = None  # None until validate_citations() runs


@dataclass
class StructuredAnswer:
    raw_text: str
    parse_ok: bool
    parse_error: "Optional[str]"
    summary: str = ""
    claims: "list[Claim]" = field(default_factory=list)
    suggested_next_steps: "list[str]" = field(default_factory=list)

    # Verifier-only fields — None/empty for a plain analyst answer.
    agreement: "Optional[str]" = None
    contradictions_found: "list[str]" = field(default_factory=list)
    unsupported_assumptions: "list[str]" = field(default_factory=list)
    citation_check_notes: "list[str]" = field(default_factory=list)

    def citation_counts(self) -> "tuple[int, int]":
        """(valid_count, invalid_count) — only counts claims whose kind
        actually requires a citation (see vocab.CITATION_REQUIRED_KINDS);
        an AI_ASSESSMENT/UNVERIFIED_HYPOTHESIS with citation_valid=None
        is neither valid nor invalid, it's simply not applicable.
        """
        valid = sum(1 for c in self.claims if c.citation_valid is True)
        invalid = sum(1 for c in self.claims if c.citation_valid is False)
        return valid, invalid

    def to_dict(self) -> dict:
        return {
            "parse_ok": self.parse_ok,
            "parse_error": self.parse_error,
            "summary": self.summary,
            "claims": [
                {"kind": c.kind, "text": c.text, "citation": c.citation, "citation_valid": c.citation_valid}
                for c in self.claims
            ],
            "suggested_next_steps": self.suggested_next_steps,
            "agreement": self.agreement,
            "contradictions_found": self.contradictions_found,
            "unsupported_assumptions": self.unsupported_assumptions,
            "citation_check_notes": self.citation_check_notes,
        }


def _extract_json_object(raw_text: str) -> "Optional[dict]":
    """Models routinely wrap JSON in markdown fences or add a little
    prose around it — try the raw text as-is first, then fall back to
    pulling the first fenced ```json ... ``` block, then the first
    top-level {...} span. Returns None (never raises) if nothing
    parses.
    """
    candidates = [raw_text.strip()]
    fence_match = _FENCE_RE.search(raw_text)
    if fence_match:
        candidates.append(fence_match.group(1))
    brace_start = raw_text.find("{")
    brace_end = raw_text.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        candidates.append(raw_text[brace_start : brace_end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _coerce_claim(raw_claim: dict) -> "Optional[Claim]":
    if not isinstance(raw_claim, dict):
        return None
    kind = raw_claim.get("kind")
    text = raw_claim.get("text")
    if not isinstance(text, str) or not text.strip():
        return None
    if kind not in VALID_CLAIM_KINDS:
        # An unrecognized kind is downgraded to the weakest, safest
        # bucket rather than dropped or guessed into a stronger one —
        # never let a malformed "kind" accidentally read as a stored
        # fact.
        kind = UNVERIFIED_HYPOTHESIS
    citation = raw_claim.get("citation")
    if not isinstance(citation, str) or not citation.strip():
        citation = None
    return Claim(kind=kind, text=text.strip(), citation=citation)


def parse_answer(raw_text: "Optional[str]", *, verifier_fields: bool = False) -> StructuredAnswer:
    """Parses one model completion into a StructuredAnswer. Never
    raises — a malformed or missing response becomes
    `parse_ok=False` with `raw_text` preserved, not a crash and not a
    fabricated empty-but-successful answer.
    """
    if not raw_text:
        return StructuredAnswer(raw_text="", parse_ok=False, parse_error="empty response")

    parsed = _extract_json_object(raw_text)
    if parsed is None:
        return StructuredAnswer(
            raw_text=raw_text, parse_ok=False,
            parse_error="could not find a valid JSON object in the model's response",
        )

    summary = parsed.get("summary")
    summary = summary if isinstance(summary, str) else ""

    raw_claims = parsed.get("claims")
    claims = []
    if isinstance(raw_claims, list):
        for raw_claim in raw_claims:
            claim = _coerce_claim(raw_claim)
            if claim is not None:
                claims.append(claim)

    raw_steps = parsed.get("suggested_next_steps")
    steps = [s for s in raw_steps if isinstance(s, str) and s.strip()] if isinstance(raw_steps, list) else []

    answer = StructuredAnswer(
        raw_text=raw_text, parse_ok=True, parse_error=None, summary=summary,
        claims=claims, suggested_next_steps=steps,
    )

    if verifier_fields:
        agreement = parsed.get("agreement")
        answer.agreement = agreement if agreement in VALID_AGREEMENT_VALUES else AGREEMENT_UNKNOWN
        for field_name, attr in (
            ("contradictions_found", "contradictions_found"),
            ("unsupported_assumptions", "unsupported_assumptions"),
            ("citation_check_notes", "citation_check_notes"),
        ):
            raw_value = parsed.get(field_name)
            setattr(
                answer, attr,
                [v for v in raw_value if isinstance(v, str) and v.strip()] if isinstance(raw_value, list) else [],
            )

    return answer


def validate_citations(answer: StructuredAnswer, manifest: "list[dict]") -> StructuredAnswer:
    """Checks every claim's citation against `manifest` (the EXACT
    evidence ids the context actually contained — see
    secure.ai.context.AnalystContext.evidence_manifest()), mutating
    each Claim's `citation_valid` in place and returning the same
    answer object for convenience. Never removes or hides a claim —
    an invalid citation stays in the answer, just marked False.
    """
    manifest_ids = {(item["source_table"], item["source_id"]) for item in manifest}

    for claim in answer.claims:
        if claim.kind not in CITATION_REQUIRED_KINDS:
            claim.citation_valid = None  # not applicable — an assessment/hypothesis needs no citation
            continue
        if claim.citation is None:
            claim.citation_valid = False  # a "fact" with no citation at all is not a valid stored fact
            continue
        table, _, id_part = claim.citation.partition("#")
        try:
            source_id = int(id_part)
        except (TypeError, ValueError):
            claim.citation_valid = False
            continue
        claim.citation_valid = (table, source_id) in manifest_ids

    return answer
