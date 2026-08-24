"""
secure/ai/analyst.py — the single top-level entry point,
`ask(conn, cfg, question, ...)`, that ties together every earlier
Phase 28 stage: build the read-only context (context.py), pick
providers (registry.py/roles.py), run the Analyst then the Verifier
(roles.py), and persist the full, honest result — including a failed
or unavailable attempt — to `ai_analyst_queries` (storage/models/ai.py).

`AskOutcome.status` is always one of "ok" / "partial" / "unavailable" /
"error" — never silently "ok" when a provider failed. "partial" means
the Analyst answered but the Verifier didn't (either only one backend
is configured and the operator hasn't been told to expect a second
opinion, or the verifier's own call failed) — the outcome is still
usable, just missing the second-opinion cross-check the governing
instruction asks for.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from secure.ai.context import MODE_ENTITY, MODE_FREEFORM, AnalystContext, build_entity_context, build_freeform_context
from secure.ai.registry import build_providers
from secure.ai.roles import AnalystRunResult, VerifierRunResult, resolve_role_providers, run_analyst, run_verifier
from secure.config import AppConfig
from secure.investigate.entity import EntityRef
from secure.storage.models import add_ai_analyst_query, complete_ai_analyst_query

STATUS_OK = "ok"
STATUS_PARTIAL = "partial"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"


@dataclass
class AskOutcome:
    query_id: int
    status: str
    context: "Optional[AnalystContext]"
    analyst: "Optional[AnalystRunResult]"
    verifier: "Optional[VerifierRunResult]"
    notes: "list[str]"


def ask(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    question: str,
    *,
    entity: "Optional[EntityRef]" = None,
) -> AskOutcome:
    mode = MODE_ENTITY if entity is not None else MODE_FREEFORM
    asked_at = datetime.now(timezone.utc).isoformat()
    query_id = add_ai_analyst_query(
        conn, asked_at=asked_at, mode=mode,
        entity_type=entity.entity_type if entity else None,
        entity_key=entity.entity_key if entity else None,
        question=question,
    )
    t0 = time.monotonic()

    providers = build_providers(cfg)
    provider_a, provider_b = resolve_role_providers(providers)

    if provider_a is None:
        completed_at = datetime.now(timezone.utc).isoformat()
        complete_ai_analyst_query(
            conn, query_id=query_id, completed_at=completed_at, provider_a=None, model_a=None,
            provider_b=None, model_b=None, context_manifest=[], analyst_raw_response=None,
            analyst_answer=None, verifier_raw_response=None, verifier_answer=None,
            citation_valid_count=0, citation_invalid_count=0,
            latency_ms=(time.monotonic() - t0) * 1000.0, status=STATUS_UNAVAILABLE,
        )
        return AskOutcome(
            query_id=query_id, status=STATUS_UNAVAILABLE, context=None, analyst=None, verifier=None,
            notes=["No local AI provider is configured — set ollama_host or local_llm_host in config.json."],
        )

    context = build_entity_context(conn, cfg, entity) if entity is not None else build_freeform_context(conn, cfg)

    analyst_run = run_analyst(provider_a, context, question)

    verifier_run: "Optional[VerifierRunResult]" = None
    notes: "list[str]" = list(context.notes)
    if provider_b is None:
        notes.append("No second provider available — the verifier pass was skipped.")
    elif not analyst_run.completion.ok:
        notes.append("The analyst call failed — the verifier pass was skipped.")
    else:
        verifier_run = run_verifier(provider_b, context, question, analyst_run.answer)

    valid_a, invalid_a = analyst_run.answer.citation_counts()
    valid_total, invalid_total = valid_a, invalid_a
    verifier_raw = None
    verifier_answer_dict = None
    provider_b_name = None
    model_b_name = None
    if verifier_run is not None:
        v1_valid, v1_invalid = verifier_run.independent_answer.citation_counts()
        v2_valid, v2_invalid = verifier_run.review_answer.citation_counts()
        valid_total += v1_valid + v2_valid
        invalid_total += v1_invalid + v2_invalid
        verifier_raw = (
            f"--- independent pass ---\n{verifier_run.independent_completion.text or ''}\n\n"
            f"--- review pass ---\n{verifier_run.review_completion.text or ''}"
        )
        verifier_answer_dict = {
            "independent": verifier_run.independent_answer.to_dict(),
            "review": verifier_run.review_answer.to_dict(),
        }
        provider_b_name = provider_b.identity.name
        model_b_name = provider_b.model_name

    if not analyst_run.completion.ok:
        status = STATUS_UNAVAILABLE if analyst_run.completion.status == "unavailable" else STATUS_ERROR
    elif verifier_run is None:
        status = STATUS_PARTIAL
    elif not (verifier_run.independent_completion.ok and verifier_run.review_completion.ok):
        status = STATUS_PARTIAL
    else:
        status = STATUS_OK

    completed_at = datetime.now(timezone.utc).isoformat()
    complete_ai_analyst_query(
        conn, query_id=query_id, completed_at=completed_at,
        provider_a=provider_a.identity.name, model_a=provider_a.model_name,
        provider_b=provider_b_name, model_b=model_b_name,
        context_manifest=context.evidence_manifest(),
        analyst_raw_response=analyst_run.completion.text, analyst_answer=analyst_run.answer.to_dict(),
        verifier_raw_response=verifier_raw, verifier_answer=verifier_answer_dict,
        citation_valid_count=valid_total, citation_invalid_count=invalid_total,
        latency_ms=(time.monotonic() - t0) * 1000.0, status=status,
    )

    return AskOutcome(
        query_id=query_id, status=status, context=context, analyst=analyst_run, verifier=verifier_run,
        notes=notes,
    )
