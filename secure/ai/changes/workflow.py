"""
secure/ai/changes/workflow.py — the only place `ai_change_requests`
rows get created or move out of 'pending'. See secure/ai/changes/
__init__.py's five hard rules for the full reasoning; this module's
job is to implement them, not to relitigate them.

Two entry points:

    propose_change()  — called after Model A proposes something and
        Model B has attacked it and deterministic tests have run
        (see `propose_simplification()` below for the full pipeline).
        Always creates a 'pending' row and attempts (best-effort,
        non-blocking) an email notification.

    approve_change() / reject_change() — the ONLY functions that can
        move a row out of 'pending'. Both are meant to be called from
        exactly one place: an explicit human CLI command. Neither is
        ever called by anything in secure/ai/roles.py, analyst.py, or
        this module's own propose_change()/propose_simplification().
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure.ai.changes.model import ProposedChangeContent, compute_revision_hash
from secure.ai.changes.notify import send_change_request_notification
from secure.ai.context import AnalystContext, build_entity_context, build_freeform_context
from secure.ai.registry import build_providers
from secure.ai.roles import resolve_role_providers, run_analyst, run_verifier
from secure.ai.verify.runner import VerificationRunSummary, run_default_verification_suite
from secure.config import AppConfig
from secure.investigate.entity import EntityRef
from secure.storage.models import (
    add_ai_change_request,
    find_ai_change_request,
    mark_ai_change_request_notified,
    set_ai_change_request_status,
)
from secure.storage.models.ai import AiChangeRequestRecord

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"


class RevisionMismatchError(ValueError):
    """Raised when the revision hash a caller supplies to approve_change()
    doesn't match what's actually stored — the safeguard behind "approval
    must apply only to the exact change revision approved."""


def _next_cr_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT COUNT(*) AS c FROM ai_change_requests").fetchone()
    return f"CR-{row['c'] + 1}"


def propose_change(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    title: str,
    proposed_change: str,
    reason: str,
    affected_component: str,
    risks: str,
    model_a_opinion: str,
    model_b_opinion: str,
    verification_run_id: "Optional[int]" = None,
    verification_summary: "Optional[str]" = None,
    notify: bool = True,
) -> AiChangeRequestRecord:
    """Creates a new PENDING change request and best-effort notifies
    the operator. Never called with an approval status — see this
    module's docstring.

    `notify` (Phase 41, additive, defaults to the pre-existing True so
    every caller written before this parameter existed behaves exactly
    as it did): a caller that sends its own, more tightly sanitized
    notification passes False so the operator is not emailed twice
    about the same change request — once sanitized and once not.
    `secure/agent/changes.py` is the only such caller, because an
    agent-authored `proposed_change` embeds raw diff text, and Phase
    41's governing instruction says a notification must never carry
    secrets or sensitive model context.

    This parameter cannot affect approval in any way. It gates one
    outbound email and the `notify_status` bookkeeping column, and
    email is explicitly not an authorization path (hard rule 4).
    Suppressing it here never suppresses the change request itself,
    which is persisted as PENDING before this parameter is even read.
    """
    content = ProposedChangeContent(
        title=title, proposed_change=proposed_change, reason=reason,
        affected_component=affected_component, risks=risks,
    )
    revision_hash = compute_revision_hash(content)
    cr_id = _next_cr_id(conn)
    created_at = datetime.now(timezone.utc).isoformat()

    add_ai_change_request(
        conn, cr_id=cr_id, created_at=created_at, revision_hash=revision_hash, title=title,
        proposed_change=proposed_change, reason=reason, affected_component=affected_component,
        risks=risks, verification_run_id=verification_run_id,
        model_a_opinion=model_a_opinion, model_b_opinion=model_b_opinion,
    )
    record = find_ai_change_request(conn, cr_id)

    if not notify:
        # Recorded honestly rather than left blank: the operator WAS
        # notified about this change request, by the caller, using a
        # sanitized body. See secure/agent/notify.py.
        mark_ai_change_request_notified(
            conn, cr_id=cr_id, notified_at=datetime.now(timezone.utc).isoformat(),
            notify_status="deferred_to_caller",
        )
        return find_ai_change_request(conn, cr_id)

    notify_status, notify_detail = send_change_request_notification(
        cfg, record, verification_summary=verification_summary
    )
    mark_ai_change_request_notified(
        conn, cr_id=cr_id, notified_at=datetime.now(timezone.utc).isoformat(), notify_status=notify_status
    )
    return find_ai_change_request(conn, cr_id)


def approve_change(
    conn: sqlite3.Connection, cr_id: str, *, revision_hash: str, approved_by: str
) -> AiChangeRequestRecord:
    """The ONLY function in this codebase that can set a change
    request's status to 'approved'. Intended to be called from exactly
    one place: `secure ai changes approve <cr_id> <revision_hash>`,
    triggered by a human typing that command themselves. Requires the
    exact revision hash the change request was created with — a
    mismatch (which can only happen if the caller is looking at stale
    or wrong information) raises rather than silently approving
    whatever is currently stored.
    """
    record = find_ai_change_request(conn, cr_id)
    if record is None:
        raise ValueError(f"No change request with id {cr_id!r}.")
    if record.status != STATUS_PENDING:
        raise ValueError(f"{cr_id} is not pending (current status: {record.status!r}) — nothing to approve.")
    if record.revision_hash != revision_hash:
        raise RevisionMismatchError(
            f"Revision hash mismatch for {cr_id}: expected {record.revision_hash!r}, got {revision_hash!r}. "
            "Re-run `secure ai changes show` to see the current proposal before approving."
        )

    updated = set_ai_change_request_status(
        conn, cr_id=cr_id, status=STATUS_APPROVED,
        approved_at=datetime.now(timezone.utc).isoformat(), approved_by=approved_by,
    )
    return updated


def reject_change(conn: sqlite3.Connection, cr_id: str, *, approved_by: str) -> AiChangeRequestRecord:
    record = find_ai_change_request(conn, cr_id)
    if record is None:
        raise ValueError(f"No change request with id {cr_id!r}.")
    if record.status != STATUS_PENDING:
        raise ValueError(f"{cr_id} is not pending (current status: {record.status!r}) — nothing to reject.")

    updated = set_ai_change_request_status(
        conn, cr_id=cr_id, status=STATUS_REJECTED,
        approved_at=datetime.now(timezone.utc).isoformat(), approved_by=approved_by,
    )
    return updated


@dataclass
class SimplificationOutcome:
    change_request: "Optional[AiChangeRequestRecord]"
    verification: "Optional[VerificationRunSummary]"
    notes: "list[str]"


def _verification_text_summary(verification: "Optional[VerificationRunSummary]") -> "Optional[str]":
    if verification is None:
        return None
    lines = [f"Verification run #{verification.run_id} — overall: {verification.overall_status}"]
    for result in verification.results:
        lines.append(f"  [{result.status}] {result.op}")
    return "\n".join(lines)


def propose_simplification(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    title: str,
    topic: str,
    affected_component: str,
    entity: "Optional[EntityRef]" = None,
    project_root: "Optional[Path]" = None,
) -> SimplificationOutcome:
    """Implements the full pipeline the governing instruction requires
    for an AI-originated simplification:

        Model A proposes change -> Model B attacks proposal
        -> deterministic tests run -> change request created
        -> human approval required

    Reuses Stage 5's two-role orchestration unchanged (the same
    run_analyst/run_verifier that answers ordinary questions) — a
    "propose a simplification" question is just a differently-phrased
    question to the exact same Analyst/Verifier machinery, with Model
    B's independent pass giving it a real chance to reach its own
    conclusion before it ever sees what Model A proposed. Reuses Stage
    6's default verification suite unchanged for "deterministic tests
    run." Adds no new model-calling code of its own.
    """
    notes: "list[str]" = []
    providers = build_providers(cfg)
    provider_a, provider_b = resolve_role_providers(providers)

    if provider_a is None:
        return SimplificationOutcome(
            change_request=None, verification=None,
            notes=["No local AI provider is configured — set ollama_host or local_llm_host in config.json."],
        )

    context: AnalystContext = (
        build_entity_context(conn, cfg, entity) if entity is not None else build_freeform_context(conn, cfg)
    )
    question = (
        f"Propose ONE concrete, specific simplification for: {topic}. Explain exactly what would "
        "change, why it would not reduce security, and what could go wrong. If you cannot find a "
        "safe simplification, say so plainly instead of inventing one."
    )

    analyst_run = run_analyst(provider_a, context, question)

    if provider_b is None:
        notes.append("No second provider available — proceeding without an adversarial Model B review.")
        model_b_opinion = "(no second provider configured — this proposal was not independently attacked)"
        risks = "UNVERIFIED: no Model B review was performed. Treat this proposal with extra caution."
    else:
        verifier_run = run_verifier(provider_b, context, question, analyst_run.answer)
        model_b_opinion = (
            f"Independent view: {verifier_run.independent_answer.summary}\n\n"
            f"Review of Model A's proposal (agreement={verifier_run.review_answer.agreement}):\n"
            f"{verifier_run.review_answer.summary}\n"
            f"Contradictions found: {verifier_run.review_answer.contradictions_found}\n"
            f"Unsupported assumptions: {verifier_run.review_answer.unsupported_assumptions}"
        )
        risk_bits = list(verifier_run.review_answer.contradictions_found) + list(
            verifier_run.review_answer.unsupported_assumptions
        )
        risks = "; ".join(risk_bits) if risk_bits else "Model B found no specific contradictions or unsupported assumptions, but agreement alone is not approval."

    verification = run_default_verification_suite(conn, cfg, root=project_root)
    if verification.overall_status != "ok":
        notes.append(
            f"Deterministic verification run #{verification.run_id} did not fully complete "
            f"(overall status: {verification.overall_status}) — review it before approving."
        )

    model_a_opinion = f"{analyst_run.answer.summary}\nSuggested next steps: {analyst_run.answer.suggested_next_steps}"

    record = propose_change(
        conn, cfg,
        title=title,
        proposed_change=analyst_run.answer.summary,
        reason="\n".join(c.text for c in analyst_run.answer.claims) or analyst_run.answer.summary,
        affected_component=affected_component,
        risks=risks,
        model_a_opinion=model_a_opinion,
        model_b_opinion=model_b_opinion,
        verification_run_id=verification.run_id,
        verification_summary=_verification_text_summary(verification),
    )
    notes.append(f"Created {record.cr_id} (status: {record.status}). Human approval is required before anything is acted on.")

    return SimplificationOutcome(change_request=record, verification=verification, notes=notes)
