"""
ai.py — Phase 28 Local AI Security Analyst: `ai_analyst_queries`,
`ai_verification_runs`, `ai_change_requests` — see secure/ai/ and
database.py's own schema comments for the full design reasoning.

Same "this module doesn't interpret, it only persists" separation
every other domain file in this package keeps: this file has no idea
what a citation is, how a prompt is built, or what makes a change
request safe to approve — it only knows how to store and retrieve the
already-decided rows secure/ai/ hands it.

One deliberate asymmetry from the rest of this package, worth calling
out: `list_ai_change_requests()` DOES accept an optional status filter.
That's not the same situation as validation_scenario_results' own
"must never accept an outcome filter" rule (Phase 27) — a change
request's status is a workflow state an operator legitimately wants to
filter on ("show me what's pending"), not a finding that could be
hidden to make Secure look better. Nothing here can ever move a change
request INTO 'approved' except set_ai_change_request_status(), and
nothing in this module decides when that's appropriate to call — see
secure/ai/changes/workflow.py's own hard rule that only an explicit
human CLI/GUI action may do that.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Optional


@dataclass
class AiAnalystQueryRecord:
    id: int
    asked_at: str
    completed_at: "Optional[str]"
    mode: str
    entity_type: "Optional[str]"
    entity_key: "Optional[str]"
    question: str
    provider_a: "Optional[str]"
    model_a: "Optional[str]"
    provider_b: "Optional[str]"
    model_b: "Optional[str]"
    context_manifest: list
    analyst_raw_response: "Optional[str]"
    analyst_answer: "Optional[dict]"
    verifier_raw_response: "Optional[str]"
    verifier_answer: "Optional[dict]"
    citation_valid_count: int
    citation_invalid_count: int
    latency_ms: "Optional[float]"
    status: str


@dataclass
class AiVerificationRunRecord:
    id: int
    query_id: "Optional[int]"
    started_at: str
    completed_at: "Optional[str]"
    operations: list
    results: list
    overall_status: str


@dataclass
class AiChangeRequestRecord:
    id: int
    cr_id: str
    created_at: str
    revision_hash: str
    title: str
    proposed_change: str
    reason: str
    affected_component: str
    risks: str
    verification_run_id: "Optional[int]"
    model_a_opinion: str
    model_b_opinion: str
    status: str
    approved_at: "Optional[str]"
    approved_by: "Optional[str]"
    notified_at: "Optional[str]"
    notify_status: str
    # Phase 39 — the change class, denormalized for querying. Defaulted
    # so every pre-Phase-39 construction site still builds a valid
    # record without naming it.
    classification: "Optional[str]" = None


def _row_to_query(row: sqlite3.Row) -> AiAnalystQueryRecord:
    data = dict(row)
    context_manifest = json.loads(data.pop("context_manifest_json") or "[]")
    analyst_answer_json = data.pop("analyst_answer_json")
    verifier_answer_json = data.pop("verifier_answer_json")
    return AiAnalystQueryRecord(
        context_manifest=context_manifest,
        analyst_answer=json.loads(analyst_answer_json) if analyst_answer_json else None,
        verifier_answer=json.loads(verifier_answer_json) if verifier_answer_json else None,
        **data,
    )


def _row_to_verification_run(row: sqlite3.Row) -> AiVerificationRunRecord:
    data = dict(row)
    operations = json.loads(data.pop("operations_json") or "[]")
    results = json.loads(data.pop("results_json") or "[]")
    return AiVerificationRunRecord(operations=operations, results=results, **data)


def _row_to_change_request(row: sqlite3.Row) -> AiChangeRequestRecord:
    # `classification` is popped with a default so this still works
    # against a database that has not yet been healed by
    # _COLUMN_MIGRATIONS.
    data = dict(row)
    classification = data.pop("classification", None)
    return AiChangeRequestRecord(classification=classification, **data)


def set_ai_change_request_classification(
    conn: sqlite3.Connection, *, cr_id: str, classification: str
) -> "Optional[AiChangeRequestRecord]":
    """Phase 39. Denormalizes the change class onto an existing change
    request for querying by the Change Request Center (Phase 40) and
    the notification rules (Phase 41).

    Deliberately a separate, narrow setter rather than a new argument
    to add_ai_change_request(): secure/ai/changes/workflow.py's five
    hard rules live around that function and Phase 31 established the
    discipline of extending this workflow WITHOUT editing it. This
    column is for querying, never for deciding — the copy that a human
    actually approves is the classification text embedded in `risks`,
    which is covered by revision_hash. Writing this column can
    therefore never move a change request toward approval; it cannot
    even change what the approval hash covers.
    """
    conn.execute("UPDATE ai_change_requests SET classification = ? WHERE cr_id = ?", (classification, cr_id))
    conn.commit()
    return find_ai_change_request(conn, cr_id)


# ---------- ai_analyst_queries ----------


def add_ai_analyst_query(
    conn: sqlite3.Connection,
    *,
    asked_at: str,
    mode: str,
    entity_type: "Optional[str]",
    entity_key: "Optional[str]",
    question: str,
) -> int:
    """Creates the row BEFORE any provider call happens (status='running')
    — a crash mid-flight still leaves an honest, findable audit record
    rather than nothing at all, consistent with add_validation_run()'s
    own create-then-complete two-step shape."""
    cursor = conn.execute(
        "INSERT INTO ai_analyst_queries (asked_at, completed_at, mode, entity_type, entity_key, "
        "question, context_manifest_json, status) VALUES (?, NULL, ?, ?, ?, ?, '[]', 'running')",
        (asked_at, mode, entity_type, entity_key, question),
    )
    conn.commit()
    return cursor.lastrowid


def complete_ai_analyst_query(
    conn: sqlite3.Connection,
    *,
    query_id: int,
    completed_at: str,
    provider_a: "Optional[str]",
    model_a: "Optional[str]",
    provider_b: "Optional[str]",
    model_b: "Optional[str]",
    context_manifest: list,
    analyst_raw_response: "Optional[str]",
    analyst_answer: "Optional[dict]",
    verifier_raw_response: "Optional[str]",
    verifier_answer: "Optional[dict]",
    citation_valid_count: int,
    citation_invalid_count: int,
    latency_ms: "Optional[float]",
    status: str,
) -> None:
    conn.execute(
        "UPDATE ai_analyst_queries SET completed_at = ?, provider_a = ?, model_a = ?, "
        "provider_b = ?, model_b = ?, context_manifest_json = ?, analyst_raw_response = ?, "
        "analyst_answer_json = ?, verifier_raw_response = ?, verifier_answer_json = ?, "
        "citation_valid_count = ?, citation_invalid_count = ?, latency_ms = ?, status = ? "
        "WHERE id = ?",
        (
            completed_at, provider_a, model_a, provider_b, model_b,
            json.dumps(context_manifest), analyst_raw_response,
            json.dumps(analyst_answer) if analyst_answer is not None else None,
            verifier_raw_response,
            json.dumps(verifier_answer) if verifier_answer is not None else None,
            citation_valid_count, citation_invalid_count, latency_ms, status, query_id,
        ),
    )
    conn.commit()


def find_ai_analyst_query(conn: sqlite3.Connection, query_id: int) -> "Optional[AiAnalystQueryRecord]":
    row = conn.execute("SELECT * FROM ai_analyst_queries WHERE id = ?", (query_id,)).fetchone()
    return _row_to_query(row) if row else None


def list_ai_analyst_queries(conn: sqlite3.Connection, limit: int = 50) -> "list[AiAnalystQueryRecord]":
    rows = conn.execute(
        "SELECT * FROM ai_analyst_queries ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_query(row) for row in rows]


# ---------- ai_verification_runs ----------


def add_ai_verification_run(
    conn: sqlite3.Connection, *, query_id: "Optional[int]", started_at: str
) -> int:
    cursor = conn.execute(
        "INSERT INTO ai_verification_runs (query_id, started_at, completed_at, operations_json, "
        "results_json, overall_status) VALUES (?, ?, NULL, '[]', '[]', 'running')",
        (query_id, started_at),
    )
    conn.commit()
    return cursor.lastrowid


def complete_ai_verification_run(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    completed_at: str,
    operations: list,
    results: list,
    overall_status: str,
) -> None:
    conn.execute(
        "UPDATE ai_verification_runs SET completed_at = ?, operations_json = ?, results_json = ?, "
        "overall_status = ? WHERE id = ?",
        (completed_at, json.dumps(operations), json.dumps(results), overall_status, run_id),
    )
    conn.commit()


def find_ai_verification_run(conn: sqlite3.Connection, run_id: int) -> "Optional[AiVerificationRunRecord]":
    row = conn.execute("SELECT * FROM ai_verification_runs WHERE id = ?", (run_id,)).fetchone()
    return _row_to_verification_run(row) if row else None


def list_ai_verification_runs(conn: sqlite3.Connection, limit: int = 50) -> "list[AiVerificationRunRecord]":
    rows = conn.execute(
        "SELECT * FROM ai_verification_runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_verification_run(row) for row in rows]


# ---------- ai_change_requests ----------


def add_ai_change_request(
    conn: sqlite3.Connection,
    *,
    cr_id: str,
    created_at: str,
    revision_hash: str,
    title: str,
    proposed_change: str,
    reason: str,
    affected_component: str,
    risks: str,
    verification_run_id: "Optional[int]",
    model_a_opinion: str,
    model_b_opinion: str,
) -> int:
    """Always created with status='pending' — nothing in this function
    (or anywhere else in this module) can create a row in any other
    state. See this module's own docstring for who's allowed to change
    that afterward."""
    cursor = conn.execute(
        "INSERT INTO ai_change_requests (cr_id, created_at, revision_hash, title, proposed_change, "
        "reason, affected_component, risks, verification_run_id, model_a_opinion, model_b_opinion, "
        "status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
        (
            cr_id, created_at, revision_hash, title, proposed_change, reason, affected_component,
            risks, verification_run_id, model_a_opinion, model_b_opinion,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def find_ai_change_request(conn: sqlite3.Connection, cr_id: str) -> "Optional[AiChangeRequestRecord]":
    row = conn.execute("SELECT * FROM ai_change_requests WHERE cr_id = ?", (cr_id,)).fetchone()
    return _row_to_change_request(row) if row else None


def list_ai_change_requests(
    conn: sqlite3.Connection, status: "Optional[str]" = None, limit: int = 50
) -> "list[AiChangeRequestRecord]":
    if status is not None:
        rows = conn.execute(
            "SELECT * FROM ai_change_requests WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM ai_change_requests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_change_request(row) for row in rows]


def set_ai_change_request_status(
    conn: sqlite3.Connection,
    *,
    cr_id: str,
    status: str,
    approved_at: "Optional[str]" = None,
    approved_by: "Optional[str]" = None,
) -> "Optional[AiChangeRequestRecord]":
    """Dumb state transition — this function does not itself enforce
    WHO may call it or WHEN it's appropriate; secure/ai/changes/
    workflow.py owns that (revision-hash re-check, human-only trigger).
    Returns None if `cr_id` doesn't exist."""
    existing = find_ai_change_request(conn, cr_id)
    if existing is None:
        return None
    conn.execute(
        "UPDATE ai_change_requests SET status = ?, approved_at = ?, approved_by = ? WHERE cr_id = ?",
        (status, approved_at, approved_by, cr_id),
    )
    conn.commit()
    return find_ai_change_request(conn, cr_id)


def mark_ai_change_request_notified(
    conn: sqlite3.Connection, *, cr_id: str, notified_at: str, notify_status: str
) -> None:
    conn.execute(
        "UPDATE ai_change_requests SET notified_at = ?, notify_status = ? WHERE cr_id = ?",
        (notified_at, notify_status, cr_id),
    )
    conn.commit()
