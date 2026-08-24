"""
agent.py — Phase 31 Agent Foundation: `agent_repair_runs`. See
secure/agent/ for the actual orchestration logic and
database.py's own schema comment for the full design reasoning.

Same "this module doesn't interpret, it only persists" separation
every other domain file in this package keeps: this file has no idea
what a git worktree is, how mini-SWE-agent is invoked, or what makes a
diff safe to propose — it only knows how to store and retrieve the
already-decided rows secure/agent/ hands it.

One row is created (status='running') before the external tool is ever
invoked — the same create-then-complete shape add_validation_run() and
add_ai_analyst_query() already use — so a crash mid-run always leaves
an honest, findable audit record instead of nothing at all. Nothing
here writes to ai_change_requests directly; secure/agent/changes.py
calls secure.ai.changes.workflow.propose_change() for that (Phase 28's
five hard rules are enforced there, unchanged, not reimplemented here)
and then calls set_change_request_id() below to link the two rows by
id only, never by copying approval state — a run's own approval status
is always read by joining to ai_change_requests, never duplicated onto
this table, so the two can never disagree.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentRepairRunRecord:
    id: int
    run_id: str
    created_at: str
    completed_at: "Optional[str]"
    status: str
    attempt_number: int
    max_attempts: int
    trigger_kind: str
    trigger_ref: str
    trigger_detail: str
    base_commit: str
    worktree_path: str
    agent_home_path: str
    tool_name: str
    tool_version: str
    model_name: str
    tool_argv: list
    mini_config_yaml: str
    transcript_hash: "Optional[str]"
    transcript_path: "Optional[str]"
    agent_exit_status: "Optional[str]"
    diff_path: "Optional[str]"
    diff_hash: "Optional[str]"
    changed_files: list
    denylist_violation: "Optional[str]"
    pytest_status: "Optional[str]"
    pytest_summary: str
    validate_status: "Optional[str]"
    validate_summary: str
    verification_passed: "Optional[bool]"
    change_request_id: "Optional[str]"
    stop_reason: str
    notes: str
    # Phase 38 — both assessments. Defaulted so every pre-Phase-38
    # construction site (and every existing test) still builds a valid
    # record without naming them.
    coder_assessment: str = ""
    review_status: "Optional[str]" = None
    review_provider: str = ""
    review_model: str = ""
    review_answers: list = field(default_factory=list)
    review_blocking: list = field(default_factory=list)
    review_summary: str = ""
    review_error: "Optional[str]" = None
    review_disagreement: "Optional[bool]" = None
    # Phase 39 — deterministic change classification.
    classification: "Optional[str]" = None
    classification_reasons: str = ""
    # Phase 43 — reproduction evidence, recorded before any repair ran.
    reproduction_status: "Optional[str]" = None
    reproduced: "Optional[bool]" = None
    reproduction_detail: str = ""
    reproduction_command: str = ""


def _row_to_record(row: sqlite3.Row) -> AgentRepairRunRecord:
    data = dict(row)
    changed_files = json.loads(data.pop("changed_files_json") or "[]")
    tool_argv = json.loads(data.pop("tool_argv_json") or "[]")
    verification_passed = data.pop("verification_passed")
    # Phase 38 columns are popped with a default so this function still
    # works against a row read from a database that has not yet been
    # healed by _COLUMN_MIGRATIONS.
    review_answers = json.loads(data.pop("review_answers_json", None) or "[]")
    review_blocking = json.loads(data.pop("review_blocking_json", None) or "[]")
    review_disagreement = data.pop("review_disagreement", None)
    data.setdefault("classification", None)
    data.setdefault("classification_reasons", "")
    data.setdefault("reproduction_status", None)
    data.setdefault("reproduction_detail", "")
    data.setdefault("reproduction_command", "")
    reproduced = data.pop("reproduced", None)
    return AgentRepairRunRecord(
        reproduced=None if reproduced is None else bool(reproduced),
        changed_files=changed_files,
        tool_argv=tool_argv,
        verification_passed=None if verification_passed is None else bool(verification_passed),
        review_answers=review_answers,
        review_blocking=review_blocking,
        review_disagreement=None if review_disagreement is None else bool(review_disagreement),
        **data,
    )


def _next_run_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT COUNT(*) AS c FROM agent_repair_runs").fetchone()
    return f"AR-{row['c'] + 1}"


def add_agent_repair_run(
    conn: sqlite3.Connection,
    *,
    created_at: str,
    attempt_number: int,
    max_attempts: int,
    trigger_kind: str,
    trigger_ref: str,
    trigger_detail: str,
    base_commit: str,
    worktree_path: str,
    agent_home_path: str,
    tool_name: str,
    model_name: str,
) -> str:
    """Creates the row with status='running' BEFORE the external tool is
    invoked. Returns the new row's public run_id (e.g. "AR-1")."""
    run_id = _next_run_id(conn)
    conn.execute(
        "INSERT INTO agent_repair_runs (run_id, created_at, completed_at, status, attempt_number, "
        "max_attempts, trigger_kind, trigger_ref, trigger_detail, base_commit, worktree_path, "
        "agent_home_path, tool_name, tool_version, model_name, changed_files_json) "
        "VALUES (?, ?, NULL, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, '[]')",
        (
            run_id, created_at, attempt_number, max_attempts, trigger_kind, trigger_ref,
            trigger_detail, base_commit, worktree_path, agent_home_path, tool_name, model_name,
        ),
    )
    conn.commit()
    return run_id


def complete_agent_repair_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    completed_at: str,
    status: str,
    tool_version: str = "",
    transcript_path: "Optional[str]" = None,
    agent_exit_status: "Optional[str]" = None,
    diff_path: "Optional[str]" = None,
    diff_hash: "Optional[str]" = None,
    changed_files: "Optional[list]" = None,
    denylist_violation: "Optional[str]" = None,
    pytest_status: "Optional[str]" = None,
    pytest_summary: str = "",
    validate_status: "Optional[str]" = None,
    validate_summary: str = "",
    verification_passed: "Optional[bool]" = None,
    stop_reason: str = "",
    notes: str = "",
    tool_argv: "Optional[list]" = None,
    mini_config_yaml: str = "",
    transcript_hash: "Optional[str]" = None,
    coder_assessment: "Optional[str]" = None,
    review_status: "Optional[str]" = None,
    review_provider: "Optional[str]" = None,
    review_model: "Optional[str]" = None,
    review_answers: "Optional[list]" = None,
    review_blocking: "Optional[list]" = None,
    review_summary: "Optional[str]" = None,
    review_error: "Optional[str]" = None,
    review_disagreement: "Optional[bool]" = None,
    classification: "Optional[str]" = None,
    classification_reasons: "Optional[str]" = None,
    reproduction_status: "Optional[str]" = None,
    reproduced: "Optional[bool]" = None,
    reproduction_detail: "Optional[str]" = None,
    reproduction_command: "Optional[str]" = None,
) -> "Optional[AgentRepairRunRecord]":
    """tool_argv/mini_config_yaml/transcript_hash: reproducibility
    fields — the exact argv and generated mini-SWE-agent config YAML
    this run was invoked with, plus a sha256 of the raw transcript file
    bytes actually read back. Populated from secure/agent/runner.py's
    MiniRunResult (fresh runs) or reconstructed from what's still on
    disk (secure/agent/orchestrator.py's resume_repair_run()) — never
    left silently blank on a completed run when the source data is
    available, so a repair stays independently reproducible/auditable
    without requiring the live worktree to still exist."""
    existing = find_agent_repair_run(conn, run_id)
    if existing is None:
        return None
    conn.execute(
        "UPDATE agent_repair_runs SET completed_at = ?, status = ?, tool_version = ?, "
        "transcript_path = ?, agent_exit_status = ?, diff_path = ?, diff_hash = ?, "
        "changed_files_json = ?, denylist_violation = ?, pytest_status = ?, pytest_summary = ?, "
        "validate_status = ?, validate_summary = ?, verification_passed = ?, stop_reason = ?, "
        "notes = ?, tool_argv_json = ?, mini_config_yaml = ?, transcript_hash = ? WHERE run_id = ?",
        (
            completed_at, status, tool_version, transcript_path, agent_exit_status, diff_path,
            diff_hash, json.dumps(changed_files or []), denylist_violation, pytest_status,
            pytest_summary, validate_status, validate_summary,
            None if verification_passed is None else int(verification_passed),
            stop_reason, notes, json.dumps(tool_argv or []), mini_config_yaml, transcript_hash, run_id,
        ),
    )
    # Phase 38 assessments are written in a SEPARATE, all-optional
    # statement rather than being folded into the UPDATE above. Every
    # pre-Phase-38 caller passes none of them and must leave the
    # existing values untouched — a caller that says nothing about the
    # review must never silently blank one out. Only the fields
    # actually supplied are written.
    _set_assessments(
        conn, run_id=run_id, coder_assessment=coder_assessment, review_status=review_status,
        review_provider=review_provider, review_model=review_model, review_answers=review_answers,
        review_blocking=review_blocking, review_summary=review_summary, review_error=review_error,
        review_disagreement=review_disagreement, classification=classification,
        classification_reasons=classification_reasons,
        reproduction_status=reproduction_status, reproduced=reproduced,
        reproduction_detail=reproduction_detail, reproduction_command=reproduction_command,
    )
    conn.commit()
    return find_agent_repair_run(conn, run_id)


def _set_assessments(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    coder_assessment: "Optional[str]" = None,
    review_status: "Optional[str]" = None,
    review_provider: "Optional[str]" = None,
    review_model: "Optional[str]" = None,
    review_answers: "Optional[list]" = None,
    review_blocking: "Optional[list]" = None,
    review_summary: "Optional[str]" = None,
    review_error: "Optional[str]" = None,
    review_disagreement: "Optional[bool]" = None,
    classification: "Optional[str]" = None,
    classification_reasons: "Optional[str]" = None,
    reproduction_status: "Optional[str]" = None,
    reproduced: "Optional[bool]" = None,
    reproduction_detail: "Optional[str]" = None,
    reproduction_command: "Optional[str]" = None,
) -> None:
    assignments: "list[str]" = []
    values: list = []
    for column, value in (
        ("coder_assessment", coder_assessment),
        ("review_status", review_status),
        ("review_provider", review_provider),
        ("review_model", review_model),
        ("review_summary", review_summary),
        ("review_error", review_error),
        ("classification", classification),
        ("classification_reasons", classification_reasons),
        ("reproduction_status", reproduction_status),
        ("reproduction_detail", reproduction_detail),
        ("reproduction_command", reproduction_command),
    ):
        if value is not None:
            assignments.append(f"{column} = ?")
            values.append(value)
    if review_answers is not None:
        assignments.append("review_answers_json = ?")
        values.append(json.dumps(review_answers))
    if review_blocking is not None:
        assignments.append("review_blocking_json = ?")
        values.append(json.dumps(review_blocking))
    if review_disagreement is not None:
        assignments.append("review_disagreement = ?")
        values.append(int(review_disagreement))
    if reproduced is not None:
        assignments.append("reproduced = ?")
        values.append(int(reproduced))
    if not assignments:
        return
    values.append(run_id)
    conn.execute(f"UPDATE agent_repair_runs SET {', '.join(assignments)} WHERE run_id = ?", values)


def set_agent_repair_run_change_request(
    conn: sqlite3.Connection, *, run_id: str, change_request_id: str
) -> "Optional[AgentRepairRunRecord]":
    """Links a completed run to the ai_change_requests row Secure.ai's
    own propose_change() already created. Does not touch that row's
    status — approval state is only ever read by joining to
    ai_change_requests, never copied here."""
    existing = find_agent_repair_run(conn, run_id)
    if existing is None:
        return None
    conn.execute(
        "UPDATE agent_repair_runs SET change_request_id = ? WHERE run_id = ?",
        (change_request_id, run_id),
    )
    conn.commit()
    return find_agent_repair_run(conn, run_id)


def find_agent_repair_run(conn: sqlite3.Connection, run_id: str) -> "Optional[AgentRepairRunRecord]":
    row = conn.execute("SELECT * FROM agent_repair_runs WHERE run_id = ?", (run_id,)).fetchone()
    return _row_to_record(row) if row else None


def list_agent_repair_runs(
    conn: sqlite3.Connection, *, status: "Optional[str]" = None, limit: int = 50
) -> "list[AgentRepairRunRecord]":
    if status is not None:
        rows = conn.execute(
            "SELECT * FROM agent_repair_runs WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM agent_repair_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_record(row) for row in rows]


def list_agent_repair_runs_for_trigger(
    conn: sqlite3.Connection, *, trigger_kind: str, trigger_ref: str, limit: int = 20
) -> "list[AgentRepairRunRecord]":
    """Every prior attempt against the same failure — how
    secure/agent/policy.py decides whether agent_max_attempts has
    already been reached before starting another run."""
    rows = conn.execute(
        "SELECT * FROM agent_repair_runs WHERE trigger_kind = ? AND trigger_ref = ? "
        "ORDER BY id DESC LIMIT ?",
        (trigger_kind, trigger_ref, limit),
    ).fetchall()
    return [_row_to_record(row) for row in rows]


# ---------- Phase 31.5: agent_actions (action audit trail) ----------


@dataclass
class AgentActionRecord:
    id: int
    run_id: "Optional[str]"
    timestamp: str
    component: str
    action: str
    argv: list
    cwd: "Optional[str]"
    target: str
    mutating: bool
    approval_required: bool
    exit_code: "Optional[int]"
    result_summary: str
    duration_seconds: "Optional[float]"


def _row_to_action_record(row: sqlite3.Row) -> AgentActionRecord:
    data = dict(row)
    argv = json.loads(data.pop("argv_json") or "[]")
    return AgentActionRecord(
        argv=argv,
        mutating=bool(data.pop("mutating")),
        approval_required=bool(data.pop("approval_required")),
        **data,
    )


def add_agent_action(
    conn: sqlite3.Connection,
    *,
    run_id: "Optional[str]",
    timestamp: str,
    component: str,
    action: str,
    argv: "Optional[list]" = None,
    cwd: "Optional[str]" = None,
    target: str = "",
    mutating: bool = False,
    approval_required: bool = False,
    exit_code: "Optional[int]" = None,
    result_summary: str = "",
    duration_seconds: "Optional[float]" = None,
) -> int:
    """Persists one already-redacted audited action. This function does
    no redaction of its own — secure/agent/audit.py's record_action()
    is the only intended caller, and it redacts argv/result_summary
    before this ever runs; see that module's docstring for the rules.
    Returns the new row's own integer id (never a public "AA-N" style
    id the way agent_repair_runs has one — this table is queried by
    run_id/timestamp, not referenced elsewhere by its own id)."""
    cur = conn.execute(
        "INSERT INTO agent_actions (run_id, timestamp, component, action, argv_json, cwd, "
        "target, mutating, approval_required, exit_code, result_summary, duration_seconds) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id, timestamp, component, action, json.dumps(argv or []), cwd, target,
            int(mutating), int(approval_required), exit_code, result_summary, duration_seconds,
        ),
    )
    conn.commit()
    return cur.lastrowid


def list_agent_actions(
    conn: sqlite3.Connection, *, run_id: "Optional[str]" = None, limit: int = 200
) -> "list[AgentActionRecord]":
    if run_id is not None:
        rows = conn.execute(
            "SELECT * FROM agent_actions WHERE run_id = ? ORDER BY id DESC LIMIT ?",
            (run_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM agent_actions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_action_record(row) for row in rows]
