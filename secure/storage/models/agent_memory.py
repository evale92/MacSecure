"""
agent_memory.py — Phase 45 Maintenance Memory:
`agent_maintenance_memory`. See secure/agent/memory.py for the logic
that decides what to record, and database.py's own schema comment for
the design reasoning.

Same "this module doesn't interpret, it only persists" separation every
other domain file in this package keeps.

One property worth stating here rather than only in the agent layer:
there is no UPDATE function in this module except
`link_regression()`, and that one only ever fills two columns that
were NULL. A maintenance record is written once, from facts already
established deterministically, and is not editable afterward — a
history that can be rewritten is not a history.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MaintenanceMemoryRecord:
    id: int
    recorded_at: str
    run_id: str
    failure_signature: str
    trigger_kind: str
    trigger_ref: str
    affected_component: str
    root_cause: str
    repair_strategy: str
    framework: str
    model_name: str
    files_changed: list
    base_commit: str
    diff_hash: "Optional[str]"
    verification_summary: str
    verified: "Optional[bool]"
    reviewer_assessment: str
    classification: "Optional[str]"
    approval_decision: str
    change_request_id: "Optional[str]"
    outcome: str
    rollback: str
    regression_run_id: "Optional[str]" = None
    regression_note: str = ""


def _row_to_record(row: sqlite3.Row) -> MaintenanceMemoryRecord:
    data = dict(row)
    files_changed = json.loads(data.pop("files_changed_json") or "[]")
    verified = data.pop("verified")
    return MaintenanceMemoryRecord(
        files_changed=files_changed,
        verified=None if verified is None else bool(verified),
        **data,
    )


def add_maintenance_memory(
    conn: sqlite3.Connection,
    *,
    recorded_at: str,
    run_id: str,
    failure_signature: str,
    trigger_kind: str,
    trigger_ref: str,
    outcome: str,
    affected_component: str = "",
    root_cause: str = "",
    repair_strategy: str = "",
    framework: str = "",
    model_name: str = "",
    files_changed: "Optional[list]" = None,
    base_commit: str = "",
    diff_hash: "Optional[str]" = None,
    verification_summary: str = "",
    verified: "Optional[bool]" = None,
    reviewer_assessment: str = "",
    classification: "Optional[str]" = None,
    approval_decision: str = "none",
    change_request_id: "Optional[str]" = None,
    rollback: str = "",
) -> int:
    cursor = conn.execute(
        "INSERT INTO agent_maintenance_memory ("
        "recorded_at, run_id, failure_signature, trigger_kind, trigger_ref, affected_component, "
        "root_cause, repair_strategy, framework, model_name, files_changed_json, base_commit, "
        "diff_hash, verification_summary, verified, reviewer_assessment, classification, "
        "approval_decision, change_request_id, outcome, rollback"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            recorded_at, run_id, failure_signature, trigger_kind, trigger_ref, affected_component,
            root_cause, repair_strategy, framework, model_name, json.dumps(files_changed or []),
            base_commit, diff_hash, verification_summary,
            None if verified is None else int(verified),
            reviewer_assessment, classification, approval_decision, change_request_id, outcome, rollback,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def find_maintenance_memory_for_run(
    conn: sqlite3.Connection, run_id: str
) -> "Optional[MaintenanceMemoryRecord]":
    row = conn.execute(
        "SELECT * FROM agent_maintenance_memory WHERE run_id = ? ORDER BY id DESC LIMIT 1", (run_id,)
    ).fetchone()
    return _row_to_record(row) if row else None


def list_maintenance_memory(
    conn: sqlite3.Connection, *, limit: int = 50
) -> "list[MaintenanceMemoryRecord]":
    rows = conn.execute(
        "SELECT * FROM agent_maintenance_memory ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def find_maintenance_memory_by_signature(
    conn: sqlite3.Connection, failure_signature: str, *, limit: int = 20
) -> "list[MaintenanceMemoryRecord]":
    rows = conn.execute(
        "SELECT * FROM agent_maintenance_memory WHERE failure_signature = ? ORDER BY id DESC LIMIT ?",
        (failure_signature, limit),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def find_maintenance_memory_by_component(
    conn: sqlite3.Connection, component: str, *, limit: int = 20
) -> "list[MaintenanceMemoryRecord]":
    """Looser than a signature match — used when nothing shares the
    exact signature but prior work touched the same area."""
    rows = conn.execute(
        "SELECT * FROM agent_maintenance_memory WHERE affected_component LIKE ? ORDER BY id DESC LIMIT ?",
        (f"%{component}%", limit),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def link_regression(
    conn: sqlite3.Connection, *, memory_id: int, regression_run_id: str, note: str = ""
) -> "Optional[MaintenanceMemoryRecord]":
    """The one UPDATE in this module. Fills two columns that were NULL
    when a later failure is attributed to this repair; changes nothing
    else, and never rewrites what was originally recorded."""
    conn.execute(
        "UPDATE agent_maintenance_memory SET regression_run_id = ?, regression_note = ? WHERE id = ?",
        (regression_run_id, note, memory_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM agent_maintenance_memory WHERE id = ?", (memory_id,)).fetchone()
    return _row_to_record(row) if row else None


# ---------------------------------------------------------------------
# Phase 46 — observed external tool versions
# ---------------------------------------------------------------------


@dataclass
class ToolVersionRecord:
    id: int
    component: str
    tool_version: str
    first_seen: str
    last_seen: str


def record_tool_version(
    conn: sqlite3.Connection, *, component: str, tool_version: str, seen_at: str
) -> None:
    """Upserts one OBSERVATION. Recording a version never pins,
    requires, or installs anything — see the schema comment."""
    existing = conn.execute(
        "SELECT id FROM agent_tool_versions WHERE component = ? AND tool_version = ?",
        (component, tool_version),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE agent_tool_versions SET last_seen = ? WHERE id = ?", (seen_at, existing["id"])
        )
    else:
        conn.execute(
            "INSERT INTO agent_tool_versions (component, tool_version, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?)",
            (component, tool_version, seen_at, seen_at),
        )
    conn.commit()


def latest_tool_version(conn: sqlite3.Connection, component: str) -> "Optional[ToolVersionRecord]":
    row = conn.execute(
        "SELECT * FROM agent_tool_versions WHERE component = ? ORDER BY last_seen DESC, id DESC LIMIT 1",
        (component,),
    ).fetchone()
    return ToolVersionRecord(**dict(row)) if row else None


def list_tool_versions(conn: sqlite3.Connection, component: str) -> "list[ToolVersionRecord]":
    rows = conn.execute(
        "SELECT * FROM agent_tool_versions WHERE component = ? ORDER BY id", (component,)
    ).fetchall()
    return [ToolVersionRecord(**dict(r)) for r in rows]
