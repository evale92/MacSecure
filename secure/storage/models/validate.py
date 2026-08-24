"""
validate.py — Phase 27 Security Validation: `validation_runs` and
`validation_scenario_results` — see secure/validate/ and database.py's
own schema comment for the full design reasoning.

Same "this module doesn't interpret, it only persists" separation every
other domain file in this package keeps: this file has no idea what a
scenario IS, how a fixture is built, or what counts as PASS vs. PARTIAL
— it only knows how to store and retrieve the already-decided run/
result rows secure/validate/ hands it. Both tables are append-only —
there is no update/delete function in this file, on purpose: a
validation run's own history must never be edited after the fact.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ValidationRunRecord:
    id: int
    run_id: str
    started_at: str
    completed_at: "Optional[str]"
    secure_version: str
    scenario_count: int
    detail: str


@dataclass
class ValidationScenarioResultRecord:
    id: int
    run_id: str
    scenario_id: str
    technique_id: "Optional[str]"
    technique_name: "Optional[str]"
    category: str
    description: str
    expected_result: str
    sensors_observed: "list[str]"
    findings: "list[dict]"
    correlation_result: "Optional[str]"
    explanation_checklist: "dict[str, bool]"
    dedup_result: "Optional[str]"
    latency_ms: "Optional[float]"
    outcome: str
    notes: str
    started_at: str
    completed_at: str


def _row_to_run(row: sqlite3.Row) -> ValidationRunRecord:
    return ValidationRunRecord(**dict(row))


def _row_to_result(row: sqlite3.Row) -> ValidationScenarioResultRecord:
    data = dict(row)
    sensors_observed = json.loads(data.pop("sensors_observed_json"))
    findings = json.loads(data.pop("findings_json"))
    explanation_checklist = json.loads(data.pop("explanation_checklist_json"))
    return ValidationScenarioResultRecord(
        sensors_observed=sensors_observed,
        findings=findings,
        explanation_checklist=explanation_checklist,
        **data,
    )


def add_validation_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    started_at: str,
    secure_version: str,
) -> int:
    cursor = conn.execute(
        "INSERT INTO validation_runs (run_id, started_at, completed_at, secure_version, "
        "scenario_count, detail) VALUES (?, ?, NULL, ?, 0, '')",
        (run_id, started_at, secure_version),
    )
    conn.commit()
    return cursor.lastrowid


def complete_validation_run(
    conn: sqlite3.Connection, *, run_id: str, completed_at: str, scenario_count: int, detail: str
) -> None:
    conn.execute(
        "UPDATE validation_runs SET completed_at = ?, scenario_count = ?, detail = ? WHERE run_id = ?",
        (completed_at, scenario_count, detail, run_id),
    )
    conn.commit()


def find_validation_run(conn: sqlite3.Connection, run_id: str) -> "Optional[ValidationRunRecord]":
    row = conn.execute("SELECT * FROM validation_runs WHERE run_id = ?", (run_id,)).fetchone()
    return _row_to_run(row) if row else None


def find_latest_validation_run(conn: sqlite3.Connection) -> "Optional[ValidationRunRecord]":
    row = conn.execute(
        "SELECT * FROM validation_runs WHERE completed_at IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return _row_to_run(row) if row else None


def list_validation_runs(conn: sqlite3.Connection, limit: int = 50) -> "list[ValidationRunRecord]":
    rows = conn.execute(
        "SELECT * FROM validation_runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_run(row) for row in rows]


def add_validation_scenario_result(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    scenario_id: str,
    technique_id: "Optional[str]",
    technique_name: "Optional[str]",
    category: str,
    description: str,
    expected_result: str,
    sensors_observed: "list[str]",
    findings: "list[dict]",
    correlation_result: "Optional[str]",
    explanation_checklist: "dict[str, bool]",
    dedup_result: "Optional[str]",
    latency_ms: "Optional[float]",
    outcome: str,
    notes: str,
    started_at: str,
    completed_at: "Optional[str]" = None,
) -> int:
    cursor = conn.execute(
        "INSERT INTO validation_scenario_results "
        "(run_id, scenario_id, technique_id, technique_name, category, description, "
        "expected_result, sensors_observed_json, findings_json, correlation_result, "
        "explanation_checklist_json, dedup_result, latency_ms, outcome, notes, started_at, "
        "completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id, scenario_id, technique_id, technique_name, category, description,
            expected_result, json.dumps(sensors_observed), json.dumps(findings),
            correlation_result, json.dumps(explanation_checklist), dedup_result, latency_ms,
            outcome, notes, started_at, completed_at or datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_validation_scenario_results(
    conn: sqlite3.Connection, run_id: str
) -> "list[ValidationScenarioResultRecord]":
    """Every scenario result for one run, unfiltered — this function is
    the report generator's ONLY read path, and it never accepts an
    `outcome` filter on purpose: nothing in this module is able to hide
    a MISS/NOT_EVALUABLE/SENSOR_UNAVAILABLE row from a caller.
    """
    rows = conn.execute(
        "SELECT * FROM validation_scenario_results WHERE run_id = ? ORDER BY id", (run_id,)
    ).fetchall()
    return [_row_to_result(row) for row in rows]
