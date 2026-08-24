"""
detect.py — Phase 25 Detection Engineering Workbench: `detection_rules`
and `detection_rule_test_runs` — see secure/detect/ and database.py's
own schema comment for the full design reasoning.

Same "this module doesn't interpret, it only persists" separation every
other domain file in this package keeps: this file has no idea what a
Sigma condition or a YARA pattern IS, what "evaluable" means, or how a
fixture decides pass/fail — it only knows how to store and retrieve the
already-decided catalog row and test-run history secure/detect/ hands
it.

`upsert_detection_rule()` is the one function with real behavior worth
calling out: a routine `secure detect sync` re-discovering an
already-known rule must NEVER reset operator-owned state (`enabled`,
`validation_status`, `last_tested_at`, `false_positive_notes`) back to
defaults — only the family's own freshly-discovered facts (title,
source, version, telemetry, capability) are ever overwritten on an
existing row.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class DetectionRuleRecord:
    id: int
    family: str
    rule_key: str
    title: str
    source: str
    version_label: str
    enabled: bool
    required_telemetry: str
    capability_status: str
    capability_reason: str
    validation_status: str
    last_tested_at: "Optional[str]"
    false_positive_notes: str
    first_seen_at: str
    updated_at: str


@dataclass
class DetectionRuleTestRunRecord:
    id: int
    rule_id: int
    tested_at: str
    fixture_name: str
    expected: str
    actual: str
    passed: bool
    detail: str


def _row_to_rule(row: sqlite3.Row) -> DetectionRuleRecord:
    data = dict(row)
    data["enabled"] = bool(data["enabled"])
    return DetectionRuleRecord(**data)


def _row_to_test_run(row: sqlite3.Row) -> DetectionRuleTestRunRecord:
    data = dict(row)
    data["passed"] = bool(data["passed"])
    return DetectionRuleTestRunRecord(**data)


def find_detection_rule_by_id(conn: sqlite3.Connection, rule_id: int) -> "Optional[DetectionRuleRecord]":
    row = conn.execute("SELECT * FROM detection_rules WHERE id = ?", (rule_id,)).fetchone()
    return _row_to_rule(row) if row else None


def find_detection_rule(conn: sqlite3.Connection, family: str, rule_key: str) -> "Optional[DetectionRuleRecord]":
    row = conn.execute(
        "SELECT * FROM detection_rules WHERE family = ? AND rule_key = ?", (family, rule_key)
    ).fetchone()
    return _row_to_rule(row) if row else None


def list_detection_rules(
    conn: sqlite3.Connection,
    *,
    family: "Optional[str]" = None,
    enabled: "Optional[bool]" = None,
    validation_status: "Optional[str]" = None,
    limit: int = 200,
) -> "list[DetectionRuleRecord]":
    clauses = []
    params: list = []
    if family is not None:
        clauses.append("family = ?")
        params.append(family)
    if enabled is not None:
        clauses.append("enabled = ?")
        params.append(1 if enabled else 0)
    if validation_status is not None:
        clauses.append("validation_status = ?")
        params.append(validation_status)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM detection_rules {where}ORDER BY family, rule_key LIMIT ?", params
    ).fetchall()
    return [_row_to_rule(row) for row in rows]


def upsert_detection_rule(
    conn: sqlite3.Connection,
    *,
    family: str,
    rule_key: str,
    title: str,
    source: str,
    version_label: str,
    required_telemetry: str,
    capability_status: str,
    capability_reason: str,
) -> "tuple[DetectionRuleRecord, bool]":
    """Insert a brand-new (family, rule_key), or refresh an existing
    row's discovered facts only. Returns (record, created). Never
    touches `enabled`, `validation_status`, `last_tested_at`, or
    `false_positive_notes` on an existing row — those are operator-
    owned state that a routine re-discovery must never silently reset.
    """
    now = datetime.now(timezone.utc).isoformat()
    existing = find_detection_rule(conn, family, rule_key)

    if existing is None:
        conn.execute(
            "INSERT INTO detection_rules "
            "(family, rule_key, title, source, version_label, enabled, required_telemetry, "
            "capability_status, capability_reason, validation_status, last_tested_at, "
            "false_positive_notes, first_seen_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, 'unvalidated', NULL, '', ?, ?)",
            (family, rule_key, title, source, version_label, required_telemetry,
             capability_status, capability_reason, now, now),
        )
        conn.commit()
        record = find_detection_rule(conn, family, rule_key)
        assert record is not None
        return record, True

    conn.execute(
        "UPDATE detection_rules SET title = ?, source = ?, version_label = ?, "
        "required_telemetry = ?, capability_status = ?, capability_reason = ?, updated_at = ? "
        "WHERE id = ?",
        (title, source, version_label, required_telemetry, capability_status, capability_reason,
         now, existing.id),
    )
    conn.commit()
    record = find_detection_rule_by_id(conn, existing.id)
    assert record is not None
    return record, False


def set_detection_rule_enabled(conn: sqlite3.Connection, rule_id: int, enabled: bool) -> "Optional[DetectionRuleRecord]":
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE id = ?",
        (1 if enabled else 0, now, rule_id),
    )
    conn.commit()
    return find_detection_rule_by_id(conn, rule_id)


def set_detection_rule_validation(
    conn: sqlite3.Connection, rule_id: int, *, validation_status: str, last_tested_at: str
) -> "Optional[DetectionRuleRecord]":
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE detection_rules SET validation_status = ?, last_tested_at = ?, updated_at = ? WHERE id = ?",
        (validation_status, last_tested_at, now, rule_id),
    )
    conn.commit()
    return find_detection_rule_by_id(conn, rule_id)


def set_detection_rule_fp_notes(conn: sqlite3.Connection, rule_id: int, notes: str) -> "Optional[DetectionRuleRecord]":
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE detection_rules SET false_positive_notes = ?, updated_at = ? WHERE id = ?",
        (notes, now, rule_id),
    )
    conn.commit()
    return find_detection_rule_by_id(conn, rule_id)


def add_detection_rule_test_run(
    conn: sqlite3.Connection,
    *,
    rule_id: int,
    tested_at: str,
    fixture_name: str,
    expected: str,
    actual: str,
    passed: bool,
    detail: str,
) -> int:
    cursor = conn.execute(
        "INSERT INTO detection_rule_test_runs "
        "(rule_id, tested_at, fixture_name, expected, actual, passed, detail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rule_id, tested_at, fixture_name, expected, actual, 1 if passed else 0, detail),
    )
    conn.commit()
    return cursor.lastrowid


def list_detection_rule_test_runs(
    conn: sqlite3.Connection, rule_id: int, limit: int = 50
) -> "list[DetectionRuleTestRunRecord]":
    rows = conn.execute(
        "SELECT * FROM detection_rule_test_runs WHERE rule_id = ? ORDER BY id DESC LIMIT ?",
        (rule_id, limit),
    ).fetchall()
    return [_row_to_test_run(row) for row in rows]
