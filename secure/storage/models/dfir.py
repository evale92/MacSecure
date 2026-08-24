"""
dfir.py — Phase 24 Targeted DFIR Integration: `forensic_collections`
and `forensic_evidence_items` — see secure/dfir/ and database.py's own
schema comment for the full design reasoning.

Same "this module doesn't interpret, it only persists" separation every
other domain file in this package keeps: this file has no idea what
Velociraptor is, what an artifact does, or what counts as an allowed
artifact name (that check happens in secure/dfir/ BEFORE any of these
functions are ever called) — it only knows how to store and retrieve
the already-decided collection attempt and its already-normalized
result rows.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ForensicCollectionRecord:
    id: int
    created_at: str
    requested_at: str
    started_at: "Optional[str]"
    completed_at: "Optional[str]"
    artifact_name: str
    parameters_json: str
    reason: str
    entity_type: str
    entity_key: str
    source_table: "Optional[str]"
    source_id: "Optional[int]"
    status: str
    detail: str
    tool_version: "Optional[str]"
    evidence_item_count: int

    @property
    def parameters(self) -> dict:
        return json.loads(self.parameters_json) if self.parameters_json else {}


@dataclass
class ForensicEvidenceItemRecord:
    id: int
    created_at: str
    collection_id: int
    kind: str
    raw_row_index: int
    fields_json: str
    collected_at: str

    @property
    def fields(self) -> dict:
        return json.loads(self.fields_json) if self.fields_json else {}


def _row_to_collection(row: sqlite3.Row) -> ForensicCollectionRecord:
    return ForensicCollectionRecord(**dict(row))


def _row_to_evidence_item(row: sqlite3.Row) -> ForensicEvidenceItemRecord:
    return ForensicEvidenceItemRecord(**dict(row))


def add_forensic_collection(
    conn: sqlite3.Connection,
    *,
    requested_at: str,
    started_at: "Optional[str]",
    completed_at: "Optional[str]",
    artifact_name: str,
    parameters: dict,
    reason: str,
    entity_type: str,
    entity_key: str,
    source_table: "Optional[str]",
    source_id: "Optional[int]",
    status: str,
    detail: str,
    tool_version: "Optional[str]",
    evidence_item_count: int = 0,
) -> int:
    """Insert one forensic_collections row and return its new id.
    Always an INSERT, recording the collection attempt's OUTCOME — the
    caller (secure/dfir/collector.py) has already run the collection
    (or determined it couldn't be run) by the time this is called, so
    `status`/`detail`/`tool_version` here are final, not placeholders.
    `reason` and every other request field are recorded exactly as the
    operator supplied them at the moment of the explicit
    `secure dfir collect` invocation — that invocation IS the approval
    (see database.py's own schema comment for why there is no separate
    request/approve row).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO forensic_collections "
        "(created_at, requested_at, started_at, completed_at, artifact_name, parameters_json, "
        "reason, entity_type, entity_key, source_table, source_id, status, detail, "
        "tool_version, evidence_item_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            created_at, requested_at, started_at, completed_at, artifact_name,
            json.dumps(parameters), reason, entity_type, entity_key, source_table, source_id,
            status, detail, tool_version, evidence_item_count,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def find_forensic_collection_by_id(conn: sqlite3.Connection, collection_id: int) -> "Optional[ForensicCollectionRecord]":
    row = conn.execute("SELECT * FROM forensic_collections WHERE id = ?", (collection_id,)).fetchone()
    return _row_to_collection(row) if row else None


def list_forensic_collections(
    conn: sqlite3.Connection,
    *,
    entity_type: "Optional[str]" = None,
    entity_key: "Optional[str]" = None,
    limit: int = 100,
) -> "list[ForensicCollectionRecord]":
    """Most recent collections first, optionally filtered to one
    entity — the read behind `secure dfir list` and an entity's own
    collection history.
    """
    clauses = []
    params: list = []
    if entity_type is not None:
        clauses.append("entity_type = ?")
        params.append(entity_type)
    if entity_key is not None:
        clauses.append("entity_key = ?")
        params.append(entity_key)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM forensic_collections {where}ORDER BY id DESC LIMIT ?", params
    ).fetchall()
    return [_row_to_collection(row) for row in rows]


def add_forensic_evidence_item(
    conn: sqlite3.Connection,
    *,
    collection_id: int,
    kind: str,
    raw_row_index: int,
    fields: dict,
    collected_at: str,
) -> int:
    """Insert one normalized forensic evidence row and return its new
    id. Always an INSERT — every row from a fresh collection is, by
    definition, new; there is no dedup concept here (a re-collection of
    the same artifact is a genuinely new forensic_collections row with
    its own full set of evidence items, never merged into an earlier
    one — forensic evidence is a point-in-time snapshot, not an
    ongoing identity table).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO forensic_evidence_items "
        "(created_at, collection_id, kind, raw_row_index, fields_json, collected_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (created_at, collection_id, kind, raw_row_index, json.dumps(fields), collected_at),
    )
    conn.commit()
    return cursor.lastrowid


def find_forensic_evidence_item_by_id(conn: sqlite3.Connection, item_id: int) -> "Optional[ForensicEvidenceItemRecord]":
    row = conn.execute("SELECT * FROM forensic_evidence_items WHERE id = ?", (item_id,)).fetchone()
    return _row_to_evidence_item(row) if row else None


def list_forensic_evidence_items_for_collection(
    conn: sqlite3.Connection, collection_id: int, limit: int = 500
) -> "list[ForensicEvidenceItemRecord]":
    rows = conn.execute(
        "SELECT * FROM forensic_evidence_items WHERE collection_id = ? ORDER BY raw_row_index ASC LIMIT ?",
        (collection_id, limit),
    ).fetchall()
    return [_row_to_evidence_item(row) for row in rows]
