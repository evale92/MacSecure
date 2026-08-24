"""
Tests for secure/storage/models/dfir.py (Phase 24 Stage 1: schema +
storage for forensic_collections / forensic_evidence_items).

Same Database/tmp_path convention as the rest of this test suite.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.integrations.base import STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE
from secure.storage.database import Database
from secure.storage.models import (
    add_forensic_collection,
    add_forensic_evidence_item,
    find_forensic_collection_by_id,
    find_forensic_evidence_item_by_id,
    list_forensic_collections,
    list_forensic_evidence_items_for_collection,
)


def _add_collection(conn, **overrides):
    defaults = dict(
        requested_at="2026-01-01T12:00:00+00:00",
        started_at="2026-01-01T12:00:01+00:00",
        completed_at="2026-01-01T12:00:05+00:00",
        artifact_name="MacOS.System.Pslist",
        parameters={"pid": 123},
        reason="investigating suspicious curl process",
        entity_type="process",
        entity_key="/usr/bin/curl",
        source_table="persistence_alerts",
        source_id=1,
        status=STATUS_OK,
        detail="collection completed",
        tool_version="0.7.0",
    )
    defaults.update(overrides)
    return add_forensic_collection(conn, **defaults)


def test_add_and_find_forensic_collection_round_trips_every_field(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        collection_id = _add_collection(db.conn)
        record = find_forensic_collection_by_id(db.conn, collection_id)
        assert record is not None
        assert record.artifact_name == "MacOS.System.Pslist"
        assert record.parameters == {"pid": 123}
        assert record.reason == "investigating suspicious curl process"
        assert record.entity_type == "process"
        assert record.entity_key == "/usr/bin/curl"
        assert record.source_table == "persistence_alerts"
        assert record.source_id == 1
        assert record.status == STATUS_OK
        assert record.tool_version == "0.7.0"
        assert record.evidence_item_count == 0


def test_find_forensic_collection_missing_id_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert find_forensic_collection_by_id(db.conn, 999) is None


def test_forensic_collection_preserves_unavailable_and_error_status_honestly(tmp_path: Path):
    # The instruction's own explicit requirement: a failed/unavailable
    # collection must be stored AS unavailable/error, never silently
    # coerced into anything that reads as "ran cleanly, found nothing."
    with Database(tmp_path / "test.db") as db:
        unavailable_id = _add_collection(
            db.conn, status=STATUS_UNAVAILABLE, detail="velociraptor binary not found",
            started_at=None, completed_at=None, tool_version=None,
        )
        error_id = _add_collection(
            db.conn, status=STATUS_ERROR, detail="collection process exited nonzero",
        )
        unavailable = find_forensic_collection_by_id(db.conn, unavailable_id)
        error = find_forensic_collection_by_id(db.conn, error_id)
        assert unavailable.status == STATUS_UNAVAILABLE
        assert unavailable.started_at is None
        assert error.status == STATUS_ERROR


def test_list_forensic_collections_filters_by_entity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        _add_collection(db.conn, entity_type="process", entity_key="/usr/bin/curl")
        _add_collection(db.conn, entity_type="process", entity_key="/usr/bin/ssh")
        results = list_forensic_collections(db.conn, entity_type="process", entity_key="/usr/bin/curl")
        assert len(results) == 1
        assert results[0].entity_key == "/usr/bin/curl"


def test_list_forensic_collections_most_recent_first(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        first_id = _add_collection(db.conn)
        second_id = _add_collection(db.conn)
        results = list_forensic_collections(db.conn)
        assert [r.id for r in results] == [second_id, first_id]


def test_add_and_list_forensic_evidence_items(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        collection_id = _add_collection(db.conn)
        add_forensic_evidence_item(
            db.conn, collection_id=collection_id, kind="MacOS.System.Pslist",
            raw_row_index=0, fields={"pid": 123, "name": "curl"}, collected_at="2026-01-01T12:00:03+00:00",
        )
        add_forensic_evidence_item(
            db.conn, collection_id=collection_id, kind="MacOS.System.Pslist",
            raw_row_index=1, fields={"pid": 456, "name": "bash"}, collected_at="2026-01-01T12:00:03+00:00",
        )
        items = list_forensic_evidence_items_for_collection(db.conn, collection_id)
        assert len(items) == 2
        assert items[0].fields == {"pid": 123, "name": "curl"}
        assert items[1].raw_row_index == 1


def test_find_forensic_evidence_item_by_id(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        collection_id = _add_collection(db.conn)
        item_id = add_forensic_evidence_item(
            db.conn, collection_id=collection_id, kind="MacOS.System.Pslist",
            raw_row_index=0, fields={"pid": 123}, collected_at="2026-01-01T12:00:03+00:00",
        )
        item = find_forensic_evidence_item_by_id(db.conn, item_id)
        assert item is not None
        assert item.collection_id == collection_id
        assert find_forensic_evidence_item_by_id(db.conn, 999999) is None


def test_re_collection_of_same_artifact_creates_a_second_independent_collection(tmp_path: Path):
    # Forensic evidence is a point-in-time snapshot, not an ongoing
    # identity table — collecting the same artifact against the same
    # entity twice must never merge or overwrite the earlier collection.
    with Database(tmp_path / "test.db") as db:
        first_id = _add_collection(db.conn)
        second_id = _add_collection(db.conn)
        assert first_id != second_id
        assert find_forensic_collection_by_id(db.conn, first_id) is not None
        assert find_forensic_collection_by_id(db.conn, second_id) is not None
