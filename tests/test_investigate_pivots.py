"""
Tests for secure/investigate/pivots.py (Phase 23 Stage 4: pivot
discovery — evidence-linked pivots via resolve_observation() +
native/structural pivots via existing filtered list_*_for_*()
functions and each entity's own resolved summary fields).

Same Database/tmp_path + record_link() fixture convention as
tests/test_investigate_timeline.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE, EvidenceLink, ObservationRef
from secure.evidence.record import record_link
from secure.investigate.entity import (
    DESTINATION,
    FILE,
    PERSISTENCE,
    PROCESS,
    PROCESS_DESTINATION,
    EntityRef,
    destination_key,
    file_key,
    persistence_key,
    process_destination_key,
    process_key,
)
from secure.investigate.pivots import discover_pivots
from secure.storage.database import Database
from secure.storage.models import (
    add_watch_path,
    insert_file_entry,
    upsert_persistence_entry,
    upsert_process_destination,
    upsert_process_entry,
    upsert_remote_endpoint,
)


def _link(conn, from_table, from_id, to_table, to_id, relationship, *, detail="test"):
    record_link(
        conn,
        EvidenceLink(
            from_ref=ObservationRef(source_table=from_table, source_id=from_id),
            to_ref=ObservationRef(source_table=to_table, source_id=to_id),
            relationship=relationship,
            match_basis="identity+timing",
            detail=detail,
            created_by="test",
        ),
    )


def test_discover_pivots_nonexistent_entity_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        pivots = discover_pivots(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/no/such")))
        assert pivots == []


def test_discover_pivots_no_relationships_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        pivots = discover_pivots(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert pivots == []


def test_discover_pivots_evidence_linked_reaches_persistence(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        persistence_record, _, _ = upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        _link(db.conn, "process_entries", process_record.id, "persistence_entries", persistence_record.id, RELATIONSHIP_DERIVED_EVIDENCE)

        pivots = discover_pivots(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        entities = {p.entity for p in pivots}
        assert EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist")) in entities
        # the persistence pivot must be grounded in the exact observation that produced it
        persistence_pivot = next(p for p in pivots if p.entity.entity_type == PERSISTENCE)
        assert persistence_pivot.via == ObservationRef(source_table="persistence_entries", source_id=persistence_record.id)


def test_discover_pivots_native_process_to_destination(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        dest_record, _ = upsert_process_destination(db.conn, "curl", "203.0.113.5", 443, "tcp")

        pivots = discover_pivots(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        entities = {p.entity for p in pivots}
        expected = EntityRef(
            entity_type=PROCESS_DESTINATION,
            entity_key=process_destination_key("curl", "203.0.113.5", 443, "tcp"),
        )
        assert expected in entities


def test_discover_pivots_native_destination_to_process(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        upsert_process_destination(db.conn, "curl", "203.0.113.5", 443, "tcp")
        upsert_remote_endpoint(db.conn, "203.0.113.5", 443, "tcp", "curl")

        entity = EntityRef(entity_type=DESTINATION, entity_key=destination_key("203.0.113.5", 443, "tcp"))
        pivots = discover_pivots(db.conn, entity)
        entities = {p.entity for p in pivots}
        assert EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")) in entities


def test_discover_pivots_native_persistence_to_running_process(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")

        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))
        pivots = discover_pivots(db.conn, entity)
        entities = {p.entity for p in pivots}
        assert EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")) in entities


def test_discover_pivots_persistence_program_path_not_a_running_process_is_omitted(tmp_path: Path):
    # program_path exists but no matching process_entries row is on
    # record — must not fabricate a pivot to a process that isn't
    # actually known to exist.
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))
        pivots = discover_pivots(db.conn, entity)
        assert pivots == []


def test_discover_pivots_native_file_to_running_process(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        watch_path, _ = add_watch_path(db.conn, "/etc")
        insert_file_entry(
            db.conn, watch_path.id, "/etc/hosts",
            {"hash": "abc", "is_executable": 0, "is_symlink": 0, "unreadable": 0, "program_path": "/usr/bin/curl"},
            known=True,
        )

        entity = EntityRef(entity_type=FILE, entity_key=file_key("/etc/hosts"))
        pivots = discover_pivots(db.conn, entity)
        entities = {p.entity for p in pivots}
        assert EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")) in entities


def test_discover_pivots_never_includes_the_entity_itself(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        persistence_record, _, _ = upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        _link(db.conn, "process_entries", process_record.id, "persistence_entries", persistence_record.id, RELATIONSHIP_DERIVED_EVIDENCE)

        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
        pivots = discover_pivots(db.conn, entity)
        assert entity not in {p.entity for p in pivots}
