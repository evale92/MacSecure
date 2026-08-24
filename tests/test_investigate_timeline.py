"""
Tests for secure/investigate/timeline.py (Phase 23 Stage 3:
build_timeline() and related_evidence(), both built on top of Stage 2's
resolve_entity() and Phase 22's walk_chain()).

Same Database/tmp_path + record_link() fixture convention as
tests/test_correlate_chains.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE, RELATIONSHIP_SAME_EVENT_CONFIRMATION, EvidenceLink, ObservationRef
from secure.evidence.record import record_link
from secure.investigate.entity import PERSISTENCE, PROCESS, EntityRef, persistence_key, process_key
from secure.investigate.timeline import build_timeline, related_evidence
from secure.storage.database import Database
from secure.storage.models import upsert_persistence_entry, upsert_process_entry


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


def _seed_connection_event(conn, *, created_at="2026-01-01T12:00:20+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO connection_events (created_at, run_id, proto, local_addr, local_port, "
        "remote_addr, remote_port, state, pid, process_name) VALUES (?, 'r', 'tcp', '10.0.0.1', "
        "51000, '203.0.113.5', 443, 'ESTABLISHED', 100, 'curl')",
        (created_at,),
    )
    conn.commit()
    return cursor.lastrowid


# ---------- build_timeline() ----------


def test_build_timeline_nonexistent_entity_does_not_exist(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        timeline = build_timeline(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/no/such")))
        assert timeline.exists is False
        assert timeline.events == []


def test_build_timeline_single_anchor_no_links(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        timeline = build_timeline(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert timeline.exists is True
        assert len(timeline.events) == 1
        event = timeline.events[0]
        assert event.source_table == "process_entries"
        assert event.is_anchor is True
        assert event.hops_from_entity == 0


def test_build_timeline_includes_linked_evidence_with_correct_hop_and_anchor_flags(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        persistence_record, _, _ = upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        conn_id = _seed_connection_event(db.conn)

        # process -> persistence (1 hop), persistence -> connection_events (2 hops from process)
        _link(db.conn, "process_entries", process_record.id, "persistence_entries", persistence_record.id, RELATIONSHIP_DERIVED_EVIDENCE)
        _link(db.conn, "persistence_entries", persistence_record.id, "connection_events", conn_id, RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        timeline = build_timeline(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert timeline.exists is True
        by_table = {e.source_table: e for e in timeline.events}
        assert set(by_table) == {"process_entries", "persistence_entries", "connection_events"}

        assert by_table["process_entries"].is_anchor is True
        assert by_table["process_entries"].hops_from_entity == 0
        assert by_table["persistence_entries"].is_anchor is False
        assert by_table["persistence_entries"].hops_from_entity == 1
        assert by_table["connection_events"].is_anchor is False
        assert by_table["connection_events"].hops_from_entity == 2


def test_build_timeline_orders_events_chronologically(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        conn_id = _seed_connection_event(db.conn, created_at="2020-01-01T00:00:00+00:00")
        _link(db.conn, "process_entries", process_record.id, "connection_events", conn_id, RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        timeline = build_timeline(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        # connection_events was seeded with an intentionally much older
        # timestamp than process_entries' own last_seen (set to "now" by
        # upsert_process_entry) — it must sort first.
        assert timeline.events[0].source_table == "connection_events"


def test_build_timeline_row_with_no_timestamp_column_sorts_last(tmp_path: Path):
    # file_watch_paths is deliberately NOT in chain.py's
    # _TIMESTAMP_COLUMN_BY_TABLE — its node's timestamp resolves to
    # None, and it must not crash the sort or disappear from the
    # timeline; it just sorts after every dated event.
    with Database(tmp_path / "test.db") as db:
        from secure.storage.models import add_watch_path

        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        watch_path, _ = add_watch_path(db.conn, "/etc")
        _link(db.conn, "process_entries", process_record.id, "file_watch_paths", watch_path.id, RELATIONSHIP_DERIVED_EVIDENCE)

        timeline = build_timeline(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert timeline.events[-1].source_table == "file_watch_paths"
        assert timeline.events[-1].timestamp is None


# ---------- related_evidence() ----------


def test_related_evidence_nonexistent_entity_does_not_exist(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        related = related_evidence(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/no/such")))
        assert related.exists is False
        assert related.groups == []


def test_related_evidence_excludes_the_entitys_own_anchor(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        related = related_evidence(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert related.exists is True
        assert related.groups == []  # nothing linked, and the anchor itself is never listed as "related"


def test_related_evidence_groups_by_hop_distance(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        persistence_record, _, _ = upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        conn_id = _seed_connection_event(db.conn)

        _link(db.conn, "process_entries", process_record.id, "persistence_entries", persistence_record.id, RELATIONSHIP_DERIVED_EVIDENCE)
        _link(db.conn, "persistence_entries", persistence_record.id, "connection_events", conn_id, RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        related = related_evidence(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert [g.hops for g in related.groups] == [1, 2]
        assert related.groups[0].observations == [ObservationRef(source_table="persistence_entries", source_id=persistence_record.id)]
        assert related.groups[1].observations == [ObservationRef(source_table="connection_events", source_id=conn_id)]
        assert len(related.edges) == 2


def test_related_evidence_from_persistence_entity_sees_process_at_hop_one(tmp_path: Path):
    # Symmetry check: walking FROM the persistence entity reaches the
    # SAME evidence_links row, just starting from the other side.
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        persistence_record, _, _ = upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        _link(db.conn, "process_entries", process_record.id, "persistence_entries", persistence_record.id, RELATIONSHIP_DERIVED_EVIDENCE)

        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))
        related = related_evidence(db.conn, entity)
        assert len(related.groups) == 1
        assert related.groups[0].hops == 1
        assert related.groups[0].observations == [ObservationRef(source_table="process_entries", source_id=process_record.id)]
