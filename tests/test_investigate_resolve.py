"""
Tests for secure/investigate/resolve.py (Phase 23 Stage 2: entity
resolution, both directions) — plus the small number of new read-only
storage functions added alongside it
(list_process_destinations_for_process/_for_remote,
find_remote_endpoint_by_identity, find_file_entries_by_hash).

Same Database/tmp_path convention as the rest of this test suite.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.evidence.model import ObservationRef
from secure.investigate.entity import (
    DESTINATION,
    FILE,
    INDICATOR,
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
from secure.investigate.resolve import resolve_entity, resolve_observation
from secure.storage.database import Database
from secure.storage.models import (
    add_watch_path,
    find_remote_endpoint_by_identity,
    insert_file_entry,
    list_process_destinations_for_process,
    list_process_destinations_for_remote,
    upsert_persistence_entry,
    upsert_process_destination,
    upsert_process_entry,
    upsert_remote_endpoint,
)


# ---------- resolve_entity() ----------


def test_resolve_process_found(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        result = resolve_entity(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert result.exists is True
        assert result.summary["executable_path"] == "/usr/bin/curl"
        assert result.anchors == [ObservationRef(source_table="process_entries", source_id=result.anchors[0].source_id)]


def test_resolve_process_not_found(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        result = resolve_entity(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/no/such/path")))
        assert result.exists is False
        assert result.anchors == []


def test_resolve_process_destination(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_destination(db.conn, "curl", "203.0.113.5", 443, "tcp")
        key = process_destination_key("curl", "203.0.113.5", 443, "tcp")
        result = resolve_entity(db.conn, EntityRef(entity_type=PROCESS_DESTINATION, entity_key=key))
        assert result.exists is True
        assert result.summary["remote_addr"] == "203.0.113.5"


def test_resolve_destination_independent_of_process(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_remote_endpoint(db.conn, "203.0.113.5", 443, "tcp", "curl")
        key = destination_key("203.0.113.5", 443, "tcp")
        result = resolve_entity(db.conn, EntityRef(entity_type=DESTINATION, entity_key=key))
        assert result.exists is True
        assert result.summary["process_name"] == "curl"
        assert result.anchors[0].source_table == "remote_endpoints"


def test_resolve_persistence(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/bin/x", "signed")
        key = persistence_key("launch_agent", "/x.plist")
        result = resolve_entity(db.conn, EntityRef(entity_type=PERSISTENCE, entity_key=key))
        assert result.exists is True
        assert result.summary["path"] == "/x.plist"


def test_resolve_file(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        watch_path, _ = add_watch_path(db.conn, "/etc")
        insert_file_entry(db.conn, watch_path.id, "/etc/hosts", {"hash": "abc123", "is_executable": 0, "is_symlink": 0, "unreadable": 0}, known=True)
        result = resolve_entity(db.conn, EntityRef(entity_type=FILE, entity_key=file_key("/etc/hosts")))
        assert result.exists is True
        assert result.summary["hash"] == "abc123"


def test_resolve_indicator_hash_cross_references_file_entries(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        watch_path, _ = add_watch_path(db.conn, "/etc")
        insert_file_entry(db.conn, watch_path.id, "/etc/hosts", {"hash": "deadbeef" * 8, "is_executable": 0, "is_symlink": 0, "unreadable": 0}, known=True)
        entity = EntityRef(entity_type=INDICATOR, entity_key=f"hash:{'deadbeef' * 8}")
        result = resolve_entity(db.conn, entity)
        assert result.exists is True
        assert result.summary["matching_file_count"] == 1
        assert result.anchors[0].source_table == "file_entries"


def test_resolve_indicator_with_nothing_on_record_does_not_exist(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity = EntityRef(entity_type=INDICATOR, entity_key="ip:8.8.8.8")
        result = resolve_entity(db.conn, entity)
        assert result.exists is False


def test_resolve_unknown_watch_path_id_is_not_found(tmp_path: Path):
    from secure.investigate.entity import FILE_WATCH_PATH

    with Database(tmp_path / "test.db") as db:
        result = resolve_entity(db.conn, EntityRef(entity_type=FILE_WATCH_PATH, entity_key="999"))
        assert result.exists is False


# ---------- resolve_observation() (reverse direction) ----------


def test_resolve_observation_process_entries(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        refs = resolve_observation(db.conn, ObservationRef(source_table="process_entries", source_id=record.id))
        assert refs == [EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))]


def test_resolve_observation_process_destinations_yields_two_entities(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_process_destination(db.conn, "curl", "203.0.113.5", 443, "tcp")
        refs = resolve_observation(db.conn, ObservationRef(source_table="process_destinations", source_id=record.id))
        types = {r.entity_type for r in refs}
        assert types == {PROCESS_DESTINATION, DESTINATION}


def test_resolve_observation_anomaly_events_reuses_stored_entity_columns(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        cursor = db.conn.execute(
            "INSERT INTO anomaly_events (created_at, run_id, entity_type, entity_key, feature_name, "
            "observed_value, observed_at, expected_summary, score_breakdown, anomaly_score, anomaly_tier, "
            "maturity_state_at_time, eligible_weight_total_at_time, eligible_distinct_days_at_time, "
            "source_table, source_id, known) VALUES "
            "('2026-01-01T00:00:00+00:00', 'r', 'process', 'process:/usr/bin/curl', 'signing_status', "
            "'unsigned', '2026-01-01T00:00:00+00:00', 'usually signed', '{}', 5, 'weak', 'mature', 10.0, 5, "
            "'process_entries', 1, 0)"
        )
        db.conn.commit()
        refs = resolve_observation(db.conn, ObservationRef(source_table="anomaly_events", source_id=cursor.lastrowid))
        assert refs == [EntityRef(entity_type=PROCESS, entity_key="process:/usr/bin/curl")]


def test_resolve_observation_unrecognized_table_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        refs = resolve_observation(db.conn, ObservationRef(source_table="integration_alerts", source_id=1))
        assert refs == []


def test_resolve_observation_missing_row_returns_empty_not_raise(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        refs = resolve_observation(db.conn, ObservationRef(source_table="process_entries", source_id=999999))
        assert refs == []


# ---------- new storage read functions ----------


def test_list_process_destinations_for_process(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_destination(db.conn, "curl", "203.0.113.5", 443, "tcp")
        upsert_process_destination(db.conn, "curl", "203.0.113.6", 80, "tcp")
        upsert_process_destination(db.conn, "other", "203.0.113.7", 443, "tcp")
        results = list_process_destinations_for_process(db.conn, "curl")
        assert len(results) == 2
        assert all(r.process_name == "curl" for r in results)


def test_list_process_destinations_for_remote(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_destination(db.conn, "curl", "203.0.113.5", 443, "tcp")
        upsert_process_destination(db.conn, "other", "203.0.113.5", 443, "tcp")
        upsert_process_destination(db.conn, "curl", "203.0.113.6", 443, "tcp")
        results = list_process_destinations_for_remote(db.conn, "203.0.113.5", 443, "tcp")
        assert len(results) == 2
        assert {r.process_name for r in results} == {"curl", "other"}


def test_find_remote_endpoint_by_identity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_remote_endpoint(db.conn, "203.0.113.5", 443, "tcp", "curl")
        found = find_remote_endpoint_by_identity(db.conn, "203.0.113.5", 443, "tcp")
        assert found is not None
        assert found.process_name == "curl"
        assert find_remote_endpoint_by_identity(db.conn, "203.0.113.9", 443, "tcp") is None
