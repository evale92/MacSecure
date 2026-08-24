"""
Tests for the connection_events real-per-row-id fix (Phase 14 Stage 4C
follow-up, "Option 4" from the process_destination source-identity
STOP): process_destination anomaly provenance now references the exact
underlying connection_events row (source_table="connection_events",
source_id=connection_events.id) instead of an approximation.

Background: connection_events has ALWAYS had a genuine, stable
`id INTEGER PRIMARY KEY AUTOINCREMENT` — no schema migration was
needed. The actual gap was purely in the application layer:
add_connection_events() used to insert its whole batch with one
executemany() call, whose cursor.lastrowid is not a reliable per-row
id in Python's sqlite3 module, so no caller could ever learn which row
got which id. That's fixed by inserting one row at a time (still one
commit for the whole batch) and returning the real ids in insertion
order — see add_connection_events()'s docstring in
secure/storage/models.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import process_destination_key
from secure.connections._shell import ShellResult
from secure.connections.scanner import scan_connections
from secure.storage.database import Database
from secure.storage.models import (
    add_connection_events,
    find_baseline_entity,
    list_anomaly_events,
    list_baseline_entities,
    list_recent_connection_events,
)

NOW = "2026-08-19T12:00:00+00:00"

_HEADER = "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"


def _lsof_line(process, pid, local_port, remote_addr, remote_port, proto="TCP"):
    return (
        f"{process:<10} {pid}  erick   55u  IPv4 0x1111111111111111      0t0  "
        f"{proto} 192.168.1.23:{local_port}->{remote_addr}:{remote_port} (ESTABLISHED)\n"
    )


# ---------- add_connection_events(): real per-row ids ----------


def test_add_connection_events_returns_unique_ids_matching_row_count(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("TCP", "192.168.1.23", 1000 + i, "1.2.3.4", 443, "ESTABLISHED", 100, "Chrome")
            for i in range(5)
        ]
        ids = add_connection_events(db.conn, run_id="run1", rows=rows)

    assert len(ids) == 5
    assert len(set(ids)) == 5  # every id is unique
    assert all(isinstance(i, int) for i in ids)


def test_add_connection_events_ids_correspond_to_the_right_rows(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("TCP", "192.168.1.23", 1000, "1.1.1.1", 443, "ESTABLISHED", 100, "Chrome"),
            ("TCP", "192.168.1.23", 1001, "2.2.2.2", 443, "ESTABLISHED", 200, "curl"),
        ]
        ids = add_connection_events(db.conn, run_id="run1", rows=rows)
        stored = {r.id: r for r in list_recent_connection_events(db.conn)}

    assert stored[ids[0]].remote_addr == "1.1.1.1"
    assert stored[ids[0]].process_name == "Chrome"
    assert stored[ids[1]].remote_addr == "2.2.2.2"
    assert stored[ids[1]].process_name == "curl"


def test_add_connection_events_empty_rows_returns_empty_list(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        ids = add_connection_events(db.conn, run_id="run1", rows=[])
    assert ids == []


def test_add_connection_events_sequential_batches_never_collide(tmp_path: Path):
    # Two separate scans (two separate calls) must never reuse an id —
    # this is what makes source_id a durable, unambiguous reference
    # rather than something only meaningful within one batch.
    with Database(tmp_path / "test.db") as db:
        rows = [("TCP", "192.168.1.23", 1000, "1.1.1.1", 443, "ESTABLISHED", 100, "Chrome")]
        ids1 = add_connection_events(db.conn, run_id="run1", rows=rows)
        ids2 = add_connection_events(db.conn, run_id="run2", rows=rows)
    assert set(ids1).isdisjoint(set(ids2))


# ---------- "migration preserves existing connection_events" ----------


def test_reopening_database_preserves_existing_connection_events_and_ids(tmp_path: Path):
    # Simulates the historical-data concern directly: rows recorded in
    # an earlier session must survive re-opening the database (which
    # re-runs init_schema() — see Database.__enter__) with their exact
    # same ids and contents, not renumbered or discarded.
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        ids = add_connection_events(
            db.conn, run_id="run1",
            rows=[("TCP", "192.168.1.23", 1000, "1.1.1.1", 443, "ESTABLISHED", 100, "Chrome")],
        )
    original_id = ids[0]

    # Re-open — a fresh connection, schema init runs again (CREATE
    # TABLE IF NOT EXISTS + the additive _ensure_column() migrations).
    with Database(db_path) as db:
        rows = list_recent_connection_events(db.conn)
        assert len(rows) == 1
        assert rows[0].id == original_id
        assert rows[0].remote_addr == "1.1.1.1"
        assert rows[0].process_name == "Chrome"

        # New rows inserted after reopening continue the same id space
        # rather than colliding with or resetting past the preserved row.
        new_ids = add_connection_events(
            db.conn, run_id="run2",
            rows=[("TCP", "192.168.1.23", 1001, "2.2.2.2", 443, "ESTABLISHED", 200, "curl")],
        )
    assert new_ids[0] > original_id


# ---------- end-to-end scanner wiring: exact provenance ----------


def test_scan_connections_process_destination_anomaly_references_real_connection_event(
    tmp_path: Path, monkeypatch
):
    import secure.connections.scanner as scanner_module

    stdout = _HEADER + _lsof_line("Chrome", 1234, 54321, "9.9.9.9", 443)
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_connections(db.conn)

        key = process_destination_key("Chrome", "9.9.9.9", 443, "TCP")
        events = list_anomaly_events(db.conn, "process_destination", key)
        assert len(events) == 1
        event = events[0]

        assert event.source_table == "connection_events"
        assert event.source_id is not None

        # The referenced row must be the EXACT connection observation
        # that produced this anomaly — not an approximation like
        # remote_endpoints.id (destination-only, no process) or
        # process_destinations.id (an aggregate dedup row that can span
        # many individual connections).
        rows = {r.id: r for r in list_recent_connection_events(db.conn)}
        referenced = rows[event.source_id]
        assert referenced.process_name == "Chrome"
        assert referenced.remote_addr == "9.9.9.9"
        assert referenced.remote_port == 443
        assert referenced.proto == "TCP"


def test_two_processes_same_destination_remain_distinct_entities(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    stdout = (
        _HEADER
        + _lsof_line("Chrome", 1234, 54321, "1.2.3.4", 443)
        + _lsof_line("curl", 5678, 54322, "1.2.3.4", 443)
    )
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_connections(db.conn)

        chrome_key = process_destination_key("Chrome", "1.2.3.4", 443, "TCP")
        curl_key = process_destination_key("curl", "1.2.3.4", 443, "TCP")
        chrome_entity = find_baseline_entity(db.conn, "process_destination", chrome_key)
        curl_entity = find_baseline_entity(db.conn, "process_destination", curl_key)

    assert chrome_entity is not None
    assert curl_entity is not None
    assert chrome_entity.id != curl_entity.id
    assert chrome_entity.entity_key != curl_entity.entity_key


def test_one_process_two_destinations_remain_distinct_entities(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    stdout = (
        _HEADER
        + _lsof_line("Chrome", 1234, 54321, "1.1.1.1", 443)
        + _lsof_line("Chrome", 1234, 54322, "2.2.2.2", 443)
    )
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_connections(db.conn)

        key_a = process_destination_key("Chrome", "1.1.1.1", 443, "TCP")
        key_b = process_destination_key("Chrome", "2.2.2.2", 443, "TCP")
        entity_a = find_baseline_entity(db.conn, "process_destination", key_a)
        entity_b = find_baseline_entity(db.conn, "process_destination", key_b)

    assert entity_a is not None
    assert entity_b is not None
    assert entity_a.id != entity_b.id


def test_multiple_sockets_same_process_destination_pair_evaluated_once(tmp_path: Path, monkeypatch):
    # Two simultaneous sockets from the same process to the same
    # destination (common — e.g. Chrome opening several connections to
    # the same CDN endpoint) represent ONE (process, destination)
    # relationship, not two — scanner.py's seen_process_destinations_
    # this_scan set is what guarantees "re-evaluating the same
    # connection event must not create duplicate baseline
    # observations" in practice. source_id ends up referencing exactly
    # one of the underlying connection_events rows (the first one
    # encountered) — a real row, never a fabricated/guessed id.
    import secure.connections.scanner as scanner_module

    stdout = (
        _HEADER
        + _lsof_line("Chrome", 1234, 54321, "9.9.9.9", 443)
        + _lsof_line("Chrome", 1234, 54322, "9.9.9.9", 443)
    )
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_connections(db.conn)

        key = process_destination_key("Chrome", "9.9.9.9", 443, "TCP")
        entity = find_baseline_entity(db.conn, "process_destination", key)
        events = list_anomaly_events(db.conn, "process_destination", key)

        assert entity.observation_count == 1  # not 2 — one relationship, one observation
        assert len(events) == 1

        connection_rows = list_recent_connection_events(db.conn)
        assert len(connection_rows) == 2  # both raw sockets ARE still logged individually
        assert events[0].source_id in {r.id for r in connection_rows}


# ---------- idempotence: same run_id, repeat call ----------


def test_repeated_evaluation_same_run_and_source_does_not_duplicate_anomaly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        ids = add_connection_events(
            db.conn, run_id="run1",
            rows=[("TCP", "192.168.1.23", 1000, "1.2.3.4", 443, "ESTABLISHED", 100, "Chrome")],
        )
        event_id = ids[0]
        key = process_destination_key("Chrome", "1.2.3.4", 443, "TCP")

        first = engine.evaluate_and_record_process_destination_observation(
            db.conn, "run1", key, NOW,
            source_table="connection_events", source_id=event_id,
        )
        # A retried/duplicated call for the exact same run_id + same
        # underlying connection observation — must not mint a second
        # anomaly_events row.
        engine.evaluate_and_record_process_destination_observation(
            db.conn, "run1", key, NOW,
            source_table="connection_events", source_id=event_id,
        )

        events = list_anomaly_events(db.conn, "process_destination", key)

    assert len(events) == 1
    assert events[0].source_id == event_id
    assert events[0].id == first["anomaly_event_id"]


# ---------- historical/pre-migration honesty ----------


def test_evaluation_without_known_source_stores_null_not_fabricated(tmp_path: Path):
    # Simulates a hypothetical historical/backfill evaluation where the
    # exact connection_events row can't be determined (e.g. ambiguous
    # matching against old data) — source_table/source_id must be left
    # NULL, never guessed at (no MAX(id), no "closest timestamp", no
    # remote_endpoints.id substitute).
    with Database(tmp_path / "test.db") as db:
        key = process_destination_key("Chrome", "1.2.3.4", 443, "TCP")
        engine.evaluate_and_record_process_destination_observation(db.conn, "run1", key, NOW)

        events = list_anomaly_events(db.conn, "process_destination", key)

    assert len(events) == 1
    assert events[0].source_table is None
    assert events[0].source_id is None


# ---------- rarity against populated baseline_entities ----------


def test_process_destination_rarity_operates_against_populated_baseline_entities(
    tmp_path: Path, monkeypatch
):
    import secure.connections.scanner as scanner_module

    def _stdout_for(dest_ip):
        return _HEADER + _lsof_line("Chrome", 1234, 54321, dest_ip, 443)

    with Database(tmp_path / "test.db") as db:
        monkeypatch.setattr(
            scanner_module, "run",
            lambda *a, **k: ShellResult(ok=True, stdout=_stdout_for("1.1.1.1"), stderr="", returncode=0),
        )
        for _ in range(10):
            scan_connections(db.conn)

        # Real, populated baseline_entities rows — not test fixtures
        # inserted by hand — is what "production-style" means here.
        pd_entities = list_baseline_entities(db.conn, "process_destination")
        assert len(pd_entities) == 1
        assert pd_entities[0].observation_count == 10
        assert pd_entities[0].eligible_weight_total == 10.0

        monkeypatch.setattr(
            scanner_module, "run",
            lambda *a, **k: ShellResult(ok=True, stdout=_stdout_for("9.9.9.9"), stderr="", returncode=0),
        )
        scan_connections(db.conn)

        pd_entities = list_baseline_entities(db.conn, "process_destination")
        assert len(pd_entities) == 2  # sibling now exists alongside the established one

        key = process_destination_key("Chrome", "9.9.9.9", 443, "TCP")
        events = list_anomaly_events(db.conn, "process_destination", key)
        assert len(events) == 1
        # Rarity is scored relative to Chrome's OWN sibling destinations
        # (10 eligible observations to 1.1.1.1, 0 to 9.9.9.9 before this
        # one) — this is score_process_destination_rarity() reading
        # directly from the now-populated baseline_entities table,
        # exactly as Stage 3's approved formula (unchanged here).
        assert events[0].score_breakdown["rarity"] == 40
        assert events[0].source_table == "connection_events"
        assert events[0].source_id is not None
