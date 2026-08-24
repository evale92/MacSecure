"""
Tests for the listening-domain provenance fix (Phase 14.5 Stage B):
bind_scope anomaly provenance now references the exact underlying
listening_events row (source_table="listening_events",
source_id=listening_events.id) instead of listening_services.id.

Background: add_listening_events() previously used one
conn.executemany() call for the whole scan's rows and returned
nothing — cursor.lastrowid after executemany() is not a reliable
per-row id in Python's sqlite3 module, the same gap
add_connection_events() had. Fixed by inserting one row at a time
(still one commit for the whole batch) and returning the real ids in
insertion order — see add_listening_events()'s docstring in
secure/storage/models.py. secure/listening/scanner.py was then wired
to reference the exact row that produced each entry's bind_scope
observation, instead of listening_services.id (a DEDUPED identity row
updated in place across every scan of the same service).

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import listening_key
from secure.connections._shell import ShellResult
from secure.listening.scanner import scan_listening_services
from secure.storage.database import Database
from secure.storage.models import (
    add_listening_events,
    list_anomaly_events,
    list_recent_listening_events,
)

NOW = "2026-08-19T12:00:00+00:00"

_HEADER = "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"


def _listening_line(process, pid, local_addr, local_port, proto="TCP"):
    if proto == "TCP":
        return (
            f"{process:<10} {pid}  erick   3u  IPv4 0x1111111111111111      0t0  "
            f"TCP {local_addr}:{local_port} (LISTEN)\n"
        )
    return (
        f"{process:<10} {pid}  erick   3u  IPv4 0x1111111111111111      0t0  "
        f"UDP {local_addr}:{local_port}\n"
    )


# ---------- add_listening_events(): real per-row ids ----------


def test_add_listening_events_returns_unique_ids_matching_row_count(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("TCP", "*", 8000 + i, "network", 100, "sshd")
            for i in range(5)
        ]
        ids = add_listening_events(db.conn, run_id="run1", rows=rows)

    assert len(ids) == 5
    assert len(set(ids)) == 5
    assert all(isinstance(i, int) for i in ids)


def test_add_listening_events_ids_correspond_to_the_right_rows(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("TCP", "*", 22, "network", 100, "sshd"),
            ("TCP", "127.0.0.1", 49220, "localhost", 200, "Postman"),
        ]
        ids = add_listening_events(db.conn, run_id="run1", rows=rows)
        stored = {r.id: r for r in list_recent_listening_events(db.conn, limit=50)}

    assert stored[ids[0]].process_name == "sshd"
    assert stored[ids[0]].local_port == 22
    assert stored[ids[1]].process_name == "Postman"
    assert stored[ids[1]].local_port == 49220


def test_add_listening_events_empty_rows_returns_empty_list(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        ids = add_listening_events(db.conn, run_id="run1", rows=[])
    assert ids == []


def test_add_listening_events_sequential_batches_never_collide(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [("TCP", "*", 22, "network", 100, "sshd")]
        ids1 = add_listening_events(db.conn, run_id="run1", rows=rows)
        ids2 = add_listening_events(db.conn, run_id="run2", rows=rows)
    assert set(ids1).isdisjoint(set(ids2))


# ---------- end-to-end scanner wiring: exact provenance ----------


def test_scan_listening_bind_scope_references_real_listening_event(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    stdout = _HEADER + _listening_line("sshd", 99, "*", 22)
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_listening_services(db.conn)

        key = listening_key("sshd", "22", "TCP")
        events = list_anomaly_events(db.conn, "listening", key)
        assert len(events) == 1
        event = events[0]

        assert event.source_table == "listening_events"
        assert event.source_id is not None

        # The referenced row must be the EXACT scan observation, not
        # listening_services.id — an aggregate identity row updated in
        # place across every scan of this service.
        rows = {r.id: r for r in list_recent_listening_events(db.conn, limit=50)}
        referenced = rows[event.source_id]
        assert referenced.process_name == "sshd"
        assert referenced.local_port == 22
        assert referenced.proto == "TCP"


def test_scan_listening_two_services_remain_distinct_anomaly_sources(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    stdout = (
        _HEADER
        + _listening_line("sshd", 99, "*", 22)
        + _listening_line("mDNSRespo", 80, "*", 5353, proto="UDP")
    )
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_listening_services(db.conn)

        sshd_key = listening_key("sshd", "22", "TCP")
        mdns_key = listening_key("mDNSRespo", "5353", "UDP")
        sshd_events = list_anomaly_events(db.conn, "listening", sshd_key)
        mdns_events = list_anomaly_events(db.conn, "listening", mdns_key)

    assert len(sshd_events) == 1
    assert len(mdns_events) == 1
    assert sshd_events[0].source_id != mdns_events[0].source_id


def test_scan_listening_duplicate_socket_same_service_evaluated_once(tmp_path: Path, monkeypatch):
    # lsof commonly lists the same listener twice (IPv4 + IPv6) — one
    # service identity, one baseline observation, but both raw sockets
    # are still logged individually in listening_events.
    import secure.listening.scanner as scanner_module

    stdout = (
        _HEADER
        + _listening_line("sshd", 99, "*", 22)
        + _listening_line("sshd", 99, "*", 22)
    )
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_listening_services(db.conn)

        key = listening_key("sshd", "22", "TCP")
        events = list_anomaly_events(db.conn, "listening", key)
        event_rows = list_recent_listening_events(db.conn, limit=50)

    assert len(events) == 1
    assert len(event_rows) == 2  # both raw sockets still logged
    assert events[0].source_id in {r.id for r in event_rows}


# ---------- idempotence: same run_id, repeat call ----------


def test_repeated_evaluation_same_run_and_source_does_not_duplicate_anomaly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        ids = add_listening_events(
            db.conn, run_id="run1", rows=[("TCP", "*", 22, "network", 100, "sshd")],
        )
        event_id = ids[0]
        key = listening_key("sshd", "22", "TCP")

        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", key, "bind_scope", "network", NOW,
            is_network_bind=True,
            source_table="listening_events", source_id=event_id,
        )
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", key, "bind_scope", "network", NOW,
            is_network_bind=True,
            source_table="listening_events", source_id=event_id,
        )

        events = list_anomaly_events(db.conn, "listening", key)

    assert len(events) == 1
    assert events[0].source_id == event_id


# ---------- historical/pre-migration honesty ----------


def test_evaluation_without_known_source_stores_null_not_fabricated(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = listening_key("sshd", "22", "TCP")
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", key, "bind_scope", "network", NOW,
            is_network_bind=True,
        )

        events = list_anomaly_events(db.conn, "listening", key)

    assert len(events) == 1
    assert events[0].source_table is None
    assert events[0].source_id is None
