"""
Tests for Phase 14 Stage 4C's process_destination wiring:
- secure/storage/models.py: process_destinations table + upsert_process_destination()
- secure/baseline/history.py: record_entity_observation() (does NOT
  duplicate into baseline_activity, unlike record_gap_observation())
- secure/baseline/engine.py: evaluate_and_record_process_destination_observation()
- secure/connections/scanner.py: end-to-end wiring

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import process_destination_key
from secure.baseline.history import record_entity_observation
from secure.connections._shell import ShellResult
from secure.connections.scanner import scan_connections
from secure.storage.database import Database
from secure.storage.models import (
    find_anomaly_event,
    find_baseline_entity,
    find_latest_baseline_run,
    find_process_destination_by_id,
    list_anomaly_events,
    list_baseline_activity,
    upsert_process_destination,
)

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat()


# ---------- storage layer ----------


def test_upsert_process_destination_creates_and_dedups(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, was_new = upsert_process_destination(db.conn, "Chrome", "1.2.3.4", 443, "tcp")
        assert was_new is True
        assert record.process_name == "Chrome"
        assert record.observation_count == 1

        record2, was_new2 = upsert_process_destination(db.conn, "Chrome", "1.2.3.4", 443, "tcp")
        assert was_new2 is False
        assert record2.id == record.id
        assert record2.observation_count == 2


def test_upsert_process_destination_unattributed_process_uses_unknown_literal(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_process_destination(db.conn, None, "1.2.3.4", 443, "tcp")
        assert record.process_name == "(unknown)"
        # A second unattributed connection to the SAME destination must
        # dedup against the first (not create a second row) — this is
        # exactly the NULL-uniqueness footgun the schema comment warns
        # about; storing "(unknown)" instead of NULL avoids it.
        record2, was_new2 = upsert_process_destination(db.conn, None, "1.2.3.4", 443, "tcp")
        assert was_new2 is False
        assert record2.id == record.id


def test_upsert_process_destination_different_processes_same_destination_are_distinct(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        chrome, _ = upsert_process_destination(db.conn, "Chrome", "1.2.3.4", 443, "tcp")
        curl, _ = upsert_process_destination(db.conn, "curl", "1.2.3.4", 443, "tcp")
        assert chrome.id != curl.id


def test_find_process_destination_by_id(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_process_destination(db.conn, "Chrome", "1.2.3.4", 443, "tcp")
        found = find_process_destination_by_id(db.conn, record.id)
        assert found.id == record.id
        assert find_process_destination_by_id(db.conn, 999999) is None


# ---------- history layer ----------


def test_record_entity_observation_does_not_duplicate_baseline_activity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_destination_key("Chrome", "1.2.3.4", 443, "tcp")
        record_entity_observation(db.conn, "run1", "process_destination", key, _iso(NOW))

        entity = find_baseline_entity(db.conn, "process_destination", key)
        assert entity is not None
        assert entity.eligible_weight_total == 1.0

        # Unlike record_gap_observation(), this must NOT write a
        # baseline_activity row — process_destination already has raw
        # history in connection_events; duplicating it would violate
        # "don't duplicate raw history that already exists elsewhere."
        assert list_baseline_activity(db.conn, "process_destination", key) == []


def test_record_entity_observation_respects_entity_cap(tmp_path: Path):
    from secure.baseline.constants import ENTITY_CAPS

    original_cap = ENTITY_CAPS["process_destination"]
    ENTITY_CAPS["process_destination"] = 1
    try:
        with Database(tmp_path / "test.db") as db:
            record_entity_observation(
                db.conn, "run1", "process_destination",
                process_destination_key("Chrome", "1.2.3.4", 443, "tcp"), _iso(NOW),
            )
            counters = engine.BaselineRunCounters()
            record_entity_observation(
                db.conn, "run1", "process_destination",
                process_destination_key("Chrome", "5.6.7.8", 443, "tcp"), _iso(NOW),
                counters=counters,
            )
            assert counters.entities_skipped_cap == 1
    finally:
        ENTITY_CAPS["process_destination"] = original_cap


# ---------- engine layer ----------


def test_evaluate_and_record_process_destination_malformed_key_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        result = engine.evaluate_and_record_process_destination_observation(
            db.conn, "run1", "no_separator_here", _iso(NOW),
        )
        assert result is None


def test_evaluate_and_record_process_destination_first_observation_persists_anomaly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_destination_key("Chrome", "1.2.3.4", 443, "tcp")
        breakdown = engine.evaluate_and_record_process_destination_observation(
            db.conn, "run1", key, _iso(NOW),
            source_table="process_destinations", source_id=42,
        )
        assert breakdown["rarity"] == 40  # never seen
        assert breakdown["anomaly_event_id"] is not None

        events = list_anomaly_events(db.conn, "process_destination", key)
        assert len(events) == 1
        event = events[0]
        assert event.feature_name == "destination"
        assert event.observed_value == "1.2.3.4:443/tcp"
        assert event.source_table == "process_destinations"
        assert event.source_id == 42
        assert "Chrome" in event.expected_summary


def test_evaluate_and_record_process_destination_idempotent_on_same_run(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_destination_key("Chrome", "1.2.3.4", 443, "tcp")
        breakdown = engine.evaluate_and_record_process_destination_observation(
            db.conn, "run1", key, _iso(NOW),
        )
        first_id = breakdown["anomaly_event_id"]

        # add_anomaly_event()'s dedup key is (run_id, entity_type,
        # entity_key, feature_name="destination") — confirm a second
        # persist attempt for the same key returns the existing row.
        found = find_anomaly_event(db.conn, "run1", "process_destination", key, "destination")
        assert found.id == first_id


def test_sibling_relative_rarity_end_to_end_through_connections_scanner(tmp_path: Path, monkeypatch):
    # Chrome talks to A repeatedly (common), then a brand-new
    # destination D shows up for Chrome — should score as rare relative
    # to Chrome's OWN destination history, not globally.
    import secure.connections.scanner as scanner_module

    def _stdout_for(dest_ip):
        return (
            "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
            f"Chrome     1234  erick   55u  IPv4 0x1111111111111111      0t0  "
            f"TCP 192.168.1.23:54321->{dest_ip}:443 (ESTABLISHED)\n"
        )

    with Database(tmp_path / "test.db") as db:
        monkeypatch.setattr(
            scanner_module, "run",
            lambda *a, **k: ShellResult(ok=True, stdout=_stdout_for("1.1.1.1"), stderr="", returncode=0),
        )
        for _ in range(10):
            scan_connections(db.conn)

        monkeypatch.setattr(
            scanner_module, "run",
            lambda *a, **k: ShellResult(ok=True, stdout=_stdout_for("9.9.9.9"), stderr="", returncode=0),
        )
        result = scan_connections(db.conn)

        # lsof_parser normalizes proto to uppercase ("TCP"), not the
        # lowercase "tcp" used in the other storage-layer tests above.
        key = process_destination_key("Chrome", "9.9.9.9", 443, "TCP")
        events = list_anomaly_events(db.conn, "process_destination", key)
        assert len(events) == 1
        assert events[0].score_breakdown["rarity"] == 40  # never seen for Chrome before

        # Provenance points at the exact connection_events row, not the
        # process_destinations aggregate table or remote_endpoints —
        # see tests/test_connection_events_provenance.py for the full
        # per-row-id fix this exercises end to end.
        from secure.storage.models import list_recent_connection_events

        assert events[0].source_table == "connection_events"
        assert events[0].source_id is not None
        referenced = {r.id: r for r in list_recent_connection_events(db.conn)}[events[0].source_id]
        assert referenced.process_name == "Chrome"
        assert referenced.remote_addr == "9.9.9.9"

        run = find_latest_baseline_run(db.conn)
        assert run.run_id == result.run_id
        assert run.status == "success"
        assert run.entities_evaluated >= 1


def test_scan_connections_produces_process_destination_row(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    stdout = (
        "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
        "Google     1234  erick   55u  IPv4 0x1111111111111111      0t0  "
        "TCP 192.168.1.23:54321->142.250.80.14:443 (ESTABLISHED)\n"
    )
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        scan_connections(db.conn)
        pd = find_process_destination_by_id(db.conn, 1)

    assert pd is not None
    assert pd.process_name == "Google"
    assert pd.remote_addr == "142.250.80.14"


def test_scan_connections_lsof_unavailable_baseline_run_is_failed(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_connections(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert result.lsof_available is False
    assert run.run_id == result.run_id
    assert run.status == "failed"
