"""
Tests for secure_gui/tokens.py and secure_gui/data_access.py — the two
Product Phase 12 modules that don't import tkinter, and so are the
only ones this test file can actually exercise. secure_gui/components.py
and secure_gui/alerts_view.py are tkinter-dependent and, like
secure_gui.py itself, are verified only by syntax-checking (ast.parse),
never imported by any test — see PROJECT_NOTES.md and
docs/DESIGN_SYSTEM.md for why.

tokens.py is tested for completeness/safety of its lookup tables (every
severity the backend actually emits must be covered, and every lookup
must have a safe fallback rather than raising or rendering blank).
data_access.py is tested end-to-end against a real temp database
seeded through secure.storage.models, the same "seed a real temp DB"
pattern tests/test_correlate.py already uses for signals.py — this
exercises the real normalization code path, not a mock of it.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import LISTENING, PERSISTENCE, PROCESS, listening_key, persistence_key, process_key
from secure.baseline.history import record_gap_observation
from secure.storage.database import Database
from secure.storage.models import (
    add_arp_alert,
    add_ble_alert,
    add_bluetooth_alert,
    add_correlation_alert,
    add_file_integrity_alert,
    add_persistence_alert,
    add_wifi_alert,
    get_or_create_baseline_entity,
    set_baseline_entity_excluded,
)
from secure_gui import tokens
from secure_gui.data_access import (
    ALERT_MARK_COMMANDS,
    MODULE_LABELS,
    SIGNAL_MODULE_LABELS,
    AlertRow,
    AnomalyRow,
    fetch_baseline_overview,
    list_all_alerts,
    list_all_anomalies,
)

# ---------- tokens.py ----------

# Every severity string any backend module actually emits today. If a
# module starts emitting a new one, it needs to be added to
# tokens.SEVERITY (and to this list) deliberately, not silently fall
# through to "unknown" forever.
BACKEND_SEVERITIES = ["informational", "low", "medium", "high", "critical"]


def test_severity_covers_every_backend_severity_string():
    for sev in BACKEND_SEVERITIES:
        assert sev in tokens.SEVERITY, f"tokens.SEVERITY is missing {sev!r}"


def test_severity_text_never_raises_on_unexpected_input():
    for bad in (None, "", "made_up_severity", "HIGH", "  high  "):
        text = tokens.severity_text(bad)
        assert isinstance(text, str) and text


def test_severity_text_is_case_insensitive():
    assert tokens.severity_text("high") == tokens.severity_text("HIGH") == tokens.severity_text("High")


def test_severity_rank_orders_correctly():
    ranks = [tokens.severity_rank(s) for s in ("informational", "low", "medium", "high", "critical")]
    assert ranks == sorted(ranks), "severity rank should increase with severity"
    assert tokens.severity_rank("critical") > tokens.severity_rank("high")


def test_severity_unknown_fallback_has_lowest_rank():
    assert tokens.severity_rank("nonsense") == tokens.SEVERITY["unknown"]["rank"]
    assert tokens.severity_rank("nonsense") <= tokens.severity_rank("informational")


def test_every_severity_and_status_entry_has_glyph_label_color():
    for table in (tokens.SEVERITY, tokens.SENSOR_STATUS):
        for key, entry in table.items():
            assert entry.get("glyph"), f"{key} missing glyph"
            assert entry.get("label"), f"{key} missing label"
            assert entry.get("color"), f"{key} missing color"


def test_sensor_status_text_never_raises_on_unexpected_input():
    for bad in (None, "", "not_a_real_status"):
        text = tokens.sensor_status_text(bad)
        assert isinstance(text, str) and text


def test_sensor_status_covers_the_seven_documented_states():
    expected = {
        "success",
        "degraded",
        "unavailable",
        "permission_required",
        "timeout",
        "failed",
        "not_yet_run",
    }
    assert expected.issubset(tokens.SENSOR_STATUS.keys())


def test_run_outcome_text_covers_execute_outcomes():
    for outcome in ("success", "findings", "stopped", "timeout", "failed"):
        text = tokens.run_outcome_text(outcome)
        assert isinstance(text, str) and text


def test_empty_state_has_five_distinct_conditions():
    expected = {"no_data_yet", "clean_result", "filtered_empty", "unavailable", "permission_required"}
    assert set(tokens.EMPTY_STATE.keys()) == expected
    # Every state must render distinguishably from every other one —
    # the whole point is that a failed sensor can never look like a
    # clean result.
    seen_headings = [entry["heading"] for entry in tokens.EMPTY_STATE.values()]
    assert len(seen_headings) == len(set(seen_headings))


# ---------- data_access.py ----------


def _seed_one_of_each(conn) -> None:
    add_arp_alert(conn, "run1", "mac_change", "high", "10.0.0.5", "aa:bb", "cc:dd", "MAC changed for 10.0.0.5")
    add_wifi_alert(conn, "run1", "new_ap", "medium", "HomeNet", "aa:aa:aa", "New AP seen for HomeNet")
    add_bluetooth_alert(conn, "run1", "new_device", "low", "dev-1", "AirPods", "New Bluetooth device seen")
    add_ble_alert(conn, "run1", "new_peripheral", "informational", "uuid-1", "Tile", "New BLE peripheral seen")
    add_persistence_alert(
        conn, "run1", "new_agent", "high", "launch_agent", "com.evil.thing", "Evil Thing",
        "New LaunchAgent installed",
    )
    add_file_integrity_alert(conn, "run1", "hash_changed", "critical", "/etc/hosts", "Hash changed for /etc/hosts")
    add_correlation_alert(
        conn, "run1", "fp1", 300.0, "2026-08-19T00:00:00", "2026-08-19T00:05:00",
        3, 3, 80, "high", "multi_module", None,
        "Three related signals seen close together",
        [
            {"module": "arpwatch", "kind": "mac_change", "strength": "STRONG", "identifier": "10.0.0.5",
             "source_table": "arp_alerts", "source_id": 1, "timestamp": "2026-08-19T00:00:00"},
            {"module": "wifi", "kind": "new_ap", "strength": "MEDIUM", "identifier": "HomeNet",
             "source_table": "wifi_alerts", "source_id": 1, "timestamp": "2026-08-19T00:01:00"},
        ],
    )


def test_list_all_alerts_normalizes_all_seven_tables(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_of_each(db.conn)
        rows = list_all_alerts(db.conn, limit=50)

    assert len(rows) == 7
    assert {r.source_table for r in rows} == set(ALERT_MARK_COMMANDS.keys())
    for row in rows:
        assert isinstance(row, AlertRow)
        assert row.summary, f"{row.source_table} row has no summary"
        assert row.module == MODULE_LABELS[row.source_table]
        assert isinstance(row.raw, dict) and row.raw, f"{row.source_table} row has empty raw"


def test_list_all_alerts_sorted_newest_first(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_of_each(db.conn)
        rows = list_all_alerts(db.conn, limit=50)

    created_ats = [r.created_at for r in rows]
    assert created_ats == sorted(created_ats, reverse=True)


def test_list_all_alerts_respects_limit(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_of_each(db.conn)
        rows = list_all_alerts(db.conn, limit=3)

    assert len(rows) == 3


def test_list_all_alerts_empty_db_returns_empty_list(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        rows = list_all_alerts(db.conn, limit=50)
    assert rows == []


def test_every_alert_row_has_a_working_mark_command(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_of_each(db.conn)
        rows = list_all_alerts(db.conn, limit=50)

    for row in rows:
        assert row.mark_command is not None, f"{row.source_table} has no mark command"
        assert row.mark_command == ALERT_MARK_COMMANDS[row.source_table]


def test_arpwatch_mark_command_has_no_alert_suffix(tmp_path: Path):
    # arpwatch is the one exception: `arpwatch mark`, not
    # `arpwatch mark-alert` like the other six tables. Pin this down
    # explicitly since it's easy to "fix" into looking consistent with
    # the others and accidentally break the real CLI routing.
    assert ALERT_MARK_COMMANDS["arp_alerts"] == ("arpwatch", "mark")
    for table, command in ALERT_MARK_COMMANDS.items():
        if table != "arp_alerts":
            assert command[-1] == "mark-alert", f"{table} should route through mark-alert"


def test_correlation_row_deduplicates_and_maps_member_modules(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_of_each(db.conn)
        rows = list_all_alerts(db.conn, limit=50)

    correlation_rows = [r for r in rows if r.source_table == "correlation_alerts"]
    assert len(correlation_rows) == 1
    row = correlation_rows[0]
    # The two members were "arpwatch" and "wifi" — SIGNAL_MODULE_LABELS
    # maps those to human-readable, deduplicated names.
    assert row.contributing_modules == (SIGNAL_MODULE_LABELS["arpwatch"], SIGNAL_MODULE_LABELS["wifi"])
    assert row.evidence_count == 3  # signal_count, not len(members)


def test_correlation_row_falls_back_gracefully_for_unmapped_member_module(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_correlation_alert(
            db.conn, "run1", "fp2", 60.0, "2026-08-19T00:00:00", "2026-08-19T00:01:00",
            1, 1, 20, "low", None, None, "One odd signal",
            [{"module": "some_future_module", "kind": "x", "strength": "WEAK", "identifier": "y",
              "source_table": "?", "source_id": 1, "timestamp": "2026-08-19T00:00:00"}],
        )
        rows = list_all_alerts(db.conn, limit=50)

    row = next(r for r in rows if r.source_table == "correlation_alerts")
    # Must not raise and must not silently drop the module — falls
    # back to the raw string rather than mislabeling it as something
    # else.
    assert row.contributing_modules == ("some_future_module",)


# ---------- Phase 14.5 Stage D: Baseline & Anomalies ----------

# Relative to the real clock: maturity compares last-seen against
# datetime.now() (secure/baseline/maturity.py), so a fixed date here
# silently turns into STALE once it is more than STALE_AFTER_DAYS old.
NOW = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def test_fetch_baseline_overview_empty_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        overview = fetch_baseline_overview(db.conn)

    assert overview.total_entities == 0
    assert overview.maturity_counts == {}
    assert overview.excluded_count == 0
    assert overview.frozen_count == 0
    assert overview.total_anomalies == 0
    assert overview.unreviewed_anomalies == 0
    assert overview.latest_run is None
    assert overview.total_runs == 0


def test_fetch_baseline_overview_reflects_real_entities_and_anomalies(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        record_gap_observation(db.conn, "run1", PROCESS, process_key("/usr/bin/curl"), NOW)
        engine.evaluate_and_record_feature_observation(
            db.conn, "run2", PERSISTENCE, persistence_key("login_item", "/Applications/Dropbox.app"),
            "signing_status", "unsigned", NOW, is_unsigned=True,
        )
        overview = fetch_baseline_overview(db.conn)

    assert overview.total_entities == 1
    assert overview.maturity_counts.get("learning") == 1
    assert overview.total_anomalies == 1
    assert overview.unreviewed_anomalies == 1


def test_list_all_anomalies_normalizes_real_anomaly_event(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", LISTENING, listening_key("sshd", "22", "TCP"),
            "bind_scope", "network", NOW, is_network_bind=True,
        )
        rows = list_all_anomalies(db.conn, limit=50)

    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, AnomalyRow)
    assert row.entity_type == LISTENING
    assert row.feature_name == "bind_scope"
    assert row.observed_value == "network"
    assert row.anomaly_tier in ("low", "medium", "high", "critical")
    assert isinstance(row.score_breakdown, dict) and row.score_breakdown
    assert row.mark_command == ("anomalies", "mark")
    assert isinstance(row.raw, dict) and row.raw


def test_list_all_anomalies_across_multiple_entity_types(tmp_path: Path):
    # list_all_anomalies() must not scope to one entity_type — a global
    # view across every domain is the whole point of this screen.
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", LISTENING, listening_key("sshd", "22", "TCP"),
            "bind_scope", "network", NOW, is_network_bind=True,
        )
        engine.evaluate_and_record_feature_observation(
            db.conn, "run2", PERSISTENCE, persistence_key("login_item", "/Applications/Dropbox.app"),
            "signing_status", "unsigned", NOW, is_unsigned=True,
        )
        rows = list_all_anomalies(db.conn, limit=50)

    assert {r.entity_type for r in rows} == {LISTENING, PERSISTENCE}


def test_anomaly_row_caveats_flag_excluded_entity(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", PERSISTENCE, persistence_key("login_item", "/Applications/Dropbox.app"),
            "signing_status", "unsigned", NOW, is_unsigned=True,
        )
        rows = list_all_anomalies(db.conn, limit=50)
        entity_key = rows[0].entity_key
        # Exclude via the real model function, same one `secure baseline
        # exclude` uses, then re-fetch — the caveat must reflect real
        # current state, not a fabricated one.
        entity, _ = get_or_create_baseline_entity(db.conn, PERSISTENCE, entity_key)
        set_baseline_entity_excluded(db.conn, entity.id, True)
        rows_after = list_all_anomalies(db.conn, limit=50)

    assert any("EXCLUDED" in c for c in rows_after[0].caveats)


def test_anomaly_row_no_caveats_when_nothing_has_changed(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", LISTENING, listening_key("sshd", "22", "TCP"),
            "bind_scope", "network", NOW, is_network_bind=True,
        )
        rows = list_all_anomalies(db.conn, limit=50)

    # Feature-only entity_types (listening/persistence) never get an
    # automatic baseline_entities row from a scanner (see
    # get_or_create_baseline_entity()'s docstring) — that absence
    # itself is the one expected, honest caveat, not silence.
    assert len(rows[0].caveats) == 1
    assert "no entity-level baseline record" in rows[0].caveats[0].lower()
