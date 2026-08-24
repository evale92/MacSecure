"""
Tests for Phase 14 Stage 4B: baseline_runs lifecycle bookkeeping —
secure/baseline/engine.py's BaselineRunCounters/finalize_baseline_run(),
and the counters= plumbing through evaluate_and_record_feature_observation()
and secure/baseline/history.py's record_gap_observation().

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline import engine
from secure.baseline.constants import ENTITY_CAPS
from secure.baseline.history import record_gap_observation
from secure.baseline.entities import PROCESS, process_key
from secure.storage.database import Database
from secure.storage.models import (
    add_persistence_alert,
    count_baseline_runs,
    find_latest_baseline_run,
    list_baseline_runs,
)

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat()


def test_clean_run_with_no_activity_is_success(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        counters = engine.BaselineRunCounters()
        started_at = NOW
        engine.finalize_baseline_run(db.conn, "run1", started_at, counters, now=NOW + timedelta(seconds=2))

        run = find_latest_baseline_run(db.conn)
        assert run.run_id == "run1"
        assert run.status == "success"
        assert run.entities_evaluated == 0
        assert run.features_evaluated == 0
        assert run.errors_count == 0
        assert run.error_summary is None
        assert run.duration_seconds == 2.0


def test_clean_run_with_successful_evaluations_is_success(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        counters = engine.BaselineRunCounters()
        for i, entity_key in enumerate(["a::/1.plist", "b::/2.plist", "c::/3.plist"]):
            engine.evaluate_and_record_feature_observation(
                db.conn, "run1", "persistence", entity_key, "signing_status",
                "signed_developer", _iso(NOW), counters=counters,
            )
        engine.finalize_baseline_run(db.conn, "run1", NOW, counters, now=NOW + timedelta(seconds=1))

        run = find_latest_baseline_run(db.conn)
        assert run.status == "success"
        assert run.features_evaluated == 3
        assert run.features_updated == 3
        assert run.comparisons_skipped_insufficient_history == 0
        assert run.incomplete_inputs == 0


def test_incomplete_sensor_input_makes_run_partial(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        counters = engine.BaselineRunCounters()
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "wifi", "GoodNet", "security", "WPA3", _iso(NOW), counters=counters,
        )
        # This one's sensor failed to determine security this scan.
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "wifi", "BadNet", "security", None, _iso(NOW), counters=counters,
        )
        engine.finalize_baseline_run(db.conn, "run1", NOW, counters, now=NOW + timedelta(seconds=1))

        run = find_latest_baseline_run(db.conn)
        assert run.status == "partial"
        assert run.features_evaluated == 2
        assert run.features_updated == 1
        assert run.incomplete_inputs == 1
        assert run.comparisons_skipped_insufficient_history == 1  # superset of incomplete


def test_unreviewed_alert_ineligibility_alone_does_not_make_run_partial(tmp_path: Path):
    # Poisoning-protection eligibility rules doing their job correctly
    # is NOT a degraded pass — only genuinely incomplete/unavailable
    # sensor input or real errors should demote status from 'success'.
    with Database(tmp_path / "test.db") as db:
        add_persistence_alert(
            db.conn, "run0", "unusual_unsigned_process", "high", "launch_agent",
            "/x.plist", "x", "unsigned launch agent",
        )
        counters = engine.BaselineRunCounters()
        result = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", "launch_agent::/x.plist", "signing_status",
            "signed_developer", _iso(NOW), counters=counters,
        )
        assert result is None  # ineligible, never scored
        engine.finalize_baseline_run(db.conn, "run1", NOW, counters, now=NOW + timedelta(seconds=1))

        run = find_latest_baseline_run(db.conn)
        assert run.status == "success"
        assert run.comparisons_skipped_insufficient_history == 1
        assert run.incomplete_inputs == 0


def test_errors_with_some_success_makes_run_partial(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        counters = engine.BaselineRunCounters()
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", "svc:80/tcp", "bind_scope", "localhost",
            _iso(NOW), counters=counters,
        )
        counters.record_error("unexpected KeyError parsing item #4")
        engine.finalize_baseline_run(db.conn, "run1", NOW, counters, now=NOW + timedelta(seconds=1))

        run = find_latest_baseline_run(db.conn)
        assert run.status == "partial"
        assert run.errors_count == 1
        assert run.error_summary == ["unexpected KeyError parsing item #4"]


def test_errors_with_nothing_updated_makes_run_failed(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        counters = engine.BaselineRunCounters()
        counters.record_error("lsof not found")
        counters.record_error("permission denied enumerating sockets")
        engine.finalize_baseline_run(db.conn, "run1", NOW, counters, now=NOW + timedelta(seconds=1))

        run = find_latest_baseline_run(db.conn)
        assert run.status == "failed"
        assert run.errors_count == 2
        assert len(run.error_summary) == 2


def test_record_gap_observation_updates_counters(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        counters = engine.BaselineRunCounters()
        record_gap_observation(
            db.conn, "run1", PROCESS, process_key("/usr/bin/curl"), _iso(NOW), counters=counters,
        )
        record_gap_observation(
            db.conn, "run1", PROCESS, process_key("/usr/bin/ssh"), _iso(NOW), counters=counters,
        )
        assert counters.entities_evaluated == 2
        assert counters.entities_updated == 2
        assert counters.comparisons_skipped == 0


def test_record_gap_observation_counts_cap_skips(tmp_path: Path):
    original_cap = ENTITY_CAPS["process"]
    ENTITY_CAPS["process"] = 1
    try:
        with Database(tmp_path / "test.db") as db:
            counters = engine.BaselineRunCounters()
            record_gap_observation(
                db.conn, "run1", PROCESS, process_key("/usr/bin/curl"), _iso(NOW), counters=counters,
            )
            record_gap_observation(
                db.conn, "run1", PROCESS, process_key("/usr/bin/ssh"), _iso(NOW), counters=counters,
            )
            record_gap_observation(
                db.conn, "run1", PROCESS, process_key("/usr/bin/wget"), _iso(NOW), counters=counters,
            )
            assert counters.entities_evaluated == 3
            assert counters.entities_skipped_cap >= 1
    finally:
        ENTITY_CAPS["process"] = original_cap


def test_list_and_count_baseline_runs_by_status(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        c1 = engine.BaselineRunCounters()
        engine.finalize_baseline_run(db.conn, "run1", NOW, c1, now=NOW)

        c2 = engine.BaselineRunCounters()
        c2.record_error("boom")
        engine.finalize_baseline_run(db.conn, "run2", NOW, c2, now=NOW)

        assert count_baseline_runs(db.conn) == 2
        assert count_baseline_runs(db.conn, status="success") == 1
        assert count_baseline_runs(db.conn, status="failed") == 1
        assert len(list_baseline_runs(db.conn, status="failed")) == 1


def test_baseline_run_list_empty_database(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert list_baseline_runs(db.conn) == []
        assert find_latest_baseline_run(db.conn) is None
        assert count_baseline_runs(db.conn) == 0
