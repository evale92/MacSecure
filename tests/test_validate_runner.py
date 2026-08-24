"""
Tests for secure/validate/runner.py — Phase 27 Stage 7. run_validation_suite()
is the orchestration layer: it must run every registered scenario
exactly once, against its own fresh sandbox, and persist both the run
and every individual result into the CALLER's database (never the
sandbox) — unfiltered, including MISS/NOT_EVALUABLE/SENSOR_UNAVAILABLE
rows.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import find_latest_validation_run, find_validation_run, list_validation_scenario_results
from secure.validate import VALID_OUTCOMES
from secure.validate.runner import all_scenario_functions, run_validation_suite


def _real_db(tmp_path: Path) -> Database:
    return Database(tmp_path / "real.db")


def test_run_validation_suite_persists_a_run_record(tmp_path: Path):
    with _real_db(tmp_path) as db:
        summary = run_validation_suite(db.conn)
        run = find_validation_run(db.conn, summary.run_id)

    assert run is not None
    assert run.run_id == summary.run_id
    assert run.completed_at is not None
    assert run.scenario_count == summary.total_count


def test_run_validation_suite_persists_every_scenario_result_unfiltered(tmp_path: Path):
    with _real_db(tmp_path) as db:
        summary = run_validation_suite(db.conn)
        stored = list_validation_scenario_results(db.conn, summary.run_id)

    assert len(stored) == summary.total_count == len(all_scenario_functions())
    stored_ids = {r.scenario_id for r in stored}
    summary_ids = {r.scenario_id for r in summary.results}
    assert stored_ids == summary_ids

    # At least one non-PASS outcome must exist and be genuinely present in
    # storage — nothing in this path is able to drop a MISS/NOT_EVALUABLE/
    # SENSOR_UNAVAILABLE row before it reaches the database.
    non_pass = [r for r in stored if r.outcome != "PASS"]
    assert len(non_pass) > 0


def test_counts_by_outcome_always_includes_every_outcome_key_even_at_zero(tmp_path: Path):
    with _real_db(tmp_path) as db:
        summary = run_validation_suite(db.conn)

    assert set(summary.counts_by_outcome.keys()) == set(VALID_OUTCOMES)
    assert sum(summary.counts_by_outcome.values()) == summary.total_count


def test_run_validation_suite_leaves_the_operators_real_database_otherwise_untouched(tmp_path: Path):
    # A second, unrelated table write before/after the run must survive
    # completely unaffected — proves scenario fixture injection never
    # touches the caller's conn, only the final persisted result rows do.
    from secure.storage.models import add_watch_path, list_watch_paths

    with _real_db(tmp_path) as db:
        add_watch_path(db.conn, "/tmp/operators-own-watch-path", sensitivity="normal")
        run_validation_suite(db.conn)
        paths = list_watch_paths(db.conn)

    assert len(paths) == 1
    assert paths[0].path == "/tmp/operators-own-watch-path"


def test_two_consecutive_runs_get_independent_run_ids_and_both_persist(tmp_path: Path):
    with _real_db(tmp_path) as db:
        first = run_validation_suite(db.conn)
        second = run_validation_suite(db.conn)

        assert first.run_id != second.run_id
        assert len(list_validation_scenario_results(db.conn, first.run_id)) == first.total_count
        assert len(list_validation_scenario_results(db.conn, second.run_id)) == second.total_count

        latest = find_latest_validation_run(db.conn)
        assert latest.run_id == second.run_id
