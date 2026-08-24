"""
Tests for secure/storage/models/detect.py (Phase 25 Stage 1:
detection_rules + detection_rule_test_runs storage). Pure storage
tests only — no secure/detect/ orchestration logic exists yet.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import (
    add_detection_rule_test_run,
    find_detection_rule,
    find_detection_rule_by_id,
    list_detection_rule_test_runs,
    list_detection_rules,
    set_detection_rule_enabled,
    set_detection_rule_fp_notes,
    set_detection_rule_validation,
    upsert_detection_rule,
)


def _upsert(conn, **overrides):
    base = dict(
        family="sigma", rule_key="rule-1", title="Suspicious cmdline", source="/rules/rule-1.yml",
        version_label="rule-1@abc123", required_telemetry="osquery:process_creation",
        capability_status="evaluable", capability_reason="ok",
    )
    base.update(overrides)
    return upsert_detection_rule(conn, **base)


def test_upsert_creates_new_row_with_defaults(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, created = _upsert(db.conn)
        assert created is True
        assert record.family == "sigma"
        assert record.rule_key == "rule-1"
        assert record.enabled is True
        assert record.validation_status == "unvalidated"
        assert record.last_tested_at is None
        assert record.false_positive_notes == ""
        assert record.first_seen_at == record.updated_at


def test_upsert_same_identity_updates_not_inserts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        first, created1 = _upsert(db.conn)
        second, created2 = _upsert(db.conn, title="Suspicious cmdline v2", version_label="rule-1@def456")
        assert created1 is True
        assert created2 is False
        assert first.id == second.id
        assert second.title == "Suspicious cmdline v2"
        assert second.version_label == "rule-1@def456"
        assert list_detection_rules(db.conn) == [second] or len(list_detection_rules(db.conn)) == 1


def test_upsert_never_resets_operator_owned_state_on_resync(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = _upsert(db.conn)
        set_detection_rule_enabled(db.conn, record.id, False)
        set_detection_rule_fp_notes(db.conn, record.id, "fires on legit admin scripts")
        set_detection_rule_validation(db.conn, record.id, validation_status="passed", last_tested_at="2026-01-01T00:00:00+00:00")

        # A routine resync with fresh discovered facts must not disturb
        # any of the operator-owned columns just set above.
        resynced, created = _upsert(db.conn, title="new title", capability_status="not_evaluable")
        assert created is False
        assert resynced.enabled is False
        assert resynced.false_positive_notes == "fires on legit admin scripts"
        assert resynced.validation_status == "passed"
        assert resynced.last_tested_at == "2026-01-01T00:00:00+00:00"
        assert resynced.title == "new title"
        assert resynced.capability_status == "not_evaluable"


def test_different_family_same_rule_key_is_a_distinct_row(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        sigma_record, _ = _upsert(db.conn, family="sigma", rule_key="shared-key")
        yarax_record, _ = _upsert(db.conn, family="yarax", rule_key="shared-key")
        assert sigma_record.id != yarax_record.id


def test_find_detection_rule_by_family_and_key(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = _upsert(db.conn)
        found = find_detection_rule(db.conn, "sigma", "rule-1")
        assert found is not None
        assert found.id == record.id
        assert find_detection_rule(db.conn, "sigma", "nonexistent") is None


def test_list_detection_rules_filters(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        r1, _ = _upsert(db.conn, family="sigma", rule_key="a")
        r2, _ = _upsert(db.conn, family="yarax", rule_key="b")
        set_detection_rule_enabled(db.conn, r2.id, False)

        assert [r.id for r in list_detection_rules(db.conn, family="sigma")] == [r1.id]
        assert [r.id for r in list_detection_rules(db.conn, enabled=False)] == [r2.id]
        assert len(list_detection_rules(db.conn)) == 2


def test_set_detection_rule_enabled_toggles(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = _upsert(db.conn)
        assert record.enabled is True
        updated = set_detection_rule_enabled(db.conn, record.id, False)
        assert updated.enabled is False
        updated2 = set_detection_rule_enabled(db.conn, record.id, True)
        assert updated2.enabled is True


def test_set_detection_rule_enabled_missing_id_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert set_detection_rule_enabled(db.conn, 999, False) is None


def test_add_and_list_detection_rule_test_runs(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = _upsert(db.conn)
        run_id = add_detection_rule_test_run(
            db.conn, rule_id=record.id, tested_at="2026-01-01T00:00:00+00:00",
            fixture_name="suspicious", expected="fire", actual="fire", passed=True, detail="matched",
        )
        assert run_id is not None
        runs = list_detection_rule_test_runs(db.conn, record.id)
        assert len(runs) == 1
        assert runs[0].passed is True
        assert runs[0].fixture_name == "suspicious"


def test_test_runs_are_append_only_history(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, _ = _upsert(db.conn)
        add_detection_rule_test_run(
            db.conn, rule_id=record.id, tested_at="2026-01-01T00:00:00+00:00",
            fixture_name="benign", expected="no_fire", actual="no_fire", passed=True, detail="d1",
        )
        add_detection_rule_test_run(
            db.conn, rule_id=record.id, tested_at="2026-01-02T00:00:00+00:00",
            fixture_name="suspicious", expected="fire", actual="no_fire", passed=False, detail="d2",
        )
        runs = list_detection_rule_test_runs(db.conn, record.id)
        assert len(runs) == 2
        # Most recent first (ORDER BY id DESC)
        assert runs[0].fixture_name == "suspicious"
        assert runs[0].passed is False
        assert runs[1].fixture_name == "benign"


def test_find_detection_rule_by_id_missing_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert find_detection_rule_by_id(db.conn, 999) is None
