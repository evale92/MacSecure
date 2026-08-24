"""
Tests for the Phase 14 Stage 3 storage extension:
baseline_feature_activity and baseline_feature_maturity
(secure/storage/models.py + database.py).

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database, init_schema
from secure.storage.models import (
    add_baseline_feature_activity,
    find_baseline_feature_maturity,
    get_or_create_baseline_feature_maturity,
    list_baseline_feature_activity,
    record_baseline_observation,
    record_feature_maturity_observation,
    set_baseline_entity_maturity,
    set_baseline_feature_maturity_state,
)


def test_schema_creates_feature_activity_and_maturity_tables(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        tables = {
            row["name"]
            for row in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert "baseline_feature_activity" in tables
    assert "baseline_feature_maturity" in tables


def test_init_schema_idempotent_with_feature_tables(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        init_schema(db.conn)
        init_schema(db.conn)


def test_add_baseline_feature_activity_is_append_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_baseline_feature_activity(
            db.conn, "run1", "persistence", "launch_agent_user::/x.plist",
            "signing_status", "signed_developer", "2026-08-01T00:00:00+00:00",
            True, "eligible", 1.0,
        )
        add_baseline_feature_activity(
            db.conn, "run2", "persistence", "launch_agent_user::/x.plist",
            "signing_status", "signed_developer", "2026-08-02T00:00:00+00:00",
            True, "eligible", 1.0,
        )
        rows = list_baseline_feature_activity(
            db.conn, "persistence", "launch_agent_user::/x.plist", "signing_status"
        )
        assert len(rows) == 2


def test_repeated_unchanged_feature_values_are_both_logged(tmp_path: Path):
    # "signed_developer, signed_developer, signed_developer" must each
    # be their own row — frequency needs every observation, not just
    # the first/changed ones (Phase 14 extension approval item 5).
    with Database(tmp_path / "test.db") as db:
        for day in range(1, 5):
            add_baseline_feature_activity(
                db.conn, f"run{day}", "persistence", "launch_agent_user::/x.plist",
                "signing_status", "signed_developer", f"2026-08-0{day}T00:00:00+00:00",
                True, "eligible", 1.0,
            )
        rows = list_baseline_feature_activity(
            db.conn, "persistence", "launch_agent_user::/x.plist", "signing_status"
        )
        assert len(rows) == 4
        assert all(r.feature_value == "signed_developer" for r in rows)


def test_feature_value_none_is_stored_for_unavailable_sensor(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_baseline_feature_activity(
            db.conn, "run1", "wifi", "SomeNet", "security", None,
            "2026-08-01T00:00:00+00:00", False, "partial_sensor_data", 0.0,
        )
        rows = list_baseline_feature_activity(db.conn, "wifi", "SomeNet", "security")
        assert rows[0].feature_value is None
        assert rows[0].eligible is False
        assert rows[0].eligibility_reason == "partial_sensor_data"


def test_feature_maturity_starts_at_no_baseline(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        feature, was_new = get_or_create_baseline_feature_maturity(
            db.conn, "persistence", "launch_agent_user::/x.plist", "signing_status"
        )
        assert was_new is True
        assert feature.maturity_state == "no_baseline"
        assert feature.observation_count == 0


def test_feature_maturity_is_independent_of_entity_maturity(tmp_path: Path):
    # A process/persistence entity can have a long, mature history
    # (tracked in baseline_entities via record_gap_observation
    # elsewhere) while its signing_status FEATURE history is brand new
    # — this table has no connection to baseline_entities at all,
    # which is exactly the independence required.
    with Database(tmp_path / "test.db") as db:
        for day in range(1, 4):
            record_feature_maturity_observation(
                db.conn, "persistence", "launch_agent_user::/x.plist", "signing_status",
                f"2026-08-0{day}T00:00:00+00:00", True, 1.0,
            )
        feature = find_baseline_feature_maturity(
            db.conn, "persistence", "launch_agent_user::/x.plist", "signing_status"
        )
        assert feature.observation_count == 3
        assert feature.eligible_weight_total == 3.0
        # Far below MIN_ELIGIBLE_OBSERVATIONS/DISTINCT_DAYS/SPAN — still
        # LEARNING regardless of whatever the parent entity's own
        # baseline_entities row says.
        from secure.baseline import maturity

        state = maturity.compute_maturity(
            eligible_weight_total=feature.eligible_weight_total,
            eligible_distinct_days=feature.eligible_distinct_days,
            first_eligible_observed_at=feature.first_eligible_observed_at,
            last_eligible_observed_at=feature.last_eligible_observed_at,
            last_observed_at=feature.last_observed_at,
        )
        assert state == maturity.LEARNING


def test_set_baseline_feature_maturity_state(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        feature, _ = get_or_create_baseline_feature_maturity(
            db.conn, "wifi", "HomeNet", "security"
        )
        set_baseline_feature_maturity_state(db.conn, feature.id, "established")
        updated = find_baseline_feature_maturity(db.conn, "wifi", "HomeNet", "security")
        assert updated.maturity_state == "established"


def test_ineligible_feature_observation_does_not_advance_eligible_counters(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        feature = record_feature_maturity_observation(
            db.conn, "listening", "svc:80/tcp", "bind_scope",
            "2026-08-01T00:00:00+00:00", False, 0.0,
        )
        assert feature.observation_count == 1  # visible for audit
        assert feature.eligible_weight_total == 0
        assert feature.first_eligible_observed_at is None


def test_no_fabricated_backfill_despite_mature_entity_history(tmp_path: Path):
    # A persistence entity can already have years of ENTITY-level
    # history (baseline_entities, via record_baseline_observation, e.g.
    # from Stage 2's gap-filling) at the moment Stage 3's feature
    # logging for signing_status ships. That existing entity maturity
    # must NOT be reflected, copied, or approximated into this brand
    # new FEATURE dimension (Phase 14 extension approval item 1: "ZERO
    # BACKFILL... the first feature observation begins when this
    # logging ships").
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent_user::/x.plist"
        entity = None
        for day in range(60):
            entity = record_baseline_observation(
                db.conn, "persistence", entity_key,
                f"2026-06-{(day % 28) + 1:02d}T00:00:00+00:00", True, 1.0,
            )
        set_baseline_entity_maturity(db.conn, entity.id, "established")
        assert entity.eligible_weight_total == 60  # entity itself is long-lived

        # No baseline_feature_activity rows exist yet for this entity's
        # signing_status feature — nothing has ever logged it.
        activity = list_baseline_feature_activity(db.conn, "persistence", entity_key, "signing_status")
        assert activity == []

        # The feature maturity row, created fresh, starts at zero —
        # not seeded from the entity's 60 eligible observations above.
        feature, was_new = get_or_create_baseline_feature_maturity(
            db.conn, "persistence", entity_key, "signing_status"
        )
        assert was_new is True
        assert feature.maturity_state == "no_baseline"
        assert feature.observation_count == 0
        assert feature.eligible_weight_total == 0
        assert feature.first_eligible_observed_at is None
