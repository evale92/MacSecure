"""
Tests for the Phase 14 storage layer added to secure/storage/models.py
and secure/storage/database.py: baseline_entities, baseline_activity,
baseline_feature_stats, baseline_time_stats, anomaly_events, and
baseline_runs.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database, init_schema
from secure.storage.models import (
    add_anomaly_event,
    add_baseline_activity,
    add_baseline_run,
    count_baseline_entities,
    delete_baseline_entity,
    find_anomaly_event_by_id,
    find_baseline_entity,
    find_baseline_entity_by_id,
    find_latest_baseline_run,
    get_baseline_feature_stat,
    get_baseline_time_stat,
    get_or_create_baseline_entity,
    list_anomaly_events,
    list_baseline_activity,
    list_baseline_entities,
    list_baseline_feature_stats,
    list_baseline_runs,
    record_baseline_observation,
    set_anomaly_event_known,
    set_baseline_entity_excluded,
    set_baseline_entity_frozen,
    set_baseline_entity_maturity,
    upsert_baseline_feature_stat,
    upsert_baseline_time_stat,
)


def test_schema_creates_all_six_new_tables(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        tables = {
            row["name"]
            for row in db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    for table in (
        "baseline_entities",
        "baseline_activity",
        "baseline_feature_stats",
        "baseline_time_stats",
        "anomaly_events",
        "baseline_runs",
    ):
        assert table in tables


def test_init_schema_is_idempotent_with_new_tables(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        init_schema(db.conn)  # calling twice must not error
        init_schema(db.conn)


def test_get_or_create_baseline_entity_starts_at_no_baseline(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity, was_new = get_or_create_baseline_entity(db.conn, "process", "/usr/bin/curl")
        assert was_new is True
        assert entity.maturity_state == "no_baseline"
        assert entity.observation_count == 0
        assert entity.eligible_weight_total == 0

        entity2, was_new2 = get_or_create_baseline_entity(db.conn, "process", "/usr/bin/curl")
        assert was_new2 is False
        assert entity2.id == entity.id


def test_record_baseline_observation_increments_counters(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        e1 = record_baseline_observation(
            db.conn, "process", "/usr/bin/curl", "2026-08-01T10:00:00+00:00", True, 1.0
        )
        assert e1.observation_count == 1
        assert e1.distinct_days_observed == 1
        assert e1.eligible_weight_total == 1.0
        assert e1.eligible_distinct_days == 1
        assert e1.first_observed_at == "2026-08-01T10:00:00+00:00"
        assert e1.first_eligible_observed_at == "2026-08-01T10:00:00+00:00"

        # Same calendar day, second observation -> count grows, distinct
        # days does not.
        e2 = record_baseline_observation(
            db.conn, "process", "/usr/bin/curl", "2026-08-01T18:00:00+00:00", True, 1.0
        )
        assert e2.observation_count == 2
        assert e2.distinct_days_observed == 1
        assert e2.eligible_weight_total == 2.0
        assert e2.eligible_distinct_days == 1

        # A new calendar day -> distinct-day counters grow too.
        e3 = record_baseline_observation(
            db.conn, "process", "/usr/bin/curl", "2026-08-02T09:00:00+00:00", True, 1.0
        )
        assert e3.observation_count == 3
        assert e3.distinct_days_observed == 2
        assert e3.eligible_distinct_days == 2
        assert e3.last_observed_at == "2026-08-02T09:00:00+00:00"


def test_ineligible_observation_still_counts_lifetime_but_not_eligible(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        e1 = record_baseline_observation(
            db.conn, "process", "/opt/sketchy/tool", "2026-08-01T10:00:00+00:00", False, 0.0
        )
        assert e1.observation_count == 1  # visible for audit
        assert e1.distinct_days_observed == 1
        assert e1.eligible_weight_total == 0
        assert e1.eligible_distinct_days == 0
        assert e1.first_eligible_observed_at is None
        assert e1.first_observed_at == "2026-08-01T10:00:00+00:00"


def test_half_weight_medium_alert_observation_adds_half(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        e1 = record_baseline_observation(
            db.conn, "listening", "svc:80/tcp", "2026-08-01T10:00:00+00:00", True, 0.5
        )
        assert e1.eligible_weight_total == 0.5


def test_maturity_state_is_stored_not_computed_by_models(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity, _ = get_or_create_baseline_entity(db.conn, "wifi", "HomeNet")
        assert entity.maturity_state == "no_baseline"
        set_baseline_entity_maturity(db.conn, entity.id, "established")
        updated = find_baseline_entity_by_id(db.conn, entity.id)
        assert updated.maturity_state == "established"


def test_exclude_and_freeze_flags(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity, _ = get_or_create_baseline_entity(db.conn, "ble", "ABCD-1234")
        assert entity.excluded is False
        assert entity.frozen is False

        set_baseline_entity_excluded(db.conn, entity.id, True)
        set_baseline_entity_frozen(db.conn, entity.id, True)
        updated = find_baseline_entity_by_id(db.conn, entity.id)
        assert updated.excluded is True
        assert updated.frozen is True


def test_count_baseline_entities_scoped_by_type(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        get_or_create_baseline_entity(db.conn, "process", "/usr/bin/a")
        get_or_create_baseline_entity(db.conn, "process", "/usr/bin/b")
        get_or_create_baseline_entity(db.conn, "wifi", "SomeNet")

        assert count_baseline_entities(db.conn, "process") == 2
        assert count_baseline_entities(db.conn, "wifi") == 1
        assert count_baseline_entities(db.conn) == 3


def test_list_baseline_entities_filters_by_type(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        get_or_create_baseline_entity(db.conn, "process", "/usr/bin/a")
        get_or_create_baseline_entity(db.conn, "wifi", "SomeNet")
        assert len(list_baseline_entities(db.conn, "process")) == 1
        assert len(list_baseline_entities(db.conn)) == 2


def test_delete_baseline_entity_resets_one_entity_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record_baseline_observation(
            db.conn, "process", "/usr/bin/a", "2026-08-01T00:00:00+00:00", True, 1.0
        )
        record_baseline_observation(
            db.conn, "process", "/usr/bin/b", "2026-08-01T00:00:00+00:00", True, 1.0
        )
        upsert_baseline_feature_stat(
            db.conn, "process", "/usr/bin/a", "signing_status", "signed",
            1.0, 1, 1.0, 1, "2026-08-01T00:00:00+00:00", "2026-08-01T00:00:00+00:00",
        )

        removed = delete_baseline_entity(db.conn, "process", "/usr/bin/a")
        assert removed is True
        assert find_baseline_entity(db.conn, "process", "/usr/bin/a") is None
        assert list_baseline_feature_stats(db.conn, "process", "/usr/bin/a") == []
        # The other entity is untouched.
        assert find_baseline_entity(db.conn, "process", "/usr/bin/b") is not None

        # Nothing to reset the second time.
        assert delete_baseline_entity(db.conn, "process", "/usr/bin/a") is False


def test_baseline_activity_gap_filler_log(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_baseline_activity(db.conn, "run1", "inventory", "aa:bb:cc:dd:ee:ff", "eligible", 1.0)
        add_baseline_activity(
            db.conn, "run2", "inventory", "aa:bb:cc:dd:ee:ff", "unreviewed_high_alert", 0.0
        )
        rows = list_baseline_activity(db.conn, "inventory", "aa:bb:cc:dd:ee:ff")
        assert len(rows) == 2
        assert rows[0].eligibility_reason == "eligible"
        assert rows[1].eligibility_reason == "unreviewed_high_alert"
        assert rows[1].weight == 0.0


def test_baseline_feature_stat_upsert_replaces_whole_row(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_baseline_feature_stat(
            db.conn, "process_destination", "Syncthing::203.0.113.5:22067/tcp",
            "destination", "203.0.113.5:22067/tcp",
            5.0, 3, 5.0, 3, "2026-07-01T00:00:00+00:00", "2026-08-01T00:00:00+00:00",
        )
        stat = get_baseline_feature_stat(
            db.conn, "process_destination", "Syncthing::203.0.113.5:22067/tcp",
            "destination", "203.0.113.5:22067/tcp",
        )
        assert stat.lifetime_weight_total == 5.0

        # Replace with updated values (simulating a later recompute).
        upsert_baseline_feature_stat(
            db.conn, "process_destination", "Syncthing::203.0.113.5:22067/tcp",
            "destination", "203.0.113.5:22067/tcp",
            8.0, 5, 8.0, 5, "2026-07-01T00:00:00+00:00", "2026-08-10T00:00:00+00:00",
        )
        stat2 = get_baseline_feature_stat(
            db.conn, "process_destination", "Syncthing::203.0.113.5:22067/tcp",
            "destination", "203.0.113.5:22067/tcp",
        )
        assert stat2.lifetime_weight_total == 8.0
        assert stat2.lifetime_distinct_days == 5

        # Still exactly one row for this identity (no duplicate insert).
        all_stats = list_baseline_feature_stats(
            db.conn, "process_destination", "Syncthing::203.0.113.5:22067/tcp"
        )
        assert len(all_stats) == 1


def test_baseline_time_stat_upsert(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_baseline_time_stat(
            db.conn, "process", "/usr/bin/curl",
            night_weight=1.0, morning_weight=5.0, afternoon_weight=10.0, evening_weight=4.0,
            weekday_weight=18.0, weekend_weight=2.0, distinct_days_observed=15, total_weight=20.0,
        )
        stat = get_baseline_time_stat(db.conn, "process", "/usr/bin/curl")
        assert stat.morning_weight == 5.0
        assert stat.total_weight == 20.0

        upsert_baseline_time_stat(
            db.conn, "process", "/usr/bin/curl",
            night_weight=1.0, morning_weight=6.0, afternoon_weight=10.0, evening_weight=4.0,
            weekday_weight=19.0, weekend_weight=2.0, distinct_days_observed=16, total_weight=21.0,
        )
        stat2 = get_baseline_time_stat(db.conn, "process", "/usr/bin/curl")
        assert stat2.morning_weight == 6.0
        assert stat2.distinct_days_observed == 16


def test_anomaly_event_round_trip_and_score_breakdown_json(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        event, was_new = add_anomaly_event(
            db.conn, "run1", "process_destination", "Syncthing::203.0.113.5:22067/tcp",
            "destination", "203.0.113.5:22067/tcp", "2026-08-19T00:00:00+00:00",
            "Syncthing has never contacted this destination before.",
            {"rarity": 40, "security_context": 0},
            40, "medium", "established", 43.0, 22,
            source_table="connection_events", source_id=17,
        )
        assert was_new is True
        event_id = event.id
        event = find_anomaly_event_by_id(db.conn, event_id)
        assert event.anomaly_tier == "medium"
        assert event.observed_at == "2026-08-19T00:00:00+00:00"
        assert event.score_breakdown == {"rarity": 40, "security_context": 0}
        assert event.known is False
        assert event.source_table == "connection_events"

        set_anomaly_event_known(db.conn, event_id, True)
        updated = find_anomaly_event_by_id(db.conn, event_id)
        assert updated.known is True


def test_list_anomaly_events_filters_by_entity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_anomaly_event(
            db.conn, "run1", "process", "/usr/bin/a", "signing_status", "unsigned",
            "2026-08-19T00:00:00+00:00", "expected signed", {"behavior_change": 20},
            20, "low", "established", 25.0, 15,
        )
        add_anomaly_event(
            db.conn, "run1", "process", "/usr/bin/b", "signing_status", "unsigned",
            "2026-08-19T00:00:00+00:00", "expected signed", {"behavior_change": 20},
            20, "low", "established", 25.0, 15,
        )
        assert len(list_anomaly_events(db.conn)) == 2
        assert len(list_anomaly_events(db.conn, "process", "/usr/bin/a")) == 1


def test_baseline_run_round_trip(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_baseline_run(
            db.conn, "run1", "2026-08-19T00:00:00+00:00", "2026-08-19T00:00:05+00:00", 5.0,
            entities_evaluated=10, entities_updated=8, anomalies_generated=2,
            comparisons_skipped_insufficient_history=3, entities_skipped_cap=0,
        )
        latest = find_latest_baseline_run(db.conn)
        assert latest.run_id == "run1"
        assert latest.entities_evaluated == 10
        assert latest.comparisons_skipped_insufficient_history == 3

        runs = list_baseline_runs(db.conn)
        assert len(runs) == 1
