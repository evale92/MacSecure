"""
Tests for Phase 14 Stage 4G: EXCLUDE / FREEZE / RESET / INCLUDE /
UNFREEZE semantics, precisely defined by the Stage 4 approval:

EXCLUDE  — entity remains historically visible, no new anomaly
           scoring, baseline history is not deleted.
FREEZE   — continue observing, do not adapt current-normal statistics
           from new eligible observations, anomaly comparisons
           continue against the frozen baseline.
RESET    — clear/reinitialize derived baseline state for only that
           entity, preserve raw underlying module history, set
           maturity back appropriately, never silently destroy
           forensic records.
INCLUDE/UNFREEZE — resume normal behavior from that point forward,
           never retroactively rewrite history.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import PROCESS, process_key
from secure.baseline.history import record_gap_observation
from secure.storage.database import Database
from secure.storage.models import (
    add_baseline_run,
    find_baseline_entity,
    find_baseline_feature_maturity,
    get_baseline_feature_stat,
    get_or_create_baseline_entity,
    list_anomaly_events,
    list_baseline_activity,
    list_baseline_feature_activity,
    reset_baseline_entity,
    set_baseline_entity_excluded,
    set_baseline_entity_frozen,
)

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat()


# ---------- EXCLUDE ----------


def test_exclude_entity_remains_visible(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity, _ = get_or_create_baseline_entity(db.conn, "persistence", "launch_agent::/x.plist")
        set_baseline_entity_excluded(db.conn, entity.id, True)

        still_there = find_baseline_entity(db.conn, "persistence", "launch_agent::/x.plist")
        assert still_there is not None
        assert still_there.excluded is True


def test_exclude_prevents_new_anomaly_scoring_but_still_logs(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent::/x.plist"
        entity, _ = get_or_create_baseline_entity(db.conn, "persistence", entity_key)
        set_baseline_entity_excluded(db.conn, entity.id, True)

        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )
        assert breakdown is None  # excluded -> weight 0 -> never scored

        # Still visible/logged for audit, at weight 0.
        activity = list_baseline_feature_activity(db.conn, "persistence", entity_key, "signing_status")
        assert len(activity) == 1
        assert activity[0].eligible is False
        assert activity[0].eligibility_reason == "excluded_entity"

        assert list_anomaly_events(db.conn, "persistence", entity_key) == []


def test_exclude_does_not_delete_baseline_history(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_key("/usr/bin/curl")
        # Build up some real history first.
        for day in range(5):
            record_gap_observation(db.conn, f"run{day}", PROCESS, key, _iso(NOW + timedelta(days=day)))
        before = find_baseline_entity(db.conn, "process", key)
        assert before.eligible_weight_total == 5.0

        set_baseline_entity_excluded(db.conn, before.id, True)

        after = find_baseline_entity(db.conn, "process", key)
        assert after.eligible_weight_total == 5.0  # untouched, not deleted
        assert len(list_baseline_activity(db.conn, "process", key)) == 5  # raw log intact


# ---------- INCLUDE (un-exclude) ----------


def test_include_resumes_normal_eligibility_forward_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent::/x.plist"
        entity, _ = get_or_create_baseline_entity(db.conn, "persistence", entity_key)
        set_baseline_entity_excluded(db.conn, entity.id, True)

        excluded_breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "signed_developer", _iso(NOW),
        )
        assert excluded_breakdown is None

        set_baseline_entity_excluded(db.conn, entity.id, False)

        # The EARLIER (excluded) observation is not retroactively made
        # eligible — forward-only, same as unresolved-alert eligibility.
        feature = find_baseline_feature_maturity(db.conn, "persistence", entity_key, "signing_status")
        assert feature.eligible_weight_total == 0

        included_breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run2", "persistence", entity_key, "signing_status",
            "signed_developer", _iso(NOW + timedelta(days=1)), now=NOW + timedelta(days=1),
        )
        assert included_breakdown is not None  # NEW observation is eligible

        feature = find_baseline_feature_maturity(db.conn, "persistence", entity_key, "signing_status")
        assert feature.eligible_weight_total == 1.0


# ---------- FREEZE ----------


def test_freeze_continues_observing_without_adapting_stats(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "svc:80/tcp"
        # Establish some history first (unfrozen).
        for day in range(3):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "listening", entity_key, "bind_scope", "localhost",
                _iso(NOW + timedelta(days=day)), now=NOW + timedelta(days=day),
            )
        feature_before = find_baseline_feature_maturity(db.conn, "listening", entity_key, "bind_scope")
        assert feature_before.eligible_weight_total == 3.0

        # "listening" is a feature-only entity_type — no scanner ever
        # creates its baseline_entities row automatically (only
        # process/inventory/process_destination do). An operator action
        # like freeze must establish the row first via get_or_create,
        # exactly as the CLI will do. The entity-level eligible_weight_total
        # stays 0 here — that counter only advances via
        # record_baseline_observation(), which feature-only entity types
        # never call; freeze/exclude act on the row's id, not its counters.
        entity, _ = get_or_create_baseline_entity(db.conn, "listening", entity_key)
        set_baseline_entity_frozen(db.conn, entity.id, True)

        before_stat = get_baseline_feature_stat(db.conn, "listening", entity_key, "bind_scope", "localhost")
        before_weight = before_stat.lifetime_weight_total

        # A new observation while frozen: still logged (raw activity),
        # still scored (comparisons continue against the frozen
        # baseline), but must not advance the stats.
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run3", "listening", entity_key, "bind_scope", "network",
            _iso(NOW + timedelta(days=3)), is_network_bind=True, now=NOW + timedelta(days=3),
        )
        assert breakdown is not None  # still scored
        assert breakdown["behavior_change"] == 20  # comparison still happened

        activity = list_baseline_feature_activity(db.conn, "listening", entity_key, "bind_scope")
        assert len(activity) == 4  # still observing (3 before + 1 frozen)

        after_stat = get_baseline_feature_stat(db.conn, "listening", entity_key, "bind_scope", "localhost")
        assert after_stat.lifetime_weight_total == before_weight  # unchanged

        feature = find_baseline_feature_maturity(db.conn, "listening", entity_key, "bind_scope")
        assert feature.eligible_weight_total == 3.0  # frozen at pre-freeze value


def test_freeze_anomaly_comparisons_continue_against_frozen_baseline(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent::/x.plist"
        for day in range(20):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "persistence", entity_key, "signing_status",
                "signed_developer", _iso(NOW + timedelta(days=day)), now=NOW + timedelta(days=day),
            )
        entity = find_baseline_entity(db.conn, "persistence", entity_key)
        # persistence entity_type has no baseline_entities row from any
        # scanner (only process/inventory/process_destination do) —
        # freeze/exclude on it works via get_or_create, exactly like
        # the CLI will do.
        entity, _ = get_or_create_baseline_entity(db.conn, "persistence", entity_key)
        set_baseline_entity_frozen(db.conn, entity.id, True)

        # Anomalous observation while frozen — still gets scored and
        # can still produce an anomaly event.
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run20", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW + timedelta(days=20)), is_unsigned=True,
            now=NOW + timedelta(days=20),
        )
        assert breakdown["behavior_change"] == 20
        assert breakdown["anomaly_event_id"] is not None


# ---------- UNFREEZE ----------


def test_unfreeze_resumes_stat_advancement_forward_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "svc:80/tcp"
        engine.evaluate_and_record_feature_observation(
            db.conn, "run0", "listening", entity_key, "bind_scope", "localhost", _iso(NOW),
        )
        entity, _ = get_or_create_baseline_entity(db.conn, "listening", entity_key)
        set_baseline_entity_frozen(db.conn, entity.id, True)

        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", entity_key, "bind_scope", "localhost",
            _iso(NOW + timedelta(days=1)), now=NOW + timedelta(days=1),
        )
        feature = find_baseline_feature_maturity(db.conn, "listening", entity_key, "bind_scope")
        assert feature.eligible_weight_total == 1.0  # the frozen observation did NOT advance it

        set_baseline_entity_frozen(db.conn, entity.id, False)

        engine.evaluate_and_record_feature_observation(
            db.conn, "run2", "listening", entity_key, "bind_scope", "localhost",
            _iso(NOW + timedelta(days=2)), now=NOW + timedelta(days=2),
        )
        feature = find_baseline_feature_maturity(db.conn, "listening", entity_key, "bind_scope")
        # Only the pre-freeze + post-unfreeze observations count — the
        # frozen-period one is never retroactively folded in.
        assert feature.eligible_weight_total == 2.0


# ---------- RESET ----------


def test_reset_clears_derived_state_for_one_entity_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key_a = process_key("/usr/bin/curl")
        key_b = process_key("/usr/bin/ssh")
        for day in range(5):
            record_gap_observation(db.conn, f"runA{day}", PROCESS, key_a, _iso(NOW + timedelta(days=day)))
            record_gap_observation(db.conn, f"runB{day}", PROCESS, key_b, _iso(NOW + timedelta(days=day)))

        assert reset_baseline_entity(db.conn, "process", key_a) is True

        reset_entity = find_baseline_entity(db.conn, "process", key_a)
        assert reset_entity.maturity_state == "no_baseline"
        assert reset_entity.eligible_weight_total == 0
        assert reset_entity.observation_count == 0
        assert reset_entity.first_observed_at is None

        # The OTHER entity is completely untouched.
        untouched = find_baseline_entity(db.conn, "process", key_b)
        assert untouched.eligible_weight_total == 5.0
        assert untouched.maturity_state != "no_baseline" or untouched.observation_count == 5


def test_reset_preserves_raw_source_history(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_key("/usr/bin/curl")
        for day in range(5):
            record_gap_observation(db.conn, f"run{day}", PROCESS, key, _iso(NOW + timedelta(days=day)))

        reset_baseline_entity(db.conn, "process", key)

        # baseline_activity (the raw observation log for process/
        # inventory) must survive a reset untouched — it's the only
        # raw history these two entity_types have.
        assert len(list_baseline_activity(db.conn, "process", key)) == 5


def test_reset_preserves_feature_activity_and_anomaly_events(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent::/x.plist"
        for day in range(3):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "persistence", entity_key, "signing_status",
                "signed_developer", _iso(NOW + timedelta(days=day)), now=NOW + timedelta(days=day),
            )
        activity_before = list_baseline_feature_activity(db.conn, "persistence", entity_key, "signing_status")
        anomalies_before = list_anomaly_events(db.conn, "persistence", entity_key)
        assert len(activity_before) == 3

        # "persistence" is a feature-only entity_type — reset_baseline_entity()
        # is a no-op (returns False) unless a baseline_entities row exists;
        # the CLI establishes it via get_or_create before issuing a reset.
        get_or_create_baseline_entity(db.conn, "persistence", entity_key)
        assert reset_baseline_entity(db.conn, "persistence", entity_key) is True

        activity_after = list_baseline_feature_activity(db.conn, "persistence", entity_key, "signing_status")
        anomalies_after = list_anomaly_events(db.conn, "persistence", entity_key)
        assert len(activity_after) == 3  # untouched
        assert len(anomalies_after) == len(anomalies_before)  # untouched

        # Derived feature maturity IS cleared.
        feature = find_baseline_feature_maturity(db.conn, "persistence", entity_key, "signing_status")
        assert feature is None


def test_reset_returns_maturity_to_no_baseline_and_rebuilds_forward(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_key("/usr/bin/curl")
        for day in range(25):  # enough to reach ESTABLISHED
            record_gap_observation(db.conn, f"run{day}", PROCESS, key, _iso(NOW + timedelta(days=day)))
        mature = find_baseline_entity(db.conn, "process", key)
        assert mature.maturity_state == "established"

        reset_baseline_entity(db.conn, "process", key)
        reset_entity = find_baseline_entity(db.conn, "process", key)
        assert reset_entity.maturity_state == "no_baseline"

        # A new observation after reset builds forward from zero, not
        # from the preserved raw baseline_activity history.
        record_gap_observation(db.conn, "run_after", PROCESS, key, _iso(NOW + timedelta(days=25)))
        rebuilt = find_baseline_entity(db.conn, "process", key)
        assert rebuilt.eligible_weight_total == 1.0


def test_reset_does_not_touch_excluded_or_frozen_flags(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = process_key("/usr/bin/curl")
        entity, _ = get_or_create_baseline_entity(db.conn, "process", key)
        set_baseline_entity_excluded(db.conn, entity.id, True)

        reset_baseline_entity(db.conn, "process", key)

        after = find_baseline_entity(db.conn, "process", key)
        assert after.excluded is True  # operator control, not derived state


def test_reset_nonexistent_entity_returns_false(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert reset_baseline_entity(db.conn, "process", "no/such/entity") is False
