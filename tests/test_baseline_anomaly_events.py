"""
Tests for Phase 14 Stage 4A: wiring anomaly detection results into
anomaly_events via secure/baseline/engine.py's
maybe_record_anomaly_event(), called automatically from
evaluate_and_record_feature_observation().

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline import engine
from secure.storage.database import Database
from secure.storage.models import find_anomaly_event, list_anomaly_events

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat()


def test_first_observation_persists_an_anomaly_event(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent_user::/x.plist"
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key,
            "signing_status", "signed_developer", _iso(NOW),
        )
        assert breakdown["tier"] != "none"
        assert breakdown["anomaly_event_id"] is not None

        events = list_anomaly_events(db.conn, "persistence", entity_key)
        assert len(events) == 1
        event = events[0]
        assert event.id == breakdown["anomaly_event_id"]
        assert event.feature_name == "signing_status"
        assert event.observed_value == "signed_developer"
        assert event.observed_at == _iso(NOW)
        assert event.run_id == "run1"
        assert event.known is False
        assert set(event.score_breakdown.keys()) <= {
            "rarity", "recency", "behavior_change", "security_context", "time_deviation",
        }
        assert "raw_score" not in event.score_breakdown  # metadata, not a component
        assert "This " in event.expected_summary or "No prior" in event.expected_summary


def test_zero_tier_observation_is_not_persisted(tmp_path: Path):
    # 20 consecutive days of the exact same value drives rarity/recency/
    # behavior_change/security_context/time_deviation all to 0 -> tier
    # "none" -> Stage 4 approval item 1: no noisy anomaly row.
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent_user::/x.plist"
        last_breakdown = None
        for day in range(20):
            last_breakdown = engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "persistence", entity_key,
                "signing_status", "signed_developer",
                _iso(NOW + timedelta(days=day)),
                now=NOW + timedelta(days=day),
            )
        assert last_breakdown["tier"] == "none"
        assert last_breakdown["anomaly_event_id"] is None

        # No anomaly_events row exists for the FINAL run_id specifically
        # (earlier days, still rare/new, legitimately did create rows).
        final_run_events = [
            e for e in list_anomaly_events(db.conn, "persistence", entity_key, limit=1000)
            if e.run_id == "run19"
        ]
        assert final_run_events == []


def test_idempotent_repeat_evaluation_does_not_duplicate(tmp_path: Path):
    # Exercises maybe_record_anomaly_event()'s persistence-layer
    # idempotence directly: the SAME already-computed breakdown for the
    # SAME (run_id, entity, feature) — e.g. a retry after a transient
    # DB error, or evaluation genuinely re-run without a new underlying
    # observation — must not create a second row. (Going through the
    # full evaluate_and_record_feature_observation() wrapper twice with
    # the same run_id is a different scenario: the SECOND call would
    # score against stats the FIRST call already mutated, so its
    # breakdown legitimately differs — that's not what this guarantee
    # is about; see maybe_record_anomaly_event()'s docstring.)
    with Database(tmp_path / "test.db") as db:
        entity_key = "svc:80/tcp"
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", entity_key, "bind_scope", "localhost", _iso(NOW),
        )
        assert breakdown["anomaly_event_id"] is not None

        # Re-persist the exact same breakdown for the exact same key —
        # simulates a retry / accidental re-invocation with no new data.
        again = engine.maybe_record_anomaly_event(
            db.conn, "run1", "listening", entity_key, "bind_scope", "localhost", _iso(NOW),
            breakdown, breakdown["feature_maturity_state"], 0.0, 0,
        )
        assert again is not None
        assert again.id == breakdown["anomaly_event_id"]

        matching = [
            e for e in list_anomaly_events(db.conn, "listening", entity_key, limit=1000)
            if e.run_id == "run1" and e.feature_name == "bind_scope"
        ]
        assert len(matching) == 1


def test_new_run_id_for_same_entity_creates_a_new_row(tmp_path: Path):
    # Unlike a repeat of the SAME run_id, a genuinely new scan (new
    # run_id) for the same entity/feature is a real new observation and
    # must get its own row when it, too, is anomalous.
    with Database(tmp_path / "test.db") as db:
        entity_key = "svc:80/tcp"
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", entity_key, "bind_scope", "localhost", _iso(NOW),
        )
        breakdown2 = engine.evaluate_and_record_feature_observation(
            db.conn, "run2", "listening", entity_key, "bind_scope", "network",
            _iso(NOW + timedelta(days=1)), is_network_bind=True, now=NOW + timedelta(days=1),
        )
        assert breakdown2["anomaly_event_id"] is not None
        matching = [
            e for e in list_anomaly_events(db.conn, "listening", entity_key, limit=1000)
            if e.feature_name == "bind_scope"
        ]
        assert len(matching) == 2


def test_find_anomaly_event_dedup_lookup(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "HomeNet"
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "wifi", entity_key, "security", "open", _iso(NOW),
            is_weak_wifi_security=True,
        )
        found = find_anomaly_event(db.conn, "run1", "wifi", entity_key, "security")
        assert found is not None
        assert found.id == breakdown["anomaly_event_id"]
        assert find_anomaly_event(db.conn, "run-does-not-exist", "wifi", entity_key, "security") is None


def test_malformed_source_reference_degrades_gracefully(tmp_path: Path):
    # source_table/source_id are a copied reference, not a live FK join
    # (see anomaly_events' schema comment) — a stale/nonexistent
    # source_id must not raise or block the anomaly from being recorded.
    with Database(tmp_path / "test.db") as db:
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "wifi", "SomeNet", "security", "open", _iso(NOW),
            is_weak_wifi_security=True,
            source_table="wifi_networks", source_id=999999,
        )
        assert breakdown["anomaly_event_id"] is not None
        event = list_anomaly_events(db.conn, "wifi", "SomeNet")[0]
        assert event.source_table == "wifi_networks"
        assert event.source_id == 999999


def test_anomaly_list_empty_database(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert list_anomaly_events(db.conn) == []
        assert list_anomaly_events(db.conn, "wifi", "AnyNet") == []
