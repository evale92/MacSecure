"""
Tests for secure/baseline/engine.py — Stage 3's orchestration of
feature-level scoring/recording and process_destination sibling
rarity.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline import engine, maturity
from secure.storage.database import Database
from secure.storage.models import (
    add_persistence_alert,
    find_baseline_feature_maturity,
    get_baseline_feature_stat,
    get_or_create_baseline_entity,
    record_baseline_observation,
    set_baseline_entity_maturity,
    set_persistence_alert_known,
)

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat()


def test_rejects_feature_outside_the_approved_three(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        raised = False
        try:
            engine.evaluate_and_record_feature_observation(
                db.conn, "run1", "process", "/usr/bin/curl", "run_as_user", "root",
                _iso(NOW),
            )
        except ValueError:
            raised = True
        assert raised


def test_first_observation_scores_maximum_rarity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        breakdown = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", "launch_agent_user::/x.plist",
            "signing_status", "signed_developer", _iso(NOW),
        )
        assert breakdown is not None
        assert breakdown["rarity"] == 40  # RARITY_NEVER_SEEN — nothing recorded yet
        assert breakdown["recency"] == 0


def test_repeated_common_value_scores_low_rarity_over_time(tmp_path: Path):
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
        # After 20 consistent observations, this value dominates its
        # own rolling history -> rarity should be at (or near) 0.
        assert last_breakdown["rarity"] == 0


def test_unavailable_feature_value_returns_none_and_does_not_train(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        result = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "wifi", "SomeNet", "security", None, _iso(NOW),
        )
        assert result is None
        stat = get_baseline_feature_stat(db.conn, "wifi", "SomeNet", "security", "open")
        assert stat is None  # nothing was folded into feature stats

        feature = find_baseline_feature_maturity(db.conn, "wifi", "SomeNet", "security")
        assert feature.eligible_weight_total == 0  # visible but not eligible


def test_unresolved_high_alert_makes_observation_ineligible_and_unscored(tmp_path: Path):
    # entity_type="persistence" looks up persistence_alerts WHERE
    # target_type != 'process' AND identifier = <entity_key's part
    # after "::"> (see history.py's unreviewed_alert_severities_for_entity).
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent::/x.plist"
        add_persistence_alert(
            db.conn, "run0", "unusual_unsigned_process", "high", "launch_agent",
            "/x.plist", "x", "unsigned launch agent",
        )
        result = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key,
            "signing_status", "signed_developer", _iso(NOW),
        )
        assert result is None  # unresolved HIGH alert -> ineligible, never scored

        feature = find_baseline_feature_maturity(db.conn, "persistence", entity_key, "signing_status")
        assert feature.eligible_weight_total == 0
        assert feature.observation_count == 1  # still visible for audit, just not eligible


def test_post_review_only_future_observations_become_eligible(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent::/x.plist"
        alert_id = add_persistence_alert(
            db.conn, "run0", "unusual_unsigned_process", "high", "launch_agent",
            "/x.plist", "x", "unsigned launch agent",
        )

        before = engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key,
            "signing_status", "signed_developer", _iso(NOW),
        )
        assert before is None

        set_persistence_alert_known(db.conn, alert_id, True)

        # Forward-only: the already-recorded (ineligible) observation is
        # not retroactively rewritten just because the alert was reviewed.
        feature = find_baseline_feature_maturity(db.conn, "persistence", entity_key, "signing_status")
        assert feature.eligible_weight_total == 0

        # A NEW observation made after review is eligible.
        after = engine.evaluate_and_record_feature_observation(
            db.conn, "run2", "persistence", entity_key,
            "signing_status", "signed_developer", _iso(NOW + timedelta(days=1)),
            now=NOW + timedelta(days=1),
        )
        assert after is not None
        feature = find_baseline_feature_maturity(db.conn, "persistence", entity_key, "signing_status")
        assert feature.eligible_weight_total == 1.0


# ---------- feature-specific behavior-change deviations, end-to-end ----------


def test_signing_status_deviation_signed_to_unsigned(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent_user::/x.plist"
        for day in range(20):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "persistence", entity_key,
                "signing_status", "signed_developer",
                _iso(NOW + timedelta(days=day)),
                now=NOW + timedelta(days=day),
            )
        deviation = engine.evaluate_and_record_feature_observation(
            db.conn, "run_final", "persistence", entity_key,
            "signing_status", "unsigned",
            _iso(NOW + timedelta(days=20)),
            is_unsigned=True,
            now=NOW + timedelta(days=20),
        )
        assert deviation["behavior_change"] == 20
        assert deviation["security_context"] >= 5  # is_unsigned flag


def test_bind_scope_deviation_localhost_to_network(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "svc:80/tcp"
        for day in range(20):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "listening", entity_key,
                "bind_scope", "localhost",
                _iso(NOW + timedelta(days=day)),
                now=NOW + timedelta(days=day),
            )
        deviation = engine.evaluate_and_record_feature_observation(
            db.conn, "run_final", "listening", entity_key,
            "bind_scope", "network",
            _iso(NOW + timedelta(days=20)),
            is_network_bind=True,
            now=NOW + timedelta(days=20),
        )
        assert deviation["behavior_change"] == 20
        assert deviation["security_context"] >= 5


def test_wifi_security_deviation_wpa3_to_open(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "HomeNet"
        for day in range(20):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "wifi", entity_key,
                "security", "WPA3 Personal",
                _iso(NOW + timedelta(days=day)),
                now=NOW + timedelta(days=day),
            )
        deviation = engine.evaluate_and_record_feature_observation(
            db.conn, "run_final", "wifi", entity_key,
            "security", "open",
            _iso(NOW + timedelta(days=20)),
            is_weak_wifi_security=True,
            now=NOW + timedelta(days=20),
        )
        assert deviation["behavior_change"] == 20
        assert deviation["security_context"] >= 5


def test_feature_scoring_capped_by_feature_maturity_not_entity_maturity(tmp_path: Path):
    # Only 3 observations logged -> feature maturity is LEARNING, so
    # even a maximal-looking raw score must be capped at LOW.
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent_user::/x.plist"
        for day in range(3):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "persistence", entity_key,
                "signing_status", "signed_developer",
                _iso(NOW + timedelta(days=day)),
                now=NOW + timedelta(days=day),
            )
        deviation = engine.evaluate_and_record_feature_observation(
            db.conn, "run_final", "persistence", entity_key,
            "signing_status", "unsigned",
            _iso(NOW + timedelta(days=3)),
            is_unsigned=True,
            now=NOW + timedelta(days=3),
        )
        assert deviation["feature_maturity_state"] == maturity.LEARNING
        assert deviation["tier"] == "low"  # capped, even though raw_score is high


# ---------- process_destination sibling-relative rarity ----------


def test_process_destination_rarity_against_siblings(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        # Chrome has 3 established destinations with a skewed
        # distribution: A=40, B=25, C=10 (eligible_weight_total units).
        for key, weight in (("Chrome::A", 40), ("Chrome::B", 25), ("Chrome::C", 10)):
            entity, _ = get_or_create_baseline_entity(db.conn, "process_destination", key)
            for _ in range(int(weight)):
                entity = record_baseline_observation(
                    db.conn, "process_destination", key, _iso(NOW), True, 1.0
                )
            set_baseline_entity_maturity(db.conn, entity.id, maturity.ESTABLISHED)

        # A brand-new destination D for Chrome has never been observed.
        result = engine.score_process_destination_rarity(db.conn, "Chrome::D", now=NOW)
        assert result["rarity"] == 40  # never seen
        assert result["sibling_count"] == 3  # D itself doesn't exist as an entity yet

        # Destination C (10 of 75 total = 13.3%) falls in [5%, 20%) ->
        # RARITY_MODERATE_SHARE (10 points), not the <5% or >=20% bucket.
        result_c = engine.score_process_destination_rarity(db.conn, "Chrome::C", now=NOW)
        assert result_c["rarity"] == 10
        assert result_c["sibling_count"] == 3


def test_chrome_destination_diversity_does_not_normalize_another_process(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        # Chrome has many normal destinations.
        for key in ("Chrome::A", "Chrome::B", "Chrome::C", "Chrome::D", "Chrome::E"):
            for _ in range(20):
                record_baseline_observation(db.conn, "process_destination", key, _iso(NOW), True, 1.0)

        # A single-purpose CLI tool has never contacted anything.
        result = engine.score_process_destination_rarity(db.conn, "curl::A", now=NOW)
        # curl has no sibling history at all -> its own first contact
        # with A is maximally rare, regardless of how diverse Chrome's
        # destinations are — no cross-contamination between processes.
        assert result["rarity"] == 40
        assert result["sibling_count"] == 0


def test_process_destination_rarity_malformed_key_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert engine.score_process_destination_rarity(db.conn, "no_separator_here", now=NOW) is None


# ---------- determinism ----------


def test_scoring_is_deterministic_given_fixed_history(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity_key = "launch_agent_user::/x.plist"
        for day in range(10):
            engine.evaluate_and_record_feature_observation(
                db.conn, f"run{day}", "persistence", entity_key,
                "signing_status", "signed_developer",
                _iso(NOW + timedelta(days=day)),
                now=NOW + timedelta(days=day),
            )
        # Scoring is read-only against already-recorded history — calling
        # it twice in a row with identical inputs (same fixed `now`, no
        # writes in between) must yield byte-for-byte identical output.
        final = engine.score_feature_observation(
            db.conn, "persistence", entity_key, "signing_status", "signed_developer",
            _iso(NOW + timedelta(days=10)), now=NOW + timedelta(days=10),
        )
        final2 = engine.score_feature_observation(
            db.conn, "persistence", entity_key, "signing_status", "signed_developer",
            _iso(NOW + timedelta(days=10)), now=NOW + timedelta(days=10),
        )
        assert final == final2
