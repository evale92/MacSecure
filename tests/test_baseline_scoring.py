"""
Tests for secure/baseline/scoring.py — Phase 14's deterministic
anomaly-score components. No I/O, no database.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from secure.baseline import maturity, scoring

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


# ---------- rarity + recency ----------


def test_never_seen_value_gets_max_rarity_and_zero_recency():
    result = scoring.score_rarity_and_recency(
        prior_value_weight=0, prior_total_feature_weight=50, prior_last_seen=None, now=NOW
    )
    assert result == {"rarity": scoring.RARITY_NEVER_SEEN, "recency": 0}


def test_common_value_gets_zero_rarity():
    result = scoring.score_rarity_and_recency(
        prior_value_weight=40, prior_total_feature_weight=50, prior_last_seen=None, now=NOW
    )
    assert result["rarity"] == 0


def test_low_share_value_gets_low_rarity_points():
    result = scoring.score_rarity_and_recency(
        prior_value_weight=1, prior_total_feature_weight=100, prior_last_seen=None, now=NOW
    )
    assert result["rarity"] == scoring.RARITY_LOW_SHARE


def test_moderate_share_value_gets_moderate_rarity_points():
    result = scoring.score_rarity_and_recency(
        prior_value_weight=15, prior_total_feature_weight=100, prior_last_seen=None, now=NOW
    )
    assert result["rarity"] == scoring.RARITY_MODERATE_SHARE


def test_recency_gap_beyond_stale_threshold():
    last_seen = (NOW - timedelta(days=90)).isoformat()
    result = scoring.score_rarity_and_recency(
        prior_value_weight=10, prior_total_feature_weight=100, prior_last_seen=last_seen, now=NOW
    )
    assert result["recency"] == scoring.RECENCY_STALE_POINTS


def test_recency_gap_within_quiet_threshold():
    last_seen = (NOW - timedelta(days=40)).isoformat()
    result = scoring.score_rarity_and_recency(
        prior_value_weight=10, prior_total_feature_weight=100, prior_last_seen=last_seen, now=NOW
    )
    assert result["recency"] == scoring.RECENCY_QUIET_POINTS


def test_recency_gap_recent_is_zero():
    last_seen = (NOW - timedelta(days=1)).isoformat()
    result = scoring.score_rarity_and_recency(
        prior_value_weight=10, prior_total_feature_weight=100, prior_last_seen=last_seen, now=NOW
    )
    assert result["recency"] == 0


def test_rarity_and_recency_are_mutually_exclusive_for_never_seen():
    # A never-seen value has no "last seen" gap to speak of — recency
    # must stay 0 even if a (meaningless) prior_last_seen were passed.
    result = scoring.score_rarity_and_recency(
        prior_value_weight=0,
        prior_total_feature_weight=50,
        prior_last_seen=(NOW - timedelta(days=500)).isoformat(),
        now=NOW,
    )
    assert result["rarity"] == scoring.RARITY_NEVER_SEEN
    assert result["recency"] == 0


# ---------- behavior change ----------


def test_signing_status_signed_to_unsigned_is_behavior_change():
    assert (
        scoring.score_behavior_change("signing_status", "signed_developer", "unsigned")
        == scoring.BEHAVIOR_CHANGE_POINTS
    )


def test_signing_status_signed_to_adhoc_is_also_behavior_change():
    # codesign.py treats ad-hoc as alert-worthy just like unsigned.
    assert (
        scoring.score_behavior_change("signing_status", "signed_apple", "signed_adhoc")
        == scoring.BEHAVIOR_CHANGE_POINTS
    )


def test_signing_status_unsigned_to_unsigned_is_not_a_change():
    assert scoring.score_behavior_change("signing_status", "unsigned", "unsigned") == 0


def test_signing_status_unsigned_to_signed_is_not_flagged_as_behavior_change():
    # Getting signed is not itself a security concern.
    assert scoring.score_behavior_change("signing_status", "unsigned", "signed_developer") == 0


def test_bind_scope_localhost_to_network_is_behavior_change():
    assert scoring.score_behavior_change("bind_scope", "localhost", "network") == scoring.BEHAVIOR_CHANGE_POINTS


def test_bind_scope_network_to_network_is_not_a_change():
    assert scoring.score_behavior_change("bind_scope", "network", "network") == 0


def test_wifi_security_wpa2_to_open_is_behavior_change():
    assert scoring.score_behavior_change("security", "WPA2", "open") == scoring.BEHAVIOR_CHANGE_POINTS


def test_unrecognized_feature_name_never_scores_behavior_change():
    # No documented rule for this feature_name -> always 0, never a
    # generic diff (approval item 8).
    assert scoring.score_behavior_change("some_other_field", "a", "b") == 0


# ---------- security context ----------


def test_security_context_flags_are_additive():
    points = scoring.score_security_context(
        has_unreviewed_alert=True, is_unsigned=True, is_network_bind=True
    )
    assert points == (
        scoring.SECURITY_CONTEXT_UNREVIEWED_ALERT_POINTS
        + scoring.SECURITY_CONTEXT_UNSIGNED_POINTS
        + scoring.SECURITY_CONTEXT_NETWORK_BIND_POINTS
    )


def test_security_context_all_false_is_zero():
    assert scoring.score_security_context() == 0


def test_persistently_unsigned_process_scores_security_context_every_time_not_just_on_change():
    # An executable that has ALWAYS been unsigned gets +5 every
    # observation (a persistent condition), never the +20
    # behavior-change points (no transition occurred).
    security_points = scoring.score_security_context(is_unsigned=True)
    behavior_points = scoring.score_behavior_change("signing_status", "unsigned", "unsigned")
    assert security_points == scoring.SECURITY_CONTEXT_UNSIGNED_POINTS
    assert behavior_points == 0


def test_signing_downgrade_scores_both_behavior_change_and_security_context():
    # These represent genuinely different facts (a change AND a
    # current condition) and are allowed to both contribute.
    behavior_points = scoring.score_behavior_change("signing_status", "signed_developer", "unsigned")
    security_points = scoring.score_security_context(is_unsigned=True)
    assert behavior_points == scoring.BEHAVIOR_CHANGE_POINTS
    assert security_points == scoring.SECURITY_CONTEXT_UNSIGNED_POINTS


# ---------- time deviation ----------


def test_time_deviation_not_scored_when_immature():
    assert scoring.is_time_dimension_mature(total_time_weight=5, distinct_days_observed=2) is False
    points = scoring.score_time_deviation(
        prior_bucket_weight=0, prior_total_time_weight=5, mature=False
    )
    assert points == 0


def test_time_dimension_mature_when_both_gates_met():
    assert scoring.is_time_dimension_mature(total_time_weight=25, distinct_days_observed=12) is True


def test_time_deviation_never_seen_bucket():
    points = scoring.score_time_deviation(
        prior_bucket_weight=0, prior_total_time_weight=30, mature=True
    )
    assert points == scoring.TIME_DEVIATION_NEVER_SEEN


def test_time_deviation_low_share_bucket():
    points = scoring.score_time_deviation(
        prior_bucket_weight=1, prior_total_time_weight=100, mature=True
    )
    assert points == scoring.TIME_DEVIATION_LOW_SHARE


def test_time_deviation_common_bucket_is_zero():
    points = scoring.score_time_deviation(
        prior_bucket_weight=50, prior_total_time_weight=100, mature=True
    )
    assert points == 0


# ---------- tiers + maturity cap ----------


def test_tier_for_score_boundaries():
    assert scoring.tier_for_score(0) == "none"
    assert scoring.tier_for_score(14) == "none"
    assert scoring.tier_for_score(15) == "low"
    assert scoring.tier_for_score(34) == "low"
    assert scoring.tier_for_score(35) == "medium"
    assert scoring.tier_for_score(59) == "medium"
    assert scoring.tier_for_score(60) == "high"
    assert scoring.tier_for_score(79) == "high"
    assert scoring.tier_for_score(80) == "critical"
    assert scoring.tier_for_score(100) == "critical"


def test_learning_entity_never_exceeds_low_tier():
    assert scoring.apply_maturity_cap("critical", maturity.LEARNING) == "low"
    assert scoring.apply_maturity_cap("medium", maturity.LEARNING) == "low"
    assert scoring.apply_maturity_cap("low", maturity.LEARNING) == "low"
    assert scoring.apply_maturity_cap("none", maturity.LEARNING) == "none"


def test_no_baseline_entity_never_exceeds_low_tier():
    assert scoring.apply_maturity_cap("critical", maturity.NO_BASELINE) == "low"


def test_stale_entity_never_exceeds_medium_tier():
    assert scoring.apply_maturity_cap("critical", maturity.STALE) == "medium"
    assert scoring.apply_maturity_cap("high", maturity.STALE) == "medium"
    assert scoring.apply_maturity_cap("low", maturity.STALE) == "low"  # already below cap


def test_established_entity_has_no_cap():
    assert scoring.apply_maturity_cap("critical", maturity.ESTABLISHED) == "critical"


def test_combine_sums_components_and_applies_cap():
    components = {"rarity": 40, "recency": 15, "behavior_change": 20, "security_context": 15, "time_deviation": 10}
    raw_score, tier = scoring.combine(components, maturity.ESTABLISHED)
    assert raw_score == 100
    assert tier == "critical"

    raw_score2, tier2 = scoring.combine(components, maturity.LEARNING)
    assert raw_score2 == 100  # the raw score itself is never altered by maturity
    assert tier2 == "low"  # only the reported TIER is capped


def test_combine_score_never_exceeds_100_or_drops_below_0():
    raw_score, _ = scoring.combine({"a": 1000}, maturity.ESTABLISHED)
    assert raw_score == 100


def test_combine_is_deterministic():
    components = {"rarity": 25, "recency": 8}
    a = scoring.combine(components, maturity.ESTABLISHED)
    b = scoring.combine(components, maturity.ESTABLISHED)
    assert a == b
