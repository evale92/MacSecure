"""
Tests for secure/baseline/eligibility.py — Phase 14's poisoning-
protection rules. No database, no I/O.

Run with:  pytest
"""

from __future__ import annotations

from secure.baseline import eligibility


def test_plain_observation_is_eligible_full_weight():
    reason, weight = eligibility.classify_eligibility()
    assert reason == eligibility.ELIGIBLE
    assert weight == 1.0


def test_excluded_entity_always_wins_regardless_of_alerts():
    reason, weight = eligibility.classify_eligibility(
        excluded=True, unreviewed_alert_severities=["critical"]
    )
    assert reason == eligibility.EXCLUDED_ENTITY
    assert weight == 0.0


def test_partial_sensor_data_excludes_even_with_no_alerts():
    reason, weight = eligibility.classify_eligibility(partial_sensor_data=True)
    assert reason == eligibility.PARTIAL_SENSOR_DATA
    assert weight == 0.0


def test_unreviewed_critical_alert_excludes():
    reason, weight = eligibility.classify_eligibility(
        unreviewed_alert_severities=["critical"]
    )
    assert reason == eligibility.UNREVIEWED_CRITICAL_ALERT
    assert weight == 0.0


def test_unreviewed_high_alert_excludes():
    reason, weight = eligibility.classify_eligibility(unreviewed_alert_severities=["high"])
    assert reason == eligibility.UNREVIEWED_HIGH_ALERT
    assert weight == 0.0


def test_unreviewed_medium_alert_is_half_weight_not_excluded():
    reason, weight = eligibility.classify_eligibility(
        unreviewed_alert_severities=["medium"]
    )
    assert reason == eligibility.UNREVIEWED_MEDIUM_ALERT_HALF_WEIGHT
    assert weight == 0.5


def test_low_severity_alert_alone_is_still_fully_eligible():
    reason, weight = eligibility.classify_eligibility(unreviewed_alert_severities=["low"])
    assert reason == eligibility.ELIGIBLE
    assert weight == 1.0


def test_severity_matching_is_case_insensitive():
    reason, _ = eligibility.classify_eligibility(unreviewed_alert_severities=["HIGH"])
    assert reason == eligibility.UNREVIEWED_HIGH_ALERT


def test_critical_takes_priority_over_high_and_medium_together():
    reason, weight = eligibility.classify_eligibility(
        unreviewed_alert_severities=["medium", "high", "critical"]
    )
    assert reason == eligibility.UNREVIEWED_CRITICAL_ALERT
    assert weight == 0.0


def test_high_takes_priority_over_medium():
    reason, weight = eligibility.classify_eligibility(
        unreviewed_alert_severities=["medium", "high"]
    )
    assert reason == eligibility.UNREVIEWED_HIGH_ALERT
    assert weight == 0.0


def test_weight_for_reason_matches_classify_eligibility():
    for reason in eligibility.ELIGIBILITY_REASONS:
        # Every declared reason must have a defined weight — no KeyError.
        eligibility.weight_for_reason(reason)


def test_all_eligibility_reasons_are_the_six_approved_names():
    assert set(eligibility.ELIGIBILITY_REASONS) == {
        "eligible",
        "unreviewed_high_alert",
        "unreviewed_critical_alert",
        "unreviewed_medium_alert_half_weight",
        "excluded_entity",
        "partial_sensor_data",
    }


def test_poisoning_scenario_unresolved_high_alert_repeated_observations_never_become_eligible():
    # Phase 14 approval item 12's exact scenario: an unknown unsigned
    # process appears and produces a HIGH unresolved finding, then
    # reappears on days 2-30. Frequency alone must never convert it
    # into eligible/clean training data while the finding stays
    # unreviewed.
    for _day in range(30):
        reason, weight = eligibility.classify_eligibility(
            unreviewed_alert_severities=["high"]
        )
        assert reason == eligibility.UNREVIEWED_HIGH_ALERT
        assert weight == 0.0


def test_poisoning_scenario_after_review_only_future_observations_become_eligible():
    # Days 1-30: unresolved HIGH alert -> ineligible every time.
    pre_review = [eligibility.classify_eligibility(unreviewed_alert_severities=["high"]) for _ in range(30)]
    assert all(reason == eligibility.UNREVIEWED_HIGH_ALERT for reason, _ in pre_review)

    # User reviews/classifies the finding -> the caller now passes no
    # unreviewed severities for this entity going forward.
    post_review = eligibility.classify_eligibility(unreviewed_alert_severities=[])
    assert post_review == (eligibility.ELIGIBLE, 1.0)

    # The 30 historical calls are exactly what they were computed to
    # be — this module never mutates or "reclassifies" past decisions,
    # since it takes no state and returns a fresh answer every call.
    assert all(reason == eligibility.UNREVIEWED_HIGH_ALERT for reason, _ in pre_review)
