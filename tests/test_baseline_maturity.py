"""
Tests for secure/baseline/maturity.py — Phase 14's pure maturity state
machine. No database, no I/O.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from secure.baseline import maturity


def _iso(dt: datetime) -> str:
    return dt.isoformat()


NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def test_no_history_is_no_baseline():
    state = maturity.compute_maturity(
        eligible_weight_total=0,
        eligible_distinct_days=0,
        first_eligible_observed_at=None,
        last_eligible_observed_at=None,
        last_observed_at=None,
        now=NOW,
    )
    assert state == maturity.NO_BASELINE


def test_many_scans_in_a_short_period_stays_learning_not_established():
    # 50 observations, but all within a single afternoon: count is well
    # past the threshold, but distinct days and calendar span are both
    # 0/1 — must NOT reach ESTABLISHED (Phase 14 approval item 3's
    # explicit example).
    today = _iso(NOW)
    state = maturity.compute_maturity(
        eligible_weight_total=50.0,
        eligible_distinct_days=1,
        first_eligible_observed_at=today,
        last_eligible_observed_at=today,
        last_observed_at=today,
        now=NOW,
    )
    assert state == maturity.LEARNING


def test_insufficient_distinct_days_alone_stays_learning():
    first = _iso(NOW - timedelta(days=20))
    last = _iso(NOW)
    state = maturity.compute_maturity(
        eligible_weight_total=25.0,  # count OK
        eligible_distinct_days=5,  # not enough distinct days
        first_eligible_observed_at=first,
        last_eligible_observed_at=last,
        last_observed_at=last,
        now=NOW,
    )
    assert state == maturity.LEARNING


def test_insufficient_span_alone_stays_learning():
    # Enough count and enough distinct days, but they're all crammed
    # into fewer than MIN_ELIGIBLE_SPAN_DAYS calendar days.
    first = _iso(NOW - timedelta(days=5))
    last = _iso(NOW)
    state = maturity.compute_maturity(
        eligible_weight_total=30.0,
        eligible_distinct_days=6,
        first_eligible_observed_at=first,
        last_eligible_observed_at=last,
        last_observed_at=last,
        now=NOW,
    )
    assert state == maturity.LEARNING


def test_all_three_gates_together_reach_established():
    first = _iso(NOW - timedelta(days=30))
    last = _iso(NOW - timedelta(days=1))
    state = maturity.compute_maturity(
        eligible_weight_total=25.0,
        eligible_distinct_days=15,
        first_eligible_observed_at=first,
        last_eligible_observed_at=last,
        last_observed_at=last,
        now=NOW,
    )
    assert state == maturity.ESTABLISHED


def test_stale_after_30_days_of_no_observation_at_all():
    # Would otherwise be a rock-solid ESTABLISHED baseline, but hasn't
    # been observed in over STALE_AFTER_DAYS — history preserved,
    # state becomes STALE, not ESTABLISHED.
    first = _iso(NOW - timedelta(days=200))
    last = _iso(NOW - timedelta(days=100))
    state = maturity.compute_maturity(
        eligible_weight_total=100.0,
        eligible_distinct_days=60,
        first_eligible_observed_at=first,
        last_eligible_observed_at=last,
        last_observed_at=last,
        now=NOW,
    )
    assert state == maturity.STALE


def test_stale_takes_priority_over_learning_too():
    first = _iso(NOW - timedelta(days=100))
    last = _iso(NOW - timedelta(days=100))
    state = maturity.compute_maturity(
        eligible_weight_total=2.0,
        eligible_distinct_days=1,
        first_eligible_observed_at=first,
        last_eligible_observed_at=last,
        last_observed_at=last,
        now=NOW,
    )
    assert state == maturity.STALE


def test_recently_reobserved_established_entity_stays_established():
    first = _iso(NOW - timedelta(days=60))
    last = _iso(NOW - timedelta(days=2))
    state = maturity.compute_maturity(
        eligible_weight_total=40.0,
        eligible_distinct_days=20,
        last_observed_at=_iso(NOW - timedelta(days=1)),
        first_eligible_observed_at=first,
        last_eligible_observed_at=last,
        now=NOW,
    )
    assert state == maturity.ESTABLISHED


def test_deterministic_given_fixed_now():
    kwargs = dict(
        eligible_weight_total=25.0,
        eligible_distinct_days=15,
        first_eligible_observed_at=_iso(NOW - timedelta(days=30)),
        last_eligible_observed_at=_iso(NOW - timedelta(days=1)),
        last_observed_at=_iso(NOW - timedelta(days=1)),
        now=NOW,
    )
    assert maturity.compute_maturity(**kwargs) == maturity.compute_maturity(**kwargs)


def test_maturity_states_tuple_matches_constants():
    assert maturity.MATURITY_STATES == (
        maturity.NO_BASELINE,
        maturity.LEARNING,
        maturity.ESTABLISHED,
        maturity.STALE,
    )
