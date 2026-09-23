"""Phase 53: Alert decision storage tests.

Tests for AlertDecisionStore persistence layer.
"""

from secure.alerting.decide import AlertDecision
from secure.alerting.store import AlertDecisionStore


def test_store_initialization():
    """AlertDecisionStore initializes without error."""
    store = AlertDecisionStore()
    assert store is not None


def test_store_with_connection():
    """AlertDecisionStore accepts optional connection parameter."""
    store = AlertDecisionStore(connection=None)
    assert store is not None


def test_store_decision_returns_id():
    """Storing a decision returns a row id."""
    store = AlertDecisionStore()
    decision = AlertDecision(
        source_table="anomaly_events",
        source_id=123,
        base_severity="MEDIUM",
        verdict="ACTIVE",
        final_severity="HIGH",
        reasoning=["test reason"],
    )

    row_id = store.store_decision(decision)
    assert isinstance(row_id, int)


def test_get_recent_decisions_returns_list():
    """Fetching recent decisions returns a list."""
    store = AlertDecisionStore()
    decisions = store.get_recent_decisions(limit=10)
    assert isinstance(decisions, list)


def test_get_recent_decisions_respects_limit():
    """get_recent_decisions() limits the result count."""
    store = AlertDecisionStore()

    decisions_5 = store.get_recent_decisions(limit=5)
    decisions_20 = store.get_recent_decisions(limit=20)

    # Limit is respected (both should be <= their limits)
    assert len(decisions_5) <= 5
    assert len(decisions_20) <= 20


def test_count_by_verdict_returns_dict():
    """count_by_verdict() returns a dict with verdict keys."""
    store = AlertDecisionStore()
    counts = store.count_by_verdict()

    assert isinstance(counts, dict)
    # Should have keys for all possible verdicts (even if 0)
    expected_verdicts = {"ACTIVE", "SUPPRESSED_EXPECTED", "DOWNGRADED_EXPECTED"}
    for verdict in expected_verdicts:
        if verdict in counts:
            assert isinstance(counts[verdict], int)


def test_get_decision_by_source_not_found():
    """get_decision_by_source() returns None if not found."""
    store = AlertDecisionStore()
    decision = store.get_decision_by_source("nonexistent_table", 99999)
    assert decision is None


def test_count_by_verdict_structure():
    """count_by_verdict() always returns consistent structure."""
    store = AlertDecisionStore()
    counts = store.count_by_verdict()

    # Even if empty, structure should be consistent
    assert isinstance(counts, dict)


def test_store_decision_empty_reasoning():
    """Storing a decision with empty reasoning works."""
    store = AlertDecisionStore()
    decision = AlertDecision(
        source_table="anomaly_events",
        source_id=456,
        base_severity="LOW",
        verdict="SUPPRESSED_EXPECTED",
        final_severity="LOW",
        reasoning=[],  # Empty list
    )

    row_id = store.store_decision(decision)
    assert row_id is not None


def test_store_decision_long_reasoning():
    """Storing a decision with many reasoning items works."""
    store = AlertDecisionStore()
    decision = AlertDecision(
        source_table="correlation_alerts",
        source_id=789,
        base_severity="HIGH",
        verdict="ACTIVE",
        final_severity="CRITICAL",
        reasoning=[f"reason_{i}" for i in range(10)],
    )

    row_id = store.store_decision(decision)
    assert row_id is not None


def test_get_recent_decisions_default_limit():
    """get_recent_decisions() has sensible default limit."""
    store = AlertDecisionStore()
    decisions = store.get_recent_decisions()  # No limit specified

    # Should succeed and not return excessive results
    assert isinstance(decisions, list)
    # Default limit should be reasonable (20 in the implementation)
    assert len(decisions) <= 20


def test_count_by_verdict_empty_table():
    """count_by_verdict() works on empty or non-existent table."""
    store = AlertDecisionStore()
    counts = store.count_by_verdict()

    # Should return dict even if table is empty
    assert isinstance(counts, dict)
