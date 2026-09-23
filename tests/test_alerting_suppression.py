"""Phase 53: Suppression logic tests.

Tests for expected-change matching and severity capping rules.
"""

from datetime import datetime, timedelta, timezone

from secure.alerting.context import AlertContext, ExpectedChange
from secure.alerting.suppression import classify, SuppressionVerdict


def test_critical_never_suppressed():
    """CRITICAL severity is never fully suppressed (per rule 1)."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=("/Library",),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    verdict = classify(
        event_severity="CRITICAL",
        entity_type="process_key",
        entity_path="/Library/Updates/foo",
        event_timestamp=now,
        context=ctx,
    )

    assert verdict.category == "ACTIVE"
    assert "never suppressed" in verdict.reason


def test_exact_entity_type_match_required():
    """Match requires entity_type in expected_changes.entity_types."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    # Wrong entity type
    verdict = classify(
        event_severity="LOW",
        entity_type="file_change",  # Not in entity_types
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )

    assert verdict.category == "ACTIVE"


def test_path_prefix_matching():
    """Match requires path to start with one of path_prefixes."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["file_change"]),
        path_prefixes=("/Library/Updates", "/System/Library"),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    # Matching path
    verdict1 = classify(
        event_severity="LOW",
        entity_type="file_change",
        entity_path="/Library/Updates/foo.bin",
        event_timestamp=now,
        context=ctx,
    )
    assert verdict1.category == "SUPPRESSED_EXPECTED"

    # Non-matching path
    verdict2 = classify(
        event_severity="LOW",
        entity_type="file_change",
        entity_path="/Applications/foo.app",
        event_timestamp=now,
        context=ctx,
    )
    assert verdict2.category == "ACTIVE"


def test_timestamp_window_check():
    """Match requires event_timestamp inside started_at..ends_at window."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now + timedelta(hours=1),  # Starts in future
        ends_at=now + timedelta(hours=3),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    # Event timestamp before window
    verdict = classify(
        event_severity="LOW",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,  # Now, but window hasn't started
        context=ctx,
    )

    assert verdict.category == "ACTIVE"


def test_high_medium_capped_not_suppressed():
    """HIGH/MEDIUM in suppression window are capped, not fully suppressed."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    # HIGH severity
    verdict_high = classify(
        event_severity="HIGH",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )
    assert verdict_high.category == "DOWNGRADED_EXPECTED"
    assert "capped severity" in verdict_high.reason

    # MEDIUM severity
    verdict_medium = classify(
        event_severity="MEDIUM",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )
    assert verdict_medium.category == "DOWNGRADED_EXPECTED"


def test_low_informational_fully_suppressed():
    """LOW/INFORMATIONAL in suppression window are fully suppressed."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="os_update",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="test",
    )
    ctx = AlertContext(expected_changes=(change,))

    # LOW severity
    verdict_low = classify(
        event_severity="LOW",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )
    assert verdict_low.category == "SUPPRESSED_EXPECTED"

    # INFORMATIONAL severity
    verdict_info = classify(
        event_severity="INFORMATIONAL",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )
    assert verdict_info.category == "SUPPRESSED_EXPECTED"


def test_no_expected_changes_stays_active():
    """When context.expected_changes is empty, event stays ACTIVE."""
    now = datetime.now(timezone.utc)
    ctx = AlertContext(expected_changes=())

    verdict = classify(
        event_severity="LOW",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )

    assert verdict.category == "ACTIVE"


def test_matching_expected_change_recorded():
    """Suppression verdict records the matching ExpectedChange."""
    now = datetime.now(timezone.utc)
    change = ExpectedChange(
        kind="app_install",
        started_at=now - timedelta(hours=1),
        ends_at=now + timedelta(hours=1),
        entity_types=frozenset(["process_key"]),
        path_prefixes=(),
        source="user:declared",
    )
    ctx = AlertContext(expected_changes=(change,))

    verdict = classify(
        event_severity="LOW",
        entity_type="process_key",
        entity_path=None,
        event_timestamp=now,
        context=ctx,
    )

    assert verdict.matching_expected_change is change
    assert verdict.matching_expected_change.source == "user:declared"
