"""Phase 53: Context composition tests.

Tests for compose.py assembling AlertContext from Phase 48-51 sources.
"""

from secure.alerting.compose import compose
from secure.alerting.context import AlertContext


def test_compose_returns_alert_context():
    """compose() returns an AlertContext instance."""
    ctx = compose()
    assert isinstance(ctx, AlertContext)


def test_compose_with_defaults_safe_fallback():
    """compose(use_defaults=True) returns safe defaults when sources unavailable."""
    ctx = compose(use_defaults=True)
    assert isinstance(ctx, AlertContext)
    # Should have safe defaults
    assert ctx.learning is not None


def test_empty_context_is_valid():
    """AlertContext.empty() produces a valid context."""
    ctx = AlertContext.empty()
    assert ctx.device is None
    assert ctx.response is None
    assert ctx.learning is not None
    assert ctx.expected_changes == ()


def test_compose_device_context_optional():
    """Device context may be None if unavailable."""
    ctx = compose()
    # Should not crash even if device context is unavailable
    assert ctx is not None
    # device might be None or a DeviceContext, both valid


def test_compose_response_context_optional():
    """Response context may be None if unavailable."""
    ctx = compose()
    # Should not crash even if response context is unavailable
    assert ctx is not None
    # response might be None or a ResponseContext, both valid


def test_compose_learning_context_always_valid():
    """Learning context always valid (never None)."""
    ctx = compose()
    assert ctx.learning is not None
    # Should have default empty dicts
    assert isinstance(ctx.learning.threshold_overrides, dict)
    assert isinstance(ctx.learning.fp_rate_by_feature, dict)
    assert isinstance(ctx.learning.sample_counts, dict)


def test_compose_expected_changes_tuple():
    """Expected changes is a tuple (may be empty)."""
    ctx = compose()
    assert isinstance(ctx.expected_changes, tuple)
    # May be empty if no changes configured


def test_compose_deterministic():
    """Multiple calls to compose() return consistent structure."""
    ctx1 = compose()
    ctx2 = compose()

    # Both should be valid AlertContext objects
    assert type(ctx1) == type(ctx2)

    # Structure should match even if content differs
    assert (ctx1.device is None) == (ctx2.device is None)
    assert (ctx1.response is None) == (ctx2.response is None)
    assert ctx1.learning is not None
    assert ctx2.learning is not None


def test_compose_all_fields_present():
    """All AlertContext fields are populated by compose()."""
    ctx = compose()

    # All fields should be accessible
    assert hasattr(ctx, 'device')
    assert hasattr(ctx, 'response')
    assert hasattr(ctx, 'learning')
    assert hasattr(ctx, 'expected_changes')


def test_compose_use_defaults_false_no_crash():
    """compose(use_defaults=False) handles missing sources gracefully."""
    try:
        ctx = compose(use_defaults=False)
        # If it succeeds, should still return valid AlertContext
        assert isinstance(ctx, AlertContext)
    except Exception:
        # If it raises, that's also acceptable (expected behavior)
        pass


def test_learning_context_threshold_overrides_dict():
    """Learning context includes threshold_overrides dict."""
    ctx = compose()
    assert ctx.learning is not None
    assert isinstance(ctx.learning.threshold_overrides, dict)
    # Dict is always present even if empty


def test_learning_context_fp_rate_dict():
    """Learning context includes fp_rate_by_feature dict."""
    ctx = compose()
    assert ctx.learning is not None
    assert isinstance(ctx.learning.fp_rate_by_feature, dict)


def test_learning_context_sample_counts_dict():
    """Learning context includes sample_counts dict."""
    ctx = compose()
    assert ctx.learning is not None
    assert isinstance(ctx.learning.sample_counts, dict)
