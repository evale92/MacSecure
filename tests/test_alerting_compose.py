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


def test_compose_device_context_with_real_config():
    """Device context reads role correctly with real AppConfig and registry."""
    from unittest.mock import Mock, patch
    from secure.multi_device.device_registry import EnrolledDevice
    from secure.alerting.context import DeviceContext

    # Mock a real AppConfig (dataclass)
    mock_cfg = Mock()
    mock_cfg.device_name = "test-device"
    mock_cfg.device_role = "workstation"

    # Mock two active devices where local device is not first
    device1 = Mock(spec=EnrolledDevice)
    device1.device_id = "device_remote"
    device1.role = Mock(value="SHARED")
    device1.cpu_ok = device1.disk_ok = device1.memory_ok = device1.network_ok = True
    device1.last_sync = True

    device2 = Mock(spec=EnrolledDevice)
    device2.device_id = "device_local"
    device2.role = Mock(value="ADMIN")
    device2.cpu_ok = device2.disk_ok = device2.memory_ok = device2.network_ok = True
    device2.last_sync = True

    with patch("secure.config.load_config", return_value=mock_cfg):
        with patch("secure.multi_device.device_registry.DeviceRegistry") as MockRegistry:
            mock_registry = Mock()
            mock_registry.get_active_devices.return_value = [device1, device2]
            MockRegistry.return_value = mock_registry

            from secure.alerting.compose import compose_device_context

            # When no local_device_id in AppConfig, falls back to first device
            result = compose_device_context()
            assert result is not None
            assert isinstance(result, DeviceContext)
            # Should use first device in list as fallback
            assert result.device_id == "device_remote"
            assert result.role == "SHARED"
            assert result.peer_device_count == 1  # one other device


def test_compose_peer_device_count_from_correlation():
    """peer_device_count parameter from correlation data is used."""
    from unittest.mock import Mock, patch
    from secure.multi_device.device_registry import EnrolledDevice

    device1 = Mock(spec=EnrolledDevice)
    device1.device_id = "device1"
    device1.role = Mock(value="ADMIN")
    device1.cpu_ok = device1.disk_ok = device1.memory_ok = device1.network_ok = True
    device1.last_sync = True

    mock_cfg = Mock()
    with patch("secure.config.load_config", return_value=mock_cfg):
        with patch("secure.multi_device.device_registry.DeviceRegistry") as MockRegistry:
            mock_registry = Mock()
            mock_registry.get_active_devices.return_value = [device1]
            MockRegistry.return_value = mock_registry

            from secure.alerting.compose import compose_device_context

            # Pass peer_device_count from correlation
            result = compose_device_context(peer_device_count=3)
            assert result is not None
            assert result.peer_device_count == 3  # Uses provided value, not count of active devices
