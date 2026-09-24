"""Pytest configuration for integration tests."""

import pytest
from tests.integration.fixtures import MetricsCollector


@pytest.fixture
def metrics_collector():
    """Provide a metrics collector for each test."""
    return MetricsCollector()


@pytest.fixture
def integration_test_config():
    """Configuration for integration tests."""
    return {
        "timeout_seconds": 30,
        "max_latency_ms": 100,
        "max_false_positive_rate": 0.01,
        "min_detection_rate": 0.95,
    }


def pytest_configure(config):
    """Configure pytest for integration tests."""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test (requires test infrastructure)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow (may require elevated privileges)"
    )


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Add custom test report formatting."""
    outcome = yield

    if call.when == "call":
        report = outcome.get_result()
        if hasattr(item, "metrics_collector"):
            # Attach metrics to report
            report.metrics = item.metrics_collector
