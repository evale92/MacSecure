"""Phase 57: Monitor health tests."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.diagnostics.monitor_health import check_monitor_health


def test_monitor_never_run():
    """Monitor UNAVAILABLE when .monitoring directory doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        health = check_monitor_health(log_dir=tmpdir)

        assert health.status == "UNAVAILABLE"
        assert health.last_run_at is None
        assert "no monitor logs" in health.reason.lower()


def test_monitor_no_logs():
    """Monitor UNAVAILABLE when directory exists but has no logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir).mkdir(exist_ok=True)
        health = check_monitor_health(log_dir=tmpdir)

        assert health.status == "UNAVAILABLE"
        assert health.last_run_at is None
        assert "no monitor logs" in health.reason.lower()


def test_monitor_incomplete_run():
    """Monitor DEGRADED when last log doesn't have completion marker."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)
        log_file = log_dir / "monitor_20260923_140000.log"
        log_file.write_text("[2026-09-23 14:00:00] Running persistence...\n[2026-09-23 14:05:00] Failed\n")

        health = check_monitor_health(log_dir=tmpdir)

        assert health.status == "DEGRADED"
        assert health.last_run_at is not None
        assert "did not complete" in health.reason.lower()


def test_monitor_stale_run():
    """Monitor DEGRADED when last successful run is too old."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)
        log_file = log_dir / "monitor_20260923_080000.log"
        log_file.write_text("=== Secure Monitor Complete ===\n")

        # Set mtime to 8 hours ago
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(hours=8)
        old_timestamp = old_time.timestamp()
        log_file.touch()
        import os
        os.utime(log_file, (old_timestamp, old_timestamp))

        # Check with 6-hour threshold
        health = check_monitor_health(log_dir=tmpdir, max_age_seconds=3600 * 6)

        assert health.status == "DEGRADED"
        assert health.last_run_at is not None
        assert health.seconds_stale > 3600 * 6
        assert "threshold" in health.reason.lower()


def test_monitor_recent_success():
    """Monitor OK when last run completed recently."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)
        log_file = log_dir / "monitor_20260923_140000.log"
        log_file.write_text("=== Secure Monitor Complete ===\n")

        # Set mtime to 30 minutes ago
        now = datetime.now(timezone.utc)
        recent_time = now - timedelta(minutes=30)
        recent_timestamp = recent_time.timestamp()
        log_file.touch()
        import os
        os.utime(log_file, (recent_timestamp, recent_timestamp))

        # Check with 6-hour threshold
        health = check_monitor_health(log_dir=tmpdir, max_age_seconds=3600 * 6)

        assert health.status == "OK"
        assert health.last_run_at is not None
        assert health.seconds_stale < 3600
        assert health.seconds_stale > 0


def test_monitor_multiple_logs_picks_latest():
    """Monitor checks most recent log when multiple exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)

        # Old incomplete run
        old_log = log_dir / "monitor_20260923_080000.log"
        old_log.write_text("Failed run\n")
        import os
        os.utime(old_log, (100, 100))

        # Recent successful run
        new_log = log_dir / "monitor_20260923_140000.log"
        new_log.write_text("=== Secure Monitor Complete ===\n")

        health = check_monitor_health(log_dir=tmpdir)

        assert health.status == "OK"
        assert "did not complete" not in health.reason.lower()


def test_monitor_health_reason_is_always_set():
    """Every health check has a human-readable reason."""
    with tempfile.TemporaryDirectory() as tmpdir:
        health = check_monitor_health(log_dir=tmpdir)
        assert health.reason
        assert len(health.reason) > 0
