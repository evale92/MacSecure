"""Phase 57: Monitor health — detect stale or failed baseline runs.

Validates that baseline/detection pipeline has run recently.
Invariant 5: no silent clean pass. A stale monitor reports DEGRADED.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class MonitorHealth:
    """Monitor run status."""
    status: str  # OK | DEGRADED | UNAVAILABLE
    last_run_at: datetime | None
    seconds_stale: int | None
    reason: str


def check_monitor_health(
    max_age_seconds: int = 3600 * 6,  # 6 hours (default check interval)
    log_dir: str | None = None,
) -> MonitorHealth:
    """
    Check if baseline/detection monitor has run recently.

    Args:
        max_age_seconds: Alert if last run is older than this (default 6h)
        log_dir: Override .monitoring directory path (for testing)

    Returns:
        MonitorHealth with status, last_run_at, and reason
    """
    if log_dir is None:
        log_dir = str(Path.home() / ".secure" / ".monitoring")

    log_path = Path(log_dir)

    # No .monitoring directory = never run
    if not log_path.exists():
        return MonitorHealth(
            status="UNAVAILABLE",
            last_run_at=None,
            seconds_stale=None,
            reason="No .monitoring directory — monitor has never run",
        )

    # Find most recent monitor log
    monitor_logs = sorted(log_path.glob("monitor_*.log"))
    if not monitor_logs:
        return MonitorHealth(
            status="UNAVAILABLE",
            last_run_at=None,
            seconds_stale=None,
            reason="No monitor logs found in .monitoring",
        )

    last_log = monitor_logs[-1]
    mtime = last_log.stat().st_mtime
    last_run_at = datetime.fromtimestamp(mtime, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    age = (now - last_run_at).total_seconds()

    # Check for success marker in log
    try:
        content = last_log.read_text()
        has_success = "=== Secure Monitor Complete ===" in content
    except Exception:
        has_success = False

    if not has_success:
        return MonitorHealth(
            status="DEGRADED",
            last_run_at=last_run_at,
            seconds_stale=int(age),
            reason=f"Last monitor run at {last_run_at} did not complete successfully",
        )

    if age > max_age_seconds:
        return MonitorHealth(
            status="DEGRADED",
            last_run_at=last_run_at,
            seconds_stale=int(age),
            reason=f"Monitor last ran {age} seconds ago (threshold: {max_age_seconds}s)",
        )

    return MonitorHealth(
        status="OK",
        last_run_at=last_run_at,
        seconds_stale=int(age),
        reason=f"Monitor last ran {int(age)} seconds ago",
    )
