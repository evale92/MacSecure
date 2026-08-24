"""
diagnostics/budgets.py — Phase 30 requirement 5: plain, configurable
threshold warnings ("Secure using excessive RAM", "unusually long
scans", "low disk space", "rapidly growing DB/log files").

Hard rule, stated in this phase's own governing instruction and worth
repeating here since it's the one thing this module must never violate:
these are DIAGNOSTICS, not security alerts. Every function below
returns plain factual strings describing measured behavior ("Secure's
RSS was 612MB, above the configured 500MB budget") — never a severity
level, never routed through secure/explain/, secure/correlate/,
secure/baseline/, or anything else that could make a slow scan look
like a security finding. Nothing in this module writes to any
database table; it's a pure function of already-collected
measurements, same "pure formatting/comparison, no side effects" shape
as secure/validate/report.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from secure.config import AppConfig
from secure.diagnostics.self_usage import SecureSelfUsage
from secure.diagnostics.system import SystemHealth
from secure.storage.models.perf import PerfModuleRunRecord

BUDGET_SECURE_RSS = "secure_rss"
BUDGET_SCAN_DURATION = "scan_duration"
BUDGET_DISK_FREE = "disk_free"
BUDGET_DB_GROWTH = "db_growth"


@dataclass(frozen=True)
class PerfWarning:
    kind: str
    message: str


def evaluate_budgets(
    cfg: AppConfig,
    *,
    self_usage: "Optional[SecureSelfUsage]" = None,
    system_health: "Optional[SystemHealth]" = None,
    recent_module_runs: "Optional[list[PerfModuleRunRecord]]" = None,
    previous_db_size_bytes: "Optional[int]" = None,
) -> "list[PerfWarning]":
    """Compare whatever measurements are available against cfg's
    perf_budget_* thresholds. Every input is optional — a caller that
    only has some of the data (e.g. no db-size history yet) simply gets
    fewer possible warning kinds, never a crash or a fabricated one.
    """
    warnings: "list[PerfWarning]" = []

    if self_usage is not None:
        rss_mb = self_usage.peak_rss_bytes / (1024 * 1024)
        if rss_mb > cfg.perf_budget_secure_max_rss_mb:
            warnings.append(PerfWarning(
                BUDGET_SECURE_RSS,
                f"Secure's peak RSS this run was {rss_mb:.1f}MB, above the "
                f"configured {cfg.perf_budget_secure_max_rss_mb:.0f}MB budget.",
            ))

    for run in recent_module_runs or []:
        if run.duration_seconds > cfg.perf_budget_scan_max_seconds:
            warnings.append(PerfWarning(
                BUDGET_SCAN_DURATION,
                f"{run.module} ({run.operation}) took {run.duration_seconds:.1f}s, "
                f"above the configured {cfg.perf_budget_scan_max_seconds:.0f}s budget.",
            ))

    if system_health is not None and system_health.disk_free_bytes is not None:
        free_gb = system_health.disk_free_bytes / (1024 ** 3)
        if free_gb < cfg.perf_budget_min_free_disk_gb:
            warnings.append(PerfWarning(
                BUDGET_DISK_FREE,
                f"Only {free_gb:.1f}GB of disk free, below the configured "
                f"{cfg.perf_budget_min_free_disk_gb:.0f}GB minimum.",
            ))

    if (
        self_usage is not None
        and self_usage.db_size_bytes is not None
        and previous_db_size_bytes is not None
    ):
        growth_mb = (self_usage.db_size_bytes - previous_db_size_bytes) / (1024 * 1024)
        if growth_mb > cfg.perf_budget_db_growth_warn_mb_per_run:
            warnings.append(PerfWarning(
                BUDGET_DB_GROWTH,
                f"The database grew by {growth_mb:.1f}MB since the last recorded "
                f"milestone, above the configured "
                f"{cfg.perf_budget_db_growth_warn_mb_per_run:.0f}MB-per-run threshold.",
            ))

    return warnings
