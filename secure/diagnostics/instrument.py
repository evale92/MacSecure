"""
diagnostics/instrument.py — Phase 30: the per-operation timing wrapper
behind requirement 4 ("record lightweight per-run measurements for
major scans/integrations").

Wraps a scan/integration call AT THE CALL SITE (secure/cli/root.py's
cmd_run_all, secure/cli/integrations.py's per-engine scan commands) —
never inside the scanner/integration function itself. This is what
guarantees the phase's own hard rule ("performance measurement does
not alter security results"): a scanner has no idea it's being timed,
so nothing here can change what it detects, how it scores anything, or
what it returns. If the wrapped call raises, that exception is recorded
as a diagnostic fact (`error`) and then RE-RAISED unchanged — this
context manager never swallows, converts, or delays an exception, so
existing error handling anywhere that calls a scan_*() function behaves
identically whether or not instrumentation is active.

Uses `resource.getrusage(RUSAGE_SELF)` deltas (in-process, stdlib, the
same source secure/diagnostics/self_usage.py uses for the same "don't
distort what you're measuring" reason) — never a `ps` subprocess around
each individual scan, which would be far more overhead than the
scan itself for the cheaper modules.
"""

from __future__ import annotations

import resource
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from secure.diagnostics.self_usage import _peak_rss_bytes
from secure.storage.models import add_perf_module_run


@dataclass
class InFlightRecord:
    """Yielded by instrument_module() — the wrapped call sets these
    two fields (either or both may stay None; that's honest, not an
    error) before the `with` block ends.
    """

    observations_processed: "Optional[int]" = None
    findings_produced: "Optional[int]" = None


class instrument_module:
    """Context manager: `with instrument_module(conn, run_group_id=g,
    module="connections", operation="scan") as rec: result =
    scan_connections(conn); rec.findings_produced = len(result.alerts)`.

    Always writes exactly one perf_module_runs row, whether the wrapped
    call succeeds, raises, or (for the external_tool case) reports a
    tool-level timeout of its own — this wrapper does not implement its
    own timeout; it only records what the wrapped call reports about
    its own timing/errors, per requirement 4's "errors/timeouts" field.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        run_group_id: str,
        module: str,
        operation: str,
        external_tool: "Optional[str]" = None,
    ) -> None:
        self._conn = conn
        self._run_group_id = run_group_id
        self._module = module
        self._operation = operation
        self._external_tool = external_tool
        self.record = InFlightRecord()

    def __enter__(self) -> InFlightRecord:
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._start_monotonic = time.monotonic()
        self._start_rusage = resource.getrusage(resource.RUSAGE_SELF)
        return self.record

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        completed_at = datetime.now(timezone.utc).isoformat()
        duration_seconds = time.monotonic() - self._start_monotonic
        end_rusage = resource.getrusage(resource.RUSAGE_SELF)
        cpu_time_seconds = (
            (end_rusage.ru_utime + end_rusage.ru_stime)
            - (self._start_rusage.ru_utime + self._start_rusage.ru_stime)
        )
        rss_bytes_at_end = _peak_rss_bytes(end_rusage.ru_maxrss)

        error = None
        if exc_type is not None:
            error = f"{exc_type.__name__}: {exc_val}"

        add_perf_module_run(
            self._conn,
            run_group_id=self._run_group_id,
            module=self._module,
            operation=self._operation,
            external_tool=self._external_tool,
            started_at=self._started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            cpu_time_seconds=cpu_time_seconds,
            rss_bytes_at_end=rss_bytes_at_end,
            observations_processed=self.record.observations_processed,
            findings_produced=self.record.findings_produced,
            error=error,
        )
        return False  # never suppress the original exception


def best_effort_counts(result: object) -> "tuple[Optional[int], Optional[int]]":
    """(observations_processed, findings_produced) read off whatever
    attributes a scan_*() result dataclass happens to expose. Every
    native-sensor ScanResult in this app carries an `alerts` list
    (findings) and one of a small handful of observation-count shapes
    (`entries`, `devices`, `files_visited`, `process_count`) — this
    reads whichever exists rather than requiring every module's return
    shape to change for Phase 30's sake. None for a field this result
    type simply doesn't have — never a fabricated 0.
    """
    findings_produced = None
    alerts = getattr(result, "alerts", None)
    if alerts is not None:
        findings_produced = len(alerts)

    observations_processed = None
    for attr in ("entries", "devices", "files_visited", "process_count"):
        value = getattr(result, attr, None)
        if value is None:
            continue
        observations_processed = len(value) if isinstance(value, (list, tuple, set, dict)) else int(value)
        break

    return observations_processed, findings_produced
