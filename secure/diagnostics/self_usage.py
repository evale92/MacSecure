"""
diagnostics/self_usage.py — Phase 30: Secure's own resource footprint
("how much CPU/RAM/storage is Secure itself consuming?").

Secure is not a daemon — every invocation (`secure status`, `secure
run-all`, ...) is a short-lived process that exits when it's done. So
there is no running service to poll from outside; "Secure's resource
usage" here means THIS invocation's own usage-so-far, measured from
inside itself. `resource.getrusage(RUSAGE_SELF)` is the right primary
source for that (per this phase's own "prefer measurement over
estimation... use supported Python APIs rather than adding
dependencies" instruction): it's an in-process syscall wrapper, not a
forked `ps` process, so calling it does not itself meaningfully perturb
the measurement it's taking (requirement 3's "do not have the
monitoring system materially distort the measurements"). `ru_maxrss` is
already a lifetime-of-process peak, not a point sample, so "peak
memory" needs no separate sampling loop.

Historical/cross-invocation comparison (past runs' duration, past
peak RSS) comes from secure/storage/models/perf.py's `perf_module_runs`/
`perf_milestones` tables instead — this module only ever reports on the
CURRENT process.
"""

from __future__ import annotations

import os
import resource
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secure.storage.models import count_events, count_total_findings

# Captured once, at import time, as this invocation's own start
# reference — "runtime_seconds" below is always relative to when this
# process's diagnostics module was first loaded, the earliest point in
# the process's life this code can observe.
_PROCESS_START_MONOTONIC = time.monotonic()


@dataclass
class SecureSelfUsage:
    pid: int
    cpu_time_seconds: float
    peak_rss_bytes: int
    runtime_seconds: float
    thread_count: "Optional[int]"
    db_size_bytes: "Optional[int]"
    log_size_bytes: "Optional[int]"
    events_count: "Optional[int]"
    findings_count: "Optional[int]"
    findings_by_table: "dict[str, int]"


def _peak_rss_bytes(ru_maxrss: int) -> int:
    """ru_maxrss's unit differs by platform: bytes on macOS (Darwin),
    kilobytes on Linux. Secure's real target is macOS; this handles
    Linux too only so this module's own tests (and this development
    sandbox, which is Linux) measure a real, correctly-scaled number
    rather than reporting Linux's KB figure as if it were bytes.
    """
    if sys.platform == "darwin":
        return ru_maxrss
    return ru_maxrss * 1024


def _thread_count() -> "Optional[int]":
    """Python-level thread count only (threading.active_count()) — NOT
    a full OS-level thread count, which macOS has no simple portable
    `ps` column for (unlike Linux's `nlwp`). Labeled honestly as
    Python-level in every caller that displays it; Secure's own
    processes are single-threaded scripts in practice, so this is
    mostly a "did something spawn a background thread unexpectedly"
    signal, not a deep OS introspection.
    """
    import threading

    try:
        return threading.active_count()
    except Exception:
        return None


def _file_size_or_none(path: "Path | None") -> "Optional[int]":
    if path is None:
        return None
    try:
        return path.stat().st_size
    except OSError:
        return None


def collect_self_usage(
    conn: "sqlite3.Connection | None" = None,
    db_path: "Path | None" = None,
    log_path: "Path | None" = None,
) -> SecureSelfUsage:
    """One best-effort snapshot of THIS process's own usage-so-far plus
    (when a connection/paths are given) its on-disk footprint. `conn`/
    `db_path`/`log_path` are all optional so this can be called from a
    context that only wants the in-process numbers (e.g. a unit test
    with no real database).
    """
    usage = resource.getrusage(resource.RUSAGE_SELF)
    cpu_time_seconds = usage.ru_utime + usage.ru_stime
    peak_rss_bytes = _peak_rss_bytes(usage.ru_maxrss)
    runtime_seconds = time.monotonic() - _PROCESS_START_MONOTONIC

    events_count = None
    findings_count = None
    findings_by_table: "dict[str, int]" = {}
    if conn is not None:
        events_count = count_events(conn)
        findings_by_table = count_total_findings(conn)
        findings_count = sum(findings_by_table.values())

    return SecureSelfUsage(
        pid=os.getpid(),
        cpu_time_seconds=cpu_time_seconds,
        peak_rss_bytes=peak_rss_bytes,
        runtime_seconds=runtime_seconds,
        thread_count=_thread_count(),
        db_size_bytes=_file_size_or_none(db_path),
        log_size_bytes=_file_size_or_none(log_path),
        events_count=events_count,
        findings_count=findings_count,
        findings_by_table=findings_by_table,
    )
