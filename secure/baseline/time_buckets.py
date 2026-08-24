"""
secure/baseline/time_buckets.py — Phase 14's coarse time-of-day /
day-of-week classification. Pure functions, no I/O.

Four broad buckets (night/morning/afternoon/evening) plus a
weekday/weekend split, deliberately coarse per approval item 9 — never
minute-level precision, and never scored without its own maturity gate
(see scoring.py's TIME_MIN_OBSERVATIONS/TIME_MIN_DISTINCT_DAYS check).

Every timestamp already stored in this database is UTC (see every
`datetime.now(timezone.utc).isoformat()` call across secure/storage/).
Bucketing converts to the local system timezone first — time-of-day
patterns are meaningful in the user's own clock ("do I normally use
this Mac at 2am"), not in UTC, which would misclassify anyone not
already in UTC. This conversion uses the sandbox/machine's current
local timezone setting, which is a fixed environment property, not a
source of nondeterminism for a fixed `now`/timestamp input.
"""

from __future__ import annotations

from datetime import datetime, timezone

from secure.baseline.constants import TIME_BUCKETS


def _to_local(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone()


def bucket_for_hour(hour: int) -> str:
    """Return the TIME_BUCKETS name (night/morning/afternoon/evening)
    a given local hour (0-23) falls into."""
    for name, start, end in TIME_BUCKETS:
        if start <= hour < end:
            return name
    raise ValueError(f"hour {hour} not covered by any configured TIME_BUCKETS entry")


def is_weekend(weekday: int) -> bool:
    """weekday follows Python's datetime.weekday(): Monday=0 .. Sunday=6."""
    return weekday >= 5


def classify(iso_timestamp: str) -> "tuple[str, bool]":
    """Return (bucket_name, is_weekend) for a stored UTC ISO-8601
    timestamp, converted to local time first."""
    dt = datetime.fromisoformat(iso_timestamp)
    local = _to_local(dt)
    return bucket_for_hour(local.hour), is_weekend(local.weekday())
