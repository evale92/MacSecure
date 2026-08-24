"""
integrations/suricata/_timeutil.py — parses Suricata's own EVE
timestamp format, which `datetime.fromisoformat()` cannot handle on
the Python version this project targets (3.10): Suricata's default
timestamp shape is `"2017-06-08T09:38:34.784386+0000"` — microseconds
plus a UTC offset with NO colon (`+0000`, not `+00:00`). Python's
`fromisoformat()` only started accepting the no-colon offset form in
3.11; `datetime.strptime(..., "%z")` has accepted both forms for much
longer, so that's what this module uses instead. Used by both
availability.py (capture-stats staleness) and correlate.py (the
identity+timing window lookup against native connection_events) — one
shared, tested implementation rather than two.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",  # Suricata's default: microseconds + offset
    "%Y-%m-%dT%H:%M:%S%z",     # no fractional seconds, still offset-based
)


def parse_suricata_timestamp(value) -> "Optional[datetime]":
    """Best-effort parse of one EVE record's own timestamp string into
    an aware datetime. Returns None (never raises) for anything that
    doesn't match — a record with an unparseable timestamp is treated
    as having no usable timing information, not a crash.
    """
    if not isinstance(value, str) or not value:
        return None
    for fmt in _FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None
