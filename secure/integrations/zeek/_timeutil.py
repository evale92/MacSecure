"""
integrations/zeek/_timeutil.py — parses Zeek's own log timestamp
field (`ts`), a plain UNIX epoch number (seconds since epoch, usually
carrying microsecond precision as a float, e.g. `1755781200.123456`) —
unlike Suricata's EVE `timestamp` string, this needs no strptime
format juggling, just `datetime.fromtimestamp()`. Kept as its own small
module anyway (rather than inlined at each call site) for the same
"one shared, tested implementation" reasoning Suricata's
_timeutil.py's own docstring gives, and so a future Zeek log field
quirk (e.g. `ts` occasionally arriving as a string) has one place to be
handled.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def parse_zeek_timestamp(value) -> "Optional[datetime]":
    """Best-effort parse of one Zeek record's own `ts` field into an
    aware UTC datetime. Accepts an int/float epoch seconds value, or a
    numeric string (Zeek's JSON writer normally emits a real JSON
    number, but this is defensive against any producer that stringifies
    it). Returns None (never raises) for anything else — a record with
    an unparseable timestamp is treated as having no usable timing
    information, not a crash.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value:
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None
