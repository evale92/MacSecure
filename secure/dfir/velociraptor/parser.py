"""
secure/dfir/velociraptor/parser.py — reshapes Velociraptor's own JSONL
collection output into plain row dicts. Knows nothing about what any
artifact's columns MEAN (a MacOS.System.Pslist row and a
MacOS.Network.Netstat row have completely different shapes) — same
"reshape into a common container, never interpret the contents"
discipline secure/integrations/base.py's ExternalObservation already
established, applied here to Velociraptor's genuinely arbitrary
per-artifact schema instead of a fixed one.

Velociraptor's collector emits one JSON object per line (JSONL) when
run with a JSON/JSONL output format — this parser is line-oriented and
tolerant of blank lines and trailing whitespace, the same shape
secure/integrations/suricata/_eve.py's own line reader already uses for
EVE JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ParsedRows:
    """`rows` is every line that parsed as a JSON object, in original
    order (so `raw_row_index` stays meaningful downstream).
    `malformed_count` is how many non-blank lines did NOT parse — never
    silently dropped without a trace; a caller decides whether that
    downgrades the collection's own status (see collector.py).
    """

    rows: List[dict]
    malformed_count: int


def parse_jsonl(raw_output: str) -> ParsedRows:
    rows: List[dict] = []
    malformed = 0
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            malformed += 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            # A line that parses as valid JSON but isn't an object (a
            # bare number/string/array) isn't a result row this
            # integration knows how to represent — counted the same as
            # malformed rather than silently coerced into a shape it
            # never had.
            malformed += 1
    return ParsedRows(rows=rows, malformed_count=malformed)
