"""
integrations/suricata/_eve.py — the only file that reads Suricata's own
EVE JSON log file. Read-only, line-delimited JSON ("one JSON object per
line", Suricata's own EVE format) — no subprocess, no packet capture,
no interface access. Secure never runs, configures, or manages
Suricata itself; this module only tails a log file Suricata (started
and configured by the user, outside Secure entirely) already writes.

Mirrors the lazy-import-seam / one-file-does-the-I/O convention every
other integration in this codebase already uses (osquery's _shell.py,
yarax's _engine.py, sigma's _yaml.py) — except there is no third-party
library here at all, just stdlib `json` over a plain text file, so
there is no import to defer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, List, Tuple

import json

# A defensive cap, not a real-world expectation: this integration is
# host-centric (this Mac's own traffic only — see availability.py's own
# "what reliable collection means on macOS" note), so eve.json here is
# expected to be modest. This bound exists purely so a misconfigured
# path pointing at a huge, unrelated file can't make one scan pass read
# gigabytes into memory — the same "bounded, not silently unbounded"
# discipline DEFAULT_MAX_HASH_BYTES applies to file integrity hashing.
DEFAULT_MAX_LINES = 50_000


def read_eve_lines(path: Path, max_lines: int = DEFAULT_MAX_LINES) -> Tuple[List[dict], int]:
    """Read up to the LAST `max_lines` lines of `path` and parse each as
    one JSON object (one EVE record). Returns (records, malformed_count)
    — a line that isn't valid JSON, or doesn't parse to a JSON object,
    is skipped and counted rather than aborting the whole read (the
    same "one bad item, logged and skipped" discipline every other
    loader in this codebase uses for e.g. one bad YARA/Sigma rule file).

    Reading only the tail (not the whole file from the start) matters
    once eve.json has been accumulating for a while — this integration
    only cares about recent activity, the same way every other scanner
    module's own lookback window does.
    """
    if not path.is_file():
        return [], 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        # A plain rolling-window read of the last max_lines lines.
        # collections.deque(maxlen=...) keeps this O(file size) time but
        # O(max_lines) memory — acceptable for a host-centric log file,
        # and simpler than a byte-seeking tail implementation.
        from collections import deque

        tail_lines = deque(f, maxlen=max_lines)

    records: List[dict] = []
    malformed_count = 0
    for line in tail_lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            malformed_count += 1
            continue
        if not isinstance(record, dict):
            malformed_count += 1
            continue
        records.append(record)

    return records, malformed_count


def iter_by_event_type(records: List[dict], event_type: str) -> Iterator[dict]:
    for record in records:
        if record.get("event_type") == event_type:
            yield record
