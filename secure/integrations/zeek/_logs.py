"""
integrations/zeek/_logs.py — the only file that reads Zeek's own log
files. Read-only, line-delimited JSON — no subprocess, no packet
capture, no interface access, and no management of Zeek's own process
lifecycle. Secure never runs or configures Zeek; this module only
tails log files Zeek (started and configured by the user, outside
Secure entirely) already writes to its own log directory.

Deliberately supports ONLY Zeek's native JSON log output (Zeek's
`json-streaming-logs` framework script, or `redef LogAscii::use_json =
T;` in local.zeek) — NOT Zeek's default tab-separated value format.
This mirrors Phase 18's own "prefer structured EVE JSON ingestion"
choice for Suricata: Zeek's default TSV log shape carries its own
metadata header lines (#separator, #fields, #types, ...), its own
escaping conventions, and its own empty/unset sentinel markers
("-"/"(empty)") that would need a bespoke parser to handle correctly
and would still be less robust than reading the JSON Zeek itself can
already emit. A configured `zeek_log_dir` whose files are in TSV format
instead of JSON simply produces malformed/unparseable lines here (see
read_zeek_log_lines()'s malformed_count), reported honestly rather than
silently misread.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import json

# Same defensive-bound reasoning as Suricata's DEFAULT_MAX_LINES: this
# integration is host-centric (Zeek watching this Mac's own interface
# traffic — see availability.py), so any one log file is expected to be
# modest. This bound exists only so a misconfigured path pointing at an
# enormous, unrelated file can't make one scan pass read gigabytes into
# memory.
DEFAULT_MAX_LINES = 50_000

# The four Zeek log files this integration reads, matching Phase 19's
# own "highest-value structured logs" bullet list exactly. Any other
# Zeek log (weird.log, notice.log, files.log, ...) is out of scope for
# this phase — see the package docstring in __init__.py.
CONN_LOG = "conn.log"
DNS_LOG = "dns.log"
SSL_LOG = "ssl.log"
HTTP_LOG = "http.log"

LOG_FILES = (CONN_LOG, DNS_LOG, SSL_LOG, HTTP_LOG)


def read_zeek_log_lines(path: Path, max_lines: int = DEFAULT_MAX_LINES) -> Tuple[List[dict], int]:
    """Read up to the LAST `max_lines` lines of one Zeek JSON log file
    and parse each as one JSON object (one log record). Returns
    (records, malformed_count) — a line that isn't valid JSON, or
    doesn't parse to a JSON object, is skipped and counted rather than
    aborting the whole read, the same "one bad item, logged and
    skipped" discipline Suricata's read_eve_lines() already uses.

    Reading only the tail (not the whole file from the start) matters
    once a log has been accumulating for a while — this integration
    only cares about recent activity, the same way every other
    scanner's own lookback/cursor logic does.
    """
    if not path.is_file():
        return [], 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        from collections import deque

        tail_lines = deque(f, maxlen=max_lines)

    records: List[dict] = []
    malformed_count = 0
    for line in tail_lines:
        line = line.strip()
        if not line:
            continue
        # Zeek's JSON log output can, depending on configuration,
        # include ASCII log framework header/separator lines even in
        # JSON mode for some Zeek versions — these are not JSON objects
        # and are correctly counted as malformed rather than crashing
        # the read.
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
