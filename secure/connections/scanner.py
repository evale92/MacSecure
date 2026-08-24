"""
connections/scanner.py — orchestrates a full active-connection scan:
run `lsof -i -n -P`, parse it, record every connection observed (full
history), and track distinct remote destinations so a newly-seen one
can be flagged for review.

This is the only file in the connections package that touches the
database — every other module here just runs a command or parses
text, same layout as secure/inventory/.

This module never blocks, closes, or otherwise touches any
connection — it only reads and records what's already there.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from secure.baseline.engine import (
    BaselineRunCounters,
    evaluate_and_record_process_destination_observation,
    finalize_baseline_run,
)
from secure.baseline.entities import process_destination_key
from secure.connections._shell import run
from secure.connections.lsof_parser import ConnectionEntry, parse_lsof_output
from secure.storage.models import (
    RemoteEndpointRecord,
    add_connection_events,
    upsert_process_destination,
    upsert_remote_endpoint,
)

# Loopback addresses are this Mac talking to itself (e.g. a local dev
# server, or one of its own processes talking to another over
# localhost) — still recorded like anything else, just not the kind
# of thing "flag unexpected outbound connections" is meant to catch.
_LOOPBACK_PREFIXES = ("127.", "::1")


def _is_outbound(entry: ConnectionEntry) -> bool:
    """True for an entry with an actual remote peer (not a bare LISTEN socket)."""
    return entry.remote_addr is not None and entry.remote_port is not None


def is_loopback(remote_addr: Optional[str]) -> bool:
    if not remote_addr:
        return False
    return remote_addr.startswith(_LOOPBACK_PREFIXES)


@dataclass
class ConnectionScanResult:
    scanned_at: str
    run_id: str
    lsof_available: bool = True
    entries: List[ConnectionEntry] = field(default_factory=list)
    # (record, was_new) for every distinct outbound remote destination
    # seen this scan.
    endpoints: List[Tuple[RemoteEndpointRecord, bool]] = field(default_factory=list)
    # Count of "WARNING: can't stat() ..."-style lines lsof printed to
    # stderr — usually sockets belonging to another user this process
    # couldn't fully inspect without sudo. Surfaced instead of hidden,
    # same transparency approach as inventory's filtered_out count.
    permission_warnings: int = 0

    @property
    def new_endpoints(self) -> List[RemoteEndpointRecord]:
        return [record for record, was_new in self.endpoints if was_new]

    @property
    def listening_count(self) -> int:
        return sum(1 for e in self.entries if e.remote_addr is None)

    @property
    def outbound_count(self) -> int:
        return sum(1 for e in self.entries if _is_outbound(e))


def scan_connections(conn: sqlite3.Connection) -> ConnectionScanResult:
    """Run one active-connection scan and record the results.

    Every connection/listening-socket lsof reports gets a row in
    connection_events (full history, grouped by run_id). Every
    distinct outbound remote destination (address+port+protocol) gets
    upserted into remote_endpoints so a first-time destination can be
    flagged. Loopback connections are recorded like anything else but
    never flagged as "new" — see is_loopback().
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    # +c0: don't truncate the COMMAND column — see lsof_parser.py's
    # module docstring for why that flag exists and what it fixes.
    result = run(["lsof", "-i", "-n", "-P", "+c0"], timeout=15.0)
    if result.returncode is None:
        # lsof isn't installed, or the command didn't finish in time —
        # report an empty, clearly-marked result rather than pretending
        # nothing is connected to anything. A genuine sensor failure
        # (Stage 4 approval item 3/12), not a routine "nothing to do."
        failed_counters = BaselineRunCounters()
        failed_counters.record_error("lsof unavailable or timed out during connections scan")
        finalize_baseline_run(conn, run_id, started_at, failed_counters)
        return ConnectionScanResult(scanned_at=now, run_id=run_id, lsof_available=False)

    entries = parse_lsof_output(result.stdout)
    permission_warnings = sum(
        1 for line in result.stderr.splitlines() if "warning" in line.lower()
    )

    event_rows = [
        (
            e.proto,
            e.local_addr,
            e.local_port,
            e.remote_addr,
            e.remote_port,
            e.state,
            e.pid,
            e.process_name,
        )
        for e in entries
    ]
    # add_connection_events() returns the real connection_events.id
    # assigned to each row, in the same order as `entries` (event_rows
    # is built directly from `entries` above, one-to-one) — this is
    # what lets the process_destination provenance below reference the
    # EXACT underlying observation instead of an approximation. See
    # add_connection_events()'s docstring for why this used to be a
    # bulk executemany() that couldn't support that.
    event_ids: List[Optional[int]] = (
        add_connection_events(conn, run_id=run_id, rows=event_rows) if event_rows else []
    )

    endpoints: List[Tuple[RemoteEndpointRecord, bool]] = []
    seen_this_scan = set()  # avoid double-counting the same destination twice in one scan
    seen_process_destinations_this_scan = set()  # separate dedup key: (process, destination)
    counters = BaselineRunCounters()
    for entry, event_id in zip(entries, event_ids):
        if not _is_outbound(entry):
            continue
        key = (entry.remote_addr, entry.remote_port, entry.proto)
        if key not in seen_this_scan:
            seen_this_scan.add(key)
            record, was_new = upsert_remote_endpoint(
                conn,
                remote_addr=entry.remote_addr,
                remote_port=entry.remote_port,
                proto=entry.proto,
                process_name=entry.process_name,
            )
            endpoints.append((record, was_new))

        # Product Phase 14 Stage 4C: process_destination sibling-relative
        # rarity (approval item 7) — deduped by (process, destination)
        # rather than destination alone, since two different processes
        # contacting the same destination are two different baseline
        # entities (a process_destination entity_key is
        # "process::destination", see entities.py). Deliberately a
        # SEPARATE dedup set from seen_this_scan above: remote_endpoints
        # tracks "is this destination new at all," which cares nothing
        # about which process it is this time.
        pd_key = (entry.process_name, entry.remote_addr, entry.remote_port, entry.proto)
        if pd_key not in seen_process_destinations_this_scan:
            seen_process_destinations_this_scan.add(pd_key)
            try:
                # upsert_process_destination() still maintains its own
                # aggregate (process, destination) row — observation
                # count/first-seen/last-seen bookkeeping, same
                # raw-log-plus-aggregate-view pattern connection_events/
                # remote_endpoints already use — but its `id` is no
                # longer used as anomaly provenance (see database.py's
                # schema comment on process_destinations): only a real
                # connection_events row uniquely identifies WHICH
                # process+destination observation this evaluation came
                # from, since process_destinations dedupes across an
                # entire scan while connection_events is one row per
                # actual socket lsof reported.
                upsert_process_destination(
                    conn,
                    process_name=entry.process_name,
                    remote_addr=entry.remote_addr,
                    remote_port=entry.remote_port,
                    proto=entry.proto,
                )
                entity_key = process_destination_key(
                    entry.process_name, entry.remote_addr, entry.remote_port, entry.proto
                )
                evaluate_and_record_process_destination_observation(
                    conn, run_id, entity_key, now,
                    source_table="connection_events", source_id=event_id,
                    counters=counters,
                )
            except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
                counters.record_error(
                    f"process_destination baseline evaluation failed for {pd_key!r}: {exc}"
                )

    finalize_baseline_run(conn, run_id, started_at, counters)

    return ConnectionScanResult(
        scanned_at=now,
        run_id=run_id,
        lsof_available=True,
        entries=entries,
        endpoints=endpoints,
        permission_warnings=permission_warnings,
    )
