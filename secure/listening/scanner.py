"""
listening/scanner.py — orchestrates a full listening-service audit:
run `lsof -i -n -P +c0`, keep only listening sockets (TCP in LISTEN
state, or a UDP socket bound but not connected to a specific peer),
classify each one's bind scope, record the full history, and track
distinct services so a newly-appeared one can be flagged for review.

Parsing is shared with secure/connections/ (parse_lsof_output(),
ConnectionEntry) rather than duplicated — both packages turn the same
`lsof -i` output into the same shape of row, and that parser is
complex enough (IPv6 bracket handling, lsof's own \\xHH escaping, ...)
that a second independent copy would be a real maintenance risk, not
real independence. Everything else here — running lsof, deciding what
counts as "listening," bind-scope/risk analysis, and how history is
stored — is entirely this package's own, per PROJECT_NOTES.md's "keep
every monitoring feature in its own module."

This is the only file in the listening package that touches the
database. This module never blocks, closes, or otherwise acts on any
service it finds — it only observes and records.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from secure.baseline.engine import BaselineRunCounters, evaluate_and_record_feature_observation, finalize_baseline_run
from secure.baseline.entities import listening_key
from secure.connections.lsof_parser import ConnectionEntry, parse_lsof_output
from secure.connections.port_info import describe_port
from secure.listening._shell import run
from secure.listening.bind_scope import classify_bind_scope, identity_port
from secure.listening.risk import evaluate_risk
from secure.storage.models import (
    ListeningServiceRecord,
    add_listening_events,
    last_listening_run_id,
    list_listening_services,
    list_recent_listening_events,
    upsert_listening_service,
)

def _is_listening(entry: ConnectionEntry) -> bool:
    """True for a socket that's listening for connections, not an active one.

    TCP: state == "LISTEN" (an ESTABLISHED/CLOSE_WAIT/etc entry has a
    real remote peer and belongs to Phase 4's connections scan, not
    this audit). UDP has no connection state at all — a UDP entry with
    no remote peer (remote_addr is None) is "listening" in the sense
    that matters here: something is bound to that port waiting for
    traffic. A UDP entry that DOES have a remote peer (the OS's
    connect()-style UDP "session" tracking, e.g. an app mid-call to a
    remote server) is outbound traffic, not a listening service.
    """
    if entry.proto == "TCP":
        return entry.state == "LISTEN"
    return entry.remote_addr is None


@dataclass
class ListeningServiceEntry:
    """One listening socket from a single scan, with this package's own analysis attached."""

    proto: str
    local_addr: Optional[str]
    local_port: Optional[int]
    pid: int
    process_name: str
    bind_scope: str  # "localhost" or "network" — see bind_scope.py
    risk_note: str


@dataclass
class ListeningScanResult:
    scanned_at: str
    run_id: str
    lsof_available: bool = True
    entries: List[ListeningServiceEntry] = field(default_factory=list)
    # (record, was_new) for every distinct listening service seen this scan.
    services: List[Tuple[ListeningServiceRecord, bool]] = field(default_factory=list)
    # Services that WERE listening as of the immediately preceding scan
    # but aren't anymore — see _previous_scan_identities()'s docstring.
    # Empty on the very first scan (nothing to compare against yet).
    disappeared_services: List[ListeningServiceRecord] = field(default_factory=list)
    # False only on the very first scan ever run (or after lsof failed)
    # — lets callers distinguish "nothing disappeared" from "there was
    # nothing to compare against yet."
    has_previous_scan: bool = False

    @property
    def new_services(self) -> List[ListeningServiceRecord]:
        return [record for record, was_new in self.services if was_new]

    @property
    def network_exposed_count(self) -> int:
        return sum(1 for e in self.entries if e.bind_scope == "network")


def _previous_scan_identities(conn: sqlite3.Connection, previous_run_id: Optional[str]) -> set:
    """Return the identity-key set of every service listening as of the last scan.

    Reconstructed from listening_events (the append-only history)
    rather than a dedicated column on listening_services, so no schema
    migration is needed for databases that already have the table —
    the same "fetch recent rows, filter by run_id in Python" pattern
    secure/continuity.py's _posture_baseline() already uses for the
    same kind of "what did the last run look like" comparison.

    previous_run_id must be captured BEFORE this scan writes its own
    events, or this would just return the current run.
    """
    if previous_run_id is None:
        return set()
    # Generous limit: a single scan is rarely more than ~150 rows, so
    # this comfortably covers one full previous run even if several
    # scans have happened close together.
    events = list_recent_listening_events(conn, limit=1000)
    return {
        (e.proto, e.bind_scope, e.process_name, identity_port(e.local_port))
        for e in events
        if e.run_id == previous_run_id
    }


def scan_listening_services(conn: sqlite3.Connection) -> ListeningScanResult:
    """Run one listening-service audit and record the results.

    Every listening socket lsof reports gets a row in listening_events
    (full history, grouped by run_id). Every distinct service —
    deduplicated by (proto, bind_scope, process_name, identity_port),
    see bind_scope.identity_port() — gets upserted into listening_services so a
    first-time service can be flagged. Services present in the
    immediately preceding scan but absent from this one are reported
    as disappeared_services — a service quietly closing is just as
    worth noticing as a new one appearing.
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]
    # Must be read before this scan writes anything below, or it would
    # just be this run's own id.
    previous_run_id = last_listening_run_id(conn)

    # +c0: don't truncate the COMMAND column — see
    # secure/connections/lsof_parser.py's module docstring.
    result = run(["lsof", "-i", "-n", "-P", "+c0"], timeout=15.0)
    if result.returncode is None:
        # lsof itself failed/timed out — a genuine sensor failure
        # (Stage 4 approval item 3/12), not a routine "nothing to do."
        # Recorded as an error so this pass doesn't look clean.
        failed_counters = BaselineRunCounters()
        failed_counters.record_error("lsof unavailable or timed out during listening scan")
        finalize_baseline_run(conn, run_id, started_at, failed_counters)
        return ListeningScanResult(scanned_at=now, run_id=run_id, lsof_available=False)

    previous_identities = _previous_scan_identities(conn, previous_run_id)

    all_entries = parse_lsof_output(result.stdout)
    listening = [e for e in all_entries if _is_listening(e)]

    entries: List[ListeningServiceEntry] = []
    event_rows = []
    services: List[Tuple[ListeningServiceRecord, bool]] = []
    seen_this_scan = set()  # lsof often lists the same listener twice (IPv4 + IPv6) — one upsert each
    counters = BaselineRunCounters()

    for raw in listening:
        bind_scope = classify_bind_scope(raw.local_addr)
        risk_note = evaluate_risk(raw.local_port, raw.process_name, bind_scope)

        entries.append(
            ListeningServiceEntry(
                proto=raw.proto,
                local_addr=raw.local_addr,
                local_port=raw.local_port,
                pid=raw.pid,
                process_name=raw.process_name,
                bind_scope=bind_scope,
                risk_note=risk_note,
            )
        )
        event_rows.append(
            (raw.proto, raw.local_addr, raw.local_port, bind_scope, raw.pid, raw.process_name)
        )

    # Phase 14.5 Stage B: inserted here (before the upsert/feature-
    # evaluation pass below), rather than after it as before, so each
    # entry's exact listening_events.id is known in time to use as that
    # entry's anomaly provenance — the same reordering already applied
    # to secure/connections/scanner.py. event_ids is built in the same
    # order as `listening`/`event_rows`; when there's nothing to insert
    # it's simply [], and the zip() below is then a no-op.
    event_ids: List[int] = (
        add_listening_events(conn, run_id=run_id, rows=event_rows) if event_rows else []
    )

    for raw, event_id in zip(listening, event_ids):
        bind_scope = classify_bind_scope(raw.local_addr)
        identity_port_value = identity_port(raw.local_port)
        identity_key = (raw.proto, bind_scope, raw.process_name, identity_port_value)
        if identity_key in seen_this_scan:
            continue
        seen_this_scan.add(identity_key)

        record, was_new = upsert_listening_service(
            conn,
            proto=raw.proto,
            bind_scope=bind_scope,
            process_name=raw.process_name,
            identity_port=identity_port_value,
            local_addr=raw.local_addr,
            local_port=raw.local_port,
        )
        services.append((record, was_new))

        # Product Phase 14: bind_scope has no existing per-scan history
        # log of its own (listening_events stores the raw local_addr,
        # not the classified scope) — logged here via the dedicated
        # baseline_feature_activity extension (Stage 3), always a real
        # determined value (classify_bind_scope() never returns
        # "unavailable" — see its own docstring), so this is never
        # marked partial_sensor_data.
        #
        # Phase 14.5 Stage B: source_id references the exact
        # listening_events row this scan just wrote for this socket
        # (event_id, a real per-row id — see add_listening_events()'s
        # docstring), not listening_services.id — that table is a
        # DEDUPED identity row updated in place across every scan of
        # this service, so it can't identify which specific scan
        # produced a given anomaly (the same class of imprecise
        # reference process_destination's and wifi's provenance fixes
        # corrected earlier — see PROJECT_NOTES.md's change log).
        try:
            evaluate_and_record_feature_observation(
                conn, run_id, "listening",
                listening_key(raw.process_name, identity_port_value, raw.proto),
                "bind_scope", bind_scope, now,
                is_network_bind=(bind_scope == "network"),
                source_table="listening_events", source_id=event_id,
                counters=counters,
            )
        except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
            counters.record_error(f"bind_scope baseline evaluation failed for {identity_key!r}: {exc}")

    finalize_baseline_run(conn, run_id, started_at, counters)

    disappeared_identities = previous_identities - seen_this_scan
    disappeared_services = [
        record
        for record in list_listening_services(conn)
        if (record.proto, record.bind_scope, record.process_name, record.identity_port)
        in disappeared_identities
    ]

    return ListeningScanResult(
        scanned_at=now,
        run_id=run_id,
        lsof_available=True,
        entries=entries,
        services=services,
        disappeared_services=disappeared_services,
        has_previous_scan=previous_run_id is not None,
    )
