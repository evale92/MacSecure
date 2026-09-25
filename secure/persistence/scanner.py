"""
persistence/scanner.py — orchestrates one Process and Persistence
Monitor scan: inventory running processes, inventory LaunchAgents/
LaunchDaemons/login items, compare against everything this app already
knows, and flag what's worth a look.

Four things happen on every scan (step 2 also covers the extra
locations in extra_locations.py — authorization plugins, scripting
additions, kexts, startup items, periodic/emond/folder-action/ssh rc
scripts — through the same new/changed-entry path):

    1. Process inventory (processes.py) — every currently-running
       process with a resolvable executable path is recorded,
       deduplicated by path, not PID (see database.py's schema
       comment for why). A brand-new executable path gets a
       code-signing check right then, once; if it's unsigned/
       ad-hoc-signed and/or running from an unusual location, an
       alert is raised. Already-known executables are NOT re-checked
       every scan — see models.py's upsert_process_entry() docstring.
    2. LaunchAgent/LaunchDaemon inventory (launch_items.py) — every
       plist in the three scanned directories (see that module's
       scope note) is read and parsed directly, no subprocess.
    3. Login item inventory (login_items.py) — this user's classic
       System Events login items.
    4. For every persistence entry from (2) and (3): a brand-new one
       always raises an alert (MEDIUM, or HIGH if its executable is
       unsigned/ad-hoc/unresolvable); an EXISTING one whose backing
       executable's signing status just downgraded from signed to
       unsigned/ad-hoc raises a HIGH "signing_changed" alert (see
       analysis.py's is_signing_downgrade()).

Every code-signing check is deliberately bounded — new processes only,
plus every persistence entry (few enough to check every scan without
this being slow) — never the full process table.

This module never deletes, quarantines, disables, unloads, or modifies
any file, process, or persistence mechanism it finds — it only reads
and reports. Per the Claude prompt this phase was built from: "Never
delete or quarantine files automatically."
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from secure.baseline.engine import BaselineRunCounters, evaluate_and_record_feature_observation, finalize_baseline_run
from secure.baseline.history import record_gap_observation
from secure.baseline.entities import PERSISTENCE, PROCESS, persistence_key, process_key
from secure.evidence import (
    EvidenceLink,
    ObservationRef,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    record_link,
)
from secure.persistence.analysis import (
    is_signing_downgrade,
    persistence_entry_alert_severity,
    process_alert_severity,
)
from secure.persistence.codesign import UNKNOWN, check_code_signing
from secure.persistence.extra_locations import scan_extra_locations
from secure.persistence.launch_items import scan_launch_items
from secure.persistence.login_items import get_login_items
from secure.persistence.processes import is_resolvable_path, list_processes
from secure.storage.models import (
    PersistenceEntryRecord,
    ProcessEntryRecord,
    add_persistence_alert,
    add_persistence_observations,
    find_process_entry_by_path,
    upsert_persistence_entry,
    upsert_process_entry,
)

_LAUNCH_ITEM_KINDS = ("launch_agent_user", "launch_agent_global", "launch_daemon")


@dataclass
class PersistenceAlert:
    kind: str  # "unusual_unsigned_process" | "new_persistence_entry" | "signing_changed"
    severity: str
    target_type: str
    identifier: str
    label: Optional[str]
    message: str
    id: Optional[int] = None


@dataclass
class PersistenceScanResult:
    scanned_at: str
    run_id: str
    processes_available: bool = True
    login_items_available: bool = True
    process_count: int = 0
    new_processes: List[ProcessEntryRecord] = field(default_factory=list)
    new_persistence_entries: List[PersistenceEntryRecord] = field(default_factory=list)
    alerts: List[PersistenceAlert] = field(default_factory=list)
    evidence_links_recorded: int = 0


def _raise_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    target_type: str,
    identifier: str,
    label: Optional[str],
    message: str,
    alerts: List[PersistenceAlert],
) -> None:
    alert = PersistenceAlert(
        kind=kind,
        severity=severity,
        target_type=target_type,
        identifier=identifier,
        label=label,
        message=message,
    )
    alert.id = add_persistence_alert(
        conn,
        run_id=run_id,
        kind=kind,
        severity=severity,
        target_type=target_type,
        identifier=identifier,
        label=label,
        message=message,
    )
    alerts.append(alert)


def _scan_processes(
    conn: sqlite3.Connection, run_id: str, alerts: List[PersistenceAlert],
    counters: "BaselineRunCounters",
) -> "tuple[bool, int, List[ProcessEntryRecord]]":
    ok, rows = list_processes()
    if not ok:
        # A genuine sensor failure (Stage 4 approval item 3/12), not
        # "zero processes running" — must not look like a clean pass.
        counters.record_error("process listing unavailable this scan")
        return False, 0, []

    now = datetime.now(timezone.utc).isoformat()
    process_count = 0
    new_processes: List[ProcessEntryRecord] = []
    seen_paths = set()

    for row in rows:
        path_or_name = row["path_or_name"]
        if not is_resolvable_path(path_or_name):
            continue
        executable_path = path_or_name
        if executable_path in seen_paths:
            # Multiple running instances of the same executable (very
            # common: several Chrome helper processes, etc.) should
            # only be counted/checked once per scan.
            continue
        seen_paths.add(executable_path)
        process_count += 1
        process_name = executable_path.rsplit("/", 1)[-1]

        existing = find_process_entry_by_path(conn, executable_path)
        signing_status = None
        if existing is None:
            signing_status = check_code_signing(executable_path)

        record, was_new = upsert_process_entry(
            conn,
            executable_path=executable_path,
            process_name=process_name,
            run_as_user=row["user"],
            signing_status=signing_status,
        )

        # Product Phase 14: process_entries has no existing per-scan
        # log to read from (deduplicated-only by design — see
        # database.py's schema comment), so every observed process is
        # logged here via the baseline_activity gap-filler, for both
        # new and already-known executables — baseline frequency needs
        # every appearance, not just first-seen ones. One bad record
        # (Stage 4 approval item 3) is logged and skipped, not allowed
        # to abort the rest of the scan.
        try:
            record_gap_observation(conn, run_id, PROCESS, process_key(executable_path), now, counters=counters)
        except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
            counters.record_error(f"process baseline observation failed for {executable_path!r}: {exc}")

        if not was_new:
            continue

        record.signing_status = signing_status
        new_processes.append(record)

        severity = process_alert_severity(signing_status, executable_path)
        if severity:
            message = (
                f"'{process_name}' started running for the first time, from "
                f"{executable_path} (code signing: {signing_status}). A new "
                "process alone is routine — this is flagged specifically "
                "because of its signing status and/or where it's running "
                "from, not just because it's new. This does not prove "
                "anything malicious; plenty of legitimate tools are "
                "unsigned or ad-hoc signed. Worth a look if you don't "
                "recognize it."
            )
            _raise_alert(
                conn, run_id, "unusual_unsigned_process", severity, "process",
                executable_path, process_name, message, alerts,
            )

    return True, process_count, new_processes


def _collect_persistence_items() -> "tuple[bool, list, list]":
    """Gather every LaunchAgent/LaunchDaemon/login item entry from all
    four sources into one flat list of dicts sharing a common shape:
    {"kind", "path", "label", "program_path", "run_at_load", "keep_alive"}.
    Returns (login_items_ok, entries) — login_items_ok reflects only
    whether the login-items source (osascript) worked; launch agents/
    daemons have no equivalent "unavailable" state since they're plain
    filesystem reads (a missing directory just means zero entries from
    it, which is normal and expected on most Macs).
    """
    entries = []

    for kind in _LAUNCH_ITEM_KINDS:
        for item in scan_launch_items(kind):
            entries.append(
                {
                    "kind": kind,
                    "path": item["path"],
                    "label": item["label"],
                    "program_path": item["program_path"],
                    "run_at_load": item["run_at_load"],
                    "keep_alive": item["keep_alive"],
                }
            )

    login_items_ok, login_items = get_login_items()
    for item in login_items:
        entries.append(
            {
                "kind": "login_item",
                "path": item["path"],
                "label": item["name"],
                "program_path": item["path"],
                "run_at_load": None,
                "keep_alive": None,
            }
        )

    # Authorization plugins, kexts, periodic scripts, ssh rc and the rest of
    # extra_locations.py's scope. A location that exists but could not be
    # read comes back in `unavailable` and is recorded as a scan error.
    extra_entries, unavailable = scan_extra_locations()
    entries.extend(extra_entries)

    return login_items_ok, entries, unavailable


def _scan_persistence_items(
    conn: sqlite3.Connection, run_id: str, alerts: List[PersistenceAlert],
    counters: "BaselineRunCounters",
) -> "tuple[bool, List[PersistenceEntryRecord], int]":
    now = datetime.now(timezone.utc).isoformat()
    login_items_ok, entries, unavailable = _collect_persistence_items()
    for problem in unavailable:
        counters.record_error(f"persistence location unreadable this scan: {problem}")
    if not login_items_ok:
        # Partial sensor failure (Stage 4 approval item 3): login items
        # (osascript) failed, but LaunchAgent/LaunchDaemon entries were
        # still collected and are still evaluated below — only the
        # unavailable source is flagged, not the whole scan.
        counters.record_error("login items unavailable this scan (launch agents/daemons still evaluated)")

    # Phase 14.5 Stage B: observation_ids is a real per-row
    # `persistence_observations.id`, one per entry, in the same order
    # as `entries` (every entry becomes exactly one observation row
    # here — nothing is skipped or deduplicated before this insert).
    # Captured so the feature-evaluation loop below can reference the
    # exact observation row instead of persistence_entries.id — see
    # that loop's comment for why.
    observation_ids: List[int] = (
        add_persistence_observations(
            conn,
            run_id=run_id,
            rows=[
                (
                    e["kind"],
                    e["label"],
                    e["path"],
                    e["program_path"],
                    e["run_at_load"],
                    e["keep_alive"],
                )
                for e in entries
            ],
        )
        if entries
        else []
    )

    new_entries: List[PersistenceEntryRecord] = []
    evidence_links_recorded = 0
    for e, observation_id in zip(entries, observation_ids):
        program_path = e["program_path"]
        signing_status = check_code_signing(program_path) if program_path else None

        record, was_new, previous_signing_status = upsert_persistence_entry(
            conn,
            kind=e["kind"],
            path=e["path"],
            label=e["label"],
            program_path=program_path,
            signing_status=signing_status,
        )

        identifier = e["path"] or e["label"] or "(unknown)"
        label = e["label"]

        # Phase 22 Stage 1 (additive): if this persistence entry's own
        # program_path matches a KNOWN process_entries row (this scan's
        # own process inventory runs first — see scan_persistence()'s
        # call order — or an earlier scan's), record a formal
        # same_event_confirmation link. Deliberately NOT derived_evidence
        # — neither row's existence derives from the other; they're two
        # genuinely independent vantage points (launchctl/plist
        # inventory vs. the running-process list) converging on the same
        # real executable, the same relationship shape osquery's own
        # native crosscheck already uses. There was previously no
        # persisted trace of this relationship at all — only an implicit
        # shared executable_path string between two otherwise-unrelated
        # dedup tables (see docs/EVIDENCE.md's Phase 22 section).
        if program_path:
            process_record = find_process_entry_by_path(conn, program_path)
            if process_record is not None:
                try:
                    _, created = record_link(
                        conn,
                        EvidenceLink(
                            from_ref=ObservationRef(source_table="persistence_entries", source_id=record.id),
                            to_ref=ObservationRef(source_table="process_entries", source_id=process_record.id),
                            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                            match_basis="executable_path",
                            detail=(
                                f"persistence entry's program_path ({program_path!r}) matches a "
                                "known process_entries row"
                            ),
                            created_by="persistence_process_match",
                        ),
                    )
                    if created:
                        evidence_links_recorded += 1
                except Exception:  # noqa: BLE001 - defensive: enrichment must never fail the scan
                    pass

        # Product Phase 14: persistence_entries.signing_status IS
        # re-checked every scan (unlike process_entries, which only
        # computes it once at first-seen), but the past values were
        # never logged anywhere — see database.py's schema comment on
        # baseline_feature_activity. Logged for EVERY entry, new or
        # not, so repeated identical observations ("signed_developer,
        # signed_developer, ...") build real frequency history, not
        # just first-seen. signing_status == UNKNOWN means codesign
        # itself never ran (see codesign.py) — a sensor failure, not a
        # legitimate observed category, so it's marked
        # partial_sensor_data and never trains the baseline.
        #
        # Phase 14.5 Stage B: source_id references the exact
        # persistence_observations row this scan just wrote for this
        # entry (observation_id, a real per-row id — see
        # add_persistence_observations()'s docstring), not
        # persistence_entries.id — that table is a DEDUPED identity row
        # updated in place across every scan of this entry, so it can't
        # identify which specific scan produced a given anomaly (the
        # same class of imprecise reference process_destination's,
        # wifi's, and listening's provenance fixes corrected earlier —
        # see PROJECT_NOTES.md's change log).
        try:
            evaluate_and_record_feature_observation(
                conn, run_id, PERSISTENCE, persistence_key(e["kind"], identifier),
                "signing_status",
                signing_status if signing_status not in (None, UNKNOWN) else None,
                now,
                partial_sensor_data=(signing_status in (None, UNKNOWN)),
                is_unsigned=(signing_status in ("unsigned", "signed_adhoc")),
                source_table="persistence_observations", source_id=observation_id,
                counters=counters,
            )
        except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
            counters.record_error(f"signing_status baseline evaluation failed for {identifier!r}: {exc}")

        if was_new:
            new_entries.append(record)
            severity = persistence_entry_alert_severity(signing_status, program_path)
            message = (
                f"A new {e['kind'].replace('_', ' ')} entry appeared: "
                f"'{label or identifier}'"
                + (f" (program: {program_path})" if program_path else " (no resolvable program path)")
                + f". Code signing: {signing_status or 'unknown'}. This is often "
                "completely innocent — software you just installed, or a "
                "login item you just added yourself. It's flagged because "
                "any new persistence mechanism is worth a deliberate look, "
                "not because it's necessarily unwanted."
            )
            _raise_alert(
                conn, run_id, "new_persistence_entry", severity, e["kind"],
                identifier, label, message, alerts,
            )
        elif is_signing_downgrade(previous_signing_status, signing_status):
            message = (
                f"The executable behind '{label or identifier}' "
                f"({e['kind'].replace('_', ' ')}) changed from "
                f"{previous_signing_status} to {signing_status} since the last "
                "scan. This does not prove an attack, but a previously "
                "properly-signed persistence entry's backing executable "
                "silently losing its signature is exactly the pattern a "
                "hijacked or replaced binary would show, and deserves a "
                "close look."
            )
            _raise_alert(
                conn, run_id, "signing_changed", "high", e["kind"],
                identifier, label, message, alerts,
            )

    return login_items_ok, new_entries, evidence_links_recorded


def scan_persistence(conn: sqlite3.Connection) -> PersistenceScanResult:
    """Run one Process and Persistence Monitor scan and record the results."""
    import os
    import time

    # Stub: simulate slow scanner (for mutation gate testing)
    stub_latency = os.environ.get("SECURE_STUB_PERSISTENCE_LATENCY")
    if stub_latency:
        time.sleep(float(stub_latency) / 1000.0)  # Convert ms to seconds

    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    alerts: List[PersistenceAlert] = []
    counters = BaselineRunCounters()

    processes_available, process_count, new_processes = _scan_processes(conn, run_id, alerts, counters)
    login_items_available, new_persistence_entries, evidence_links_recorded = _scan_persistence_items(
        conn, run_id, alerts, counters
    )

    # One baseline_runs row per scan, covering BOTH process gap-filling
    # and persistence signing_status feature logging above — they share
    # this one run_id already, so they share one lifecycle row too
    # (Stage 4 approval item 2), rather than inventing a second run_id
    # for a "half" of one scan.
    finalize_baseline_run(conn, run_id, started_at, counters)

    return PersistenceScanResult(
        scanned_at=now,
        run_id=run_id,
        processes_available=processes_available,
        login_items_available=login_items_available,
        process_count=process_count,
        new_processes=new_processes,
        new_persistence_entries=new_persistence_entries,
        alerts=alerts,
        evidence_links_recorded=evidence_links_recorded,
    )
