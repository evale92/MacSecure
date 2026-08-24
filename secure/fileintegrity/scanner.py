"""
fileintegrity/scanner.py — orchestrates one File Integrity Monitoring
scan: walk every enabled watch path, compare what's found against the
stored baseline (secure/storage/models.py's file_entries table), and
record what changed.

Five things happen on every scan, in order:

    1. Seed the default watch list (secure/fileintegrity/paths.py) the
       very first time this ever runs, if no watch paths are
       registered yet.
    2. Walk each enabled watch path (os.walk with an onerror callback,
       never inferring anything about a directory this scan couldn't
       actually enumerate — see _walk() and _is_safe_to_infer_absence()
       below). A watch path's very first scan is its BASELINE: every
       file found is recorded with no alert (see insert_file_entry()'s
       known=True-for-baseline behavior in models.py).
    3. For files already on record: the stat-first fast path (only
       re-hash when size or mtime changed — see hashing.py and this
       phase's own PROJECT_NOTES.md entry for the honest limitation
       this implies) classifies each as unchanged / metadata_only /
       modified, and startup plists additionally get their
       Program/ProgramArguments target re-resolved every scan (see
       _enrich_plist()) since that can change independent of the
       plist's own bytes.
    4. Once every watch path has been walked, "missing" and "created"
       candidates are matched globally for CONFIRMED renames — via
       (dev, ino) identity only, never via a shared content hash alone
       (see analysis.match_renames()). Anything left over becomes a
       genuine deleted/created event.
    5. Every change_type except "baseline" and "unchanged" writes a
       file_change_events row (the full history). Only MEDIUM/HIGH
       severity findings additionally write a file_integrity_alerts
       row — LOW-severity findings (an ordinary mtime-only change, a
       documentation edit) stay in history without flooding the
       reviewable alerts queue, matching this phase's explicit
       "baseline-first, don't flood alerts" requirement even outside
       the literal first scan.

This module never deletes, quarantines, restores, chmods, or modifies
any file, and never changes filesystem permissions — read-only
monitoring only, recommendations via alerts, same rule as every other
monitoring phase in this app.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from secure.fileintegrity import analysis
from secure.fileintegrity.hashing import DEFAULT_MAX_HASH_BYTES, FileMetadata, compute_sha256, read_metadata
from secure.fileintegrity.paths import (
    DEFAULT_MAX_DEPTH,
    SENSITIVITY_SELF,
    SENSITIVITY_STARTUP,
    default_watch_paths,
    is_excluded_name,
    is_plist,
)
from secure.persistence.codesign import check_code_signing
from secure.persistence.launch_items import parse_launch_item_plist
from secure.self_update import is_in_update_context
from secure.storage.models import (
    FileEntryRecord,
    FileWatchPathRecord,
    add_file_change_event,
    add_file_integrity_alert,
    add_file_integrity_scan,
    add_watch_path,
    delete_file_entry,
    insert_file_entry,
    list_file_entries_for_watch_path,
    list_watch_paths,
    rename_file_entry,
    set_watch_path_scan_status,
    touch_file_entry_last_seen,
    update_file_entry,
)

_METADATA_COLUMNS = (
    "hash", "size", "mtime", "uid", "owner", "gid", "group_name", "mode",
    "is_executable", "is_symlink", "symlink_target", "dev", "ino",
    "program_path", "program_signing_status", "program_exists",
    "unreadable", "unreadable_reason", "skipped_reason",
)


# ---------- walking ----------


@dataclass
class WalkResult:
    visited: Dict[str, FileMetadata] = field(default_factory=dict)
    # Every directory not actually descended into this run, for ANY
    # reason (a real I/O/permission error, an exclusion rule, or a
    # depth-limit cutoff). Deliberately broader than just "errors":
    # a depth limit or exclusion is just as capable of producing a
    # false "deleted" claim as a permission error is, so the same
    # never-infer-absence protection applies uniformly — see
    # _is_safe_to_infer_absence().
    not_descended: Set[str] = field(default_factory=set)
    # The narrower subset of the above that reflects a genuine
    # failure (not an intentional exclusion/depth cutoff) — what gets
    # surfaced to the user as a coverage problem worth attention.
    failed_dirs: Dict[str, str] = field(default_factory=dict)
    root_ok: bool = True
    excluded_count: int = 0


def _walk(root: str, recursive: bool, max_depth: int) -> WalkResult:
    """Walk one watch path. Read-only: os.lstat() and os.walk()'s own
    directory listing only, nothing is opened except for hashing (a
    separate, later step) or read via readlink() for symlinks.
    """
    result = WalkResult()
    root_meta = read_metadata(root)

    if not root_meta.exists:
        if root_meta.unreadable:
            result.failed_dirs[root] = root_meta.unreadable_reason or "unreadable"
            result.not_descended.add(root)
            result.root_ok = False
        # else: genuinely doesn't exist yet (e.g. a configured watch
        # path that hasn't been created on this machine) — not a
        # failure, just nothing to scan this run.
        return result

    if root_meta.is_regular_file or root_meta.is_symlink:
        result.visited[root] = root_meta
        return result

    if root_meta.is_special:
        return result  # device/socket/fifo watch "path" — nothing sensible to monitor

    def _on_error(exc: OSError) -> None:
        failed_path = getattr(exc, "filename", None) or root
        result.failed_dirs[failed_path] = str(exc)
        result.not_descended.add(failed_path)
        if os.path.normpath(failed_path) == os.path.normpath(root):
            result.root_ok = False

    for dirpath, dirnames, filenames in os.walk(root, onerror=_on_error, followlinks=False):
        if dirpath == root:
            depth = 0
        else:
            depth = dirpath[len(root):].lstrip(os.sep).count(os.sep) + 1

        if max_depth is not None and depth >= max_depth:
            for d in dirnames:
                result.not_descended.add(os.path.join(dirpath, d))
            dirnames[:] = []

        kept = []
        for d in dirnames:
            if is_excluded_name(d):
                result.not_descended.add(os.path.join(dirpath, d))
                result.excluded_count += 1
                continue
            kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            if is_excluded_name(name):
                result.excluded_count += 1
                continue
            full_path = os.path.join(dirpath, name)
            meta = read_metadata(full_path)
            if not meta.exists and not meta.unreadable:
                continue  # raced away between directory listing and lstat
            if meta.is_special:
                continue
            result.visited[full_path] = meta

        if not recursive:
            dirnames[:] = []  # root-level files only, never descend

    return result


def _is_safe_to_infer_absence(path: str, walk: WalkResult) -> bool:
    """True only when this scan can honestly say `path` is genuinely
    gone — i.e. every directory between the watch root and this path
    was actually, successfully enumerated this run. False for anything
    under a directory this scan didn't fully visit, for ANY reason.
    """
    if not walk.root_ok:
        return False
    for not_descended in walk.not_descended:
        if path == not_descended or path.startswith(not_descended + os.sep):
            return False
    return True


# ---------- metadata helpers ----------


def _entry_to_dict(entry: FileEntryRecord) -> dict:
    return {
        "hash": entry.hash,
        "size": entry.size,
        "mtime": entry.mtime,
        "uid": entry.uid,
        "owner": entry.owner,
        "gid": entry.gid,
        "group_name": entry.group_name,
        "mode": entry.mode,
        "is_executable": entry.is_executable,
        "is_symlink": entry.is_symlink,
        "symlink_target": entry.symlink_target,
        "dev": entry.dev,
        "ino": entry.ino,
    }


def _enrich_plist(path: str) -> dict:
    """For a LaunchAgent/LaunchDaemon plist: resolve its
    Program/ProgramArguments target and that target's code-signing
    status, reusing persistence/launch_items.py's parser and
    persistence/codesign.py's classifier rather than re-implementing
    either. Severity is based on the REFERENCED EXECUTABLE, never the
    plist file's own (meaningless) signed/unsigned state.
    """
    parsed = parse_launch_item_plist(Path(path))
    program_path = parsed.get("program_path")
    if not program_path:
        return {"program_path": None, "program_signing_status": None, "program_exists": None}
    program_exists = os.path.exists(program_path)
    signing_status = check_code_signing(program_path) if program_exists else None
    return {
        "program_path": program_path,
        "program_signing_status": signing_status,
        "program_exists": program_exists,
    }


def _build_metadata_dict(meta: FileMetadata, hash_value: "Optional[str]", skipped_reason: "Optional[str]", program_info: "Optional[dict]" = None) -> dict:
    d = meta.as_dict()
    d["hash"] = hash_value
    d["skipped_reason"] = skipped_reason
    d["unreadable"] = meta.unreadable
    d["unreadable_reason"] = meta.unreadable_reason
    d.update(program_info or {"program_path": None, "program_signing_status": None, "program_exists": None})
    return d


def _hash_for(path: str, meta: FileMetadata, max_hash_bytes: int) -> "tuple[Optional[str], Optional[str]]":
    """Symlinks are never hashed (their "content" is the target path,
    already captured as symlink_target — see hashing.py's module
    docstring: lstat-based, never follows).
    """
    if meta.is_symlink or not meta.is_regular_file:
        return None, None
    return compute_sha256(path, max_bytes=max_hash_bytes)


# ---------- result shapes ----------


@dataclass
class FileIntegrityAlert:
    kind: str
    severity: str
    path: str
    message: str
    context_notes: "Optional[str]" = None
    id: "Optional[int]" = None


@dataclass
class FileIntegrityScanResult:
    run_id: str
    scanned_at: str
    duration_seconds: float
    watch_paths_attempted: List[str] = field(default_factory=list)
    watch_paths_completed: List[str] = field(default_factory=list)
    watch_paths_incomplete: List[dict] = field(default_factory=list)
    files_visited: int = 0
    files_hashed: int = 0
    files_skipped_unchanged: int = 0
    files_skipped_too_large: int = 0
    files_skipped_excluded: int = 0
    files_unreadable: int = 0
    alerts: List[FileIntegrityAlert] = field(default_factory=list)


# ---------- main orchestration ----------


def _seed_defaults_if_empty(conn) -> None:
    if list_watch_paths(conn):
        return
    for entry in default_watch_paths():
        add_watch_path(
            conn,
            path=entry["path"],
            recursive=entry["recursive"],
            sensitivity=entry["sensitivity"],
        )


def _raise_alert(
    conn,
    run_id: str,
    kind: str,
    severity: str,
    path: str,
    message: str,
    context_notes: "Optional[str]",
    alerts: List[FileIntegrityAlert],
) -> None:
    alert = FileIntegrityAlert(kind=kind, severity=severity, path=path, message=message, context_notes=context_notes)
    if severity in (analysis.MEDIUM, analysis.HIGH):
        alert.id = add_file_integrity_alert(
            conn, run_id=run_id, kind=kind, severity=severity, path=path,
            message=message, context_notes=context_notes,
        )
    alerts.append(alert)


def _message(change_type: str, path: str, reasons: "list[str]") -> str:
    reason_text = "; ".join(reasons) if reasons else "no further detail available"
    return f"{change_type.replace('_', ' ')}: {path} — {reason_text}"


def scan_file_integrity(
    conn,
    max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
    default_max_depth: int = DEFAULT_MAX_DEPTH,
) -> FileIntegrityScanResult:
    """Run one File Integrity Monitoring scan and record the results."""
    run_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()

    _seed_defaults_if_empty(conn)
    watch_paths = list_watch_paths(conn, enabled_only=True)
    in_update_context = is_in_update_context(conn)

    counters = {
        "files_visited": 0,
        "files_hashed": 0,
        "files_skipped_unchanged": 0,
        "files_skipped_too_large": 0,
        "files_skipped_excluded": 0,
        "files_unreadable": 0,
    }
    alerts: List[FileIntegrityAlert] = []
    attempted: List[str] = []
    completed: List[str] = []
    incomplete: List[dict] = []

    all_missing: List[dict] = []  # {"entry": FileEntryRecord, "watch_path": FileWatchPathRecord}
    all_created: List[dict] = []  # {"path", "meta", "watch_path", "hash", "skipped_reason"}

    for wp in watch_paths:
        attempted.append(wp.path)
        max_depth = wp.max_depth if wp.max_depth is not None else default_max_depth
        walk = _walk(wp.path, wp.recursive, max_depth)
        counters["files_skipped_excluded"] += walk.excluded_count

        existing_rows = {row.path: row for row in list_file_entries_for_watch_path(conn, wp.id)}
        # Baseline is "has this watch path ever been scanned before",
        # NOT "does it currently have zero file_entries rows" -- an
        # empty LaunchDaemons folder (or any watch path that legitimately
        # finds nothing) would otherwise stay "baseline" forever, since
        # zero prior rows looks identical to a genuinely first-ever scan.
        # last_scan_at is set at the end of every scan attempt (see
        # set_watch_path_scan_status() below), regardless of whether
        # anything was found, so it's the right signal here.
        is_baseline_scan = wp.last_scan_at is None

        for path, meta in walk.visited.items():
            counters["files_visited"] += 1

            if meta.unreadable:
                counters["files_unreadable"] += 1
                # A file we can't currently read but previously knew
                # about must NOT be treated as absent — leave it alone
                # and let it fall out of the deletion-candidate pass
                # below by removing it from existing_rows here.
                existing_rows.pop(path, None)
                continue

            prior = existing_rows.pop(path, None)
            program_info = _enrich_plist(path) if is_plist(path) and wp.sensitivity == SENSITIVITY_STARTUP else None

            if prior is None:
                # Brand-new path this scan.
                hash_value, skip_reason = _hash_for(path, meta, max_hash_bytes)
                if skip_reason == "too_large":
                    counters["files_skipped_too_large"] += 1
                elif hash_value is not None:
                    counters["files_hashed"] += 1

                if is_baseline_scan:
                    metadata = _build_metadata_dict(meta, hash_value, skip_reason, program_info)
                    insert_file_entry(conn, watch_path_id=wp.id, path=path, metadata=metadata, known=True)
                    add_file_change_event(
                        conn, run_id=run_id, watch_path_id=wp.id, path=path,
                        change_type="baseline", details={"metadata": metadata},
                        new_hash=hash_value,
                    )
                else:
                    all_created.append({
                        "path": path, "meta": meta, "watch_path": wp,
                        "hash": hash_value, "skipped_reason": skip_reason,
                        "program_info": program_info,
                    })
                continue

            # Existing file — compare.
            _compare_existing(
                conn, run_id, wp, prior, meta, program_info,
                in_update_context, max_hash_bytes, counters, alerts,
            )

        # Whatever's left in existing_rows are deletion candidates,
        # only if this watch path was safely, fully enumerated.
        for path, prior in existing_rows.items():
            if _is_safe_to_infer_absence(path, walk):
                all_missing.append({"entry": prior, "watch_path": wp})

        if walk.failed_dirs:
            incomplete.append({"path": wp.path, "reasons": dict(walk.failed_dirs)})
            set_watch_path_scan_status(conn, wp.id, "incomplete")
        else:
            completed.append(wp.path)
            set_watch_path_scan_status(conn, wp.id, "ok")

    _resolve_renames_and_finalize(conn, run_id, all_missing, all_created, in_update_context, alerts)

    completed_at = datetime.now(timezone.utc).isoformat()
    duration = time.monotonic() - t0
    add_file_integrity_scan(
        conn,
        run_id=run_id,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration,
        watch_paths_attempted=attempted,
        watch_paths_completed=completed,
        watch_paths_incomplete=incomplete,
        alerts_generated=len([a for a in alerts if a.id is not None]),
        **counters,
    )

    return FileIntegrityScanResult(
        run_id=run_id,
        scanned_at=started_at,
        duration_seconds=duration,
        watch_paths_attempted=attempted,
        watch_paths_completed=completed,
        watch_paths_incomplete=incomplete,
        alerts=alerts,
        **counters,
    )


def _finalize_severity(severity: str, reasons: "list[str]", path: str, sensitivity: str, in_update_context: bool) -> "tuple[str, Optional[str]]":
    context_notes = None
    if sensitivity == SENSITIVITY_SELF:
        severity, context_notes = analysis.apply_self_update_context(severity, in_update_context)
        severity = analysis.apply_doc_dampening(severity, path, sensitivity)
    return severity, context_notes


def _compare_existing(
    conn, run_id: str, wp: FileWatchPathRecord, prior: FileEntryRecord, meta: FileMetadata,
    program_info: "Optional[dict]", in_update_context: bool, max_hash_bytes: int,
    counters: dict, alerts: List[FileIntegrityAlert],
) -> None:
    prior_dict = _entry_to_dict(prior)
    current_dict = meta.as_dict()

    size_mtime_changed = prior.size != meta.size or prior.mtime != meta.mtime

    if size_mtime_changed:
        hash_value, skip_reason = _hash_for(prior.path, meta, max_hash_bytes)
        if skip_reason == "too_large":
            counters["files_skipped_too_large"] += 1
        elif hash_value is not None:
            counters["files_hashed"] += 1
        rehashed = True
    else:
        # Stat-first fast path: size and mtime match the stored
        # baseline, so we deliberately do NOT re-read/re-hash this
        # file — see hashing.py and PROJECT_NOTES.md for the honest
        # trade-off this implies (a file whose content changed while
        # leaving size AND mtime identical would not be caught).
        hash_value = prior.hash
        skip_reason = prior.skipped_reason
        counters["files_skipped_unchanged"] += 1
        rehashed = False

    current_dict["hash"] = hash_value

    content_changed = size_mtime_changed and hash_value is not None and hash_value != prior.hash
    metadata_reasons = analysis.diff_metadata(prior_dict, current_dict)
    metadata_changed = bool(metadata_reasons)

    program_changed = False
    program_reasons: List[str] = []
    program_severity = None
    if program_info is not None:
        program_changed = program_info.get("program_path") != prior.program_path
        program_status_changed = (
            program_info.get("program_signing_status") != prior.program_signing_status
            or program_info.get("program_exists") != prior.program_exists
        )
        if program_changed or program_status_changed:
            program_severity, program_reasons = analysis.classify_program_target_severity(
                program_info.get("program_signing_status"),
                bool(program_info.get("program_exists")),
                program_changed,
            )

    full_metadata = _build_metadata_dict(meta, hash_value, skip_reason, program_info)

    if content_changed:
        change_type = "modified"
        severity, reasons = analysis.classify_modified_severity(prior_dict, current_dict, wp.sensitivity)
    elif metadata_changed:
        change_type = "metadata_only"
        severity, reasons = analysis.classify_metadata_severity(prior_dict, current_dict, wp.sensitivity)
    else:
        change_type = "unchanged"
        severity, reasons = None, []

    program_target_event_needed = program_changed or (program_info is not None and program_severity is not None)

    if change_type == "unchanged" and not program_target_event_needed:
        # Nothing changed at all — cheapest possible update.
        touch_file_entry_last_seen(conn, prior.id)
        return

    # Something changed (the file's own state and/or its startup
    # target) — persist the refreshed metadata either way.
    update_file_entry(conn, prior.id, full_metadata, rehashed=rehashed)

    if change_type != "unchanged":
        severity, context_notes = _finalize_severity(severity, reasons, prior.path, wp.sensitivity, in_update_context)
        add_file_change_event(
            conn, run_id=run_id, watch_path_id=wp.id, path=prior.path,
            change_type=change_type, previous_hash=prior.hash, new_hash=hash_value,
            details={"reasons": reasons, "previous": prior_dict, "current": current_dict},
        )
        _raise_alert(
            conn, run_id, change_type, severity, prior.path,
            _message(change_type, prior.path, reasons), context_notes, alerts,
        )

    if program_target_event_needed:
        target_severity, target_context = _finalize_severity(
            program_severity or analysis.MEDIUM, program_reasons, prior.path, wp.sensitivity, in_update_context,
        )
        add_file_change_event(
            conn, run_id=run_id, watch_path_id=wp.id, path=prior.path,
            change_type="program_target_changed",
            details={
                "reasons": program_reasons,
                "previous_program_path": prior.program_path,
                "new_program_path": program_info.get("program_path"),
            },
        )
        _raise_alert(
            conn, run_id, "program_target_changed", target_severity, prior.path,
            _message("program_target_changed", prior.path, program_reasons), target_context, alerts,
        )


def _resolve_renames_and_finalize(
    conn, run_id: str, all_missing: "list[dict]", all_created: "list[dict]",
    in_update_context: bool, alerts: List[FileIntegrityAlert],
) -> None:
    missing_candidates = [
        {"path": m["entry"].path, "dev": m["entry"].dev, "ino": m["entry"].ino, "hash": m["entry"].hash, "_ref": m}
        for m in all_missing
    ]
    created_candidates = [
        {"path": c["path"], "dev": c["meta"].dev, "ino": c["meta"].ino, "hash": c["hash"], "_ref": c}
        for c in all_created
    ]

    renames, remaining_missing, remaining_created = analysis.match_renames(missing_candidates, created_candidates)

    for missing_cand, created_cand in renames:
        m_ref = missing_cand["_ref"]
        c_ref = created_cand["_ref"]
        entry: FileEntryRecord = m_ref["entry"]
        dest_wp: FileWatchPathRecord = c_ref["watch_path"]

        renamed_entry = rename_file_entry(conn, entry.id, c_ref["path"], dest_wp.id)
        # Refresh full metadata (owner/mode/etc may also differ) at the new path.
        metadata = _build_metadata_dict(c_ref["meta"], c_ref["hash"], c_ref.get("skipped_reason"), c_ref.get("program_info"))
        update_file_entry(conn, renamed_entry.id, metadata, rehashed=True)

        severity, reasons = analysis.classify_renamed_severity(dest_wp.sensitivity)
        severity, context_notes = _finalize_severity(severity, reasons, c_ref["path"], dest_wp.sensitivity, in_update_context)
        add_file_change_event(
            conn, run_id=run_id, watch_path_id=dest_wp.id, path=c_ref["path"], old_path=entry.path,
            change_type="renamed", previous_hash=entry.hash, new_hash=c_ref["hash"],
            rename_confidence="confirmed_inode",
            details={"reasons": reasons, "old_path": entry.path, "new_path": c_ref["path"]},
        )
        _raise_alert(
            conn, run_id, "renamed", severity, c_ref["path"],
            f"renamed/moved: {entry.path} -> {c_ref['path']}", context_notes, alerts,
        )

    for missing_cand in remaining_missing:
        m_ref = missing_cand["_ref"]
        entry: FileEntryRecord = m_ref["entry"]
        wp: FileWatchPathRecord = m_ref["watch_path"]

        severity, reasons = analysis.classify_deleted_file_severity(wp.sensitivity)
        severity, context_notes = _finalize_severity(severity, reasons, entry.path, wp.sensitivity, in_update_context)
        add_file_change_event(
            conn, run_id=run_id, watch_path_id=wp.id, path=entry.path,
            change_type="deleted", previous_hash=entry.hash,
            details={"reasons": reasons},
        )
        _raise_alert(conn, run_id, "deleted", severity, entry.path, _message("deleted", entry.path, reasons), context_notes, alerts)
        delete_file_entry(conn, entry.id)

    for created_cand in remaining_created:
        c_ref = created_cand["_ref"]
        wp: FileWatchPathRecord = c_ref["watch_path"]
        meta: FileMetadata = c_ref["meta"]

        hash_note = analysis.find_hash_correlation_note(c_ref["hash"], remaining_missing)
        severity, reasons = analysis.classify_new_file_severity(meta.as_dict(), wp.sensitivity)

        program_info = c_ref.get("program_info")
        if program_info and program_info.get("program_path"):
            prog_severity, prog_reasons = analysis.classify_program_target_severity(
                program_info.get("program_signing_status"), bool(program_info.get("program_exists")), True,
            )
            severity = analysis.max_severity(severity, prog_severity)
            reasons = reasons + prog_reasons

        if hash_note:
            reasons = reasons + [hash_note]

        severity, context_notes = _finalize_severity(severity, reasons, c_ref["path"], wp.sensitivity, in_update_context)

        metadata = _build_metadata_dict(meta, c_ref["hash"], c_ref.get("skipped_reason"), program_info)
        insert_file_entry(conn, watch_path_id=wp.id, path=c_ref["path"], metadata=metadata, known=False)
        add_file_change_event(
            conn, run_id=run_id, watch_path_id=wp.id, path=c_ref["path"],
            change_type="created", new_hash=c_ref["hash"],
            details={"reasons": reasons},
        )
        _raise_alert(conn, run_id, "created", severity, c_ref["path"], _message("created", c_ref["path"], reasons), context_notes, alerts)
