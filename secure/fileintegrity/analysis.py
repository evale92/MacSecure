"""
fileintegrity/analysis.py — pure logic: comparing two metadata
snapshots to decide what changed and how severe it is, matching
deleted/created candidates into confirmed renames, and the
self-integrity update-context rule. No filesystem access, no
database, no subprocess — every function here takes plain values
(dicts/strings/bools) and returns plain values, directly testable in
isolation, same "pure function + thin wrapper" split every other
package in this app follows (see scanner.py for the I/O side).
"""

from __future__ import annotations

from typing import Optional

from secure.fileintegrity.paths import (
    SENSITIVITY_SELF,
    SENSITIVITY_STARTUP,
    is_lower_significance_self_file,
)
from secure.persistence.codesign import SIGNED_ADHOC, UNSIGNED

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

_SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}
_UNSIGNED_LIKE = (UNSIGNED, SIGNED_ADHOC)


def _max_severity(*severities: str) -> str:
    return max(severities, key=lambda s: _SEVERITY_RANK[s])


# Public alias — scanner.py needs to combine a plist's own change
# severity with its program-target severity; every other cross-module
# severity combination in this file stays internal (_max_severity).
max_severity = _max_severity


def _sensitive(sensitivity: str) -> bool:
    return sensitivity in (SENSITIVITY_STARTUP, SENSITIVITY_SELF)


# ---------- metadata diffing ----------


def diff_metadata(previous: dict, current: dict) -> "list[str]":
    """Compare two metadata dicts (as produced by FileMetadata.as_dict()
    / file_entries rows) and return a plain-English list of what
    changed. Judges nothing about severity — see
    classify_metadata_severity() below.
    """
    reasons = []

    if previous.get("uid") != current.get("uid"):
        reasons.append(f"owner changed ({previous.get('owner')} -> {current.get('owner')})")
    if previous.get("gid") != current.get("gid"):
        reasons.append(f"group changed ({previous.get('group_name')} -> {current.get('group_name')})")
    if previous.get("mode") != current.get("mode"):
        reasons.append(f"permissions changed ({previous.get('mode')} -> {current.get('mode')})")

    if not previous.get("is_executable") and current.get("is_executable"):
        reasons.append("became executable")
    elif previous.get("is_executable") and not current.get("is_executable"):
        reasons.append("no longer executable")

    prev_symlink = bool(previous.get("is_symlink"))
    cur_symlink = bool(current.get("is_symlink"))
    if not prev_symlink and cur_symlink:
        reasons.append(f"replaced by a symlink (-> {current.get('symlink_target')})")
    elif prev_symlink and not cur_symlink:
        reasons.append("symlink replaced by a regular file")
    elif prev_symlink and cur_symlink and previous.get("symlink_target") != current.get("symlink_target"):
        reasons.append(
            f"symlink target changed ({previous.get('symlink_target')} -> {current.get('symlink_target')})"
        )

    if not reasons and previous.get("mtime") != current.get("mtime"):
        reasons.append("modification time changed")

    return reasons


def _mode_became_world_writable(previous_mode: Optional[str], current_mode: Optional[str]) -> bool:
    if previous_mode is None or current_mode is None:
        return False
    try:
        prev_bits, cur_bits = int(previous_mode, 8), int(current_mode, 8)
    except ValueError:
        return False
    return not (prev_bits & 0o002) and bool(cur_bits & 0o002)


def _mode_more_permissive(previous_mode: Optional[str], current_mode: Optional[str]) -> bool:
    """True when the new mode is a strict superset of the old one's
    permission bits — at least one bit turned on, none turned off. A
    mode that both gains and loses bits (e.g. 644 -> 600 group-loss
    plus... ) is judged only as "changed" by diff_metadata(), not
    cleanly "more permissive", since that's a genuinely ambiguous case.
    """
    if previous_mode is None or current_mode is None:
        return False
    try:
        prev_bits, cur_bits = int(previous_mode, 8), int(current_mode, 8)
    except ValueError:
        return False
    gained = cur_bits & ~prev_bits
    lost = prev_bits & ~cur_bits
    return gained != 0 and lost == 0


def classify_metadata_severity(previous: dict, current: dict, sensitivity: str) -> "tuple[str, list[str]]":
    """Severity for a metadata-only change (hash unchanged) — also used
    as the metadata-driven FLOOR for a content change (see
    classify_modified_severity(), which takes the max of this and its
    own content-specific rule). A hash staying the same does NOT
    automatically make a metadata change harmless — see individual
    rules below.
    """
    reasons = diff_metadata(previous, current)
    sensitive = _sensitive(sensitivity)
    severity = LOW

    prev_symlink = bool(previous.get("is_symlink"))
    cur_symlink = bool(current.get("is_symlink"))
    if not prev_symlink and cur_symlink:
        severity = _max_severity(severity, HIGH)
    elif prev_symlink and cur_symlink and previous.get("symlink_target") != current.get("symlink_target"):
        severity = _max_severity(severity, HIGH if sensitive else MEDIUM)

    if not previous.get("is_executable") and current.get("is_executable"):
        severity = _max_severity(severity, HIGH if sensitive else MEDIUM)

    if _mode_became_world_writable(previous.get("mode"), current.get("mode")):
        severity = _max_severity(severity, HIGH if sensitive else MEDIUM)
    elif _mode_more_permissive(previous.get("mode"), current.get("mode")):
        severity = _max_severity(severity, HIGH if sensitive else MEDIUM)

    if previous.get("uid") != current.get("uid"):
        severity = _max_severity(severity, HIGH if sensitive else MEDIUM)

    if previous.get("gid") != current.get("gid"):
        severity = _max_severity(severity, MEDIUM if sensitive else LOW)

    return severity, reasons


def classify_modified_severity(previous: dict, current: dict, sensitivity: str) -> "tuple[str, list[str]]":
    """Severity for a genuine content change (hash differs). Starts
    from the same metadata-diff floor as a metadata-only change (a
    content change can carry a metadata change too, e.g. a replaced
    file with different permissions), then folds in the content-change
    rule: any change in a startup/self location is HIGH; elsewhere an
    executable's content changing is MEDIUM, a non-executable's is LOW.
    """
    meta_severity, reasons = classify_metadata_severity(previous, current, sensitivity)
    reasons = list(reasons) + ["file content changed (hash differs)"]

    sensitive = _sensitive(sensitivity)
    if sensitive:
        content_severity = HIGH
    elif current.get("is_executable"):
        content_severity = MEDIUM
    else:
        content_severity = LOW

    return _max_severity(meta_severity, content_severity), reasons


def classify_new_file_severity(current: dict, sensitivity: str) -> "tuple[str, list[str]]":
    if sensitivity == SENSITIVITY_STARTUP:
        if current.get("is_executable"):
            return HIGH, ["new executable file in a startup location"]
        return MEDIUM, ["new file in a startup location"]
    if sensitivity == SENSITIVITY_SELF:
        return HIGH, ["new Secure self file"]
    if current.get("is_executable"):
        return MEDIUM, ["new executable file"]
    return LOW, ["new file"]


def classify_deleted_file_severity(sensitivity: str) -> "tuple[str, list[str]]":
    if sensitivity == SENSITIVITY_SELF:
        return HIGH, ["Secure self file deleted"]
    if sensitivity == SENSITIVITY_STARTUP:
        return MEDIUM, ["startup-location file deleted"]
    return LOW, ["file deleted"]


def classify_renamed_severity(sensitivity: str) -> "tuple[str, list[str]]":
    """A confirmed rename (same filesystem identity, new path) is
    lower-key than a delete+create pair by design — it IS the honest,
    more-informative classification precisely because it's LESS
    alarming than reporting two unrelated-looking events. Still worth
    noting in a sensitive location.
    """
    if sensitivity in (SENSITIVITY_STARTUP, SENSITIVITY_SELF):
        return MEDIUM, ["file renamed/moved in a sensitive location"]
    return LOW, ["file renamed/moved"]


def classify_program_target_severity(
    program_signing_status: Optional[str],
    program_exists: bool,
    program_changed: bool,
) -> "tuple[str, list[str]]":
    """Severity contribution from a LaunchAgent/LaunchDaemon's resolved
    Program/ProgramArguments target — combined (via max) with the
    plist file's own new/modified severity by the caller. Severity is
    based on the REFERENCED EXECUTABLE's signing status, never the
    plist's own (meaningless) signed/unsigned state — see
    persistence/codesign.py, reused here rather than duplicated.
    """
    if not program_exists:
        return HIGH, ["startup entry references an executable that does not exist"]
    if program_signing_status in _UNSIGNED_LIKE:
        return HIGH, [f"startup entry's referenced executable is {program_signing_status}"]
    if program_changed:
        return MEDIUM, ["startup entry now points at a different executable"]
    return MEDIUM, ["startup entry references the same, signed executable"]


def apply_self_update_context(severity: str, in_update_context: bool) -> "tuple[str, Optional[str]]":
    """For a self-sensitivity file's change: if it happened during a
    known Secure Update/reload context (see secure/self_update.py),
    cap severity at MEDIUM and return an annotation — the change is
    still recorded, still visible, just no longer treated as
    "unexplained". Outside that window, severity is returned
    unchanged: HIGH stays HIGH ("unexplained self-modification").
    """
    if not in_update_context:
        return severity, None
    capped = MEDIUM if _SEVERITY_RANK[severity] > _SEVERITY_RANK[MEDIUM] else severity
    note = (
        "Occurred during a known Secure Update/reload context — consistent with an "
        "intentional application update, not tampering. Still recorded for review."
    )
    return capped, note


def apply_doc_dampening(severity: str, path: str, sensitivity: str) -> str:
    """PROJECT_NOTES.md and similar self-sensitivity documentation
    files are real signal, but lower urgency than executable/
    configuration code changing — cap at MEDIUM.
    """
    if sensitivity == SENSITIVITY_SELF and is_lower_significance_self_file(path):
        return MEDIUM if _SEVERITY_RANK[severity] > _SEVERITY_RANK[MEDIUM] else severity
    return severity


# ---------- rename detection ----------


def match_renames(missing: "list[dict]", created: "list[dict]") -> "tuple[list[tuple[dict, dict]], list[dict], list[dict]]":
    """Match "missing" and "created" file candidates into CONFIRMED
    renames only — via shared (dev, ino), the filesystem's own
    identity, never via content hash alone. Each dict needs at least
    "path", "dev", "ino" (and "hash", used only by
    find_hash_correlation_note() below, not here).

    Returns (renames, remaining_missing, remaining_created). `renames`
    is a list of (missing_entry, created_entry) pairs. Unmatched
    entries are left as separate deleted/created candidates — per
    explicit instruction, a shared hash WITHOUT shared identity is
    supporting evidence only, never a rename claim on its own.
    """
    by_identity: dict = {}
    for entry in created:
        dev, ino = entry.get("dev"), entry.get("ino")
        if dev is not None and ino is not None:
            by_identity.setdefault((dev, ino), entry)

    renames = []
    remaining_missing = []
    matched_created_paths = set()

    for m in missing:
        dev, ino = m.get("dev"), m.get("ino")
        match = by_identity.get((dev, ino)) if dev is not None and ino is not None else None
        if match is not None and match["path"] not in matched_created_paths:
            renames.append((m, match))
            matched_created_paths.add(match["path"])
        else:
            remaining_missing.append(m)

    remaining_created = [c for c in created if c["path"] not in matched_created_paths]
    return renames, remaining_missing, remaining_created


def find_hash_correlation_note(created_hash: Optional[str], remaining_missing: "list[dict]") -> Optional[str]:
    """For a "created" candidate that was NOT matched to a rename by
    identity: if its content hash matches one of this scan's remaining
    "missing" candidates, return a supporting-evidence-only annotation
    (never a rename claim) noting the coincidence — e.g. a copy across
    filesystems, or two unrelated files that happen to be identical.
    """
    if not created_hash:
        return None
    for m in remaining_missing:
        if m.get("hash") == created_hash:
            return (
                f"content hash matches a file deleted in this same scan ({m['path']}) — "
                "possibly a copy or cross-filesystem move; not confirmed as a rename "
                "since filesystem identity (device/inode) differs"
            )
    return None
