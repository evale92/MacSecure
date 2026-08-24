"""
persistence/analysis.py — pure logic for deciding what's worth
flagging. No subprocess calls, no database access, no imports from
codesign.py's I/O — just the classification string constants it
defines (SIGNED_APPLE etc.), same "pure function + thin wrapper" split
every other package in this app follows.
"""

from __future__ import annotations

from typing import Optional

from secure.persistence.codesign import SIGNED_ADHOC, SIGNED_APPLE, SIGNED_DEVELOPER, UNSIGNED

# Directories/patterns a legitimate, user-installed application
# essentially never runs from directly, but that are trivially
# writable by anything (a downloaded script, a dropped payload, a
# browser). Deliberately a small, conservative, documented heuristic —
# same spirit as secure/listening/risk.py's "is this expected or
# risky" table — not an exhaustive malware-location database.
_UNUSUAL_LOCATION_PREFIXES = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
)
_UNUSUAL_LOCATION_SUBSTRINGS = (
    "/Downloads/",
    "/.Trash/",
    "/Library/Caches/",
)

_SIGNED_STATUSES = (SIGNED_APPLE, SIGNED_DEVELOPER)
_UNSIGNED_LIKE_STATUSES = (UNSIGNED, SIGNED_ADHOC)


def is_unusual_location(path: Optional[str]) -> bool:
    """True if this executable's path is somewhere a legitimate,
    normally-installed piece of software essentially never runs from —
    a temp directory, Downloads, Trash, a cache folder, or any hidden
    (dot-prefixed) directory segment. Conservative and heuristic, not
    exhaustive: plenty of legitimate things could technically live in
    an unusual spot, and plenty of malicious things don't have to. This
    is one signal among several, not a verdict on its own.
    """
    if not path:
        return False
    if any(path.startswith(prefix) for prefix in _UNUSUAL_LOCATION_PREFIXES):
        return True
    if any(substring in path for substring in _UNUSUAL_LOCATION_SUBSTRINGS):
        return True
    # A hidden directory segment anywhere in the path (not counting the
    # filename itself) — e.g. "/Users/erick/.cache/payload/tool".
    segments = path.split("/")[:-1]
    if any(segment.startswith(".") and segment not in ("", ".", "..") for segment in segments):
        return True
    return False


def process_alert_severity(signing_status: Optional[str], path: Optional[str]) -> Optional[str]:
    """Severity for a brand-new process's executable, or None if it
    isn't alert-worthy at all. "unknown" signing status alone is never
    alert-worthy — codesign being unavailable/timing out is not
    evidence of anything; see codesign.py's module docstring.
    """
    unsigned_like = signing_status in _UNSIGNED_LIKE_STATUSES
    unusual = is_unusual_location(path)

    if unsigned_like and unusual:
        return "high"
    if unsigned_like:
        return "medium"
    if unusual:
        return "low"
    return None


def persistence_entry_alert_severity(signing_status: Optional[str], program_path: Optional[str]) -> str:
    """Severity for a brand-new persistence entry — always at least
    MEDIUM (a new LaunchAgent/LaunchDaemon/login item is inherently
    significant; these aren't added often), escalating to HIGH when
    its backing executable is unsigned/ad-hoc-signed or couldn't even
    be resolved at all (a plist referencing a program that doesn't
    exist, or with no Program/ProgramArguments key at all, is itself
    suspicious — a legitimate installer wouldn't leave that broken).
    """
    if not program_path or signing_status in _UNSIGNED_LIKE_STATUSES:
        return "high"
    return "medium"


def is_signing_downgrade(previous_status: Optional[str], current_status: Optional[str]) -> bool:
    """True only for a genuine, confident downgrade: a persistence
    entry's backing executable was previously signed with a real chain
    of trust (Apple or a Developer ID), and has now become unsigned or
    only ad-hoc signed. Deliberately never fires to/from "unknown"
    (that's codesign availability changing, not necessarily the
    executable itself), and never fires between two already-acceptable
    statuses (e.g. Apple-signed to Developer-ID-signed, which can
    happen legitimately across an update).
    """
    return previous_status in _SIGNED_STATUSES and current_status in _UNSIGNED_LIKE_STATUSES
