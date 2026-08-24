"""
persistence/login_items.py — reads this user's classic macOS Login
Items ("Open at Login" apps) via System Events, using AppleScript
through `osascript` — a standard, documented, read-only, no-sudo way
to ask for this list, the same mechanism System Preferences/Settings'
own Login Items pane has always used under the hood.

**Scope note, stated here because it's a real, honest limitation:**
modern macOS (13 Ventura and later) also has a second, broader concept
— "Background Items" — covering things registered via the
ServiceManagement framework (SMAppService), which don't necessarily
show up in classic System Events login items and are what System
Settings' newer "Login Items & Extensions" pane actually displays in
full. There is a command, `sfltool dumpbtm`, that can dump this
Background Task Management database, but its output format is
undocumented, has changed across macOS versions, and — without a real
Mac available to verify against, the same caution this project has
followed since the Wi-Fi/system_profiler timeout bug — isn't something
this module guesses at. Classic System Events login items are still a
real, useful, and honestly-scoped signal on their own; the Background
Items gap is called out explicitly in PROJECT_NOTES.md ("What's
deliberately NOT here yet") rather than silently pretended not to
exist.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from secure.persistence._shell import run

_NAMES_SCRIPT = 'tell application "System Events" to get the name of every login item'
_PATHS_SCRIPT = 'tell application "System Events" to get the path of every login item'


def _parse_applescript_list(raw: str) -> List[str]:
    """AppleScript's `get ... of every X` returns a comma-space-joined
    string like "Dropbox, iTunesHelper" (or "" for an empty list, or a
    single bare value with no commas for a list of one). Split
    defensively rather than assuming a particular count.
    """
    text = raw.strip()
    if not text:
        return []
    return [item.strip() for item in text.split(",")]


def get_login_items() -> "tuple[bool, List[Dict[str, Optional[str]]]]":
    """Return (ok, items) — items is a list of {"name", "path"} dicts.

    `path` is None for a login item AppleScript couldn't resolve one
    for (this does happen for some items — a "missing value" comes
    back from AppleScript and is treated the same as no path). ok is
    False (items always []) only if osascript itself couldn't run —
    never conflated with "ran fine, zero login items configured",
    which is common and legitimate.
    """
    names_result = run(["osascript", "-e", _NAMES_SCRIPT], timeout=8.0)
    if not names_result.ok:
        return False, []

    names = _parse_applescript_list(names_result.stdout)
    if not names:
        return True, []

    paths_result = run(["osascript", "-e", _PATHS_SCRIPT], timeout=8.0)
    # A failure fetching paths specifically doesn't invalidate the
    # names we already have — just means every item's path comes back
    # as None instead of failing the whole login-items check.
    paths = _parse_applescript_list(paths_result.stdout) if paths_result.ok else []

    items: List[Dict[str, Optional[str]]] = []
    for i, name in enumerate(names):
        path = paths[i] if i < len(paths) else None
        if path in ("", "missing value"):
            path = None
        items.append({"name": name, "path": path})
    return True, items
