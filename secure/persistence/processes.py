"""
persistence/processes.py — pure parsing of `ps` output into a list of
process dicts, plus the thin subprocess wrapper that runs it. No
database access — see scanner.py for that.

Uses `ps -axo pid=,ppid=,user=,comm=` — read-only, no sudo, works for
every user's processes (not just this one), same as running `ps aux`
yourself in Terminal. The `=` suffix on each field suppresses ps's
header line, so there's no header row to special-case.

On macOS, `comm` is typically the full absolute path to the executable
(e.g. "/usr/sbin/cfprefsd") for real processes, though some kernel/
system processes report just a bare name with no resolvable path (e.g.
"kernel_task"). Only entries with a resolvable absolute path are
tracked as process_entries — see scanner.py — the same "skip what
can't be identified" pattern secure/bluetooth/scanner.py already uses
for Bluetooth devices with no usable address.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from secure.persistence._shell import run


def parse_ps_output(output: str) -> List[Dict[str, Optional[str]]]:
    """Parse `ps -axo pid=,ppid=,user=,comm=` output into a list of
    {"pid", "ppid", "user", "path_or_name"} dicts.

    Splits each line into at most 4 whitespace-separated fields (not
    unlimited) specifically so the last field — the executable path —
    can itself contain spaces (very common: "/Applications/Google
    Chrome.app/Contents/MacOS/Google Chrome") without being broken
    apart. pid/ppid/user are assumed not to contain spaces, which holds
    for every normal macOS process and username.
    """
    entries: List[Dict[str, Optional[str]]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        pid, ppid, user, path_or_name = parts
        entries.append({"pid": pid, "ppid": ppid, "user": user, "path_or_name": path_or_name})
    return entries


def is_resolvable_path(path_or_name: Optional[str]) -> bool:
    """True if this looks like an absolute filesystem path rather than
    a bare process name ps couldn't resolve to one.
    """
    return bool(path_or_name) and path_or_name.startswith("/")


def list_processes() -> "tuple[bool, List[Dict[str, Optional[str]]]]":
    """Run `ps` and parse its output. Returns (ok, entries) — ok is
    False (entries always []) if `ps` couldn't be run or didn't finish
    in time, distinct from "ps ran and found nothing" (which can't
    actually happen — there's always at least this process itself —
    but kept as an explicit tri-state for consistency with every other
    scan in this app that makes this distinction).
    """
    result = run(["ps", "-axo", "pid=,ppid=,user=,comm="], timeout=8.0)
    if not result.ok:
        return False, []
    return True, parse_ps_output(result.stdout)
