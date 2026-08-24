"""
persistence/launch_items.py — reads and parses LaunchAgent/
LaunchDaemon plist files directly from disk. No subprocess needed:
Python's standard-library `plistlib` reads both XML and binary plist
formats natively, so this module never shells out — a deliberate
exception to every other package's "_shell.py is the only place we
subprocess" convention, since there's simply no subprocess involved
here at all.

**Scope, stated explicitly here because it's a deliberate choice, same
as every other scope note in this app:**

    - `~/Library/LaunchAgents` (this user's own agents)
    - `/Library/LaunchAgents` (agents installed for all users)
    - `/Library/LaunchDaemons` (system-wide daemons, root-run)

`/System/Library/LaunchAgents` and `/System/Library/LaunchDaemons`
(Apple's own several-hundred built-in entries) are deliberately NOT
scanned. Since macOS Catalina, `/System/Library` is SIP-protected and
not writable by any installer, admin tool, or piece of malware without
first disabling System Integrity Protection entirely — which is a far
bigger compromise than this app could meaningfully add visibility for.
Every one of these several hundred entries is also Apple-signed and
present on every Mac, so tracking them would add enormous noise (and
enormous first-scan "NEW" spam) for essentially zero security signal.
The three locations actually scanned are exactly where third-party
software (legitimate and malicious alike) installs persistence on
macOS — this is also where Apple's own security documentation and
widely-used malware removal guides tell you to look by hand.

Reading these files never requires sudo — only *loading/managing* a
LaunchAgent/LaunchDaemon (`launchctl load`, etc.) needs elevated
privileges; the plist files themselves are ordinarily world-readable,
since macOS itself needs to read them as any user to know what to
launch. A file that genuinely can't be read (permissions, corruption)
is skipped with its error noted, never treated as "no entry there."
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Dict, List, Optional

# kind -> list of directories that kind is sourced from. A list (not a
# single path) only matters in principle here (each kind currently has
# exactly one directory), kept this shape so a future kind could span
# more than one location without changing the calling code.
_LAUNCH_ITEM_DIRECTORIES = {
    "launch_agent_user": [Path.home() / "Library" / "LaunchAgents"],
    "launch_agent_global": [Path("/Library/LaunchAgents")],
    "launch_daemon": [Path("/Library/LaunchDaemons")],
}


def list_launch_item_paths(kind: str) -> List[Path]:
    """Every *.plist path for this kind, or [] if the directory
    doesn't exist (very common — e.g. most Macs have no
    /Library/LaunchDaemons entries beyond a handful, and a fresh
    ~/Library/LaunchAgents may not exist at all).
    """
    paths: List[Path] = []
    for directory in _LAUNCH_ITEM_DIRECTORIES.get(kind, []):
        if not directory.is_dir():
            continue
        try:
            paths.extend(sorted(directory.glob("*.plist")))
        except OSError:
            continue
    return paths


def parse_launch_item_plist(path: Path) -> Dict[str, Optional[object]]:
    """Read and parse one LaunchAgent/LaunchDaemon plist.

    Returns a dict with keys: "label", "program_path", "run_at_load",
    "keep_alive", "parse_error". A file that can't be read or parsed
    (permission denied, corrupt/malformed plist — not unheard of for
    hand-edited or badly-behaved third-party installers) comes back
    with every other field None and "parse_error" holding a short
    explanation, rather than raising and aborting the whole scan — same
    fallback-resilience philosophy as every multi-source scan in this
    app since the Wi-Fi status bugfix.

    `program_path` is `Program` if the plist has one, else the first
    element of `ProgramArguments` if it has one, else None — a plist
    missing both is technically malformed (launchd requires one or the
    other) but handled gracefully rather than assumed impossible.
    """
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError) as e:
        return {
            "label": None,
            "program_path": None,
            "run_at_load": None,
            "keep_alive": None,
            "parse_error": f"{type(e).__name__}: {e}",
        }

    if not isinstance(data, dict):
        return {
            "label": None,
            "program_path": None,
            "run_at_load": None,
            "keep_alive": None,
            "parse_error": "plist root is not a dictionary",
        }

    label = data.get("Label")
    program = data.get("Program")
    program_arguments = data.get("ProgramArguments")
    if isinstance(program, str) and program:
        program_path = program
    elif isinstance(program_arguments, list) and program_arguments and isinstance(program_arguments[0], str):
        program_path = program_arguments[0]
    else:
        program_path = None

    run_at_load = data.get("RunAtLoad")
    keep_alive = data.get("KeepAlive")
    # KeepAlive can be a bool OR a dict of conditions in real plists;
    # only store it as a bool when it unambiguously is one, otherwise
    # treat "some kind of KeepAlive config exists" as True and let the
    # raw detail live only in the plist itself, not in this app's DB.
    if isinstance(keep_alive, dict):
        keep_alive = bool(keep_alive)
    elif not isinstance(keep_alive, bool):
        keep_alive = None

    if not isinstance(run_at_load, bool):
        run_at_load = None

    return {
        "label": label if isinstance(label, str) else None,
        "program_path": program_path,
        "run_at_load": run_at_load,
        "keep_alive": keep_alive,
        "parse_error": None,
    }


def scan_launch_items(kind: str) -> List[Dict[str, Optional[object]]]:
    """List and parse every LaunchAgent/LaunchDaemon plist of this
    kind. Each returned dict also includes "path" (the plist's own
    file path, as a string) alongside parse_launch_item_plist()'s keys.
    """
    results = []
    for path in list_launch_item_paths(kind):
        parsed = parse_launch_item_plist(path)
        parsed["path"] = str(path)
        results.append(parsed)
    return results
