"""
persistence/extra_locations.py — macOS persistence locations beyond
LaunchAgents/LaunchDaemons and login items, read directly from disk.

Like launch_items.py this never shells out: a directory listing and
`plistlib` are all it needs. It only reads; it never loads, unloads,
disables or deletes anything it lists.

**Scope, and why each location is here.** Every one is a documented
place third-party code (legitimate or malicious) runs from without being
a LaunchAgent/LaunchDaemon, and each is readable as a normal user:

    authorization_plugin  /Library/Security/SecurityAgentPlugins/*.bundle
                          loaded by the authorization system at login and
                          unlock prompts, with root privileges
    scripting_addition    /Library/ScriptingAdditions/*.osax and
                          ~/Library/ScriptingAdditions/*.osax
    kernel_extension      /Library/Extensions/*.kext (third-party kexts;
                          /System/Library/Extensions is SIP-protected and
                          Apple-signed, excluded for the same reason
                          launch_items.py excludes /System/Library)
    startup_item          /Library/StartupItems/* (legacy, still honoured
                          as a location malware writes to)
    periodic_script       /etc/daily.local, /etc/weekly.local,
                          /etc/monthly.local, run as root by periodic(8)
    emond_rule            /etc/emond.d/rules/*.plist (event monitor rules
                          that can run commands; absent on newer macOS)
    folder_action_script  ~/Library/Scripts/Folder Action Scripts/*
    ssh_rc                ~/.ssh/rc and /etc/ssh/sshrc, run by sshd for
                          every SSH login

Sources consulted: rmusser01/Infosec_Reference Draft/PrivescPostExmac.md
(Persistence and Privilege Escalation sections) and Draft/DFIR.md (OS X
Forensics), read 2026-09-16.

**Honest absence.** A location that does not exist is normal and yields
nothing. A location that exists but cannot be listed (permissions, I/O)
is returned in `unavailable`, never treated as empty — the caller records
it as a scan error, so a locked directory can never look like a clean one.

`program_path` is what the code-signing check runs against: the bundle
itself for bundle kinds (`codesign` verifies a bundle as a whole, and a
codeless kext has no executable to name), the file itself for script
kinds.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Dict, List, Tuple

_HOME = Path.home()

# kind -> (mode, [locations]). "bundle": each child of a directory whose
# name ends in one of the suffixes; "children": every non-hidden child of a
# directory; "files": each listed path that exists. Replaced wholesale by
# tests and validate scenarios, exactly like launch_items._LAUNCH_ITEM_DIRECTORIES.
_EXTRA_LOCATIONS: Dict[str, Tuple[str, List[Path]]] = {
    "authorization_plugin": ("bundle:.bundle", [Path("/Library/Security/SecurityAgentPlugins")]),
    "scripting_addition": ("bundle:.osax", [Path("/Library/ScriptingAdditions"), _HOME / "Library" / "ScriptingAdditions"]),
    "kernel_extension": ("bundle:.kext", [Path("/Library/Extensions")]),
    "startup_item": ("children", [Path("/Library/StartupItems")]),
    "periodic_script": ("files", [Path("/etc/daily.local"), Path("/etc/weekly.local"), Path("/etc/monthly.local")]),
    "emond_rule": ("bundle:.plist", [Path("/etc/emond.d/rules")]),
    "folder_action_script": ("children", [_HOME / "Library" / "Scripts" / "Folder Action Scripts"]),
    "ssh_rc": ("files", [_HOME / ".ssh" / "rc", Path("/etc/ssh/sshrc")]),
}


def _bundle_label(path: Path) -> str:
    """CFBundleIdentifier when the bundle's Info.plist says so, else its name."""
    try:
        with (path / "Contents" / "Info.plist").open("rb") as f:
            identifier = plistlib.load(f).get("CFBundleIdentifier")
        if isinstance(identifier, str) and identifier:
            return identifier
    except (OSError, plistlib.InvalidFileException, ValueError, AttributeError):
        pass
    return path.name


def _entry(kind: str, path: Path, label: str) -> Dict[str, object]:
    return {"kind": kind, "path": str(path), "label": label, "program_path": str(path),
            "run_at_load": None, "keep_alive": None}


def scan_extra_locations() -> Tuple[List[Dict[str, object]], List[str]]:
    """Every entry in every extra location, plus the locations that exist
    but could not be read. Returns (entries, unavailable) where each
    unavailable item is "<kind>: <path>: <error>".
    """
    entries: List[Dict[str, object]] = []
    unavailable: List[str] = []
    for kind, (mode, locations) in _EXTRA_LOCATIONS.items():
        for location in locations:
            if mode == "files":
                try:
                    if location.is_file():
                        entries.append(_entry(kind, location, location.name))
                except OSError as exc:
                    unavailable.append(f"{kind}: {location}: {type(exc).__name__}: {exc}")
                continue
            try:
                if not location.is_dir():
                    continue
                children = sorted(location.iterdir())
            except OSError as exc:
                unavailable.append(f"{kind}: {location}: {type(exc).__name__}: {exc}")
                continue
            for child in children:
                if child.name.startswith("."):
                    continue
                if mode.startswith("bundle:"):
                    if child.suffix != mode.split(":", 1)[1]:
                        continue
                    label = _bundle_label(child) if child.is_dir() else child.name
                else:
                    label = child.name
                entries.append(_entry(kind, child, label))
    return entries, unavailable
