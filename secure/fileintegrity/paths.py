"""
fileintegrity/paths.py — the default watch list, exclusion rules, and
path normalization. Pure path-string logic (plus os.path.expanduser/
abspath, which touch no filesystem I/O beyond reading $HOME and the
current working directory) — no walking, no hashing, no database.

Default watch list, stated explicitly because it's a deliberate,
conservative choice (same spirit as persistence/launch_items.py's
scope note): security-relevant startup locations plus Secure's own
source/config, never a broad or full-disk scan. A user can add more
watch paths later (`secure fileintegrity watch-add`); nothing here
auto-expands that list on its own.
"""

from __future__ import annotations

import os
from pathlib import Path

SENSITIVITY_STARTUP = "startup"
SENSITIVITY_SELF = "self"
SENSITIVITY_NORMAL = "normal"

# secure/fileintegrity/paths.py -> secure/fileintegrity/ -> secure/ -> project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_MAX_DEPTH = 6


def normalize_path(raw: str) -> str:
    """Normalize a path for storage/comparison: expand `~`, make
    absolute, and collapse redundant `./`/`../` components — purely
    LEXICALLY, without resolving symlinks. os.path.abspath() does not
    follow symlinks; it only normpaths and joins with the current
    working directory if the path is relative. This is deliberate: if
    normalization resolved symlinks, two genuinely different
    filesystem objects (a real path, and a symlink pointing somewhere
    else entirely) could silently collapse into what looks like "the
    same" watch path. Per-file symlink handling during a walk is a
    separate, explicit concern — see hashing.py's read_metadata()
    (which always lstat()s, never follows) and scanner.py.
    """
    return os.path.abspath(os.path.expanduser(raw))


def default_watch_paths() -> "list[dict]":
    """The conservative default watch list — LaunchAgents/LaunchDaemons
    (startup) plus Secure's own source/config (self). Never includes
    the whole home directory, browser profiles, caches, or any other
    large/noisy tree — those are exactly what this phase's spec calls
    out as NOT to be monitored by default.
    """
    home = Path.home()
    entries = [
        {
            "path": str(home / "Library" / "LaunchAgents"),
            "recursive": False,
            "sensitivity": SENSITIVITY_STARTUP,
        },
        {
            "path": "/Library/LaunchAgents",
            "recursive": False,
            "sensitivity": SENSITIVITY_STARTUP,
        },
        {
            "path": "/Library/LaunchDaemons",
            "recursive": False,
            "sensitivity": SENSITIVITY_STARTUP,
        },
        {
            "path": str(_PROJECT_ROOT / "secure"),
            "recursive": True,
            "sensitivity": SENSITIVITY_SELF,
        },
        {
            "path": str(_PROJECT_ROOT / "secure_gui.py"),
            "recursive": False,
            "sensitivity": SENSITIVITY_SELF,
        },
        {
            "path": str(_PROJECT_ROOT / "secure_gui"),
            "recursive": True,
            "sensitivity": SENSITIVITY_SELF,
        },
        {
            "path": str(_PROJECT_ROOT / "requirements.txt"),
            "recursive": False,
            "sensitivity": SENSITIVITY_SELF,
        },
        {
            "path": str(_PROJECT_ROOT / "PROJECT_NOTES.md"),
            "recursive": False,
            "sensitivity": SENSITIVITY_SELF,
        },
    ]
    for entry in entries:
        entry["path"] = normalize_path(entry["path"])
    return entries


# Directory names never descended into, anywhere they appear — build
# artifacts, VCS internals, dependency trees, and Secure's own runtime
# noise. Same list philosophy as continuity.py's _EXCLUDED_DIR_NAMES,
# extended with a few more (this phase watches secure/ recursively,
# continuity.py only checked mtimes).
EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".idea",
        "node_modules",
        ".Trash",
        "Caches",
        ".cache",
        "snapshots",  # ~/.secure/snapshots — Secure's own generated output, not source
    }
)

EXCLUDED_FILE_NAMES = frozenset(
    {
        "secure.db",
        "secure.db-journal",
        "secure.db-wal",
        "secure.db-shm",
        "secure.log",
        ".DS_Store",
    }
)

EXCLUDED_EXTENSIONS = frozenset({".log", ".tmp", ".pyc", ".pid", ".sock", ".lock"})

# Self-sensitivity files that are documentation rather than executable
# or configuration code — real signal, but capped at a lower severity
# ceiling than e.g. cli.py or database.py changing. See analysis.py.
_LOWER_SIGNIFICANCE_SELF_EXTENSIONS = frozenset({".md", ".txt"})


def is_lower_significance_self_file(path: str) -> bool:
    return os.path.splitext(path)[1] in _LOWER_SIGNIFICANCE_SELF_EXTENSIONS


def is_excluded_name(name: str) -> bool:
    """True if a file or directory with this NAME (not full path)
    should never be visited — checked against both directory names
    (pruning descent) and file names (skipping the file itself) by the
    scanner's walk.
    """
    if name in EXCLUDED_DIR_NAMES or name in EXCLUDED_FILE_NAMES:
        return True
    return os.path.splitext(name)[1] in EXCLUDED_EXTENSIONS


def is_plist(path: str) -> bool:
    return path.endswith(".plist")
