"""
secure/continuity.py — "Snapshot": a point-in-time summary of what
changed on this Mac recently, across four things:

    1. Files inside this project that were modified.
    2. This app's own runtime state (~/.secure) being modified.
    3. New or changed files in the two places macOS normally uses for
       persistence — ~/Library/LaunchAgents, /Library/LaunchAgents,
       /Library/LaunchDaemons — a common signal that something
       installed itself to survive a reboot.
    4. Security posture check results (see secure/checks/) that
       changed since the last time they were checked.

Two different kinds of "recent" are used here, and the output says
which is which so it's not misleading:
    - Items 1-3 are windowed by wall-clock time: "modified in the last
      N minutes" (default 15), based on file modification times.
    - Item 4 is windowed by *event*, not time: "different from the
      last time a posture check ran", however long ago that was —
      because posture checks only happen when you (or a Snapshot) run
      them, comparing to a fixed time window wouldn't make sense if
      nothing was checked in that window.

This is a snapshot you request by clicking a button (or running
`secure snapshot`), not a background watcher — see PROJECT_NOTES.md
("What's deliberately NOT here yet"). Every check here is read-only
and needs no sudo, same rules as secure/checks/. Item 4 does run the
posture checks fresh each time (the quick set — no network call, so a
snapshot stays fast enough to run often).

Where results are stored ("logs it somewhere safe"):
    - the `snapshots` table in ~/.secure/secure.db (see
      secure/storage/models.py), plus the individual posture results
      for this run go into `posture_checks` exactly like a normal
      `secure check` would.
    - a plain JSON file under ~/.secure/snapshots/, one per run, so
      the result is still readable even if the database is ever
      unavailable or you want to grep/diff snapshots directly.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from secure.checks import CheckResult, run_all_checks
from secure.storage.models import add_posture_result, add_snapshot, list_recent_posture_results

# secure/continuity.py -> secure/ -> project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Directories/files that are either huge, irrelevant, or (for
# ~/.secure specifically) guaranteed to be touched by this snapshot
# itself and therefore not a meaningful signal.
_EXCLUDED_DIR_NAMES = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".idea",
    "node_modules",
    "snapshots",  # ~/.secure/snapshots itself — avoid snapshots reporting on snapshots
}
_EXCLUDED_APP_STATE_FILES = {
    "secure.db",
    "secure.db-journal",
    "secure.db-wal",
    "secure.db-shm",
    "secure.log",
}

_DEFAULT_LAUNCH_ITEM_DIRS = [
    Path.home() / "Library" / "LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
]

_MAX_FILE_CHANGES = 200


@dataclass
class FileChange:
    path: str
    modified_at: str


@dataclass
class PostureDiff:
    check_name: str
    previous_status: str
    current_status: str


@dataclass
class SnapshotResult:
    taken_at: str
    window_minutes: int

    project_file_changes: List[FileChange] = field(default_factory=list)
    project_files_truncated: bool = False

    app_state_changes: List[FileChange] = field(default_factory=list)

    launch_item_changes: List[FileChange] = field(default_factory=list)

    posture_results: List[CheckResult] = field(default_factory=list)
    posture_run_id: str = ""
    posture_baseline_at: Optional[str] = None
    posture_diffs: List[PostureDiff] = field(default_factory=list)

    # Filled in after this result is persisted.
    db_id: Optional[int] = None
    json_path: Optional[str] = None

    def summary(self) -> str:
        counts = {"PASS": 0, "WARNING": 0, "FAIL": 0}
        for result in self.posture_results:
            counts[result.status.value] = counts.get(result.status.value, 0) + 1
        return (
            f"{len(self.project_file_changes)} project file(s), "
            f"{len(self.app_state_changes)} app-state file(s), "
            f"{len(self.launch_item_changes)} launch item(s) changed; "
            f"{len(self.posture_diffs)} posture change(s); "
            f"current posture {counts['PASS']} PASS / {counts['WARNING']} WARNING / "
            f"{counts['FAIL']} FAIL"
        )


def _find_recent_files(
    root: Path,
    since: datetime,
    *,
    exclude_dir_names: "frozenset[str]" = frozenset(),
    exclude_file_names: "frozenset[str]" = frozenset(),
    limit: int = _MAX_FILE_CHANGES,
) -> "tuple[list[FileChange], bool]":
    """Return files under `root` modified at/after `since`, newest first.

    Read-only: only os.stat() is used, nothing is opened or read.
    Silently skips anything that raises OSError (permission issues,
    broken symlinks, races where a file disappears mid-scan) rather
    than failing the whole snapshot over one unreadable file.
    """
    if not root.exists():
        return [], False

    changes: List[FileChange] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in exclude_dir_names for part in path.parts):
            continue
        if path.name in exclude_file_names:
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        if mtime < since:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        changes.append(FileChange(rel, mtime.isoformat()))

    changes.sort(key=lambda c: c.modified_at, reverse=True)
    truncated = len(changes) > limit
    return changes[:limit], truncated


def find_recent_launch_items(
    since: datetime, directories: "Optional[list[Path]]" = None
) -> "list[FileChange]":
    """Return .plist files in LaunchAgents/LaunchDaemons modified at/after `since`.

    Only lists filenames and reads modification times — never opens a
    plist's contents. Directories that don't exist or can't be listed
    (e.g. no permission) are silently skipped, since that's expected
    on plenty of systems and shouldn't fail the whole snapshot.
    """
    dirs = directories if directories is not None else _DEFAULT_LAUNCH_ITEM_DIRS
    changes: List[FileChange] = []

    for directory in dirs:
        try:
            if not directory.is_dir():
                continue
            entries = list(directory.iterdir())
        except OSError:
            continue

        for entry in entries:
            if entry.suffix != ".plist":
                continue
            try:
                if not entry.is_file():
                    continue
                mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if mtime >= since:
                changes.append(FileChange(str(entry), mtime.isoformat()))

    changes.sort(key=lambda c: c.modified_at, reverse=True)
    return changes


def _posture_baseline(conn: sqlite3.Connection) -> "tuple[Optional[str], dict[str, str]]":
    """Return (when the last posture run happened, {check_name: status}).

    Looks at the most recent run_id already stored in `posture_checks`
    — regardless of how long ago that was. (None, {}) if there's no
    prior run to compare against yet.
    """
    rows = list_recent_posture_results(conn, limit=200)
    if not rows:
        return None, {}

    latest_run_id = rows[0].run_id
    baseline = {r.check_name: r.status for r in rows if r.run_id == latest_run_id}
    baseline_at = rows[0].created_at
    return baseline_at, baseline


def _run_and_store_posture_check(conn: sqlite3.Connection) -> "tuple[str, list[CheckResult]]":
    """Run the quick posture checks and store them, returning (run_id, results).

    Quick (no pending-updates/network check) on purpose — a Snapshot
    is meant to be cheap enough to run often.
    """
    results = run_all_checks(include_pending_updates=False)
    run_id = uuid.uuid4().hex[:12]
    for result in results:
        add_posture_result(
            conn,
            run_id=run_id,
            check_name=result.name,
            status=result.status.value,
            message=result.message,
            remediation=result.remediation,
        )
    return run_id, results


def take_snapshot(
    conn: sqlite3.Connection,
    app_dir: Path,
    window_minutes: int = 15,
    project_root: "Optional[Path]" = None,
) -> SnapshotResult:
    """Take a Continuity snapshot and persist it (database + JSON file).

    `conn` must already have the schema initialized (e.g. opened via
    secure.storage.database.Database). `app_dir` is this machine's
    ~/.secure directory (cfg.app_dir_path()).
    """
    root = project_root or _PROJECT_ROOT
    app_dir = Path(app_dir)

    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_minutes)

    project_changes, project_truncated = _find_recent_files(
        root, since, exclude_dir_names=frozenset(_EXCLUDED_DIR_NAMES)
    )
    app_state_changes, _ = _find_recent_files(
        app_dir,
        since,
        exclude_dir_names=frozenset(_EXCLUDED_DIR_NAMES),
        exclude_file_names=frozenset(_EXCLUDED_APP_STATE_FILES),
    )
    launch_item_changes = find_recent_launch_items(since)

    # Baseline must be captured BEFORE this run's own posture check is
    # stored, or we'd be comparing this run against itself.
    baseline_at, baseline = _posture_baseline(conn)
    run_id, posture_results = _run_and_store_posture_check(conn)

    current_by_name = {r.name: r.status.value for r in posture_results}
    diffs = [
        PostureDiff(name, prev_status, current_by_name[name])
        for name, prev_status in baseline.items()
        if name in current_by_name and current_by_name[name] != prev_status
    ]

    snapshot = SnapshotResult(
        taken_at=now.isoformat(),
        window_minutes=window_minutes,
        project_file_changes=project_changes,
        project_files_truncated=project_truncated,
        app_state_changes=app_state_changes,
        launch_item_changes=launch_item_changes,
        posture_results=posture_results,
        posture_run_id=run_id,
        posture_baseline_at=baseline_at,
        posture_diffs=diffs,
    )

    _persist(conn, app_dir, snapshot)
    return snapshot


def _details_dict(snapshot: SnapshotResult) -> dict:
    return {
        "taken_at": snapshot.taken_at,
        "window_minutes": snapshot.window_minutes,
        "project_file_changes": [asdict(c) for c in snapshot.project_file_changes],
        "project_files_truncated": snapshot.project_files_truncated,
        "app_state_changes": [asdict(c) for c in snapshot.app_state_changes],
        "launch_item_changes": [asdict(c) for c in snapshot.launch_item_changes],
        "posture_run_id": snapshot.posture_run_id,
        "posture_baseline_at": snapshot.posture_baseline_at,
        "posture_diffs": [asdict(d) for d in snapshot.posture_diffs],
        "posture_results": [
            {
                "name": r.name,
                "status": r.status.value,
                "message": r.message,
                "remediation": r.remediation,
            }
            for r in snapshot.posture_results
        ],
    }


def _persist(conn: sqlite3.Connection, app_dir: Path, snapshot: SnapshotResult) -> None:
    details = _details_dict(snapshot)
    details_json = json.dumps(details, indent=2, sort_keys=True)

    snapshot.db_id = add_snapshot(
        conn,
        window_minutes=snapshot.window_minutes,
        summary=snapshot.summary(),
        details_json=details_json,
    )

    snapshot_dir = app_dir / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    # Include the database row id in the filename: two snapshots taken
    # within the same second would otherwise collide on a
    # second-resolution timestamp and silently overwrite each other,
    # which defeats the point of "log it somewhere safe".
    stamp = datetime.fromisoformat(snapshot.taken_at).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{stamp}-{snapshot.db_id}.json"
    path = snapshot_dir / filename
    path.write_text(details_json + "\n", encoding="utf-8")
    snapshot.json_path = str(path)
