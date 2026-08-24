"""
secure/self_update.py — the "known update context" primitive Phase 11
(File Integrity Monitoring) needs to distinguish an intentional Secure
Update/reload from unexplained self-modification.

Secure is still actively developed, so its own source files legitimately
change often — usually via `secure_gui.py`'s Update button (pull +
relaunch) or a manual git pull/edit session. File integrity monitoring
keeps self-file changes at HIGH severity by default ("unexplained
self-modification"), but a change that happens shortly after an
explicit, logged update marker gets annotated instead — see
secure/fileintegrity/analysis.py's apply_self_update_context(). The
annotation never erases or suppresses the underlying event; it only
caps severity and explains why.

The marker itself is deliberately lightweight: one row in the existing
generic `events` table (category="self_update_context"), not a new
table. `mark_update_context()` writes it; `is_in_update_context()`
checks whether one was written recently enough to still count.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from secure.storage.models import add_event, has_recent_event

UPDATE_CONTEXT_CATEGORY = "self_update_context"

# How long a marker stays "active" after being written. Generous enough
# to cover a `git pull` + relaunch cycle (which can involve a Syncthing
# sync settling, then the GUI relaunching, then a scan running) without
# staying open so long that it would mask a genuinely unrelated later
# change.
DEFAULT_WINDOW_MINUTES = 10.0


def mark_update_context(conn: sqlite3.Connection, note: str = "") -> int:
    """Record that an intentional Secure Update/reload is happening now.

    Called from secure_gui.py's Update button before it relaunches, and
    available as `secure self mark-update-context` for a manual git
    pull/edit session. Returns the new event id.
    """
    message = "Secure update/reload context started" + (f" — {note}" if note else "")
    return add_event(conn, UPDATE_CONTEXT_CATEGORY, message)


def is_in_update_context(
    conn: sqlite3.Connection,
    at: "datetime | None" = None,
    window_minutes: float = DEFAULT_WINDOW_MINUTES,
) -> bool:
    """True if a mark_update_context() call happened within
    window_minutes before `at` (defaults to now).
    """
    at = at or datetime.now(timezone.utc)
    since = (at - timedelta(minutes=window_minutes)).isoformat()
    return has_recent_event(conn, UPDATE_CONTEXT_CATEGORY, since)
