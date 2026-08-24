"""
correlate/context.py — best-effort detection of likely-benign
explanations for why several ordinary things happened close together,
per the user's explicit request to "add suppression/context logic for
likely benign bursts... do not suppress them silently; instead reduce
confidence or annotate the likely benign explanation."

Four named categories were requested: system boot, wake from sleep,
application update/install, and Secure's own run-all activity. Two are
implemented here with real (if imperfect) signal:

    - system boot — `sysctl -n kern.boottime` (read-only, no sudo)
      gives this Mac's actual last-boot timestamp, so proximity can be
      checked precisely, not guessed at.
    - run-all activity — trivial: `secure run-all` passes
      triggered_by="run_all" through to correlate() itself, so this is
      exact, not a heuristic.

Two are NOT implemented, deliberately, rather than shipped as
unreliable guesses:

    - wake from sleep — macOS has no equally simple, read-only, no-sudo
      API for "when did this Mac last wake." `pmset -g log` can show
      wake events, but its output is large, its format has shifted
      across macOS versions, and — like the Wi-Fi BSSID/Background
      Items gaps noted elsewhere in this app — this project's practice
      is to not ship parsing logic for output that hasn't been
      confirmed against a real Mac. Left out for now; see
      PROJECT_NOTES.md.
    - application update/install — covered only by a small, explicitly
      low-confidence keyword heuristic below (is_likely_update_or_install()),
      not a real signal source; there's no read-only, no-sudo API this
      app uses today for "was an installer running."

Every match here is ANNOTATED via apply_context()'s returned notes
string, always. A numeric score reduction is only ever applied when
every signal in the cluster is WEAK — a genuine MEDIUM/STRONG finding
(e.g. a real persistence mechanism activating exactly at boot, which is
the classic pattern this whole app exists to catch) is never quietly
discounted just because it coincides with one of these situations.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from secure.correlate._shell import run
from secure.correlate.strength import WEAK

if TYPE_CHECKING:
    from secure.correlate.signals import Signal

RUN_ALL_TRIGGER = "run_all"

DEFAULT_BOOT_PROXIMITY_MINUTES = 10.0

_BOOTTIME_RE = re.compile(r"sec\s*=\s*(\d+)")

_UPDATE_KEYWORDS = (
    "softwareupdate",
    "software update",
    "installer",
    "install",
    "updater",
    ".pkg",
    "app store",
    "appstore",
)


def _read_boottime_output() -> Optional[str]:
    """Thin seam around the one subprocess call this module makes —
    lets tests substitute canned output without a real Mac.
    """
    result = run(["sysctl", "-n", "kern.boottime"], timeout=5.0)
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout


def parse_boottime_output(output: Optional[str]) -> Optional[datetime]:
    """Pure parser for `sysctl -n kern.boottime` output, e.g.:

        { sec = 1700000000, usec = 123456 } Wed Nov 15 00:00:00 2023

    Returns None for empty/unparsable input rather than raising — boot
    time is a nice-to-have annotation, never something that should
    crash a correlate run if output ever looks different than expected.
    """
    if not output:
        return None
    match = _BOOTTIME_RE.search(output)
    if not match:
        return None
    try:
        return datetime.fromtimestamp(int(match.group(1)), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def get_boot_time() -> Optional[datetime]:
    """This Mac's current boot time, or None if it couldn't be
    determined. Only reflects the CURRENT boot — there's no attempt to
    reconstruct a history of past boots, so this can only annotate
    clusters from the current uptime session.
    """
    return parse_boottime_output(_read_boottime_output())


def is_recent_boot(
    cluster_start: datetime,
    boot_time: Optional[datetime],
    proximity_minutes: float = DEFAULT_BOOT_PROXIMITY_MINUTES,
) -> bool:
    """True if `cluster_start` falls within `proximity_minutes` AFTER
    `boot_time`. False (never True) for a cluster that predates the
    known boot time — that's old history from before this boot, not
    evidence of boot-time churn.
    """
    if boot_time is None:
        return False
    delta = cluster_start - boot_time
    return timedelta(0) <= delta <= timedelta(minutes=proximity_minutes)


def is_likely_update_or_install(cluster: "list[Signal]") -> bool:
    """Best-effort, deliberately low-confidence: True if any member's
    identifier or label contains a keyword commonly seen in installer/
    updater process names or paths. Not a real signal source — see this
    module's docstring — used only to annotate and modestly discount an
    all-weak cluster, never to explain away a genuine finding.
    """
    for signal in cluster:
        haystack = f"{signal.identifier or ''} {signal.label or ''}".lower()
        if any(keyword in haystack for keyword in _UPDATE_KEYWORDS):
            return True
    return False


def apply_context(
    cluster: "list[Signal]",
    score: int,
    triggered_by: Optional[str],
    boot_time: Optional[datetime],
    max_strength: str,
) -> "tuple[int, Optional[str]]":
    """Check every context category against one cluster. Returns
    (adjusted_score, notes_text). notes_text is None when nothing
    matched; otherwise it's a human-readable sentence (or several)
    naming every matched benign explanation, always attached to the
    resulting correlation_alerts row regardless of whether the score
    was actually reduced.
    """
    notes: list[str] = []
    reduction = 0
    cluster_start = min(signal.timestamp for signal in cluster)

    if triggered_by == RUN_ALL_TRIGGER:
        notes.append(
            "Produced during a run-all sweep, which scans every module back-to-back "
            "in quick succession — ordinary/expected findings can look more "
            "correlated than they are simply because of when they were checked."
        )
        if max_strength == WEAK:
            reduction += 3

    if is_recent_boot(cluster_start, boot_time):
        notes.append(
            "Occurred shortly after this Mac started up — many ordinary processes, "
            "connections, and services normally appear during a boot."
        )
        if max_strength == WEAK:
            reduction += 3

    if is_likely_update_or_install(cluster):
        notes.append(
            "One or more signals look like they may be part of a routine software "
            "update or installation (best-effort keyword match, low confidence)."
        )
        if max_strength == WEAK:
            reduction += 2

    adjusted_score = max(0, score - reduction)
    notes_text = " ".join(notes) if notes else None
    return adjusted_score, notes_text
