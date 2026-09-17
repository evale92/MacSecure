"""
checks/backup.py — does this Mac have a Time Machine backup, and is it recent?

Ransomware and disk failure are only survivable with a recent backup. Uses
`/usr/bin/tmutil destinationinfo` and `/usr/bin/tmutil latestbackup`, both
read-only and sudo-free. Whether the destination is encrypted is not
something these commands report, so this check says it did not verify it
rather than implying it did.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Optional

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

NAME = "Time Machine backup"
STALE_DAYS = 7
_STAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{6})")


def _evaluate(destinations: str, latest_ok: bool, latest: str, now: float) -> CheckResult:
    if "no destinations configured" in destinations.lower():
        return CheckResult(NAME, CheckStatus.WARNING, "No Time Machine backup destination is configured.",
                           "Set up Time Machine (System Settings > General > Time Machine) with an "
                           "encrypted disk, so ransomware or a failed disk is recoverable.")
    count = len(re.findall(r"^\s*Name\s*:", destinations, re.MULTILINE))
    if count == 0:
        return CheckResult(NAME, CheckStatus.WARNING,
                           f"Could not interpret `tmutil destinationinfo` output: {destinations.strip()[:200]!r}", "Run `tmutil destinationinfo` and `tmutil latestbackup` yourself in Terminal to check manually.")
    stamp = _STAMP_RE.search(latest) if latest_ok else None
    if stamp is None:
        return CheckResult(NAME, CheckStatus.WARNING,
                           f"{count} destination(s) configured, but the latest backup could not be determined "
                           "(destination not mounted or no completed backup).", "Run `tmutil destinationinfo` and `tmutil latestbackup` yourself in Terminal to check manually.")
    taken = datetime.strptime(stamp.group(1), "%Y-%m-%d-%H%M%S").timestamp()
    age_days = (now - taken) / 86400
    message = (f"{count} destination(s); latest backup {age_days:.0f} day(s) ago. "
               "Destination encryption not verified by this check.")
    if age_days > STALE_DAYS:
        return CheckResult(NAME, CheckStatus.WARNING, message,
                           "Connect the backup disk or check why Time Machine has not completed a backup.")
    return CheckResult(NAME, CheckStatus.PASS, message, "")


def check_backup(now: Optional[float] = None) -> CheckResult:
    info = run(["/usr/bin/tmutil", "destinationinfo"], timeout=15.0)
    if info.returncode is None:
        return CheckResult(NAME, CheckStatus.WARNING, f"Could not run `tmutil destinationinfo` ({info.stderr.strip()}).", "Run `tmutil destinationinfo` and `tmutil latestbackup` yourself in Terminal to check manually.")
    text = info.stdout + info.stderr
    latest = run(["/usr/bin/tmutil", "latestbackup"], timeout=15.0) if "no destinations" not in text.lower() else None
    return _evaluate(text, bool(latest and latest.returncode == 0), latest.stdout if latest else "",
                     time.time() if now is None else now)
