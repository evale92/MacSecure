"""
checks/xprotect.py — is Apple's built-in malware protection present and
recently updated?

XProtect is the signature set macOS checks downloaded apps against, and
XProtect Remediator is the scanner that removes known malware. Both are
updated silently by Apple, so a Mac whose updates stopped arriving (a
blocked update server, a tampered bundle, an MDM that disabled
background updates) looks perfectly normal from System Settings. The
version and age of the signature bundle are the only visible sign.

Read-only, no subprocess and no sudo: it reads each bundle's
`Info.plist` with `plistlib`. Since macOS 15, updates land in
`/var/protected/xprotect` while the copy under
`/Library/Apple/System/...` can stay behind, so every known location is
read and the newest version wins.

Source for the gap: rmusser01/Infosec_Reference @af8b68e
Draft/PrivescPostExmac.md ("XProtect" under macOS Defense Evasion).
"""

from __future__ import annotations

import os
import plistlib
import time
from dataclasses import dataclass

from secure.checks.models import CheckResult, CheckStatus

NAME = "XProtect"

# Signature bundles, newest update location first.
_SIGNATURE_BUNDLES = (
    "/var/protected/xprotect/XProtect.bundle",
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
)
_REMEDIATOR_APP = "/Library/Apple/System/Library/CoreServices/XProtect.app"

# Apple has shipped signature updates every one to four weeks since 2022.
# Two months without one means updates are not arriving.
STALE_AFTER_DAYS = 60


@dataclass
class BundleRead:
    path: str
    version: "int | None"   # None when the bundle exists but could not be read
    modified: "float | None"
    error: str = ""


def _read_bundle(path: str) -> "BundleRead | None":
    """None if the bundle is absent; a BundleRead with version None if
    it exists but its Info.plist could not be read or parsed."""
    info = os.path.join(path, "Contents", "Info.plist")
    if not os.path.lexists(path):
        return None
    try:
        with open(info, "rb") as f:
            data = plistlib.load(f)
        modified = os.stat(info).st_mtime
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        return BundleRead(path, None, None, f"{type(exc).__name__}: {exc}")
    raw = data.get("CFBundleShortVersionString") if isinstance(data, dict) else None
    try:
        version = int(str(raw).strip())
    except (TypeError, ValueError):
        return BundleRead(path, None, modified, f"unrecognised version {raw!r}")
    return BundleRead(path, version, modified)


def _evaluate(
    signatures: "list[BundleRead]",
    remediator: "BundleRead | None",
    now: float,
) -> CheckResult:
    readable = [b for b in signatures if b.version is not None]
    unreadable = [b for b in signatures if b.version is None]

    if not readable:
        if unreadable:
            detail = "; ".join(f"{b.path}: {b.error}" for b in unreadable)
            message = f"XProtect is installed but its version could not be read ({detail})."
        else:
            message = (
                "No XProtect signature bundle was found in "
                + " or ".join(_SIGNATURE_BUNDLES)
                + ". Every supported macOS ships one, so this needs a look."
            )
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            message,
            "Run `system_profiler SPInstallHistoryDataType | grep -A4 XProtect` "
            "yourself to see when XProtect last updated.",
        )

    newest = max(readable, key=lambda b: b.version)
    age_days = None if newest.modified is None else max(0.0, (now - newest.modified) / 86400)
    parts = [f"XProtect signatures version {newest.version}"]
    if age_days is not None:
        parts.append(f"updated {age_days:.0f} day(s) ago")
    if remediator is None:
        parts.append("XProtect Remediator not found")
    elif remediator.version is None:
        parts.append(f"XProtect Remediator present but unreadable ({remediator.error})")
    else:
        parts.append(f"XProtect Remediator version {remediator.version}")
    message = "; ".join(parts) + "."

    problems = []
    if age_days is None:
        problems.append("the update date could not be read")
    elif age_days > STALE_AFTER_DAYS:
        problems.append(f"no signature update in over {STALE_AFTER_DAYS} days")
    if remediator is None or remediator.version is None:
        problems.append("XProtect Remediator could not be confirmed")

    if problems:
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            f"{message} Concern: {', '.join(problems)}.",
            "Make sure System Settings -> General -> Software Update -> "
            "Automatic Updates has 'Install Security Responses and system "
            "files' turned on, then check again after the Mac has been online "
            "for a day. If it stays old, something may be blocking Apple's "
            "update servers.",
        )
    return CheckResult(NAME, CheckStatus.PASS, message, "")


def check_xprotect(
    signature_bundles: "tuple[str, ...]" = _SIGNATURE_BUNDLES,
    remediator_app: str = _REMEDIATOR_APP,
    now: "float | None" = None,
) -> CheckResult:
    signatures = [b for b in (_read_bundle(p) for p in signature_bundles) if b is not None]
    remediator = _read_bundle(remediator_app)
    return _evaluate(signatures, remediator, time.time() if now is None else now)
