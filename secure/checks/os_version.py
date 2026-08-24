"""
checks/os_version.py — reports the running macOS version.

Not a security judgment by itself (there's no single "correct"
version) — it's context that makes the other results easier to read,
since "does this need updating" is easier to reason about once you
can see which macOS version this actually is. Uses Python's own
`platform.mac_ver()`, so there's no subprocess involved at all.
"""

from __future__ import annotations

import platform

from secure.checks.models import CheckResult, CheckStatus

NAME = "macOS Version"


def check_os_version() -> CheckResult:
    version, _, _ = platform.mac_ver()

    if not version:
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            "Could not determine the macOS version — platform.mac_ver() "
            "returned nothing. This usually means the check is being run on "
            "a non-macOS system.",
            "Run this check on the Mac you want to inspect.",
        )

    return CheckResult(NAME, CheckStatus.PASS, f"Running macOS {version}.", "")
