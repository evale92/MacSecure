"""
checks/filevault.py — is FileVault (full-disk encryption) turned on?

Uses `fdesetup status`, a read-only macOS command that reports
FileVault's on/off state without needing sudo.
"""

from __future__ import annotations

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

NAME = "FileVault"


def _evaluate(stdout: str) -> CheckResult:
    text = stdout.strip()
    lowered = text.lower()

    if "filevault is on" in lowered:
        return CheckResult(NAME, CheckStatus.PASS, text or "FileVault is On.", "")

    if "filevault is off" in lowered:
        return CheckResult(
            NAME,
            CheckStatus.FAIL,
            text or "FileVault is Off.",
            "Turn on disk encryption: System Settings -> Privacy & Security -> "
            "FileVault -> Turn On FileVault. Without it, anyone with physical "
            "access to this Mac can read the disk by removing it or booting "
            "from another drive.",
        )

    return CheckResult(
        NAME,
        CheckStatus.WARNING,
        f"Could not interpret `fdesetup status` output: {text!r}",
        "Run `fdesetup status` yourself in Terminal to check manually.",
    )


def check_filevault() -> CheckResult:
    result = run(["fdesetup", "status"])
    if result.returncode is None:
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            f"Could not run `fdesetup status` ({result.stderr.strip()}).",
            "Run `fdesetup status` yourself in Terminal to check manually.",
        )
    return _evaluate(result.stdout)
