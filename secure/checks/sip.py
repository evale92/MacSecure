"""
checks/sip.py — is System Integrity Protection (SIP) turned on?

Uses `csrutil status`, a read-only macOS command. Reading SIP's status
doesn't need sudo, even though *changing* it requires booting into
Recovery Mode — which this app never attempts to do for you.
"""

from __future__ import annotations

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

NAME = "System Integrity Protection (SIP)"


def _evaluate(stdout: str) -> CheckResult:
    text = stdout.strip()
    lowered = text.lower()

    if "enabled" in lowered:
        return CheckResult(NAME, CheckStatus.PASS, text or "SIP is enabled.", "")

    if "disabled" in lowered:
        return CheckResult(
            NAME,
            CheckStatus.FAIL,
            text or "SIP is disabled.",
            "Re-enable it yourself: restart into Recovery Mode (hold the "
            "power button on Apple Silicon, or Cmd+R on Intel during boot), "
            "open Terminal from the Utilities menu, and run `csrutil enable`. "
            "SIP protects core system files from being modified, including "
            "by malware that has gained root access.",
        )

    return CheckResult(
        NAME,
        CheckStatus.WARNING,
        f"Could not interpret `csrutil status` output: {text!r}",
        "Run `csrutil status` yourself in Terminal to check manually.",
    )


def check_sip() -> CheckResult:
    result = run(["csrutil", "status"])
    if result.returncode is None:
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            f"Could not run `csrutil status` ({result.stderr.strip()}).",
            "Run `csrutil status` yourself in Terminal to check manually.",
        )
    return _evaluate(result.stdout)
