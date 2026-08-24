"""
checks/firewall.py — is the built-in Application Firewall turned on?

Uses `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`,
a read-only macOS command that doesn't need sudo.
"""

from __future__ import annotations

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

NAME = "Firewall"
_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def _evaluate(stdout: str) -> CheckResult:
    text = stdout.strip()
    lowered = text.lower()

    if "enabled" in lowered and "disabled" not in lowered:
        return CheckResult(NAME, CheckStatus.PASS, text or "Firewall is enabled.", "")

    if "disabled" in lowered:
        return CheckResult(
            NAME,
            CheckStatus.FAIL,
            text or "Firewall is disabled.",
            "Turn it on: System Settings -> Network -> Firewall -> On. It "
            "blocks unsolicited incoming connections to this Mac from the "
            "network it's connected to.",
        )

    return CheckResult(
        NAME,
        CheckStatus.WARNING,
        f"Could not interpret firewall output: {text!r}",
        f"Run `{_SOCKETFILTERFW} --getglobalstate` yourself in Terminal to "
        "check manually.",
    )


def check_firewall() -> CheckResult:
    result = run([_SOCKETFILTERFW, "--getglobalstate"])
    if result.returncode is None:
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            f"Could not run socketfilterfw ({result.stderr.strip()}).",
            f"Run `{_SOCKETFILTERFW} --getglobalstate` yourself in Terminal "
            "to check manually.",
        )
    return _evaluate(result.stdout)
