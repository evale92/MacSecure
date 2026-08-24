"""
checks/gatekeeper.py — is Gatekeeper (verifies apps are signed/
notarized before their first run) turned on?

Uses `spctl --status`, a read-only macOS command that doesn't need
sudo.
"""

from __future__ import annotations

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

NAME = "Gatekeeper"


def _evaluate(stdout: str) -> CheckResult:
    text = stdout.strip()
    lowered = text.lower()

    if "assessments enabled" in lowered:
        return CheckResult(NAME, CheckStatus.PASS, text or "Gatekeeper is enabled.", "")

    if "assessments disabled" in lowered:
        return CheckResult(
            NAME,
            CheckStatus.FAIL,
            text or "Gatekeeper is disabled.",
            "Turn it back on: run `sudo spctl --master-enable` yourself in "
            "Terminal (this app never runs sudo for you). With Gatekeeper "
            "off, macOS won't check that apps are signed/notarized before "
            "letting them run.",
        )

    return CheckResult(
        NAME,
        CheckStatus.WARNING,
        f"Could not interpret `spctl --status` output: {text!r}",
        "Run `spctl --status` yourself in Terminal to check manually.",
    )


def check_gatekeeper() -> CheckResult:
    result = run(["spctl", "--status"])
    if result.returncode is None:
        return CheckResult(
            NAME,
            CheckStatus.WARNING,
            f"Could not run `spctl --status` ({result.stderr.strip()}).",
            "Run `spctl --status` yourself in Terminal to check manually.",
        )
    return _evaluate(result.stdout)
