"""
checks/software_update.py — two related checks:

    check_automatic_updates() — are automatic update checking and
        automatic security-update installation turned on?
    check_pending_updates()   — does `softwareupdate -l` currently see
        anything waiting to be installed?

check_automatic_updates() reads a couple of system preference values
with `defaults read` (no sudo). check_pending_updates() calls Apple's
own `softwareupdate` tool in list-only mode, which talks to Apple's
update servers over the network to see what's available — it never
installs anything, but it's slower and needs network access, unlike
every other check in this package. That's why it gets a longer
timeout and can be skipped separately (see runner.py's
`include_pending_updates` flag / `secure check --quick`).
"""

from __future__ import annotations

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

_DOMAIN = "/Library/Preferences/com.apple.SoftwareUpdate"

AUTO_UPDATES_NAME = "Automatic Updates"
PENDING_UPDATES_NAME = "Pending Updates"


def _read_bool_pref(key: str) -> "bool | None":
    """Read one boolean-ish preference key. None if unset/unreadable."""
    result = run(["defaults", "read", _DOMAIN, key])
    if not result.ok:
        return None
    value = result.stdout.strip()
    if value in ("1", "true", "YES"):
        return True
    if value in ("0", "false", "NO"):
        return False
    return None


def _evaluate_automatic_updates(
    check_enabled: "bool | None", critical_install: "bool | None"
) -> CheckResult:
    if check_enabled is None and critical_install is None:
        return CheckResult(
            AUTO_UPDATES_NAME,
            CheckStatus.WARNING,
            "Could not read automatic-update preferences (the keys may be "
            "unset, which usually means macOS is using its default of On).",
            "Check manually: System Settings -> General -> Software Update "
            "-> Automatic Updates (the info button).",
        )

    if check_enabled is False or critical_install is False:
        off_bits = []
        if check_enabled is False:
            off_bits.append("checking for updates")
        if critical_install is False:
            off_bits.append("installing security updates automatically")
        return CheckResult(
            AUTO_UPDATES_NAME,
            CheckStatus.WARNING,
            f"Automatic {' and '.join(off_bits)} is turned off.",
            "Turn these on: System Settings -> General -> Software Update -> "
            "Automatic Updates. Missing security patches is one of the most "
            "common ways Macs get compromised.",
        )

    return CheckResult(
        AUTO_UPDATES_NAME,
        CheckStatus.PASS,
        "Automatic update checking and automatic security-update "
        "installation are both turned on.",
        "",
    )


def check_automatic_updates() -> CheckResult:
    check_enabled = _read_bool_pref("AutomaticCheckEnabled")
    critical_install = _read_bool_pref("CriticalUpdateInstall")
    return _evaluate_automatic_updates(check_enabled, critical_install)


def _evaluate_pending_updates(combined_output: str) -> CheckResult:
    lowered = combined_output.lower()

    if "no new software available" in lowered:
        return CheckResult(PENDING_UPDATES_NAME, CheckStatus.PASS, "No pending updates found.", "")

    if "* label" in lowered or "recommended" in lowered:
        return CheckResult(
            PENDING_UPDATES_NAME,
            CheckStatus.WARNING,
            "One or more updates are available and not yet installed:\n"
            + combined_output.strip(),
            "Install via System Settings -> General -> Software Update, or "
            "run `sudo softwareupdate -i -a` yourself in Terminal.",
        )

    return CheckResult(
        PENDING_UPDATES_NAME,
        CheckStatus.WARNING,
        f"Unrecognized output from `softwareupdate -l`:\n{combined_output.strip()[:500]}",
        "Run `softwareupdate -l` yourself in Terminal to check manually.",
    )


def check_pending_updates() -> CheckResult:
    # Slower and network-dependent — the one check here that leaves the
    # machine to ask Apple's servers what's available.
    result = run(["softwareupdate", "-l"], timeout=25.0)

    if result.returncode is None:
        return CheckResult(
            PENDING_UPDATES_NAME,
            CheckStatus.WARNING,
            "Could not check for pending updates "
            f"({result.stderr.strip() or 'timed out or command unavailable'}).",
            "Run `softwareupdate -l` yourself in Terminal, or check System "
            "Settings -> General -> Software Update.",
        )

    return _evaluate_pending_updates(result.stdout + result.stderr)
