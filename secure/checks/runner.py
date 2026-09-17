"""
checks/runner.py — runs every posture check and returns the results in
a stable, predictable order.

Each individual check module is independent and self-contained. This
file's only job is to call all of them and make sure one check
crashing (e.g. because a command isn't installed on this system)
can't take the rest down with it — a broken check turns into a
WARNING result instead of an unhandled exception.
"""

from __future__ import annotations

import logging

from secure.checks.backup import check_backup
from secure.checks.filevault import check_filevault
from secure.checks.firewall import check_firewall
from secure.checks.gatekeeper import check_gatekeeper
from secure.checks.models import CheckResult, CheckStatus
from secure.checks.os_version import check_os_version
from secure.checks.sharing import check_sharing_services
from secure.checks.sip import check_sip
from secure.checks.software_update import check_automatic_updates, check_pending_updates
from secure.checks.xprotect import check_xprotect

logger = logging.getLogger(__name__)

# Display order for the single-result checks. Deliberately a plain
# list (not a dict) so the order here is exactly the order results
# come back in.
_SINGLE_CHECKS = [
    check_os_version,
    check_filevault,
    check_firewall,
    check_gatekeeper,
    check_sip,
    check_automatic_updates,
    check_xprotect,
    check_backup,
]


def run_all_checks(include_pending_updates: bool = True) -> "list[CheckResult]":
    """Run every posture check and return one CheckResult per finding.

    include_pending_updates: the pending-updates check is the only one
    that talks to the network (Apple's update servers) and can take
    several seconds; set this False for a fast, fully-local run (the
    CLI exposes this as `secure check --quick`).

    A check that raises an unexpected exception is turned into a
    WARNING result instead of crashing the whole run — one broken
    check shouldn't hide every other check's results.
    """
    results: "list[CheckResult]" = [_run_one(fn) for fn in _SINGLE_CHECKS]

    if include_pending_updates:
        results.append(_run_one(check_pending_updates))

    results.extend(_run_sharing_checks())

    return results


def _run_one(check_fn) -> CheckResult:
    try:
        return check_fn()
    except Exception as exc:  # pragma: no cover - defensive
        name = getattr(check_fn, "__name__", str(check_fn))
        logger.exception("Posture check %s crashed", name)
        return CheckResult(
            name=name,
            status=CheckStatus.WARNING,
            message=f"This check crashed unexpectedly: {exc}",
            remediation="Check the relevant setting manually; please report this as a bug.",
        )


def _run_sharing_checks() -> "list[CheckResult]":
    try:
        return check_sharing_services()
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Sharing services check crashed")
        return [
            CheckResult(
                name="Sharing Services",
                status=CheckStatus.WARNING,
                message=f"Could not complete the sharing-services check: {exc}",
                remediation="Check System Settings -> General -> Sharing manually.",
            )
        ]
