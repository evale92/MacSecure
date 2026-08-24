"""
checks/sharing.py — is anything listening on the ports macOS's common
built-in sharing services use? Covers Remote Login/SSH and Screen
Sharing specifically (as requested), plus a few other common sharing
services worth knowing about.

Read-only, no-sudo approach: rather than asking `launchctl` or
`systemsetup` (which need administrator access for a definitive
answer), this attempts a plain TCP connect to 127.0.0.1 on each
service's default port. A successful connect means *something* is
listening there; a refused/timed-out connect means nothing is. This
never sends or receives any application data — it's the same kind of
probe your own Mac already does to itself constantly, just aimed at
loopback.

Caveats — read before trusting a WARNING here blindly:
    - This tells you a port is listening, not definitively *why*. A
      non-default port change or a third-party app reusing one of
      these ports could also produce a "listening" result. Each
      result names exactly what was probed so you can sanity-check it
      in System Settings -> General -> Sharing.
    - Port 631 (Printer Sharing) is a known false-positive source:
      macOS's printing system (CUPS) commonly listens there for its
      own local admin page even when network Printer Sharing is OFF.
      That result is worded as a hint, not a finding.
"""

from __future__ import annotations

import socket

from secure.checks.models import CheckResult, CheckStatus

# (display name, port, extra caveat text or "")
_SERVICES = [
    ("Remote Login (SSH)", 22, ""),
    ("Screen Sharing", 5900, ""),
    ("File Sharing (SMB)", 445, ""),
    ("Remote Management (Apple Remote Desktop)", 3283, ""),
    (
        "Printer Sharing",
        631,
        "Note: macOS's printing system (CUPS) commonly listens on "
        "localhost:631 for its own local admin page even when network "
        "Printer Sharing is turned OFF. Treat this result as a hint, not "
        "proof — confirm in System Settings -> General -> Sharing.",
    ),
]

_PROBE_TIMEOUT = 0.35


def _port_is_listening(port: int, timeout: float = _PROBE_TIMEOUT) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _evaluate_service(name: str, port: int, caveat: str, listening: bool) -> CheckResult:
    if listening:
        message = f"Something is listening on 127.0.0.1:{port} ({name})."
        if caveat:
            message += " " + caveat
        return CheckResult(
            name=name,
            status=CheckStatus.WARNING,
            message=message,
            remediation=(
                "If you don't need this, turn it off: System Settings -> "
                "General -> Sharing."
            ),
        )

    return CheckResult(
        name=name,
        status=CheckStatus.PASS,
        message=f"Nothing responded on 127.0.0.1:{port} — {name} appears off.",
        remediation="",
    )


def check_sharing_services() -> "list[CheckResult]":
    return [
        _evaluate_service(name, port, caveat, _port_is_listening(port))
        for name, port, caveat in _SERVICES
    ]
