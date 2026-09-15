"""
inventory/hostnames.py — best-effort reverse-DNS hostname lookup for a
discovered IP address.

Uses Python's built-in `socket` module only (no subprocess) — a
standard reverse-DNS/mDNS query, the same kind of lookup this Mac
already performs constantly. It doesn't otherwise contact the target
device. Many devices (phones, IoT gadgets) won't have a reverse-DNS
entry at all, which is normal — that is a *resolved* answer of "no
name", not a failure.

Two things this module is careful about, both learned the hard way:

**The deadline has to bind.** `socket.setdefaulttimeout()` sets the
default only for newly created socket objects, and
`socket.gethostbyaddr()` goes through the platform resolver in C
without ever creating one — so the timeout this function used to set
was inert. Measured: with the default at 1e-06s, a control
`socket.create_connection` raised TimeoutError while
`gethostbyaddr('127.0.0.1')` returned normally after 8543x that
timeout. That matters because `arp -a` was switched to `arp -an`
precisely to move hostname resolution out of arp (it "can hang for
seconds without a controlling terminal") and into here, and
scanner.py calls this once per discovered device with no worker pool.
The bound is now a real one: the lookup runs on a daemon thread the
caller stops waiting on. A thread stuck in the platform resolver is
left to finish on its own and never blocks the scan or interpreter
exit.

**A timeout is not "no PTR record".** Both come back without a name,
but one is the ordinary case for a phone and the other is a sensor
that did not answer. Collapsing them into `None` is the omission
SECURITY_INVARIANTS invariant 5 forbids, so
`resolve_hostname_with_status()` returns which one it was and
scanner.py counts the degraded ones into the scan's own
sensor-health channel.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import List, Optional

#: The resolver answered with a name.
RESOLVED = "RESOLVED"
#: The resolver answered, and the address genuinely has no PTR record —
#: the normal case for phones and IoT gadgets, not a failure.
NO_RECORD = "NO_RECORD"
#: The resolver did not answer inside the deadline.
TIMED_OUT = "TIMED_OUT"
#: The resolver itself could not be used (e.g. no network stack).
ERROR = "ERROR"

#: Statuses where a missing name says nothing about the device — the
#: sensor is what failed. Callers must report these rather than treat
#: them as "this device has no hostname".
DEGRADED_STATUSES = (TIMED_OUT, ERROR)


@dataclass(frozen=True)
class HostnameLookup:
    """One reverse-DNS answer, and whether the resolver actually gave it."""

    hostname: Optional[str]
    status: str

    @property
    def degraded(self) -> bool:
        """True when `hostname is None` because the lookup failed, not
        because the address has no name."""
        return self.status in DEGRADED_STATUSES


def _lookup(ip: str) -> HostnameLookup:
    """Run the platform resolver once, mapping each failure it can raise
    to the status that distinguishes it from the others.

    herror/gaierror are the resolver saying "no name for this address";
    a timeout or any other OSError is the resolver not answering.
    """
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return HostnameLookup(None, NO_RECORD)
    except (socket.timeout, TimeoutError):
        return HostnameLookup(None, TIMED_OUT)
    except OSError:
        return HostnameLookup(None, ERROR)
    return HostnameLookup(hostname, RESOLVED)


def resolve_hostname_with_status(ip: str, timeout: float = 1.0) -> HostnameLookup:
    """Reverse-resolve `ip`, waiting at most `timeout` seconds, and say
    which kind of answer came back.

    The deadline is enforced by not waiting on the worker any longer,
    which is the only bound available: the platform resolver call is
    not interruptible from Python. The worker is a daemon thread, so a
    lookup still stuck in the C resolver holds nothing up — not this
    scan, not interpreter exit.

    An exception that isn't one the resolver is documented to raise is
    re-raised in the caller's thread: a programming error must surface,
    not be laundered into "this device has no hostname".
    """
    outcome: List[HostnameLookup] = []
    failure: List[BaseException] = []

    def _worker() -> None:
        try:
            outcome.append(_lookup(ip))
        except BaseException as exc:  # noqa: BLE001 - re-raised below, in the caller
            failure.append(exc)

    worker = threading.Thread(target=_worker, name=f"secure-rdns-{ip}", daemon=True)
    worker.start()
    worker.join(timeout)

    if worker.is_alive():
        return HostnameLookup(None, TIMED_OUT)
    if failure:
        raise failure[0]
    if not outcome:
        # The thread finished without recording either — no path does
        # this, so report the honest gap rather than an absent name.
        return HostnameLookup(None, ERROR)
    return outcome[0]


def resolve_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """The name only, or None — for callers that have nowhere to report
    sensor health to.

    Anything that records a scan result should call
    `resolve_hostname_with_status()` instead: None here cannot be told
    apart from a lookup that never answered.
    """
    return resolve_hostname_with_status(ip, timeout=timeout).hostname
