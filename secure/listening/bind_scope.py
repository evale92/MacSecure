"""
listening/bind_scope.py — classifies a listening socket's local
address as "localhost" (only reachable from this Mac itself) or
"network" (reachable from other devices on the LAN, or in principle
the internet if the router forwards the port). Also holds
identity_port() — the two live together because Phase 14's baseline
history reader (secure/baseline/history.py) needs both without
depending on secure/listening/scanner.py itself, which (as of Phase 14)
imports secure/baseline/engine.py — putting these here instead of in
scanner.py avoids that import cycle.

This is the core fact Phase 5 adds on top of what Phase 4 (Active
Connection Monitor) already shows: `secure connections scan` displays
the raw local address, but doesn't tell you whether that address means
"nobody else can reach this" or "your whole LAN can."
"""

from __future__ import annotations

from typing import Optional

from secure.connections.port_info import describe_port

_LOCALHOST_ADDRS = {"127.0.0.1", "::1", "localhost"}
# lsof shows an unbound-to-one-interface socket as "*" (IPv4) — this
# app has not observed lsof emit a bare "0.0.0.0"/"::" here, but they
# mean the same thing (all interfaces) and are included for safety.
_ALL_INTERFACES_ADDRS = {"*", "0.0.0.0", "::", "0.0.0.0:0"}

# Ports below this need root to bind and are almost always a fixed,
# intentional configuration, not an OS-assigned ephemeral port — kept
# as part of a service's identity. See identity_port()'s docstring.
_PRIVILEGED_PORT_THRESHOLD = 1024


def classify_bind_scope(local_addr: "str | None") -> str:
    """Return "localhost" or "network" for a listening socket's local address.

    "localhost" — 127.0.0.1 / ::1 only. Nothing outside this Mac can
    connect, regardless of firewall or router state.

    "network" — anything else: "*"/0.0.0.0/:: (all interfaces,
    including whichever one is on your LAN), or a specific non-loopback
    address (e.g. this Mac's own LAN IP, or a link-local address used
    for AirDrop/Handoff). Bound this way, the service is at least
    reachable from other devices on the same network — whether it's
    reachable from the wider internet too depends on your router's
    port forwarding, which this app has no way to inspect (see "let's
    do everything without logging into the router" in PROJECT_NOTES.md).

    An unset/unrecognized address is treated as "network" — the
    cautious default when this can't be determined confidently is to
    NOT understate exposure.
    """
    if not local_addr:
        return "network"
    if local_addr in _LOCALHOST_ADDRS:
        return "localhost"
    if local_addr in _ALL_INTERFACES_ADDRS:
        return "network"
    return "network"


def identity_port(port: "Optional[int]") -> str:
    """Return the identity_port bucket used to dedupe a listening service.

    A port below 1024 needs root to bind, so a process listening there
    is a fixed, intentional configuration — kept precisely. A port at
    or above 1024 that's in the small well-known-ports table
    (connections/port_info.py) is also treated as fixed — e.g. 5353
    (mDNS) is always 5353, never OS-random. Everything else (the vast
    majority of dev-tool/IDE/local-helper listeners — JetBrains,
    Postman, VS Code, ...) gets bucketed as "ephemeral": these get a
    different OS-assigned port every time the process restarts, so
    tracking the exact number would make nearly every scan report
    "new services" for the same familiar apps. Grouping them by
    process name instead means the meaningful signal — a NEW PROCESS
    starting to listen — isn't buried under restart noise.

    This is a deliberate, documented tradeoff, not a perfect
    classifier: a genuinely new service that happens to pick a high,
    uncommon port on first run will be bucketed as "ephemeral" too,
    and would only show up as new by way of its process name being
    new. See PROJECT_NOTES.md ("Listening Port and Service Audit").
    """
    if port is None:
        return "ephemeral"
    if port < _PRIVILEGED_PORT_THRESHOLD or describe_port(port) is not None:
        return str(port)
    return "ephemeral"
