"""
integrations/osquery/queries.py — the exact SQL text this integration
runs against osqueryi, and nothing else. Kept as bare strings in one
place (not built up dynamically) so `ExternalObservation.source_query`
can record precisely what was asked, and so a reviewer can see this
integration's entire footprint against the osquery tables at a glance.

Phase 15 scope, per the explicit instruction to integrate "a small,
high-value osquery subset first": processes, process open sockets,
listening ports, and launchd/startup persistence. Deliberately NOT the
osquery tables covering areas Secure already has richer native coverage
of in other ways (e.g. full filesystem hashing — see secure/
fileintegrity/) or that aren't yet cross-checked against anything (see
crosscheck.py — v1 only cross-checks LISTENING and PERSISTENCE).
"""

from __future__ import annotations

PROCESSES = "processes"
PROCESS_OPEN_SOCKETS = "process_open_sockets"
LISTENING_PORTS = "listening_ports"
LAUNCHD = "launchd"

QUERIES = {
    PROCESSES: (
        "SELECT pid, name, path, cmdline, uid, parent "
        "FROM processes;"
    ),
    PROCESS_OPEN_SOCKETS: (
        "SELECT pid, local_address, local_port, remote_address, remote_port, "
        "protocol, family "
        "FROM process_open_sockets "
        "WHERE protocol IN (6, 17);"  # TCP, UDP only
    ),
    LISTENING_PORTS: (
        "SELECT pid, port, protocol, address, family "
        "FROM listening_ports "
        "WHERE protocol IN (6, 17);"  # TCP, UDP only
    ),
    LAUNCHD: (
        "SELECT name, label, path, program, program_arguments, run_at_load, "
        "keep_alive, disabled, username "
        "FROM launchd;"
    ),
}

# The order collection happens in — PROCESSES first, since the
# listening/socket parsers use its pid->name map to fill in a
# process_name osquery's own socket tables don't carry directly (see
# parser.py).
COLLECTION_ORDER = (PROCESSES, PROCESS_OPEN_SOCKETS, LISTENING_PORTS, LAUNCHD)
