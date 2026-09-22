"""
secure.connections — Active Connection Monitor.

Shows this Mac's active TCP connections and UDP sockets: local
address/port, remote address/port, connection state, the owning
process's PID and name (where macOS permissions allow without sudo —
see connections/lsof_parser.py), using one safe, read-only, no-sudo
method:

    - `lsof -i -n -P` — the standard, built-in macOS tool for listing
      which process has which network socket open. No sudo, nothing
      else is run.

Every connection observed goes into the `connection_events` table
(full history, one row per socket per scan — see
secure/storage/models.py). Every distinct remote destination
(address+port+protocol) this Mac has ever connected out to is tracked
separately in `remote_endpoints`, deduplicated, so a first-time
destination can be flagged for review — the same "known/unknown +
alert on new" pattern secure/inventory/ uses for local devices.
`secure connections` in secure.cli.connections (or the "Active Connections" GUI
category) explains common ports in plain English via
connections/port_info.py.

What this deliberately does NOT do, and why:
    - Never blocks, closes, kills, or otherwise touches a connection
      or the process behind it — this module only observes and
      records. Any action beyond looking is a human decision.
    - No guarantee every process/connection is identifiable. Without
      sudo, lsof can't always report the PID/process name for sockets
      owned by another user, and simply omits or warns about them
      (see ConnectionScanResult.permission_warnings) rather than this
      app trying to escalate privileges to fill in the gap.
    - No deep packet inspection, no traffic content, no DNS-based
      reputation lookups of remote addresses — this reports what's
      connected to what, not what the traffic contains or whether a
      remote address is "good" or "bad".

See PROJECT_NOTES.md ("Active Connection Monitor") for more.

    from secure.connections import scan_connections
    result = scan_connections(conn)
    for entry in result.entries:
        print(entry.proto, entry.local_addr, entry.remote_addr)
    for record in result.new_endpoints:
        print("NEW destination:", record.remote_addr, record.remote_port)
"""

from __future__ import annotations

from secure.connections.scanner import ConnectionScanResult, is_loopback, scan_connections

__all__ = ["ConnectionScanResult", "is_loopback", "scan_connections"]
