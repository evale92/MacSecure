"""
secure.listening — Listening Port and Service Audit.

Shows every TCP port and (where practical) UDP port this Mac is
currently listening on: the owning process/PID, and — the piece Phase
4 (Active Connection Monitor) doesn't answer — whether the service is
bound only to localhost (unreachable from anywhere but this Mac) or
exposed to the network (reachable from other devices on your LAN, and
potentially the wider internet if your router forwards the port).
Uses the same safe, read-only, no-sudo method as Phase 4:

    - `lsof -i -n -P +c0` — parsed with secure/connections/lsof_parser.py
      (shared, not duplicated — see scanner.py's module docstring for
      why), then filtered down to just the listening sockets.

Every listening socket observed goes into the `listening_events` table
(full history, one row per socket per scan). Every distinct service —
deduplicated by protocol, bind scope, process name, and a "identity
port" that intentionally ignores exact port numbers for ordinary
ephemeral dev-tool listeners (see scanner.py's _identity_port()) — is
tracked in `listening_services`, the same "known/unknown + alert on
new" pattern secure/inventory/ and secure/connections/ use. A
first-time service is flagged for review, and — comparing against the
immediately preceding scan — a service that WAS listening last time
but isn't anymore is flagged too (see scanner.py's
_previous_scan_identities()): a service quietly closing is just as
worth noticing as one appearing. secure/listening/risk.py adds a
one-line plain-English take on whether a given port/bind-scope
combination is ordinary or worth a second look.

What this deliberately does NOT do, and why:
    - Never blocks, closes, kills, or otherwise touches a listening
      service or its process — this module only observes and records.
    - Never connects to, probes, or exploits a listening service to
      see what it does — the Claude prompt this phase was built from
      says so explicitly, and it's consistent with how the rest of
      this app works: visibility, not intrusion testing.
    - No guarantee of catching every UDP listener — a UDP socket with
      no remote peer is treated as "listening" (see
      scanner.py's _is_listening()), which is accurate for how lsof
      reports it but, like everywhere else in this app, is read
      through a best-effort tool rather than the kernel's own
      authoritative socket table.
    - This complements, not replaces, Phase 2's dedicated sharing-
      services check (secure/checks/sharing.py) — that check is a
      fixed checklist of well-known services (SSH, Screen Sharing,
      etc); this audits *everything* currently listening, dynamically.

See PROJECT_NOTES.md ("Listening Port and Service Audit") for more.

    from secure.listening import scan_listening_services
    result = scan_listening_services(conn)
    for entry in result.entries:
        print(entry.proto, entry.local_port, entry.bind_scope, entry.risk_note)
    for record in result.new_services:
        print("NEW SERVICE:", record.process_name, record.identity_port)
"""

from __future__ import annotations

from secure.listening.scanner import ListeningScanResult, scan_listening_services

__all__ = ["ListeningScanResult", "scan_listening_services"]
