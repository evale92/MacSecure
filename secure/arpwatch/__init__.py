"""
secure.arpwatch — ARP / Neighbor Table Monitoring.

Passively watches this Mac's ARP cache (the same one
secure/inventory/ reads for device discovery) over time and flags
changes that are worth a second look:

    - **A device's MAC address changing** — usually harmless (a new
      device took over a DHCP lease, an existing device got a new
      network adapter), reported at low severity.
    - **The default gateway's MAC address changing** — the classic
      signature of ARP spoofing / a man-in-the-middle attempt, but
      also exactly what a router reboot or replacement looks like.
      Reported at high severity either way, with the message spelling
      out both possibilities rather than assuming an attack.
    - **The same IP answering as more than one MAC within a single
      scan** — a real inconsistency in the ARP cache, reported at
      medium severity.

Read-only, no sudo, same as every package here:

    - `arp -an` (via secure.inventory.arp_table's already-tested
      parser — see scanner.py's module docstring for why that's
      reused rather than duplicated).
    - `route -n get default` to find the current gateway IP
      (secure/arpwatch/gateway.py).

Every real ARP entry observed goes into `arp_observations` (full
history). This Mac's current best-known IP -> MAC state lives in
`arp_mappings`, one row per IP — what change-detection is compared
against. Every alert raised is stored in `arp_alerts`, reviewable the
same way as devices/remote_endpoints/listening_services: `secure
arpwatch list` shows them, `secure arpwatch mark <id> known|unknown`
marks one reviewed.

What this deliberately does NOT do, and why — this is the one phase
where it matters most to say clearly:

    - **Never performs any active ARP spoofing, ARP request forgery,
      or "test" traffic of any kind.** This module only reads the ARP
      cache the operating system already populated through its own
      ordinary traffic — it never sends a single crafted packet. The
      Claude prompt this phase was built from says so explicitly, and
      it's the clearest line in this app between "defensive
      visibility" and "offensive tooling."
    - Severity is deliberately conservative. IP-to-MAC churn is normal
      on any home network; only a gateway MAC change is treated as
      high severity, specifically to avoid alert fatigue that would
      make you tune this feature out.
    - No identification of *who* changed a MAC address or *why* — this
      reports the fact of a change, not a cause. Investigating further
      (checking System Settings -> Wi-Fi, restarting the router
      yourself to confirm, etc.) is on you.

See PROJECT_NOTES.md ("ARP / Neighbor Table Monitoring") for more.

    from secure.arpwatch import scan_arp_table
    result = scan_arp_table(conn)
    for alert in result.alerts:
        print(alert.severity, alert.kind, alert.message)
"""

from __future__ import annotations

from secure.arpwatch.scanner import ArpWatchResult, scan_arp_table

__all__ = ["ArpWatchResult", "scan_arp_table"]
