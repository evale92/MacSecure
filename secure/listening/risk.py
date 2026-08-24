"""
listening/risk.py — a small, hand-picked heuristic for whether a
listening service is "probably fine" or "worth a second look," in
plain English.

Same spirit and same limitation as secure/inventory/vendor.py and
secure/connections/port_info.py's tables: NOT a vulnerability scanner
and NOT an exhaustive list of every risky port — just enough
context to help you decide whether to keep reading. This never
inspects, exploits, or connects to the service itself (see the
package docstring) — the verdict is based only on the port number,
whether the port has been in Phase 2's own "sharing services" check
list, and the bind scope (secure/listening/bind_scope.py).
"""

from __future__ import annotations

from typing import Optional

# Remote-access or file-sharing services — the categories Phase 2's
# secure/checks/sharing.py already checks for specifically (SSH,
# Screen Sharing, SMB, Remote Management) plus a few more of the same
# flavor. Worth a second look if one of these is listening on "network"
# scope and you didn't turn it on yourself.
_SENSITIVE_IF_EXPOSED = {
    20: "FTP (data)",
    21: "FTP (control)",
    22: "SSH / Remote Login",
    23: "Telnet (unencrypted remote login)",
    111: "rpcbind (RPC portmapper)",
    139: "NetBIOS",
    445: "SMB file sharing",
    548: "AFP file sharing",
    2049: "NFS file sharing",
    3283: "Apple Remote Desktop / Remote Management",
    3389: "RDP (Windows Remote Desktop)",
    5900: "VNC / Screen Sharing",
}

# Local network discovery/announcement protocols — by design they
# broadcast on the network, but they don't grant remote access to
# anything; seeing these is normal and expected.
_DISCOVERY_PORTS = {
    1900,  # SSDP (UPnP discovery)
    5353,  # mDNS / Bonjour
    3722,  # Apple Continuity/Xsan service discovery
}


def evaluate_risk(port: Optional[int], process_name: Optional[str], bind_scope: str) -> str:
    """Return a one-line, plain-English take on a listening service.

    bind_scope must be "localhost" or "network" (see bind_scope.py).
    """
    if bind_scope == "localhost":
        return "Only reachable from this Mac itself — not exposed to your network."

    if port in _SENSITIVE_IF_EXPOSED:
        label = _SENSITIVE_IF_EXPOSED[port]
        return (
            f"{label} — a remote-access/file-sharing service, and it's exposed to "
            "your local network. If you didn't intentionally turn this on, check "
            "Security Posture and System Settings -> General -> Sharing."
        )

    if port in _DISCOVERY_PORTS:
        return "Local network discovery/announcement service — normal, not remote access."

    who = process_name or "this process"
    return f"Exposed to your local network — review if you don't recognize {who}."
