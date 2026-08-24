"""
connections/port_info.py — a small, hand-picked table explaining
common ports and connection types in plain English.

Same spirit and same limitation as secure/inventory/vendor.py's OUI
table: NOT an exhaustive registry of all ~65,000 possible ports (IANA
maintains that; this app deliberately makes no network calls to fetch
it — see secure/checks/software_update.py for the one documented
exception elsewhere in this app). Returning None just means "not in
this small table," not that anything is wrong with the connection.

Extend `_COMMON_PORTS` if you want more ports explained.
"""

from __future__ import annotations

from typing import Optional

# port -> (short name, plain-English description)
_COMMON_PORTS = {
    20: ("FTP data", "File Transfer Protocol data channel — unencrypted."),
    21: ("FTP control", "File Transfer Protocol control channel — unencrypted."),
    22: ("SSH", "Secure Shell — encrypted remote login/terminal access."),
    23: ("Telnet", "Unencrypted remote login — considered insecure, avoid."),
    25: ("SMTP", "Outgoing mail relay (Simple Mail Transfer Protocol)."),
    53: ("DNS", "Domain Name System — translates hostnames to IP addresses."),
    67: ("DHCP (server)", "Hands out IP addresses to devices on the network."),
    68: ("DHCP (client)", "Requesting an IP address from a DHCP server."),
    80: ("HTTP", "Unencrypted web traffic."),
    110: ("POP3", "Incoming mail retrieval — unencrypted."),
    123: ("NTP", "Network Time Protocol — keeps the clock synchronized."),
    143: ("IMAP", "Incoming mail retrieval — unencrypted."),
    179: ("BGP", "Border Gateway Protocol — internet backbone routing."),
    389: ("LDAP", "Directory service lookups (e.g. corporate login directories)."),
    443: ("HTTPS", "Encrypted web traffic (TLS) — the vast majority of normal browsing."),
    445: ("SMB", "Windows/macOS file sharing."),
    465: ("SMTPS", "Encrypted outgoing mail."),
    587: ("SMTP (submission)", "Outgoing mail submission, usually with authentication."),
    631: ("IPP / CUPS", "Printer sharing/printing protocol."),
    993: ("IMAPS", "Encrypted incoming mail."),
    995: ("POP3S", "Encrypted incoming mail."),
    1900: ("SSDP", "UPnP device discovery — smart-home/media devices finding each other."),
    3283: ("Apple Remote Desktop", "macOS Remote Management (remote administration)."),
    5000: ("AirPlay Receiver", "Apple's screen/media receiver control port (ControlCenter)."),
    7000: ("AirPlay Receiver", "Apple's screen/media receiver control port (ControlCenter)."),
    3306: ("MySQL", "MySQL database connections."),
    3389: ("RDP", "Windows Remote Desktop Protocol."),
    5060: ("SIP", "Voice-over-IP call signaling."),
    5353: ("mDNS", "Multicast DNS / Bonjour — local network device and service discovery."),
    5432: ("PostgreSQL", "PostgreSQL database connections."),
    5900: ("VNC / Screen Sharing", "Remote screen control."),
    6379: ("Redis", "Redis in-memory database connections."),
    8080: ("HTTP (alt)", "Commonly used for local development or proxy servers."),
    8443: ("HTTPS (alt)", "Commonly used for local development or proxy servers."),
}


def describe_port(port: Optional[int]) -> Optional[str]:
    """Return "Name — description" for a well-known port, or None."""
    if port is None:
        return None
    info = _COMMON_PORTS.get(port)
    if info is None:
        return None
    name, description = info
    return f"{name} — {description}"
