"""
wifi/security_level.py — a small, conservative classifier for whether
a Wi-Fi network's security type is weak, open, or fine, in plain
English.

Same spirit and same limitation as secure/listening/risk.py,
secure/inventory/vendor.py, and secure/connections/port_info.py: not a
vulnerability scanner, just enough context to help you decide whether
to keep reading. When the reported security string doesn't match
anything recognized, this deliberately returns "no alert" rather than
guessing — same "avoid false alarms" instinct as secure/arpwatch's
severity choices.
"""

from __future__ import annotations

from typing import Optional, Tuple


def classify_security(security: Optional[str]) -> Tuple[Optional[str], str]:
    """Return (severity, note). severity is None when there's nothing
    to warn about (WPA2/WPA3, or the security type wasn't reported).
    """
    if not security:
        return None, "Security type not reported."

    lowered = security.lower()

    if "wpa3" in lowered:
        return None, "Good — WPA3, the current Wi-Fi security standard."

    if "wpa2" in lowered:
        return None, "Good — WPA2, still considered secure."

    if "wep" in lowered:
        return (
            "high",
            "WEP encryption is badly broken and can be cracked in minutes with freely "
            "available tools — treat this network like it has no encryption at all.",
        )

    if "wpa" in lowered:
        return (
            "medium",
            "WPA (the original version) has known weaknesses. Prefer a network offering "
            "WPA2 or WPA3 if one is available.",
        )

    if lowered in ("none", "open", "no security", "insecure"):
        return (
            "high",
            "Open network — no encryption at all. Anyone nearby can see your unencrypted "
            "traffic. Avoid sending anything sensitive on this network.",
        )

    return None, f"Unrecognized security type ('{security}') — reported as-is, not evaluated."
