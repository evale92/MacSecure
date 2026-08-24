"""
inventory/vendor.py — best-effort vendor lookup from a MAC address's
OUI (Organizationally Unique Identifier — its first 3 bytes).

This is a small, hand-picked, built-in table of commonly-seen
consumer/networking vendor prefixes — NOT a full IEEE OUI database
(that's tens of thousands of entries, changes over time, and would
need to be fetched or updated over the network, which this app
deliberately avoids everywhere except the one documented exception in
secure/checks/software_update.py). Treat any result from this as a
helpful hint, not an authoritative identification:

    - Returning None is the common, expected case for most devices —
      it just means this particular prefix isn't in the small table
      below, not that anything is wrong.
    - A vendor manufactures the network chip, not necessarily the
      whole device — a smart-home gadget from Vendor X might report a
      chipset vendor's OUI instead.
    - Some devices randomize their MAC address (common on phones/
      laptops for privacy when scanning for networks) — the OUI won't
      correspond to the real hardware vendor at all in that case.

Extend `_OUI_VENDORS` below with more prefixes if you want to
recognize additional devices on your own network — it's just a dict.
"""

from __future__ import annotations

from typing import Optional

_OUI_VENDORS = {
    # Apple
    "3c:22:fb": "Apple",
    "a4:83:e7": "Apple",
    "f0:18:98": "Apple",
    "ac:de:48": "Apple",
    "00:1c:b3": "Apple",
    "28:cf:e9": "Apple",
    "dc:a4:ca": "Apple",
    # Google / Nest
    "54:60:09": "Google",
    "f4:f5:d8": "Google",
    # Amazon
    "44:65:0d": "Amazon",
    "fc:65:de": "Amazon",
    "68:37:e9": "Amazon",
    # Samsung
    "5c:0a:5b": "Samsung",
    "8c:79:67": "Samsung",
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    # Sonos
    "5c:aa:fd": "Sonos",
    "00:0e:58": "Sonos",
    # Ubiquiti Networks
    "24:a4:3c": "Ubiquiti Networks",
    "fc:ec:da": "Ubiquiti Networks",
    # TP-Link
    "50:c7:bf": "TP-Link",
    "ec:08:6b": "TP-Link",
    # Netgear
    "a0:40:a0": "Netgear",
    "20:e5:2a": "Netgear",
    # Espressif (common IoT/ESP32/ESP8266 chipsets)
    "24:0a:c4": "Espressif (IoT device)",
    "30:ae:a4": "Espressif (IoT device)",
    # Philips (Hue)
    "00:17:88": "Philips Hue",
    # Roku
    "b0:a7:37": "Roku",
    "dc:3a:5e": "Roku",
    # Microsoft
    "00:15:5d": "Microsoft (virtual adapter)",
}


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    parts = mac.lower().split(":")
    if len(parts) < 3:
        return None
    prefix = ":".join(parts[:3])
    return _OUI_VENDORS.get(prefix)
