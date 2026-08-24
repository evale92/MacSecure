"""
bluetooth/parser.py — pure parsing of `system_profiler
SPBluetoothDataType`'s plain-text output into a list of device dicts.
No subprocess calls, no database access — see scanner.py for that.

**Important scope note**, read this before relying on this feature for
more than it can actually do: `system_profiler SPBluetoothDataType` is
the only Bluetooth information macOS hands to an unprivileged,
no-sudo, no-extra-framework command-line process. It reports devices
macOS already has some relationship with — paired, configured, or
currently connected (the same list you'd see in System Settings ->
Bluetooth) — NOT a live radio scan of every nearby advertising BLE
device, including strangers' phones, fitness trackers, or trackers
like AirTags. A true live BLE "who's broadcasting near me right now"
scanner requires CoreBluetooth framework access from a signed app with
Bluetooth permission granted via TCC — well beyond what a script
invoking command-line tools can do, and beyond what this project's
"stdlib only, no extra dependencies" design allows. This module (and
the "Bluetooth/BLE Visibility" phase built around it) is honestly
scoped to "what's macOS already paired with / configured / connected"
visibility, not proximity radar. See PROJECT_NOTES.md for the full
explanation.

Two sections of system_profiler's output are read:

    "Devices (Paired, Configured, etc.):" — the main device list: name,
    address, whether it's paired, whether it's currently connected.

    "Connected:" — currently-active connections only, sometimes with
    RSSI (signal strength) that the "Devices" section doesn't include.
    Merged onto the matching device from the section above by address.

The exact output shape has not been verified against a real Mac in
this conversation (same caveat as every phase built this way) —
written from documented/typical structure, deliberately tolerant of
missing fields, and may need adjustment once confirmed for real.
"""

from __future__ import annotations

from typing import Dict, List, Optional


def _parse_sibling_blocks(lines: List[str], start_idx: int, header_indent: int):
    # Returns (blocks, next_idx) — a plain tuple, not annotated as one
    # so callers don't need `from typing import Tuple` just for this
    # private helper.
    """Parse a sequence of "Name:" blocks (each followed by more deeply
    indented "Key: Value" lines) that are all more indented than
    header_indent, stopping at the first line back down to
    header_indent or shallower. Returns a list of dicts, each with a
    "name" key plus whatever "Key: Value" pairs followed it.
    """
    blocks: List[Dict[str, str]] = []
    idx = start_idx
    n = len(lines)
    name_indent: Optional[int] = None
    current: Optional[Dict[str, str]] = None

    while idx < n:
        line = lines[idx]
        if not line.strip():
            idx += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= header_indent:
            break
        if name_indent is None:
            name_indent = indent

        stripped = line.strip()
        if indent == name_indent:
            if current is not None:
                blocks.append(current)
            current = {"name": stripped[:-1] if stripped.endswith(":") else stripped}
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            current[key.strip()] = value.strip()
        idx += 1

    if current is not None:
        blocks.append(current)
    return blocks, idx


def parse_system_profiler_bluetooth(output: str) -> List[Dict[str, object]]:
    """Parse `system_profiler SPBluetoothDataType` output into a list of
    dicts: {"name", "address", "paired", "connected", "rssi_raw"}.

    A device that appears in "Connected:" but wasn't also listed under
    "Devices (Paired, Configured, etc.):" (unusual, but not impossible)
    is still included. Never raises on unexpected formatting — missing
    sections just mean an empty result.
    """
    lines = output.splitlines()
    n = len(lines)

    paired_blocks: List[Dict[str, str]] = []
    connected_by_address: Dict[str, Dict[str, str]] = {}

    idx = 0
    while idx < n:
        stripped = lines[idx].strip()
        if stripped.startswith("Devices (Paired"):
            header_indent = len(lines[idx]) - len(lines[idx].lstrip(" "))
            paired_blocks, idx = _parse_sibling_blocks(lines, idx + 1, header_indent)
            continue
        if stripped == "Connected:":
            header_indent = len(lines[idx]) - len(lines[idx].lstrip(" "))
            connected_blocks, idx = _parse_sibling_blocks(lines, idx + 1, header_indent)
            for block in connected_blocks:
                address = block.get("Address")
                if address:
                    connected_by_address[address] = block
            continue
        idx += 1

    results: List[Dict[str, object]] = []
    seen_addresses = set()
    for block in paired_blocks:
        address = block.get("Address")
        seen_addresses.add(address)
        connected_extra = connected_by_address.get(address, {}) if address else {}
        results.append(
            {
                "name": block.get("name") or None,
                "address": address,
                "paired": block.get("Paired", "").strip().lower() == "yes",
                "connected": block.get("Connected", "").strip().lower() == "yes"
                or bool(connected_extra),
                "rssi_raw": connected_extra.get("RSSI") or block.get("RSSI"),
            }
        )

    for address, block in connected_by_address.items():
        if address in seen_addresses:
            continue
        results.append(
            {
                "name": block.get("name") or None,
                "address": address,
                "paired": block.get("Paired", "").strip().lower() == "yes",
                "connected": True,
                "rssi_raw": block.get("RSSI"),
            }
        )

    return results


def normalize_bluetooth_address(address: Optional[str]) -> Optional[str]:
    """"AA-BB-CC-DD-EE-FF" -> "aa:bb:cc:dd:ee:ff" — same lowercase,
    colon-separated convention this app already uses for network MAC
    addresses (see secure/inventory/arp_table.py's normalize_mac), kept
    as an independent one-liner rather than imported — logic this small
    doesn't carry meaningful duplication risk, same reasoning
    secure/arpwatch/gateway.py used for its own small gateway parser.
    """
    if not address:
        return None
    return address.strip().lower().replace("-", ":")


def parse_rssi(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None
