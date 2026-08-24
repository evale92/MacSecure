"""
wifi/status.py — reads this Mac's current Wi-Fi connection using
Apple-supported, read-only, no-sudo tools.

Revision history matters here, because the first version of this
module had a real bug, found from actual diagnostic output pasted
during development: `networksetup -getairportnetwork` can say "You
are not associated with an AirPort network" while this Mac is, in
fact, connected (a known inconsistency on modern macOS — likely a
CoreWLAN daemon quirk, not something this app can fix), and
`system_profiler SPAirPortDataType` can legitimately take well over 10
seconds to return, because populating its "Other Local Wi-Fi Networks"
section requires an actual live radio scan of everything nearby, not
just a read of the current connection. The original code treated
"networksetup said no" and "system_profiler didn't answer in time" as
proof of "not connected," which was simply wrong — a slow/failed
command is not the same as a confirmed negative answer.

The fix: determine connected/disconnected and the SSID from FAST
sources first, and use system_profiler purely as slower best-effort
*enrichment* (channel, PHY mode, security, signal/noise) whose failure
can never flip "connected" back to False:

    `ipconfig getsummary <interface>` — fast (well under a second in
    practice), and includes the current SSID and link-status
    (LinkStatusActive) without going through the same CoreWLAN path
    `networksetup -getairportnetwork` uses — the standard workaround
    for that command's unreliability. Primary source for "connected?"
    and "what's the SSID?".

    `ipconfig getifaddr <interface>` — near-instant; returns this
    Mac's IP address on that interface if it has one. Secondary
    corroborating signal for "connected" when the SSID itself couldn't
    be read from anywhere (rare, but keeps this from wrongly reporting
    "not connected" when the interface is plainly up).

    `networksetup -getairportnetwork <interface>` — kept as a second,
    independent, still-fast opinion on the SSID. A *positive* answer
    from it is treated as good evidence; a *negative* one ("not
    associated") is deliberately NOT trusted on its own to declare
    "disconnected," given the false-negative seen above — it only
    counts once no other source found evidence of a connection either.

    `system_profiler SPAirPortDataType` — channel, PHY mode, security
    type, and signal/noise, read from whichever interface block is
    "Status: Connected". Given a generous timeout (this command can
    legitimately be slow — see above) since it's enrichment-only and
    its failure doesn't affect the connected/disconnected verdict.

    `airport -I` (the deprecated CoreWLAN command-line helper at
    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/
    Current/Resources/airport) — BSSID and RSSI, but only when the
    binary still exists on this machine AND the calling process has
    been granted Location Services access for Wi-Fi info. Apple treats
    BSSID as privacy-sensitive: on modern macOS, a process without that
    permission gets back "00:00:00:00:00:00" instead of the real
    address. This module treats that placeholder as "not available,"
    never as a real BSSID — see bssid_available/bssid_unavailable_reason
    on WifiStatus, and "respect macOS privacy restrictions" in the
    Claude prompt this phase was built from.

If every source above fails or times out, WifiStatus.status_unknown is
set instead of guessing "disconnected" — see get_wifi_status()'s
docstring. This is the "distinguish 'Wi-Fi disconnected' from
'Secure could not determine Wi-Fi status'" fix.

Never joins, disconnects from, or otherwise changes any Wi-Fi
connection — read-only status only.

`ipconfig getsummary`'s exact output format was written from
documented/typical shape, same as the rest of this module, and has
NOT yet been confirmed against real output from this Mac (unlike
`networksetup`/`system_profiler`, whose real output shapes were
already pasted and matched during earlier development) — parsing is
deliberately tolerant of missing/differently-worded fields, but may
need adjustment once confirmed for real. The connected/disconnected
*logic* fix, however, does not depend on getting every field of
`ipconfig getsummary` right — even if only its SSID line parses,
that's already enough to fix the reported bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from secure.wifi._shell import run
from secure.wifi.interface import find_wifi_interface

_AIRPORT_BINARY = Path(
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
)
_NULL_BSSID = "00:00:00:00:00:00"
_SIGNAL_NOISE_RE = re.compile(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm")


@dataclass
class WifiStatus:
    connected: bool
    # True only when NO source could determine connected vs.
    # disconnected at all (every fast source failed or timed out).
    # This is deliberately a separate flag from `connected` rather
    # than folded into it, so callers can tell "confirmed not
    # connected" apart from "couldn't tell" instead of both looking
    # like connected=False. See get_wifi_status()'s docstring.
    status_unknown: bool = False
    interface: Optional[str] = None
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    bssid_available: bool = False
    # "permission" when macOS withheld the BSSID specifically because
    # this process lacks Location Services access (the null-BSSID
    # placeholder was seen) — None otherwise (including when the
    # `airport` binary simply isn't present, which isn't a permission
    # issue). Lets the CLI print "Unavailable — permission required"
    # only when that's actually why the field is missing.
    bssid_unavailable_reason: Optional[str] = None
    channel: Optional[str] = None
    phy_mode: Optional[str] = None
    security: Optional[str] = None
    rssi: Optional[int] = None
    noise: Optional[int] = None


def parse_current_ssid(getairportnetwork_output: str) -> Optional[str]:
    """"Current Wi-Fi Network: MySSID" -> "MySSID"; not associated -> None."""
    line = getairportnetwork_output.strip()
    if line.lower().startswith("you are not associated"):
        return None
    if ":" in line:
        return line.split(":", 1)[1].strip() or None
    return None


def parse_system_profiler_wifi(output: str) -> Dict[str, str]:
    """Pull ssid/channel/phy_mode/security/signal_noise_raw out of
    `system_profiler SPAirPortDataType`'s plain-text output, from
    whichever interface's "Current Network Information:" block is
    present. Returns a plain dict with whatever keys it found — never
    raises on unexpected formatting, just returns less.
    """
    result: Dict[str, str] = {}
    lines = output.splitlines()
    idx = 0
    n = len(lines)
    while idx < n:
        raw = lines[idx]
        if raw.strip() == "Current Network Information:":
            base_indent = len(raw) - len(raw.lstrip(" "))
            idx += 1
            while idx < n and not lines[idx].strip():
                idx += 1
            if idx >= n:
                break
            ssid_line = lines[idx]
            ssid_text = ssid_line.strip()
            if ssid_text.endswith(":"):
                result["ssid"] = ssid_text[:-1]
            idx += 1
            while idx < n:
                line = lines[idx]
                if not line.strip():
                    idx += 1
                    continue
                line_indent = len(line) - len(line.lstrip(" "))
                if line_indent <= base_indent:
                    break
                if ":" in line:
                    key, _, value = line.strip().partition(":")
                    key, value = key.strip(), value.strip()
                    if key == "PHY Mode":
                        result["phy_mode"] = value
                    elif key == "Channel":
                        result["channel"] = value
                    elif key == "Security":
                        result["security"] = value
                    elif key == "Signal / Noise":
                        result["signal_noise_raw"] = value
                idx += 1
            break
        idx += 1
    return result


def parse_signal_noise(raw: str) -> Tuple[Optional[int], Optional[int]]:
    match = _SIGNAL_NOISE_RE.search(raw)
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2))


def parse_airport_info(airport_output: str) -> Dict[str, str]:
    """`airport -I` prints simple "key: value" lines (keys may contain
    spaces, e.g. "agrCtlRSSI", "link auth", "BSSID")."""
    result: Dict[str, str] = {}
    for line in airport_output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        result[key.strip()] = value.strip()
    return result


def parse_ipconfig_summary(output: str) -> Dict[str, str]:
    """Pull ssid/security/phy_mode/channel/signal_noise_raw/link_active
    out of `ipconfig getsummary <interface>`'s "Key : Value" lines.
    Deliberately tolerant, same spirit as the other parsers here — an
    unrecognized or missing line just means less gets returned, never
    an exception.
    """
    result: Dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "SSID":
            result["ssid"] = value
        elif key == "Security":
            result["security"] = value
        elif key == "PHY Mode":
            result["phy_mode"] = value
        elif key == "Channel":
            result["channel"] = value
        elif key == "Signal / Noise":
            result["signal_noise_raw"] = value
        elif key == "LinkStatusActive":
            result["link_active"] = value.upper()
    return result


def get_wifi_status() -> WifiStatus:
    """Best-effort read of this Mac's current Wi-Fi connection.

    Three possible outcomes, deliberately kept distinct (see the
    module docstring for why the original version of this function got
    this wrong):

        1. connected=True, status_unknown=False — a fast source found
           positive evidence of a connection (an SSID, or at least an
           active IP on the Wi-Fi interface).
        2. connected=False, status_unknown=False — a fast source ran
           successfully and found no evidence of a connection. A real,
           confirmed "not connected" answer.
        3. connected=False, status_unknown=True — every source failed
           or timed out. We genuinely don't know either way; callers
           must not report this as "not connected."

    Enrichment fields (channel/phy_mode/security/rssi/noise/bssid) are
    filled in on a best-effort basis on top of whichever outcome above
    applies, and their absence never changes the outcome itself.
    """
    interface = find_wifi_interface()
    if interface is None:
        # find_wifi_interface() doesn't distinguish "this Mac has no
        # Wi-Fi hardware" (a real answer) from "networksetup itself
        # didn't run" (genuinely unknown) — err toward "unknown" rather
        # than risk a confidently wrong "disconnected".
        return WifiStatus(connected=False, status_unknown=True)

    summary_result = run(["ipconfig", "getsummary", interface], timeout=5.0)
    summary_data = parse_ipconfig_summary(summary_result.stdout) if summary_result.ok else {}

    ns_result = run(["networksetup", "-getairportnetwork", interface], timeout=5.0)
    ns_ssid = parse_current_ssid(ns_result.stdout) if ns_result.ok else None

    ifaddr_result = run(["ipconfig", "getifaddr", interface], timeout=3.0)
    has_ip = ifaddr_result.ok and bool(ifaddr_result.stdout.strip())

    ssid = summary_data.get("ssid") or ns_ssid

    if ssid or has_ip:
        connected = True
        status_unknown = False
    elif summary_result.ok or ns_result.ok:
        # At least one fast source ran to completion and found no
        # connection — a real negative answer, not a failure.
        connected = False
        status_unknown = False
    else:
        # Every fast source failed or timed out.
        connected = False
        status_unknown = True

    if not connected:
        return WifiStatus(connected=False, status_unknown=status_unknown, interface=interface)

    # system_profiler is enrichment-only from here down — a generous
    # timeout since it can legitimately be slow (see module docstring),
    # but its failure can no longer flip `connected` back to False.
    sp_result = run(["system_profiler", "SPAirPortDataType"], timeout=15.0)
    sp_data = parse_system_profiler_wifi(sp_result.stdout) if sp_result.ok else {}

    if not ssid:
        ssid = sp_data.get("ssid")

    # Source precedence for the fields both system_profiler and
    # ipconfig getsummary can report (channel/phy_mode/security/
    # signal-noise): system_profiler wins whenever it succeeded.
    # It's the actively-maintained Apple tool for this data (`ipconfig
    # getsummary` is a diagnostic side-effect of the DHCP client, not
    # built for this); `summary_data` only fills a field in when
    # system_profiler didn't report it at all (missing key, not merely
    # a falsy value) — a deliberate choice, not an accident of
    # `or`-chaining, so a later change to either parser can't silently
    # flip which source wins.
    channel = sp_data["channel"] if "channel" in sp_data else summary_data.get("channel")
    phy_mode = sp_data["phy_mode"] if "phy_mode" in sp_data else summary_data.get("phy_mode")
    security = sp_data["security"] if "security" in sp_data else summary_data.get("security")
    rssi: Optional[int] = None
    noise: Optional[int] = None
    if "signal_noise_raw" in sp_data:
        rssi, noise = parse_signal_noise(sp_data["signal_noise_raw"])
    elif "signal_noise_raw" in summary_data:
        rssi, noise = parse_signal_noise(summary_data["signal_noise_raw"])

    # airport (deprecated) is last in line, strictly a gap-filler: it
    # only supplies a field (rssi/noise/channel) when NEITHER of the
    # two sources above reported it, and it is the ONLY source used
    # for BSSID (system_profiler and ipconfig getsummary don't expose
    # it at all, so there's no precedence question there). A field
    # system_profiler already set is never overwritten by airport.
    bssid: Optional[str] = None
    bssid_available = False
    bssid_unavailable_reason: Optional[str] = None
    if _AIRPORT_BINARY.exists():
        airport_result = run([str(_AIRPORT_BINARY), "-I"], timeout=5.0)
        if airport_result.ok:
            airport_data = parse_airport_info(airport_result.stdout)
            raw_bssid = airport_data.get("BSSID")
            if raw_bssid and raw_bssid.lower() != _NULL_BSSID:
                bssid = raw_bssid.lower()
                bssid_available = True
            elif raw_bssid and raw_bssid.lower() == _NULL_BSSID:
                bssid_unavailable_reason = "permission"
            if rssi is None and "agrCtlRSSI" in airport_data:
                try:
                    rssi = int(airport_data["agrCtlRSSI"])
                except ValueError:
                    pass
            if noise is None and "agrCtlNoise" in airport_data:
                try:
                    noise = int(airport_data["agrCtlNoise"])
                except ValueError:
                    pass
            if channel is None and "channel" in airport_data:
                channel = airport_data["channel"]

    return WifiStatus(
        connected=True,
        status_unknown=False,
        interface=interface,
        ssid=ssid,
        bssid=bssid,
        bssid_available=bssid_available,
        bssid_unavailable_reason=bssid_unavailable_reason,
        channel=channel,
        phy_mode=phy_mode,
        security=security,
        rssi=rssi,
        noise=noise,
    )
