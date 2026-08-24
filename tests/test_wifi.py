"""
Tests for secure/wifi/* (Wi-Fi Security Monitor).

Sample networksetup/system_profiler/airport output text feeds straight
into the pure parsing functions, so these don't need a real Mac.
scan_wifi() itself is tested end-to-end with the shell calls mocked
out, same approach as test_arpwatch.py/test_listening.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.wifi._shell import ShellResult
from secure.wifi.interface import parse_wifi_interface
from secure.wifi.scanner import scan_wifi
from secure.wifi.security_level import classify_security
from secure.wifi.similarity import find_similar_known_ssids, levenshtein_distance
from secure.wifi.status import (
    get_wifi_status,
    parse_airport_info,
    parse_current_ssid,
    parse_ipconfig_summary,
    parse_signal_noise,
    parse_system_profiler_wifi,
)
from secure.storage.database import Database
from secure.storage.models import list_wifi_alerts, list_wifi_networks, set_wifi_network_known

# ---------- parse_wifi_interface ----------

_SAMPLE_HARDWAREPORTS_OUTPUT = """\
Hardware Port: Ethernet
Device: en1
Ethernet Address: aa:aa:aa:aa:aa:aa

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: bb:bb:bb:bb:bb:bb

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: N/A
"""


def test_parse_wifi_interface_finds_wifi_device():
    assert parse_wifi_interface(_SAMPLE_HARDWAREPORTS_OUTPUT) == "en0"


def test_parse_wifi_interface_missing_is_none():
    assert parse_wifi_interface("nothing useful here") is None


# ---------- parse_current_ssid ----------


def test_parse_current_ssid_extracts_name():
    assert parse_current_ssid("Current Wi-Fi Network: HomeNetwork") == "HomeNetwork"


def test_parse_current_ssid_not_associated_is_none():
    assert parse_current_ssid("You are not associated with an AirPort network.") is None


def test_parse_current_ssid_name_with_colon_is_preserved():
    assert parse_current_ssid("Current Wi-Fi Network: Office:5G") == "Office:5G"


# ---------- parse_system_profiler_wifi ----------

_SAMPLE_SYSTEM_PROFILER_OUTPUT = """\
Wi-Fi:

      Software Versions:
          CoreWLAN: 14.0 (1657)

      Interfaces:
          en0:
            Card Type: AirPort Extreme  (0x14E4, 0x4388)
            Firmware Version:
            MAC Address: aa:bb:cc:dd:ee:ff
            Locale: ETSI
            Country Code: US
            Supported PHY Modes: 802.11 a/b/g/n/ac/ax
            Status: Connected
            Current Network Information:
              HomeNetwork:
                PHY Mode: 802.11ax
                Channel: 44 (5GHz, 80MHz)
                Country Code: US
                Network Type: Infrastructure
                Security: WPA2 Personal
                Signal / Noise: -50 dBm / -92 dBm
            Preferred Networks:
              HomeNetwork
              CoffeeShop
"""


def test_parse_system_profiler_wifi_extracts_fields():
    result = parse_system_profiler_wifi(_SAMPLE_SYSTEM_PROFILER_OUTPUT)
    assert result["ssid"] == "HomeNetwork"
    assert result["phy_mode"] == "802.11ax"
    assert result["channel"] == "44 (5GHz, 80MHz)"
    assert result["security"] == "WPA2 Personal"
    assert result["signal_noise_raw"] == "-50 dBm / -92 dBm"


def test_parse_system_profiler_wifi_no_current_network_returns_empty():
    output = "Wi-Fi:\n\n      Interfaces:\n          en0:\n            Status: Off\n"
    assert parse_system_profiler_wifi(output) == {}


def test_parse_signal_noise():
    assert parse_signal_noise("-50 dBm / -92 dBm") == (-50, -92)


def test_parse_signal_noise_missing_is_none_none():
    assert parse_signal_noise("not present") == (None, None)


# ---------- parse_airport_info ----------

_SAMPLE_AIRPORT_OUTPUT = """\
     agrCtlRSSI: -55
     agrExtRSSI: 0
    agrCtlNoise: -92
    agrExtNoise: 0
          state: running
        op mode: station
     lastTxRate: 866
    lastAssocStatus: 0
    802.11 auth: open
      link auth: wpa2-psk
          BSSID: a1:b2:c3:d4:e5:f6
           SSID: HomeNetwork
        channel: 44,80
"""


def test_parse_airport_info_extracts_bssid_and_rssi():
    data = parse_airport_info(_SAMPLE_AIRPORT_OUTPUT)
    assert data["BSSID"] == "a1:b2:c3:d4:e5:f6"
    assert data["agrCtlRSSI"] == "-55"
    assert data["channel"] == "44,80"


# ---------- parse_ipconfig_summary ----------

_SAMPLE_IPCONFIG_SUMMARY = """\
en0 Interface Summary
	Type : Wi-Fi
	Bars : 3
	SSID : HomeNetwork
	BSSID : 0:0:0:0:0:0
	Security : WPA2 Personal
	PHY Mode : 11ax
	Channel : 48,80
	Signal / Noise : -50 / -90
IPv4 Summary
	Router : 192.168.1.1
LinkStatusActive : TRUE
"""


def test_parse_ipconfig_summary_extracts_ssid_and_fields():
    data = parse_ipconfig_summary(_SAMPLE_IPCONFIG_SUMMARY)
    assert data["ssid"] == "HomeNetwork"
    assert data["security"] == "WPA2 Personal"
    assert data["phy_mode"] == "11ax"
    assert data["channel"] == "48,80"
    assert data["signal_noise_raw"] == "-50 / -90"
    assert data["link_active"] == "TRUE"


def test_parse_ipconfig_summary_no_ssid_line_returns_no_ssid_key():
    data = parse_ipconfig_summary("en0 Interface Summary\n\tType : Wi-Fi\nLinkStatusActive : FALSE\n")
    assert "ssid" not in data
    assert data["link_active"] == "FALSE"


def test_parse_ipconfig_summary_empty_output_returns_empty_dict():
    assert parse_ipconfig_summary("") == {}


# ---------- get_wifi_status() tri-state connected/disconnected/unknown ----------
#
# These target get_wifi_status() directly (not scan_wifi()) for
# precision — this is the function that had the real bug: it used to
# treat "networksetup said no" and "system_profiler didn't answer in
# time" as proof of "not connected," which is wrong (see status.py's
# module docstring). Each scenario below is one of the cases explicitly
# called out when this was fixed.

_FAKE_IFCONFIG_SUMMARY_CONNECTED = "en0 Interface Summary\n\tSSID : HomeNetwork\n\tSecurity : WPA2 Personal\nLinkStatusActive : TRUE\n"
_FAKE_IFCONFIG_SUMMARY_DISCONNECTED = "en0 Interface Summary\n\tType : Wi-Fi\nLinkStatusActive : FALSE\n"
_FAKE_NETWORKSETUP_CONNECTED = "Current Wi-Fi Network: HomeNetwork"
_FAKE_NETWORKSETUP_NOT_ASSOCIATED = "You are not associated with an AirPort network."


def _make_fake_status_run(ipconfig_summary=None, ipconfig_getifaddr=None, networksetup=None, system_profiler=None):
    """Build a fake secure.wifi.status.run(). Any argument left None
    simulates that source failing or timing out (ShellResult ok=False)
    — indistinguishable at this layer, by design (see _shell.py).
    """

    def fake_run(args, timeout=5.0):
        if args[0] == "ipconfig" and args[1] == "getsummary":
            if ipconfig_summary is None:
                return ShellResult(ok=False, stdout="", stderr="command timed out", returncode=None)
            return ShellResult(ok=True, stdout=ipconfig_summary, stderr="", returncode=0)
        if args[0] == "ipconfig" and args[1] == "getifaddr":
            if ipconfig_getifaddr is None:
                return ShellResult(ok=False, stdout="", stderr="", returncode=1)
            return ShellResult(ok=True, stdout=ipconfig_getifaddr, stderr="", returncode=0)
        if args[0] == "networksetup":
            if networksetup is None:
                return ShellResult(ok=False, stdout="", stderr="command timed out", returncode=None)
            return ShellResult(ok=True, stdout=networksetup, stderr="", returncode=0)
        if args[0] == "system_profiler":
            if system_profiler is None:
                return ShellResult(ok=False, stdout="", stderr="command timed out", returncode=None)
            return ShellResult(ok=True, stdout=system_profiler, stderr="", returncode=0)
        return ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)

    return fake_run


def _patch_status_run(monkeypatch, fake_run):
    import secure.wifi.interface as interface_module
    import secure.wifi.status as status_module

    monkeypatch.setattr(
        interface_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_SAMPLE_HARDWAREPORTS_OUTPUT, stderr="", returncode=0),
    )
    monkeypatch.setattr(status_module, "run", fake_run)
    monkeypatch.setattr(status_module, "_AIRPORT_BINARY", Path("/nonexistent/airport-for-tests"))
    return status_module


# 1. connected Wi-Fi
def test_get_wifi_status_connected(monkeypatch):
    fake_run = _make_fake_status_run(
        ipconfig_summary=_FAKE_IFCONFIG_SUMMARY_CONNECTED,
        ipconfig_getifaddr="192.168.1.50\n",
        networksetup=_FAKE_NETWORKSETUP_CONNECTED,
        system_profiler=_SAMPLE_SYSTEM_PROFILER_OUTPUT,
    )
    _patch_status_run(monkeypatch, fake_run)

    status = get_wifi_status()

    assert status.connected is True
    assert status.status_unknown is False
    assert status.ssid == "HomeNetwork"
    assert status.security == "WPA2 Personal"


# 2. disconnected Wi-Fi
def test_get_wifi_status_disconnected(monkeypatch):
    fake_run = _make_fake_status_run(
        ipconfig_summary=_FAKE_IFCONFIG_SUMMARY_DISCONNECTED,
        ipconfig_getifaddr=None,
        networksetup=_FAKE_NETWORKSETUP_NOT_ASSOCIATED,
        system_profiler=None,
    )
    _patch_status_run(monkeypatch, fake_run)

    status = get_wifi_status()

    assert status.connected is False
    assert status.status_unknown is False  # a real, confirmed negative — not "couldn't tell"


# 3. command timeout (one source times out; scan doesn't crash and
#    still reaches a correct answer via another source)
def test_get_wifi_status_one_source_timeout_falls_back(monkeypatch):
    fake_run = _make_fake_status_run(
        ipconfig_summary=None,  # simulates a timeout
        networksetup=_FAKE_NETWORKSETUP_CONNECTED,
    )
    _patch_status_run(monkeypatch, fake_run)

    status = get_wifi_status()

    assert status.connected is True
    assert status.status_unknown is False
    assert status.ssid == "HomeNetwork"


# 4. permission-restricted BSSID
def test_get_wifi_status_bssid_permission_restricted(monkeypatch, tmp_path):
    fake_airport_path = tmp_path / "airport"
    fake_airport_path.write_text("#!/bin/sh\n")

    def fake_run(args, timeout=5.0):
        if args[0] == "ipconfig" and args[1] == "getsummary":
            return ShellResult(ok=True, stdout=_FAKE_IFCONFIG_SUMMARY_CONNECTED, stderr="", returncode=0)
        if args[0] == "ipconfig" and args[1] == "getifaddr":
            return ShellResult(ok=True, stdout="192.168.1.50\n", stderr="", returncode=0)
        if args[0] == "networksetup":
            return ShellResult(ok=True, stdout=_FAKE_NETWORKSETUP_CONNECTED, stderr="", returncode=0)
        if args[0] == "system_profiler":
            # Deliberately omit the Signal/Noise line here so this test
            # can prove airport's RSSI/noise enrichment still applies
            # even though its BSSID is permission-restricted.
            no_signal = _SAMPLE_SYSTEM_PROFILER_OUTPUT.replace("                Signal / Noise: -50 dBm / -92 dBm\n", "")
            return ShellResult(ok=True, stdout=no_signal, stderr="", returncode=0)
        if args[0] == str(fake_airport_path):
            return ShellResult(
                ok=True,
                stdout="agrCtlRSSI: -55\nagrCtlNoise: -92\nBSSID: 00:00:00:00:00:00\nchannel: 44,80\n",
                stderr="", returncode=0,
            )
        return ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)

    import secure.wifi.interface as interface_module
    import secure.wifi.status as status_module

    monkeypatch.setattr(
        interface_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_SAMPLE_HARDWAREPORTS_OUTPUT, stderr="", returncode=0),
    )
    monkeypatch.setattr(status_module, "run", fake_run)
    monkeypatch.setattr(status_module, "_AIRPORT_BINARY", fake_airport_path)

    status = get_wifi_status()

    assert status.connected is True
    assert status.bssid_available is False
    assert status.bssid_unavailable_reason == "permission"
    assert status.bssid is None
    # system_profiler didn't report signal/noise in this test (see the
    # fake system_profiler output above), so this RSSI came from
    # airport -- proving BSSID being permission-gated doesn't block
    # airport's OTHER fields (RSSI/noise/channel) from being used too.
    assert status.rssi == -55
    assert status.noise == -92


# 5. partial information available from one source
def test_get_wifi_status_partial_information(monkeypatch):
    # ipconfig getsummary gives only an SSID; everything else fails.
    fake_run = _make_fake_status_run(
        ipconfig_summary="en0 Interface Summary\n\tSSID : HomeNetwork\n",
    )
    _patch_status_run(monkeypatch, fake_run)

    status = get_wifi_status()

    assert status.connected is True
    assert status.ssid == "HomeNetwork"
    assert status.security is None
    assert status.channel is None
    assert status.rssi is None


# 6. fallback source succeeds (primary fails, secondary source alone determines status)
def test_get_wifi_status_fallback_source_succeeds(monkeypatch):
    fake_run = _make_fake_status_run(
        ipconfig_summary=None,  # primary source unavailable
        networksetup=_FAKE_NETWORKSETUP_CONNECTED,  # fallback succeeds
        system_profiler=_SAMPLE_SYSTEM_PROFILER_OUTPUT,
    )
    _patch_status_run(monkeypatch, fake_run)

    status = get_wifi_status()

    assert status.connected is True
    assert status.ssid == "HomeNetwork"
    assert status.channel == "44 (5GHz, 80MHz)"  # enrichment still worked


# 7. all sources unavailable
def test_get_wifi_status_all_sources_unavailable(monkeypatch):
    fake_run = _make_fake_status_run()  # every argument left None -> every source fails
    _patch_status_run(monkeypatch, fake_run)

    status = get_wifi_status()

    assert status.connected is False
    assert status.status_unknown is True  # NOT the same as "confirmed disconnected"


def test_get_wifi_status_no_wifi_interface_is_status_unknown(monkeypatch):
    import secure.wifi.interface as interface_module

    monkeypatch.setattr(
        interface_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout="Hardware Port: Ethernet\nDevice: en0\n", stderr="", returncode=0),
    )

    status = get_wifi_status()

    assert status.connected is False
    assert status.status_unknown is True


# ---------- classify_security ----------


def test_classify_security_wpa2_is_fine():
    severity, note = classify_security("WPA2 Personal")
    assert severity is None
    assert "WPA2" in note


def test_classify_security_wpa3_is_fine():
    severity, note = classify_security("WPA3 Personal")
    assert severity is None


def test_classify_security_open_is_high():
    severity, note = classify_security("None")
    assert severity == "high"


def test_classify_security_wep_is_high():
    severity, note = classify_security("WEP")
    assert severity == "high"


def test_classify_security_wpa1_is_medium():
    severity, note = classify_security("WPA Personal")
    assert severity == "medium"


def test_classify_security_missing_is_no_alert():
    severity, note = classify_security(None)
    assert severity is None


def test_classify_security_unrecognized_is_no_alert():
    severity, note = classify_security("Some Future Protocol")
    assert severity is None


# ---------- similarity ----------


def test_levenshtein_distance_identical_is_zero():
    assert levenshtein_distance("HomeNetwork", "HomeNetwork") == 0


def test_levenshtein_distance_one_char_off():
    assert levenshtein_distance("HomeNetwork", "HomeNetwerk") == 1


def test_find_similar_known_ssids_flags_close_match():
    similar = find_similar_known_ssids("HomeNetwokr", ["HomeNetwork", "OtherPlace"])
    assert similar == ["HomeNetwork"]


def test_find_similar_known_ssids_exact_match_not_flagged():
    similar = find_similar_known_ssids("HomeNetwork", ["HomeNetwork"])
    assert similar == []


def test_find_similar_known_ssids_skips_short_names():
    # Short SSIDs are skipped entirely — edit distance is nearly
    # meaningless on a 3-character name.
    similar = find_similar_known_ssids("Bob", ["Bab", "Bib"])
    assert similar == []


def test_find_similar_known_ssids_unrelated_names_not_flagged():
    similar = find_similar_known_ssids("HomeNetwork", ["CoffeeShopGuest"])
    assert similar == []


# ---------- scan_wifi (end-to-end, shell mocked) ----------

_FAKE_HARDWAREPORTS = _SAMPLE_HARDWAREPORTS_OUTPUT
_FAKE_GETAIRPORTNETWORK = "Current Wi-Fi Network: HomeNetwork"
_FAKE_SYSTEM_PROFILER = _SAMPLE_SYSTEM_PROFILER_OUTPUT


def _patch_shells(monkeypatch, ssid="HomeNetwork", security="WPA2 Personal"):
    import secure.wifi.interface as interface_module
    import secure.wifi.status as status_module

    sp_output = _FAKE_SYSTEM_PROFILER.replace("HomeNetwork", ssid).replace(
        "WPA2 Personal", security
    )
    ns_output = f"Current Wi-Fi Network: {ssid}"

    def fake_run(args, timeout=5.0):
        if args[0] == "networksetup":
            return ShellResult(ok=True, stdout=ns_output, stderr="", returncode=0)
        if args[0] == "system_profiler":
            return ShellResult(ok=True, stdout=sp_output, stderr="", returncode=0)
        # airport binary path — not present in the test environment
        return ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)

    monkeypatch.setattr(
        interface_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_HARDWAREPORTS, stderr="", returncode=0),
    )
    monkeypatch.setattr(status_module, "run", fake_run)
    # The airport binary almost certainly doesn't exist in the sandbox
    # anyway, but pin it explicitly so this test doesn't depend on
    # whatever machine it happens to run on.
    # Point the "airport" binary lookup at a path that's guaranteed not
    # to exist, rather than relying on it being absent from whatever
    # machine these tests happen to run on. (Path has no __dict__ for
    # arbitrary instance-attribute patching, so the module-level
    # constant itself is swapped out instead.)
    monkeypatch.setattr(status_module, "_AIRPORT_BINARY", Path("/nonexistent/airport-for-tests"))


def test_scan_wifi_first_scan_is_new_network(tmp_path: Path, monkeypatch):
    _patch_shells(monkeypatch)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_wifi(db.conn)
        networks = list_wifi_networks(db.conn)

    assert result.connected is True
    assert result.status.ssid == "HomeNetwork"
    assert result.status.bssid_available is False
    assert result.is_new_network is True
    assert result.security_severity is None  # WPA2 is fine
    assert len(networks) == 1
    assert networks[0].known is False


def test_scan_wifi_second_scan_same_network_not_new(tmp_path: Path, monkeypatch):
    _patch_shells(monkeypatch)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_wifi(db.conn)
        second = scan_wifi(db.conn)

    assert first.is_new_network is True
    assert second.is_new_network is False


def test_scan_wifi_flags_open_network(tmp_path: Path, monkeypatch):
    _patch_shells(monkeypatch, security="None")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_wifi(db.conn)

    assert result.security_severity == "high"


def test_scan_wifi_detects_lookalike_ssid(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        # Establish "HomeNetwork" as a trusted, known network first.
        _patch_shells(monkeypatch, ssid="HomeNetwork")
        first = scan_wifi(db.conn)
        set_wifi_network_known(db.conn, first.network_record.id, True)

        # Now "connect" to a suspiciously similar name.
        _patch_shells(monkeypatch, ssid="HomeNetwokr")
        second = scan_wifi(db.conn)
        alerts = list_wifi_alerts(db.conn)

    assert second.is_new_network is True
    assert len(second.alerts) == 1
    assert second.alerts[0].kind == "similar_ssid"
    assert second.alerts[0].id is not None
    assert len(alerts) == 1


def test_scan_wifi_not_connected(tmp_path: Path, monkeypatch):
    import secure.wifi.interface as interface_module
    import secure.wifi.status as status_module

    monkeypatch.setattr(
        interface_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_HARDWAREPORTS, stderr="", returncode=0),
    )

    def fake_run(args, timeout=5.0):
        if args[0] == "networksetup":
            return ShellResult(
                ok=True, stdout="You are not associated with an AirPort network.",
                stderr="", returncode=0,
            )
        return ShellResult(ok=True, stdout="Wi-Fi:\n\n      Interfaces:\n", stderr="", returncode=0)

    monkeypatch.setattr(status_module, "run", fake_run)
    # Point the "airport" binary lookup at a path that's guaranteed not
    # to exist, rather than relying on it being absent from whatever
    # machine these tests happen to run on. (Path has no __dict__ for
    # arbitrary instance-attribute patching, so the module-level
    # constant itself is swapped out instead.)
    monkeypatch.setattr(status_module, "_AIRPORT_BINARY", Path("/nonexistent/airport-for-tests"))

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_wifi(db.conn)
        networks = list_wifi_networks(db.conn)

    assert result.connected is False
    assert networks == []


def test_scan_wifi_no_wifi_interface(tmp_path: Path, monkeypatch):
    import secure.wifi.interface as interface_module

    monkeypatch.setattr(
        interface_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout="Hardware Port: Ethernet\nDevice: en0\n", stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_wifi(db.conn)

    assert result.connected is False
