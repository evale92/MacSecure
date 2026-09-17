"""
Tests for secure/persistence/* (Phase 10: Process and Persistence
Monitor).

Pure parsing/classification functions are tested directly with sample
data, no Mac needed. launch_items.py is tested against real temp
plist files (plistlib itself does the parsing, so this exercises the
real code path, not a mock of it). login_items.py/processes.py/
codesign.py each have their subprocess call mocked via the same
"patch the wrapper" pattern every other package in this app uses.
scan_persistence() is tested end-to-end with every I/O source
(list_processes, get_login_items, check_code_signing) patched on
secure.persistence.scanner directly, since that's the module that
imported those names into its own namespace.

Run with:  pytest
"""

from __future__ import annotations

import plistlib
from pathlib import Path

from secure.persistence._shell import ShellResult
from secure.persistence.analysis import (
    is_signing_downgrade,
    is_unusual_location,
    persistence_entry_alert_severity,
    process_alert_severity,
)
from secure.persistence.codesign import (
    SIGNED_ADHOC,
    SIGNED_APPLE,
    SIGNED_DEVELOPER,
    UNKNOWN,
    UNSIGNED,
    classify_signing,
)
from secure.persistence.launch_items import (
    list_launch_item_paths,
    parse_launch_item_plist,
    scan_launch_items,
)
from secure.persistence.login_items import _parse_applescript_list, get_login_items
from secure.persistence.processes import is_resolvable_path, parse_ps_output
from secure.storage.database import Database
from secure.storage.models import (
    list_evidence_links_for,
    list_persistence_alerts,
    list_persistence_entries,
    list_process_entries,
)
from secure.evidence.model import RELATIONSHIP_SAME_EVENT_CONFIRMATION

# ---------- processes.py ----------


def test_parse_ps_output_basic():
    sample = "    1     0 root /sbin/launchd\n  100     1 erick /usr/bin/true\n"
    rows = parse_ps_output(sample)
    assert rows == [
        {"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/sbin/launchd"},
        {"pid": "100", "ppid": "1", "user": "erick", "path_or_name": "/usr/bin/true"},
    ]


def test_parse_ps_output_path_with_spaces_preserved():
    sample = "  200     1 erick /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"
    rows = parse_ps_output(sample)
    assert rows[0]["path_or_name"] == "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def test_parse_ps_output_bare_name_no_path():
    sample = "  300     1 root kernel_task\n"
    rows = parse_ps_output(sample)
    assert rows[0]["path_or_name"] == "kernel_task"


def test_parse_ps_output_skips_blank_and_malformed_lines():
    sample = "\n   \n1 0 root /sbin/launchd\nnotenoughfields\n"
    rows = parse_ps_output(sample)
    assert len(rows) == 1
    assert rows[0]["path_or_name"] == "/sbin/launchd"


def test_is_resolvable_path():
    assert is_resolvable_path("/usr/bin/true") is True
    assert is_resolvable_path("kernel_task") is False
    assert is_resolvable_path(None) is False
    assert is_resolvable_path("") is False


# ---------- codesign.py ----------


def test_classify_signing_apple():
    out = "Executable=/usr/sbin/cfprefsd\nAuthority=Software Signing\nAuthority=Apple Root CA\n"
    assert classify_signing("", out, 0) == SIGNED_APPLE


def test_classify_signing_developer():
    out = "Authority=Developer ID Application: Some Co (TEAMID)\nAuthority=Apple Root CA\n"
    assert classify_signing("", out, 0) == SIGNED_DEVELOPER


def test_classify_signing_unknown_authority_chain_treated_as_developer():
    out = "Authority=Some Internal Enterprise CA\n"
    assert classify_signing("", out, 0) == SIGNED_DEVELOPER


def test_classify_signing_adhoc():
    assert classify_signing("", "Signature=adhoc\n", 0) == SIGNED_ADHOC


def test_classify_signing_unsigned():
    assert classify_signing("", "/tmp/x: code object is not signed at all\n", 1) == UNSIGNED


def test_classify_signing_unknown_when_command_never_ran():
    # returncode is None -- this app's ShellResult convention for
    # "genuinely didn't run" (not found / timed out) -- must never be
    # conflated with a confirmed "unsigned" answer.
    assert classify_signing("", "", None) == UNKNOWN


def test_classify_signing_no_recognizable_output_is_unknown():
    assert classify_signing("", "some unrelated garbage", 0) == UNKNOWN


def test_check_code_signing_uses_shell_seam(monkeypatch):
    import secure.persistence.codesign as codesign_module

    monkeypatch.setattr(
        codesign_module,
        "run",
        lambda *a, **k: ShellResult(ok=False, stdout="", stderr="Signature=adhoc\n", returncode=1),
    )
    assert codesign_module.check_code_signing("/tmp/tool") == SIGNED_ADHOC


# ---------- analysis.py ----------


def test_is_unusual_location_tmp():
    assert is_unusual_location("/tmp/evil/tool") is True
    assert is_unusual_location("/private/tmp/tool") is True


def test_is_unusual_location_hidden_directory():
    assert is_unusual_location("/Users/erick/.cache/tool") is True


def test_is_unusual_location_downloads_and_trash():
    assert is_unusual_location("/Users/erick/Downloads/tool") is True
    assert is_unusual_location("/Users/erick/.Trash/tool") is True


def test_is_unusual_location_normal_path_false():
    assert is_unusual_location("/usr/local/bin/tool") is False
    assert is_unusual_location("/Applications/Foo.app/Contents/MacOS/Foo") is False


def test_is_unusual_location_none_is_false():
    assert is_unusual_location(None) is False


def test_process_alert_severity_unsigned_and_unusual_is_high():
    assert process_alert_severity(UNSIGNED, "/tmp/evil/tool") == "high"


def test_process_alert_severity_unsigned_only_is_medium():
    assert process_alert_severity(UNSIGNED, "/usr/local/bin/tool") == "medium"


def test_process_alert_severity_signed_but_unusual_is_low():
    assert process_alert_severity(SIGNED_APPLE, "/tmp/weird") == "low"


def test_process_alert_severity_signed_and_normal_is_none():
    assert process_alert_severity(SIGNED_APPLE, "/usr/sbin/cfprefsd") is None


def test_process_alert_severity_unknown_signing_alone_is_none():
    # codesign being unavailable is not evidence of anything.
    assert process_alert_severity(UNKNOWN, "/usr/local/bin/tool") is None


def test_persistence_entry_alert_severity_signed_is_medium():
    assert persistence_entry_alert_severity(SIGNED_DEVELOPER, "/Applications/Foo.app/foo") == "medium"


def test_persistence_entry_alert_severity_unsigned_is_high():
    assert persistence_entry_alert_severity(UNSIGNED, "/tmp/foo") == "high"


def test_persistence_entry_alert_severity_missing_program_is_high():
    assert persistence_entry_alert_severity(None, None) == "high"


def test_is_signing_downgrade_true_case():
    assert is_signing_downgrade(SIGNED_APPLE, UNSIGNED) is True
    assert is_signing_downgrade(SIGNED_DEVELOPER, SIGNED_ADHOC) is True


def test_is_signing_downgrade_false_from_unknown():
    assert is_signing_downgrade(UNKNOWN, UNSIGNED) is False


def test_is_signing_downgrade_false_between_two_signed_statuses():
    assert is_signing_downgrade(SIGNED_APPLE, SIGNED_DEVELOPER) is False


def test_is_signing_downgrade_false_when_nothing_changed():
    assert is_signing_downgrade(UNSIGNED, UNSIGNED) is False


# ---------- launch_items.py ----------


def test_parse_launch_item_plist_program_key(tmp_path: Path):
    path = tmp_path / "com.example.agent.plist"
    with path.open("wb") as f:
        plistlib.dump({"Label": "com.example.agent", "Program": "/usr/local/bin/agent"}, f)
    parsed = parse_launch_item_plist(path)
    assert parsed["label"] == "com.example.agent"
    assert parsed["program_path"] == "/usr/local/bin/agent"
    assert parsed["parse_error"] is None


def test_parse_launch_item_plist_program_arguments_fallback(tmp_path: Path):
    path = tmp_path / "com.example.agent2.plist"
    with path.open("wb") as f:
        plistlib.dump({"Label": "x", "ProgramArguments": ["/usr/local/bin/agent2", "--flag"]}, f)
    parsed = parse_launch_item_plist(path)
    assert parsed["program_path"] == "/usr/local/bin/agent2"


def test_parse_launch_item_plist_missing_program_is_none(tmp_path: Path):
    path = tmp_path / "broken.plist"
    with path.open("wb") as f:
        plistlib.dump({"Label": "broken"}, f)
    parsed = parse_launch_item_plist(path)
    assert parsed["program_path"] is None
    assert parsed["parse_error"] is None  # a valid plist, just missing a program


def test_parse_launch_item_plist_run_at_load_and_keep_alive_bool(tmp_path: Path):
    path = tmp_path / "x.plist"
    with path.open("wb") as f:
        plistlib.dump({"Label": "x", "Program": "/bin/x", "RunAtLoad": True, "KeepAlive": False}, f)
    parsed = parse_launch_item_plist(path)
    assert parsed["run_at_load"] is True
    assert parsed["keep_alive"] is False


def test_parse_launch_item_plist_keep_alive_dict_form(tmp_path: Path):
    path = tmp_path / "x.plist"
    with path.open("wb") as f:
        plistlib.dump({"Label": "x", "Program": "/bin/x", "KeepAlive": {"SuccessfulExit": False}}, f)
    parsed = parse_launch_item_plist(path)
    assert parsed["keep_alive"] is True  # some KeepAlive config exists


def test_parse_launch_item_plist_malformed_file_does_not_raise(tmp_path: Path):
    path = tmp_path / "corrupt.plist"
    path.write_bytes(b"this is not a plist")
    parsed = parse_launch_item_plist(path)
    assert parsed["parse_error"] is not None
    assert parsed["label"] is None
    assert parsed["program_path"] is None


def _patch_launch_dirs(monkeypatch, tmp_path: Path, **overrides):
    """Replace launch_items._LAUNCH_ITEM_DIRECTORIES wholesale with an
    isolated, test-only mapping — every kind not explicitly overridden
    points at a directory that doesn't exist, so tests never
    accidentally read this sandbox/machine's real LaunchAgents/
    LaunchDaemons. The harness's monkeypatch only supports setattr, not
    setitem, so this replaces the whole module-level dict rather than
    mutating one key of the original.
    """
    import secure.persistence.launch_items as launch_items_module

    fresh = {kind: [tmp_path / f"_unused_{kind}"] for kind in launch_items_module._LAUNCH_ITEM_DIRECTORIES}
    fresh.update(overrides)
    monkeypatch.setattr(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh)
    import secure.persistence.extra_locations as extra_locations_module
    monkeypatch.setattr(extra_locations_module, "_EXTRA_LOCATIONS", {})


def test_list_launch_item_paths_missing_directory_is_empty(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path, launch_daemon=[tmp_path / "does_not_exist"])
    assert list_launch_item_paths("launch_daemon") == []


def test_scan_launch_items_end_to_end(tmp_path: Path, monkeypatch):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    with (agents_dir / "com.example.agent.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.agent", "Program": "/usr/local/bin/agent"}, f)

    _patch_launch_dirs(monkeypatch, tmp_path, launch_agent_user=[agents_dir])

    items = scan_launch_items("launch_agent_user")
    assert len(items) == 1
    assert items[0]["label"] == "com.example.agent"
    assert items[0]["path"] == str(agents_dir / "com.example.agent.plist")


# ---------- login_items.py ----------


def test_parse_applescript_list_multiple():
    assert _parse_applescript_list("Dropbox, iTunesHelper") == ["Dropbox", "iTunesHelper"]


def test_parse_applescript_list_single():
    assert _parse_applescript_list("Dropbox") == ["Dropbox"]


def test_parse_applescript_list_empty():
    assert _parse_applescript_list("") == []
    assert _parse_applescript_list("   ") == []


def _patch_login_items_shell(monkeypatch, names_stdout, paths_stdout, names_ok=True, paths_ok=True):
    import secure.persistence.login_items as login_items_module

    def fake_run(args, timeout=8.0):
        if "name of every login item" in args[-1]:
            return ShellResult(ok=names_ok, stdout=names_stdout, stderr="", returncode=0 if names_ok else 1)
        return ShellResult(ok=paths_ok, stdout=paths_stdout, stderr="", returncode=0 if paths_ok else 1)

    monkeypatch.setattr(login_items_module, "run", fake_run)


def test_get_login_items_pairs_names_and_paths(monkeypatch):
    _patch_login_items_shell(monkeypatch, "Dropbox, iTunesHelper", "/Applications/Dropbox.app, /Applications/iTunesHelper.app")
    ok, items = get_login_items()
    assert ok is True
    assert items == [
        {"name": "Dropbox", "path": "/Applications/Dropbox.app"},
        {"name": "iTunesHelper", "path": "/Applications/iTunesHelper.app"},
    ]


def test_get_login_items_empty_list(monkeypatch):
    _patch_login_items_shell(monkeypatch, "", "")
    ok, items = get_login_items()
    assert ok is True
    assert items == []


def test_get_login_items_missing_value_path_becomes_none(monkeypatch):
    _patch_login_items_shell(monkeypatch, "SomeItem", "missing value")
    ok, items = get_login_items()
    assert items == [{"name": "SomeItem", "path": None}]


def test_get_login_items_names_command_fails(monkeypatch):
    _patch_login_items_shell(monkeypatch, "", "", names_ok=False)
    ok, items = get_login_items()
    assert ok is False
    assert items == []


def test_get_login_items_paths_command_fails_names_still_used(monkeypatch):
    _patch_login_items_shell(monkeypatch, "Dropbox", "", paths_ok=False)
    ok, items = get_login_items()
    assert ok is True
    assert items == [{"name": "Dropbox", "path": None}]


# ---------- scanner.py (end-to-end, all I/O mocked) ----------


def _patch_scanner(monkeypatch, ps_result=None, login_items_result=None, signing_map=None):
    import secure.persistence.scanner as scanner_module

    if ps_result is not None:
        monkeypatch.setattr(scanner_module, "list_processes", lambda: ps_result)
    if login_items_result is not None:
        monkeypatch.setattr(scanner_module, "get_login_items", lambda: login_items_result)
    if signing_map is not None:
        monkeypatch.setattr(
            scanner_module, "check_code_signing", lambda path: signing_map.get(path, UNKNOWN)
        )
    return scanner_module


def test_scan_persistence_processes_unavailable(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)  # isolate from this machine's real LaunchAgents/Daemons
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=(False, []), login_items_result=(True, []), signing_map={}
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
    assert result.processes_available is False
    assert result.process_count == 0
    assert result.new_processes == []


def test_scan_persistence_dedups_repeated_executable_path(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)
    ps = (True, [
        {"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/usr/bin/true"},
        {"pid": "2", "ppid": "0", "user": "root", "path_or_name": "/usr/bin/true"},
    ])
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/usr/bin/true": SIGNED_APPLE},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
        procs = list_process_entries(db.conn)
    assert result.process_count == 1
    assert len(procs) == 1


def test_scan_persistence_flags_unsigned_process_in_unusual_location(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)
    ps = (True, [{"pid": "1", "ppid": "0", "user": "erick", "path_or_name": "/tmp/sketchy/tool"}])
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/tmp/sketchy/tool": UNSIGNED},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
    assert len(result.new_processes) == 1
    assert len(result.alerts) == 1
    assert result.alerts[0].kind == "unusual_unsigned_process"
    assert result.alerts[0].severity == "high"


def test_scan_persistence_signed_normal_process_no_alert(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)
    ps = (True, [{"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/usr/sbin/cfprefsd"}])
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/usr/sbin/cfprefsd": SIGNED_APPLE},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
    assert len(result.new_processes) == 1
    assert result.alerts == []


def test_scan_persistence_known_process_not_rechecked_second_scan(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)
    ps = (True, [{"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/usr/bin/true"}])
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/usr/bin/true": SIGNED_APPLE},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scanner_module.scan_persistence(db.conn)
        second = scanner_module.scan_persistence(db.conn)
    assert len(first.new_processes) == 1
    assert second.new_processes == []
    assert second.alerts == []


def test_scan_persistence_new_launch_daemon_alert(tmp_path: Path, monkeypatch):
    daemons_dir = tmp_path / "LaunchDaemons"
    daemons_dir.mkdir()
    with (daemons_dir / "com.example.daemon.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.daemon", "Program": "/tmp/payload"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_daemon=[daemons_dir])

    scanner_module = _patch_scanner(
        monkeypatch, ps_result=(True, []), login_items_result=(True, []),
        signing_map={"/tmp/payload": UNSIGNED},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
        entries = list_persistence_entries(db.conn)

    assert len(result.new_persistence_entries) == 1
    assert entries[0].kind == "launch_daemon"
    assert entries[0].signing_status == UNSIGNED
    new_alert = [a for a in result.alerts if a.kind == "new_persistence_entry"][0]
    assert new_alert.severity == "high"  # unsigned program


def test_scan_persistence_links_matching_process_evidence(tmp_path: Path, monkeypatch):
    """Phase 22 Stage 1 (additive): a persistence entry whose program_path
    matches a KNOWN process_entries row (here, from THIS SAME scan's own
    process inventory, which runs first) now gets a formal
    same_event_confirmation evidence_links row — previously there was no
    persisted trace of this relationship at all.
    """
    daemons_dir = tmp_path / "LaunchDaemons"
    daemons_dir.mkdir()
    with (daemons_dir / "com.example.daemon.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.daemon", "Program": "/usr/local/bin/agent"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_daemon=[daemons_dir])

    ps = (True, [{"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/usr/local/bin/agent"}])
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/usr/local/bin/agent": SIGNED_APPLE},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
        entries = list_persistence_entries(db.conn)
        procs = list_process_entries(db.conn)

        assert result.evidence_links_recorded == 1
        persistence_entry = entries[0]
        process_entry = procs[0]
        links = list_evidence_links_for(db.conn, "process_entries", process_entry.id)
        assert len(links) == 1
        assert links[0].relationship == RELATIONSHIP_SAME_EVENT_CONFIRMATION
        assert links[0].created_by == "persistence_process_match"
        assert links[0].from_source_table == "persistence_entries"
        assert links[0].from_source_id == persistence_entry.id


def test_scan_persistence_no_link_when_no_matching_process(tmp_path: Path, monkeypatch):
    """No process_entries row shares this persistence entry's program_path
    — correctly no evidence_links row at all, not a fabricated one.
    """
    daemons_dir = tmp_path / "LaunchDaemons"
    daemons_dir.mkdir()
    with (daemons_dir / "com.example.daemon.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.daemon", "Program": "/usr/local/bin/never-running"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_daemon=[daemons_dir])

    scanner_module = _patch_scanner(
        monkeypatch, ps_result=(True, []), login_items_result=(True, []),
        signing_map={"/usr/local/bin/never-running": SIGNED_APPLE},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
        entries = list_persistence_entries(db.conn)

        assert result.evidence_links_recorded == 0
        links = list_evidence_links_for(db.conn, "persistence_entries", entries[0].id)
        assert links == []


def test_scan_persistence_process_link_is_idempotent_on_rescan(tmp_path: Path, monkeypatch):
    daemons_dir = tmp_path / "LaunchDaemons"
    daemons_dir.mkdir()
    with (daemons_dir / "com.example.daemon.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.daemon", "Program": "/usr/local/bin/agent"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_daemon=[daemons_dir])

    ps = (True, [{"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/usr/local/bin/agent"}])
    scanner_module = _patch_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/usr/local/bin/agent": SIGNED_APPLE},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scanner_module.scan_persistence(db.conn)
        second = scanner_module.scan_persistence(db.conn)
        procs = list_process_entries(db.conn)

        assert first.evidence_links_recorded == 1
        assert second.evidence_links_recorded == 0  # already-known relationship, touched not duplicated
        links = list_evidence_links_for(db.conn, "process_entries", procs[0].id)
        assert len(links) == 1
        assert links[0].times_seen == 2


def test_scan_persistence_new_login_item_alert_medium_when_signed(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)
    scanner_module = _patch_scanner(
        monkeypatch,
        ps_result=(True, []),
        login_items_result=(True, [{"name": "Dropbox", "path": "/Applications/Dropbox.app"}]),
        signing_map={"/Applications/Dropbox.app": SIGNED_DEVELOPER},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)

    assert len(result.new_persistence_entries) == 1
    new_alert = [a for a in result.alerts if a.kind == "new_persistence_entry"][0]
    assert new_alert.severity == "medium"
    assert new_alert.target_type == "login_item"


def test_scan_persistence_signing_downgrade_alert(tmp_path: Path, monkeypatch):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    with (agents_dir / "com.example.agent.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.agent", "Program": "/usr/local/bin/agent"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_agent_user=[agents_dir])

    db_path = tmp_path / "test.db"

    scanner_module = _patch_scanner(
        monkeypatch, ps_result=(True, []), login_items_result=(True, []),
        signing_map={"/usr/local/bin/agent": SIGNED_DEVELOPER},
    )
    with Database(db_path) as db:
        first = scanner_module.scan_persistence(db.conn)
    assert first.alerts[0].kind == "new_persistence_entry"
    assert first.alerts[0].severity == "medium"

    # Second scan: same entry, no change -- quiet.
    with Database(db_path) as db:
        second = scanner_module.scan_persistence(db.conn)
    assert second.alerts == []

    # Third scan: the backing binary's signature downgrades.
    scanner_module = _patch_scanner(
        monkeypatch, signing_map={"/usr/local/bin/agent": UNSIGNED}
    )
    with Database(db_path) as db:
        third = scanner_module.scan_persistence(db.conn)
    assert len(third.alerts) == 1
    assert third.alerts[0].kind == "signing_changed"
    assert third.alerts[0].severity == "high"


def test_scan_persistence_signing_upgrade_is_quiet(tmp_path: Path, monkeypatch):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    with (agents_dir / "com.example.agent.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.agent", "Program": "/usr/local/bin/agent"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_agent_user=[agents_dir])

    db_path = tmp_path / "test.db"

    scanner_module = _patch_scanner(
        monkeypatch, ps_result=(True, []), login_items_result=(True, []),
        signing_map={"/usr/local/bin/agent": UNSIGNED},
    )
    with Database(db_path) as db:
        scanner_module.scan_persistence(db.conn)

    # codesign now reports it as signed -- an upgrade, not a downgrade,
    # deliberately not alert-worthy (see is_signing_downgrade()).
    scanner_module = _patch_scanner(monkeypatch, signing_map={"/usr/local/bin/agent": SIGNED_DEVELOPER})
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)
    assert result.alerts == []


def test_scan_persistence_login_items_unavailable_does_not_block_launch_items(tmp_path: Path, monkeypatch):
    agents_dir = tmp_path / "LaunchAgents"
    agents_dir.mkdir()
    with (agents_dir / "com.example.agent.plist").open("wb") as f:
        plistlib.dump({"Label": "com.example.agent", "Program": "/usr/local/bin/agent"}, f)
    _patch_launch_dirs(monkeypatch, tmp_path, launch_agent_user=[agents_dir])

    scanner_module = _patch_scanner(
        monkeypatch, ps_result=(True, []), login_items_result=(False, []),
        signing_map={"/usr/local/bin/agent": SIGNED_DEVELOPER},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scanner_module.scan_persistence(db.conn)

    assert result.login_items_available is False
    assert len(result.new_persistence_entries) == 1  # the launch agent was still found
