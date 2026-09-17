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
