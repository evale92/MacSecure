"""storage/models/macos_readonly.py and the TCC grant source it feeds.

Fixture databases are built in tmp_path with the column names macOS uses;
nothing here opens this machine's real TCC.db or quarantine log.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

import secure.persistence.extra_locations as extra
from secure.storage.models.macos_readonly import (
    MacDatabaseUnavailable,
    read_quarantine_events,
    read_tcc_grants,
)

COCOA = 978307200


def _tcc(path: Path, rows) -> Path:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, last_modified INTEGER)")
    conn.executemany("INSERT INTO access VALUES (?,?,?,?,?)", rows)
    conn.commit()
    conn.close()
    return path


def _quarantine(path: Path, rows) -> Path:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL, "
        "LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, "
        "LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT, "
        "LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, "
        "LSQuarantineOriginAlias BLOB)"
    )
    conn.executemany(
        "INSERT INTO LSQuarantineEvent (LSQuarantineEventIdentifier, LSQuarantineTimeStamp, "
        "LSQuarantineAgentBundleIdentifier, LSQuarantineAgentName, LSQuarantineDataURLString, "
        "LSQuarantineOriginURLString) VALUES (?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()
    return path


def test_tcc_grants_are_read(tmp_path):
    db = _tcc(tmp_path / "TCC.db", [("kTCCServiceScreenCapture", "/tmp/x", 1, 2, 5)])
    assert [(g.service, g.client, g.client_type, g.auth_value) for g in read_tcc_grants(db)] == [
        ("kTCCServiceScreenCapture", "/tmp/x", 1, 2)
    ]


def test_reading_creates_no_file_next_to_the_database(tmp_path):
    # invariant 12: nothing written outside the app directory, not even -journal/-shm.
    folder = tmp_path / "tcc"
    folder.mkdir()
    db = _tcc(folder / "TCC.db", [("kTCCServiceCamera", "com.x", 0, 2, 1)])
    os.chmod(folder, 0o500)
    try:
        before = sorted(os.listdir(folder))
        read_tcc_grants(db)
        assert sorted(os.listdir(folder)) == before
    finally:
        os.chmod(folder, 0o700)


def test_missing_and_malformed_databases_are_unavailable_not_empty(tmp_path):
    with pytest.raises(MacDatabaseUnavailable):
        read_tcc_grants(tmp_path / "absent.db")
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not sqlite at all" * 100)
    with pytest.raises(MacDatabaseUnavailable):
        read_tcc_grants(junk)
    wrong = tmp_path / "wrong.db"
    sqlite3.connect(wrong).execute("CREATE TABLE other (x)").connection.close()
    with pytest.raises(MacDatabaseUnavailable):
        read_tcc_grants(wrong)


def test_quarantine_events_newest_first_since_and_limited(tmp_path):
    base = 1_800_000_000
    db = _quarantine(tmp_path / "q", [
        ("old", base - 10 * 86400 - COCOA, "com.google.Chrome", "Chrome", "https://a/old.dmg", ""),
        ("mid", base - 60 - COCOA, "com.apple.Safari", "Safari", "https://b/mid.pkg", "https://b/"),
        ("new", base - COCOA, "com.tinyspeck.slackmacgap", "Slack", "", ""),
    ])
    events = read_quarantine_events(db, since_unix=base - 86400, limit=10)
    assert [e.identifier for e in events] == ["new", "mid"]
    assert events[1].timestamp == pytest.approx(base - 60)
    assert [e.identifier for e in read_quarantine_events(db, base - 86400, limit=1)] == ["new"]


def test_only_allowed_sensitive_tcc_grants_become_persistence_entries(tmp_path, monkeypatch):
    db = _tcc(tmp_path / "TCC.db", [
        ("kTCCServiceSystemPolicyAllFiles", "com.example.backup", 0, 2, 1),
        ("kTCCServiceScreenCapture", "/Users/x/.local/bin/grabber", 1, 2, 1),
        ("kTCCServiceAccessibility", "com.example.denied", 0, 0, 1),     # denied: no access
        ("kTCCServiceAddressBook", "com.example.contacts", 0, 2, 1),     # not in the sensitive set
    ])
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"tcc_grant": ("tcc", [db, tmp_path / "absent" / "TCC.db"])})
    entries, unavailable = extra.scan_extra_locations()
    assert unavailable == []            # an absent user TCC.db is not a failed read
    # read_tcc_grants orders by service: ScreenCapture sorts before SystemPolicyAllFiles.
    assert [(e["label"], e["program_path"]) for e in entries] == [
        ("Screen Recording allowed: /Users/x/.local/bin/grabber", "/Users/x/.local/bin/grabber"),
        ("Full Disk Access allowed: com.example.backup", None),
    ]


def test_unreadable_tcc_database_is_unavailable_with_the_reason(tmp_path, monkeypatch):
    db = tmp_path / "TCC.db"
    db.write_bytes(b"x")

    def refuse(path):
        raise MacDatabaseUnavailable(f"{path}: OperationalError: unable to open database file")

    monkeypatch.setattr(extra, "read_tcc_grants", refuse)
    monkeypatch.setattr(extra, "_EXTRA_LOCATIONS", {"tcc_grant": ("tcc", [db])})
    entries, unavailable = extra.scan_extra_locations()
    assert entries == [] and len(unavailable) == 1 and "Full Disk Access" in unavailable[0]
