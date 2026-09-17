"""secure/downloads and `secure downloads`, against a fixture quarantine database."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import secure.cli.downloads as cli_downloads
import secure.downloads.history as history
from secure.downloads import download_history
from secure.downloads.history import flags_for
from secure.storage.models.macos_readonly import QuarantineEvent

COCOA = 978307200
NOW = 1_800_000_000.0


def _db(path: Path, rows) -> Path:
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
        "LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString) VALUES (?,?,?,?,?)",
        [(i, NOW - age - COCOA, agent, data, origin) for i, age, agent, data, origin in rows],
    )
    conn.commit()
    conn.close()
    return path


def _event(data="", origin=""):
    return QuarantineEvent("x", NOW, "", "", data, origin, "", None)


def test_flags_are_deterministic_string_rules():
    assert flags_for(_event("https://dl.example.com/Tool%20Setup.PKG")) == ["executable_type"]
    assert flags_for(_event("http://203.0.113.9/a.dmg")) == ["executable_type", "ip_literal_host", "plain_http"]
    assert flags_for(_event("https://[2001:db8::1]/notes.txt")) == ["ip_literal_host"]
    assert flags_for(_event("https://example.com/report.pdf", "https://example.com/")) == []


def test_plain_http_origin_flags_even_when_the_data_url_is_https():
    # The page that led to the download is part of the event: an https file
    # linked from a plain-http page was still reachable by a network rewrite.
    assert flags_for(_event("https://cdn.example.com/report.pdf", "http://example.com/")) == ["plain_http"]
    assert flags_for(_event("https://cdn.example.com/report.pdf", "HTTP://example.com/")) == ["plain_http"]


def test_history_skips_url_less_rows_orders_newest_first_and_flags(tmp_path):
    db = _db(tmp_path / "q", [
        ("a", 3600, "Safari", "https://example.com/a.pdf", ""),
        ("b", 60, "Chrome", "http://198.51.100.4/payload.command", ""),
        ("c", 30, "Chrome", "", ""),                         # no URL at all: left out
        ("d", 40 * 86400, "Safari", "https://old.example/x.dmg", ""),  # outside the window
    ])
    report = download_history(days=30, limit=10, database=db, now=NOW)
    assert report.status == "OK" and not report.truncated
    assert [e.event.identifier for e in report.events] == ["b", "a"]
    assert [e.event.identifier for e in report.flagged] == ["b"]


def test_limit_reports_truncation(tmp_path):
    db = _db(tmp_path / "q", [(str(i), i, "Safari", f"https://e.com/{i}.pdf", "") for i in range(5)])
    report = download_history(days=1, limit=3, database=db, now=NOW)
    assert len(report.events) == 3 and report.truncated


def test_missing_database_is_unavailable_not_an_empty_history(tmp_path):
    report = download_history(database=tmp_path / "absent", now=NOW)
    assert report.status == "UNAVAILABLE" and report.events == [] and "not found" in report.reason


def test_cli_prints_unavailable_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli_downloads, "_bootstrap", lambda: None)
    monkeypatch.setattr(history, "QUARANTINE_DB", tmp_path / "absent")
    monkeypatch.setattr(history.download_history, "__defaults__", (30, 500, tmp_path / "absent", None))
    code = cli_downloads.cmd_downloads(argparse.Namespace(days=30, limit=500, flagged=False))
    out = capsys.readouterr().out
    assert code == 1 and "UNAVAILABLE" in out and "not the same as" in out


def test_cli_lists_flagged_with_the_coverage_note(tmp_path, monkeypatch, capsys):
    db = _db(tmp_path / "q", [
        ("a", 60, "Safari", "https://example.com/a.pdf", ""),
        ("b", 30, "Chrome", "http://198.51.100.4/p.command", "https://lure.example/"),
    ])
    monkeypatch.setattr(cli_downloads, "_bootstrap", lambda: None)
    monkeypatch.setattr(cli_downloads, "download_history",
                        lambda days, limit: download_history(days, limit, database=db, now=NOW))
    code = cli_downloads.cmd_downloads(argparse.Namespace(days=30, limit=500, flagged=True))
    out = capsys.readouterr().out
    assert code == 0
    assert "flagged: 1" in out and "Terminal never appear" in out
    assert "p.command" in out and "a.pdf" not in out
