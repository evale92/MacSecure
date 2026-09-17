"""Tests for secure/checks/xprotect.py, against fake bundles in tmp_path."""

from __future__ import annotations

import os
import plistlib
from pathlib import Path

from secure.checks.models import CheckStatus
from secure.checks.xprotect import STALE_AFTER_DAYS, check_xprotect

NOW = 2_000_000_000.0
DAY = 86400


def _bundle(root: Path, name: str, version, age_days: float = 3) -> str:
    contents = root / name / "Contents"
    contents.mkdir(parents=True)
    info = contents / "Info.plist"
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": str(version)}))
    mtime = NOW - age_days * DAY
    os.utime(info, (mtime, mtime))
    return str(root / name)


def test_recent_signatures_and_remediator_pass(tmp_path):
    sig = _bundle(tmp_path, "XProtect.bundle", 5358)
    rem = _bundle(tmp_path, "XProtect.app", 157)
    result = check_xprotect((sig,), rem, now=NOW)
    assert result.status == CheckStatus.PASS
    assert "5358" in result.message and "157" in result.message


def test_newest_of_several_locations_wins(tmp_path):
    new = _bundle(tmp_path / "a", "XProtect.bundle", 5358, age_days=2)
    old = _bundle(tmp_path / "b", "XProtect.bundle", 5100, age_days=200)
    rem = _bundle(tmp_path, "XProtect.app", 157)
    result = check_xprotect((old, new), rem, now=NOW)
    assert result.status == CheckStatus.PASS
    assert "5358" in result.message


def test_stale_signatures_warn(tmp_path):
    sig = _bundle(tmp_path, "XProtect.bundle", 5100, age_days=STALE_AFTER_DAYS + 1)
    rem = _bundle(tmp_path, "XProtect.app", 157)
    result = check_xprotect((sig,), rem, now=NOW)
    assert result.status == CheckStatus.WARNING
    assert result.remediation


def test_no_bundle_anywhere_is_a_warning_not_a_clean_pass(tmp_path):
    result = check_xprotect((str(tmp_path / "missing.bundle"),), str(tmp_path / "missing.app"), now=NOW)
    assert result.status == CheckStatus.WARNING
    assert "No XProtect signature bundle" in result.message


def test_unreadable_plist_is_a_warning_naming_the_error(tmp_path):
    bad = tmp_path / "XProtect.bundle" / "Contents"
    bad.mkdir(parents=True)
    (bad / "Info.plist").write_bytes(b"not a plist")
    rem = _bundle(tmp_path, "XProtect.app", 157)
    result = check_xprotect((str(tmp_path / "XProtect.bundle"),), rem, now=NOW)
    assert result.status == CheckStatus.WARNING
    assert "could not be read" in result.message


def test_missing_remediator_does_not_pass(tmp_path):
    sig = _bundle(tmp_path, "XProtect.bundle", 5358)
    result = check_xprotect((sig,), str(tmp_path / "missing.app"), now=NOW)
    assert result.status == CheckStatus.WARNING
    assert "Remediator" in result.message


def test_non_numeric_version_is_not_trusted(tmp_path):
    sig = _bundle(tmp_path, "XProtect.bundle", "banana")
    rem = _bundle(tmp_path, "XProtect.app", 157)
    result = check_xprotect((sig,), rem, now=NOW)
    assert result.status == CheckStatus.WARNING
