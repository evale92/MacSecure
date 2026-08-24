"""
Tests for secure/fileintegrity/* (Phase 11: File Integrity Monitoring).

Pure functions (hashing.py's read_metadata/compute_sha256, paths.py,
analysis.py) are tested directly against real temp files/synthetic
dicts, no mocking needed for the filesystem-facing pieces since this
phase's whole point is real, honest filesystem inspection. scan_file_
integrity() is tested end-to-end against a real temp Database and real
temp watch directories — the same "seed real files, run the real
scanner, read real rows back" style test_persistence.py and
test_correlate.py already use. Code-signing lookups (secure.
persistence.codesign.check_code_signing, imported into scanner.py's
own namespace) are monkeypatched, same "patch the wrapper" pattern
every other package in this app uses for its own subprocess/I/O seam —
codesign itself isn't available in this sandbox anyway.

Run with:  pytest
"""

from __future__ import annotations

import os
import plistlib
from pathlib import Path

from secure.fileintegrity import analysis
from secure.fileintegrity.hashing import compute_sha256, read_metadata
from secure.fileintegrity.paths import (
    default_watch_paths,
    is_excluded_name,
    is_plist,
    normalize_path,
)
from secure.fileintegrity.scanner import scan_file_integrity
from secure.persistence.codesign import SIGNED_DEVELOPER, UNSIGNED
from secure.storage.database import Database
from secure.storage.models import (
    add_watch_path,
    list_file_change_events,
    list_file_entries,
    list_file_integrity_alerts,
    list_watch_paths,
)


# ---------- paths.py ----------


def test_normalize_path_expands_tilde(tmp_path: Path):
    old_home = os.environ.get("HOME")
    os.environ["HOME"] = str(tmp_path)
    try:
        assert normalize_path("~/foo") == str(tmp_path / "foo")
    finally:
        if old_home is not None:
            os.environ["HOME"] = old_home
        else:
            del os.environ["HOME"]


def test_normalize_path_collapses_dotdot():
    assert normalize_path("/a/b/../c") == "/a/c"


def test_normalize_path_relative_made_absolute():
    result = normalize_path("some/relative/path")
    assert os.path.isabs(result)


def test_is_excluded_name_dirs_and_files():
    assert is_excluded_name(".git") is True
    assert is_excluded_name("__pycache__") is True
    assert is_excluded_name("secure.db") is True
    assert is_excluded_name("foo.pyc") is True
    assert is_excluded_name("normal_file.py") is False


def test_is_plist():
    assert is_plist("/x/y/com.example.agent.plist") is True
    assert is_plist("/x/y/file.txt") is False


def test_default_watch_paths_shape():
    entries = default_watch_paths()
    sensitivities = {e["sensitivity"] for e in entries}
    assert "startup" in sensitivities
    assert "self" in sensitivities
    for e in entries:
        assert os.path.isabs(e["path"])


# ---------- hashing.py ----------


def test_read_metadata_missing_file(tmp_path: Path):
    meta = read_metadata(str(tmp_path / "nope.txt"))
    assert meta.exists is False
    assert meta.unreadable is False


def test_read_metadata_regular_file(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    meta = read_metadata(str(f))
    assert meta.exists is True
    assert meta.is_regular_file is True
    assert meta.is_symlink is False
    assert meta.size == 5
    assert meta.mode is not None


def test_read_metadata_symlink_never_followed(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_text("hi")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    meta = read_metadata(str(link))
    assert meta.exists is True
    assert meta.is_symlink is True
    assert meta.is_regular_file is False
    assert meta.symlink_target == str(target)


def test_read_metadata_permission_denied_parent_dir(tmp_path: Path):
    locked = tmp_path / "locked"
    locked.mkdir()
    f = locked / "secret.txt"
    f.write_text("s3cr3t")
    os.chmod(locked, 0o000)
    try:
        meta = read_metadata(str(f))
        assert meta.exists is False
        assert meta.unreadable is True
    finally:
        os.chmod(locked, 0o755)


def test_compute_sha256_basic(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"hello world")
    hash_value, skipped = compute_sha256(str(f))
    assert skipped is None
    import hashlib
    assert hash_value == hashlib.sha256(b"hello world").hexdigest()


def test_compute_sha256_too_large(tmp_path: Path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"x" * 1000)
    hash_value, skipped = compute_sha256(str(f), max_bytes=10)
    assert hash_value is None
    assert skipped == "too_large"


def test_compute_sha256_missing_file(tmp_path: Path):
    hash_value, skipped = compute_sha256(str(tmp_path / "nope.txt"))
    assert hash_value is None
    assert skipped == "unreadable"


# ---------- analysis.py: metadata diffing ----------


def _meta(**overrides) -> dict:
    base = {
        "hash": "h1", "size": 10, "mtime": "t1", "uid": 501, "owner": "erick",
        "gid": 20, "group_name": "staff", "mode": "0644", "is_executable": False,
        "is_symlink": False, "symlink_target": None, "dev": 1, "ino": 100,
    }
    base.update(overrides)
    return base


def test_diff_metadata_no_change():
    assert analysis.diff_metadata(_meta(), _meta()) == []


def test_diff_metadata_owner_changed():
    reasons = analysis.diff_metadata(_meta(), _meta(uid=0, owner="root"))
    assert any("owner changed" in r for r in reasons)


def test_diff_metadata_executable_bit_added():
    reasons = analysis.diff_metadata(_meta(), _meta(is_executable=True))
    assert any("became executable" in r for r in reasons)


def test_diff_metadata_symlink_replaces_regular_file():
    reasons = analysis.diff_metadata(_meta(), _meta(is_symlink=True, symlink_target="/etc/passwd"))
    assert any("replaced by a symlink" in r for r in reasons)


def test_diff_metadata_symlink_target_changed():
    prev = _meta(is_symlink=True, symlink_target="/a")
    cur = _meta(is_symlink=True, symlink_target="/b")
    reasons = analysis.diff_metadata(prev, cur)
    assert any("symlink target changed" in r for r in reasons)


# ---------- analysis.py: severity classification ----------


def test_classify_metadata_severity_mtime_only_is_low():
    prev = _meta()
    cur = _meta(mtime="t2")
    severity, reasons = analysis.classify_metadata_severity(prev, cur, "normal")
    assert severity == analysis.LOW


def test_classify_metadata_severity_executable_added_normal_medium():
    severity, _ = analysis.classify_metadata_severity(_meta(), _meta(is_executable=True), "normal")
    assert severity == analysis.MEDIUM


def test_classify_metadata_severity_executable_added_startup_high():
    severity, _ = analysis.classify_metadata_severity(_meta(), _meta(is_executable=True), "startup")
    assert severity == analysis.HIGH


def test_classify_metadata_severity_world_writable_startup_high():
    severity, _ = analysis.classify_metadata_severity(_meta(mode="0644"), _meta(mode="0646"), "startup")
    assert severity == analysis.HIGH


def test_classify_metadata_severity_world_writable_normal_medium():
    severity, _ = analysis.classify_metadata_severity(_meta(mode="0644"), _meta(mode="0646"), "normal")
    assert severity == analysis.MEDIUM


def test_classify_metadata_severity_owner_changed_startup_high():
    severity, _ = analysis.classify_metadata_severity(_meta(), _meta(uid=0, owner="root"), "startup")
    assert severity == analysis.HIGH


def test_classify_metadata_severity_owner_changed_normal_medium():
    severity, _ = analysis.classify_metadata_severity(_meta(), _meta(uid=0, owner="root"), "normal")
    assert severity == analysis.MEDIUM


def test_classify_metadata_severity_group_changed_normal_low():
    severity, _ = analysis.classify_metadata_severity(_meta(), _meta(gid=99, group_name="wheel"), "normal")
    assert severity == analysis.LOW


def test_classify_metadata_severity_symlink_replaces_file_high_regardless_of_location():
    severity, _ = analysis.classify_metadata_severity(
        _meta(), _meta(is_symlink=True, symlink_target="/etc/passwd"), "normal"
    )
    assert severity == analysis.HIGH


def test_classify_modified_severity_sensitive_location_always_high():
    severity, reasons = analysis.classify_modified_severity(_meta(), _meta(hash="h2"), "self")
    assert severity == analysis.HIGH
    assert any("content changed" in r for r in reasons)


def test_classify_modified_severity_normal_executable_medium():
    severity, _ = analysis.classify_modified_severity(
        _meta(is_executable=True), _meta(hash="h2", is_executable=True), "normal"
    )
    assert severity == analysis.MEDIUM


def test_classify_modified_severity_normal_nonexecutable_low():
    severity, _ = analysis.classify_modified_severity(_meta(), _meta(hash="h2"), "normal")
    assert severity == analysis.LOW


def test_classify_new_file_severity_startup_executable_high():
    severity, _ = analysis.classify_new_file_severity({"is_executable": True}, "startup")
    assert severity == analysis.HIGH


def test_classify_new_file_severity_self_always_high():
    severity, _ = analysis.classify_new_file_severity({"is_executable": False}, "self")
    assert severity == analysis.HIGH


def test_classify_new_file_severity_normal_low():
    severity, _ = analysis.classify_new_file_severity({"is_executable": False}, "normal")
    assert severity == analysis.LOW


def test_classify_deleted_file_severity_self_high_startup_medium_normal_low():
    assert analysis.classify_deleted_file_severity("self")[0] == analysis.HIGH
    assert analysis.classify_deleted_file_severity("startup")[0] == analysis.MEDIUM
    assert analysis.classify_deleted_file_severity("normal")[0] == analysis.LOW


def test_classify_renamed_severity_sensitive_vs_normal():
    assert analysis.classify_renamed_severity("startup")[0] == analysis.MEDIUM
    assert analysis.classify_renamed_severity("normal")[0] == analysis.LOW


def test_classify_program_target_severity_unsigned_high():
    severity, reasons = analysis.classify_program_target_severity(UNSIGNED, True, False)
    assert severity == analysis.HIGH


def test_classify_program_target_severity_missing_target_high():
    severity, _ = analysis.classify_program_target_severity(SIGNED_DEVELOPER, False, False)
    assert severity == analysis.HIGH


def test_classify_program_target_severity_changed_target_signed_medium():
    severity, _ = analysis.classify_program_target_severity(SIGNED_DEVELOPER, True, True)
    assert severity == analysis.MEDIUM


def test_classify_program_target_severity_unchanged_signed_medium():
    severity, _ = analysis.classify_program_target_severity(SIGNED_DEVELOPER, True, False)
    assert severity == analysis.MEDIUM


def test_apply_self_update_context_caps_high_to_medium():
    severity, note = analysis.apply_self_update_context(analysis.HIGH, True)
    assert severity == analysis.MEDIUM
    assert note is not None


def test_apply_self_update_context_no_context_unchanged():
    severity, note = analysis.apply_self_update_context(analysis.HIGH, False)
    assert severity == analysis.HIGH
    assert note is None


def test_apply_doc_dampening_md_capped():
    severity = analysis.apply_doc_dampening(analysis.HIGH, "/x/PROJECT_NOTES.md", "self")
    assert severity == analysis.MEDIUM


def test_apply_doc_dampening_py_not_capped():
    severity = analysis.apply_doc_dampening(analysis.HIGH, "/x/cli.py", "self")
    assert severity == analysis.HIGH


# ---------- analysis.py: rename matching ----------


def test_match_renames_confirmed_by_inode():
    missing = [{"path": "/a/old.txt", "dev": 1, "ino": 42, "hash": "h1"}]
    created = [{"path": "/a/new.txt", "dev": 1, "ino": 42, "hash": "h1"}]
    renames, rem_missing, rem_created = analysis.match_renames(missing, created)
    assert len(renames) == 1
    assert rem_missing == []
    assert rem_created == []


def test_match_renames_same_hash_different_inode_not_a_rename():
    missing = [{"path": "/a/old.txt", "dev": 1, "ino": 42, "hash": "samehash"}]
    created = [{"path": "/b/copy.txt", "dev": 1, "ino": 999, "hash": "samehash"}]
    renames, rem_missing, rem_created = analysis.match_renames(missing, created)
    assert renames == []
    assert len(rem_missing) == 1
    assert len(rem_created) == 1


def test_find_hash_correlation_note_present_for_matching_hash():
    remaining_missing = [{"path": "/a/old.txt", "hash": "samehash"}]
    note = analysis.find_hash_correlation_note("samehash", remaining_missing)
    assert note is not None
    assert "not confirmed as a rename" in note


def test_find_hash_correlation_note_none_when_no_match():
    note = analysis.find_hash_correlation_note("uniquehash", [{"path": "/a", "hash": "other"}])
    assert note is None


# ---------- scanner.py: end-to-end ----------


def _watched_dir(tmp_path: Path) -> Path:
    d = tmp_path / "watched"
    d.mkdir()
    return d


def test_scan_baseline_no_alerts_and_known_true(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    (watched / "a.txt").write_text("hello")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        result = scan_file_integrity(db.conn)

        assert result.files_visited == 1
        assert len(result.alerts) == 0

        events = list_file_change_events(db.conn)
        assert len(events) == 1
        assert events[0].change_type == "baseline"

        entries = list_file_entries(db.conn)
        assert len(entries) == 1
        assert entries[0].known is True


def test_scan_repeated_unchanged_produces_no_new_events(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    (watched / "a.txt").write_text("hello")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)
        before = list_file_change_events(db.conn)
        result2 = scan_file_integrity(db.conn)
        after = list_file_change_events(db.conn)

        assert len(before) == len(after)
        assert result2.files_hashed == 0  # fast path: size+mtime unchanged, no rehash


def test_scan_content_modified_detected(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    f = watched / "a.txt"
    f.write_text("hello")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)

        f.write_text("hello, but very different content now")
        result = scan_file_integrity(db.conn)

        kinds = [a.kind for a in result.alerts]
        assert "modified" in kinds


def test_scan_executable_bit_added_metadata_only_alert(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    f = watched / "script.sh"
    f.write_text("#!/bin/sh\necho hi\n")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)

        os.chmod(f, 0o755)
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.kind == "metadata_only" and a.path == str(f)]
        assert len(matching) == 1
        assert matching[0].severity == "medium"
        assert matching[0].id is not None  # persisted, since medium+


def test_scan_world_writable_permission_introduced(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    f = watched / "config.txt"
    f.write_text("setting=1")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="startup")
        scan_file_integrity(db.conn)

        os.chmod(f, 0o646)  # world-writable
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.path == str(f)]
        assert len(matching) == 1
        assert matching[0].severity == "high"


def test_scan_owner_changed_detected_via_seeded_prior_state(tmp_path: Path):
    """chown to an arbitrary uid isn't available without root in this
    sandbox, so this seeds the STORED baseline with a fake previous
    owner different from the real filesystem owner, then lets a real
    scan compare against the real (different) current owner — this
    exercises the exact same comparison code path a genuine owner
    change on disk would, without needing root.
    """
    watched = _watched_dir(tmp_path)
    f = watched / "owned.txt"
    f.write_text("data")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="startup")
        scan_file_integrity(db.conn)

        entries = list_file_entries(db.conn)
        entry = entries[0]
        real_uid = entry.uid
        # Directly poke a fake "previous" uid into the stored baseline.
        db.conn.execute(
            "UPDATE file_entries SET uid = ?, owner = ? WHERE id = ?",
            (real_uid + 12345, "someone_else", entry.id),
        )
        db.conn.commit()

        result = scan_file_integrity(db.conn)
        matching = [a for a in result.alerts if a.path == str(f)]
        assert len(matching) == 1
        assert matching[0].severity == "high"
        assert "owner" in matching[0].message


def test_scan_regular_file_replaced_by_symlink(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    f = watched / "trusted.txt"
    f.write_text("trusted content")
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("evil")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)

        f.unlink()
        f.symlink_to(elsewhere)
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.path == str(f)]
        assert len(matching) == 1
        assert matching[0].severity == "high"
        assert "symlink" in matching[0].message


def test_scan_symlink_target_changed(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    target1 = tmp_path / "t1.txt"
    target1.write_text("one")
    target2 = tmp_path / "t2.txt"
    target2.write_text("two")
    link = watched / "link.txt"
    link.symlink_to(target1)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="startup")
        scan_file_integrity(db.conn)

        link.unlink()
        link.symlink_to(target2)
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.path == str(link)]
        assert len(matching) == 1
        assert matching[0].severity == "high"


def test_scan_deleted_file_removes_entry(tmp_path: Path):
    # Deliberately not a .txt/.md name -- those are "lower significance"
    # self-sensitivity files (see paths.py) and would get their
    # severity dampened, which isn't what this test is checking.
    watched = _watched_dir(tmp_path)
    f = watched / "gone.py"
    f.write_text("bye")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="self")
        scan_file_integrity(db.conn)

        f.unlink()
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.kind == "deleted"]
        assert len(matching) == 1
        assert matching[0].severity == "high"  # self-sensitivity

        entries = list_file_entries(db.conn)
        assert len(entries) == 0

        events = list_file_change_events(db.conn)
        assert any(e.change_type == "deleted" for e in events)


def test_scan_real_rename_detected_via_inode(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    old = watched / "old_name.txt"
    old.write_text("some content")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)
        entries_before = list_file_entries(db.conn)
        original_id = entries_before[0].id

        new = watched / "new_name.txt"
        old.rename(new)
        result = scan_file_integrity(db.conn)

        events = list_file_change_events(db.conn)
        rename_events = [e for e in events if e.change_type == "renamed"]
        assert len(rename_events) == 1
        assert rename_events[0].rename_confidence == "confirmed_inode"
        assert rename_events[0].old_path == str(old)
        assert rename_events[0].path == str(new)

        entries_after = list_file_entries(db.conn)
        assert len(entries_after) == 1
        assert entries_after[0].id == original_id  # identity preserved, not delete+insert
        assert entries_after[0].path == str(new)


def test_scan_same_hash_copy_not_treated_as_rename(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    original = watched / "original.txt"
    original.write_text("identical content")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)

        # Delete the original and create an unrelated NEW file with the
        # exact same content (same hash) but a genuinely different
        # inode -- this must NOT be reported as a rename. Some
        # filesystems (this sandbox's included) immediately reuse a
        # just-freed inode number for the very next file created, which
        # would defeat this test by accident rather than by design --
        # a throwaway "decoy" file absorbs that freed inode first, so
        # `copy` below is guaranteed a genuinely different one.
        original.unlink()
        decoy = tmp_path / "decoy.txt"
        decoy.write_text("unrelated, just here to consume the freed inode number")
        copy = watched / "unrelated_copy.txt"
        copy.write_text("identical content")
        scan_file_integrity(db.conn)

        events = list_file_change_events(db.conn)
        assert not any(e.change_type == "renamed" for e in events)
        assert any(e.change_type == "deleted" and e.path == str(original) for e in events)
        created_events = [e for e in events if e.change_type == "created" and e.path == str(copy)]
        assert len(created_events) == 1
        # Supporting-evidence-only note should still be present.
        reasons = created_events[0].details.get("reasons", [])
        assert any("not confirmed as a rename" in r for r in reasons)


def test_scan_directory_enumeration_failure_preserves_baseline(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    locked = watched / "locked"
    locked.mkdir()
    secret = locked / "secret.txt"
    secret.write_text("s3cr3t")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)  # baseline, including secret.txt

        os.chmod(locked, 0o000)
        try:
            result = scan_file_integrity(db.conn)
            assert len(result.watch_paths_incomplete) == 1

            entries = list_file_entries(db.conn)
            assert any(e.path == str(secret) for e in entries)  # NOT falsely deleted

            events = list_file_change_events(db.conn)
            assert not any(e.change_type == "deleted" and e.path == str(secret) for e in events)

            wps = list_watch_paths(db.conn)
            assert wps[0].last_scan_status == "incomplete"
        finally:
            os.chmod(locked, 0o755)


def test_scan_incomplete_then_recovered_scan_works_normally(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    locked = watched / "locked"
    locked.mkdir()
    secret = locked / "secret.txt"
    secret.write_text("s3cr3t")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)

        os.chmod(locked, 0o000)
        scan_file_integrity(db.conn)
        os.chmod(locked, 0o755)

        result = scan_file_integrity(db.conn)
        assert len(result.watch_paths_incomplete) == 0
        wps = list_watch_paths(db.conn)
        assert wps[0].last_scan_status == "ok"

        entries = list_file_entries(db.conn)
        assert any(e.path == str(secret) for e in entries)


def test_scan_launch_agent_program_target_change_flags_high_when_unsigned(tmp_path: Path, monkeypatch):
    import secure.fileintegrity.scanner as scanner_module

    watched = _watched_dir(tmp_path)
    program1 = tmp_path / "program1"
    program1.write_text("#!/bin/sh\n")
    program2 = tmp_path / "program2"
    program2.write_text("#!/bin/sh\n")

    plist_path = watched / "com.example.agent.plist"
    plist_path.write_bytes(plistlib.dumps({"Label": "com.example.agent", "Program": str(program1)}))

    monkeypatch.setattr(scanner_module, "check_code_signing", lambda path: SIGNED_DEVELOPER)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="startup")
        scan_file_integrity(db.conn)  # baseline

        # Point the plist at a DIFFERENT, unsigned executable.
        monkeypatch.setattr(scanner_module, "check_code_signing", lambda path: UNSIGNED)
        plist_path.write_bytes(plistlib.dumps({"Label": "com.example.agent", "Program": str(program2)}))
        result = scan_file_integrity(db.conn)

        target_alerts = [a for a in result.alerts if a.kind == "program_target_changed"]
        assert len(target_alerts) == 1
        assert target_alerts[0].severity == "high"

        events = list_file_change_events(db.conn)
        assert any(e.change_type == "program_target_changed" for e in events)
        # The plist's own byte-level "modified" event is preserved too
        # -- independent evidence, not replaced by the target-change event.
        assert any(e.change_type == "modified" and e.path == str(plist_path) for e in events)


def test_scan_new_launch_agent_unsigned_executable_is_high(tmp_path: Path, monkeypatch):
    import secure.fileintegrity.scanner as scanner_module

    watched = _watched_dir(tmp_path)
    program = tmp_path / "sketchy_binary"
    program.write_text("#!/bin/sh\n")
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda path: UNSIGNED)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="startup")
        scan_file_integrity(db.conn)  # baseline the (empty) watch path first

        plist_path = watched / "com.example.new.plist"
        plist_path.write_bytes(plistlib.dumps({"Label": "com.example.new", "Program": str(program)}))
        result = scan_file_integrity(db.conn)  # plist appears AFTER baseline -> "created", not "baseline"

        created_alerts = [a for a in result.alerts if a.kind == "created" and a.path == str(plist_path)]
        assert len(created_alerts) == 1
        assert created_alerts[0].severity == "high"


def test_scan_self_update_context_caps_severity(tmp_path: Path, monkeypatch):
    from secure.self_update import mark_update_context

    watched = _watched_dir(tmp_path)
    f = watched / "cli.py"
    f.write_text("print('v1')")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="self")
        scan_file_integrity(db.conn)

        mark_update_context(db.conn, note="test update")
        f.write_text("print('v2 -- an intentional update')")
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.path == str(f)]
        assert len(matching) == 1
        assert matching[0].severity == "medium"
        assert matching[0].context_notes is not None
        assert "update" in matching[0].context_notes.lower()


def test_scan_unexplained_self_modification_stays_high(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    f = watched / "cli.py"
    f.write_text("print('v1')")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="self")
        scan_file_integrity(db.conn)

        # No mark_update_context() call this time.
        f.write_text("print('v2 -- unexplained')")
        result = scan_file_integrity(db.conn)

        matching = [a for a in result.alerts if a.path == str(f)]
        assert len(matching) == 1
        assert matching[0].severity == "high"
        assert matching[0].context_notes is None


def test_scan_low_severity_change_recorded_in_history_not_alerts(tmp_path: Path):
    watched = _watched_dir(tmp_path)
    f = watched / "notes.txt"
    f.write_text("v1")

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(db.conn)

        f.write_text("v1 with a tiny edit")
        result = scan_file_integrity(db.conn)

        # LOW severity (non-executable, normal location) -- present in
        # the in-memory result for CLI/GUI display, but not persisted
        # to the file_integrity_alerts table (no flooding).
        assert any(a.path == str(f) for a in result.alerts)
        assert all(a.id is None for a in result.alerts if a.path == str(f))
        db_alerts = list_file_integrity_alerts(db.conn)
        assert not any(a.path == str(f) for a in db_alerts)


def test_scan_order_independence_fileintegrity_does_not_depend_on_persistence(tmp_path: Path, monkeypatch):
    """The file-integrity <-> persistence dedup design must not depend
    on which module scans first (refinement #10). Since fileintegrity
    never reads persistence_alerts/persistence_entries at all (see
    scanner.py and correlate/signals.py's _collect_file_integrity()
    docstring), running it standalone -- with no persistence scan
    having ever run in this database -- must produce identical alerts
    to running it after a persistence scan. This test demonstrates the
    "before" half directly; the "after" half is structurally
    guaranteed by fileintegrity/scanner.py never querying
    persistence_* tables at all (verified by inspection, not by a
    join that could silently start depending on ordering later).
    """
    import secure.fileintegrity.scanner as scanner_module

    watched = _watched_dir(tmp_path)
    program = tmp_path / "prog"
    program.write_text("#!/bin/sh\n")
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda path: UNSIGNED)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        # No persistence scan has ever run against this database.
        add_watch_path(db.conn, normalize_path(str(watched)), sensitivity="startup")
        scan_file_integrity(db.conn)  # baseline the empty watch path first

        plist_path = watched / "com.example.standalone.plist"
        plist_path.write_bytes(plistlib.dumps({"Label": "com.example.standalone", "Program": str(program)}))
        result = scan_file_integrity(db.conn)

        created_alerts = [a for a in result.alerts if a.path == str(plist_path)]
        assert len(created_alerts) == 1
        assert created_alerts[0].severity == "high"  # unsigned referenced executable


def test_scan_seeds_default_watch_paths_when_empty(tmp_path: Path, monkeypatch):
    import secure.fileintegrity.scanner as scanner_module

    fake_home = tmp_path / "home"
    fake_project = tmp_path / "project"
    fake_project.mkdir()
    (fake_project / "secure").mkdir()
    (fake_project / "secure" / "cli.py").write_text("x = 1")
    (fake_project / "secure_gui.py").write_text("x = 1")
    (fake_project / "requirements.txt").write_text("x")
    (fake_project / "PROJECT_NOTES.md").write_text("# notes")

    monkeypatch.setattr(
        "secure.fileintegrity.paths._PROJECT_ROOT", fake_project
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        assert list_watch_paths(db.conn) == []
        scan_file_integrity(db.conn)
        watch_paths = list_watch_paths(db.conn)
        assert len(watch_paths) >= 4
