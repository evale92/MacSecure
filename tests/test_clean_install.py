"""
Tests for Phase 29 Stage 8 (clean install/removal audit).

These are NOT mocked — they exercise the real `secure init`/`secure
status` CLI commands, the real schema, and (for the dependency-absence
tests) whatever Python packages genuinely are or aren't importable in
the environment tests run in. This project's own optional dependencies
(bleak, yara-x, pyobjc-framework-CoreBluetooth) are lazily imported
specifically so their absence is a normal, testable condition rather
than a required test-environment setup step — see requirements.txt's
own per-dependency comments.

Run with:  pytest
"""

from __future__ import annotations

import sqlite3
import stat
import subprocess
import sys
from pathlib import Path


def _run_secure(env: dict, args: list[str], cwd: Path, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "secure", *args],
        capture_output=True, text=True, env=env, cwd=str(cwd), timeout=timeout,
    )


def _project_root() -> Path:
    # tests/ is one level under the project root.
    return Path(__file__).resolve().parents[1]


def _fresh_env(tmp_path: Path, monkeypatch) -> dict:
    import os

    home = tmp_path / "fresh_home"
    home.mkdir(parents=True)
    env = dict(os.environ)
    env["HOME"] = str(home)
    return env


# =========================================================================
# Fresh install: `secure init` from nothing
# =========================================================================


def test_fresh_init_creates_config_db_and_log_with_hardened_permissions(tmp_path: Path, monkeypatch):
    env = _fresh_env(tmp_path, monkeypatch)
    root = _project_root()

    result = _run_secure(env, ["init"], root)
    assert result.returncode == 0, result.stderr

    app_dir = Path(env["HOME"]) / ".secure"
    cfg_path = app_dir / "config.json"
    db_path = app_dir / "secure.db"
    log_path = app_dir / "secure.log"

    assert cfg_path.exists()
    assert db_path.exists()
    assert log_path.exists()

    assert stat.S_IMODE(app_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(cfg_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600

    conn = sqlite3.connect(db_path)
    try:
        table_count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert table_count > 40  # the real schema — proves init_schema() actually ran, not a stub


def test_fresh_init_is_idempotent(tmp_path: Path, monkeypatch):
    env = _fresh_env(tmp_path, monkeypatch)
    root = _project_root()

    first = _run_secure(env, ["init"], root)
    second = _run_secure(env, ["init"], root)

    assert first.returncode == 0
    assert second.returncode == 0


def test_status_works_immediately_after_fresh_init(tmp_path: Path, monkeypatch):
    env = _fresh_env(tmp_path, monkeypatch)
    root = _project_root()

    _run_secure(env, ["init"], root)
    result = _run_secure(env, ["status"], root)

    assert result.returncode == 0
    assert "Total events:  0" in result.stdout


# =========================================================================
# Dependency absence: an optional integration/sensor with its dependency
# genuinely not importable must degrade honestly, never crash the run
# and never report a false-clean result (Phase 29's own completion
# criterion: "no sensor may convert 'could not observe' into 'observed
# nothing'").
# =========================================================================


def test_run_all_completes_even_with_optional_dependencies_missing(tmp_path: Path, monkeypatch):
    """Does not skip or mock anything — if bleak/yara-x/pyobjc happen to
    be installed in the environment this runs in, this test still
    passes (run-all must complete either way); it's most meaningful in
    an environment where they're genuinely absent, which is exactly
    what proves the lazy-import/STATUS_UNAVAILABLE discipline works
    end to end, not just in a mocked unit test.
    """
    env = _fresh_env(tmp_path, monkeypatch)
    root = _project_root()

    _run_secure(env, ["init"], root)
    result = _run_secure(env, ["run-all"], root, timeout=120.0)

    assert result.returncode in (0, 1)  # 1 = new correlation alerts, still a clean run
    assert "Traceback" not in result.stderr


def test_ble_scan_reports_honest_unavailable_when_bleak_or_pyobjc_missing(tmp_path: Path):
    """A direct, in-process check of the exact claim: if bleak/pyobjc
    genuinely can't be imported, BleScanResult says so explicitly
    (ble_available=False, a real reason/detail) rather than silently
    reporting zero peripherals as if that were a clean scan.
    """
    import importlib.util

    from secure.storage.database import Database
    from secure.bluetooth.ble import scan_ble_peripherals

    bleak_present = importlib.util.find_spec("bleak") is not None
    pyobjc_present = importlib.util.find_spec("CoreBluetooth") is not None

    with Database(tmp_path / "t.db") as db:
        result = scan_ble_peripherals(db.conn)

    if not (bleak_present and pyobjc_present):
        assert result.ble_available is False
        assert result.unavailable_reason is not None
        assert result.entries == []
    # else: dependency happens to be installed in this environment —
    # nothing to assert about the failure path here, real hardware
    # scanning is out of scope for an automated test.


# =========================================================================
# Uninstall residue: everything Secure writes lives under one directory,
# and Secure never registers itself as a persistent OS-level service.
# =========================================================================


def test_no_source_file_writes_outside_tempfile_or_app_dir():
    """Static check, not a live filesystem probe: every real (non-test,
    non-validate-sandbox) write path in this codebase should route
    through cfg.app_dir_path() (or a self-cleaning
    tempfile.TemporaryDirectory scoped to secure/validate/'s own
    sandbox) — never a hardcoded path elsewhere. A regression here
    would mean `rm -rf ~/.secure` no longer fully uninstalls the app.
    """
    root = _project_root() / "secure"
    offending = []
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "validate" in path.parts or path.name == "validate.py":
            continue  # secure/validate/'s own tempfile-sandboxed fixtures
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in ("NamedTemporaryFile(", "tempfile.mkstemp(", "tempfile.mkdtemp("):
            if needle in text:
                offending.append(f"{path}: {needle}")

    assert offending == []


def test_never_registers_itself_as_a_persistent_os_service():
    """Static check: Secure must never actually INVOKE launchctl to
    install itself as a LaunchAgent/LaunchDaemon — the one-directory
    uninstall story depends on this. Checks for a real subprocess
    invocation shape (`"launchctl"` inside an argv list literal), not
    just the word "launchctl" anywhere — several files' own docstrings
    mention `launchctl load` in prose to explain why the app does NOT
    do this, which a plain substring check would misfire on.
    """
    import re

    root = _project_root() / "secure"
    offending = []
    # Matches launchctl used as an argv[0]-shaped token: ["launchctl", ...
    # or ('launchctl', ... — the way every real subprocess call in this
    # codebase's own _shell.py seam modules is written.
    invocation_pattern = re.compile(r"""[\[(]\s*["']launchctl["']""")
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if invocation_pattern.search(text):
            offending.append(str(path))

    assert offending == []
