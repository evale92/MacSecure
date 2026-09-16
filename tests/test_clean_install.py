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

import ast

import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest


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
    db_path = Path(env["HOME"]) / ".secure" / "secure.db"

    _run_secure(env, ["init"], root)
    try:
        result = _run_secure_while_scans_progress(env, ["run-all"], root, db_path, tmp_path)
    except _NoProgress as exc:
        pytest.fail(f"{exc}; {_perf_rows_so_far(db_path)}")

    assert result.returncode in (0, 1)  # 1 = new correlation alerts, still a clean run
    # The run's output is read back from files, so prove it was read back at
    # all: an empty capture would make the next assertion true of nothing.
    assert "inventory" in result.stdout.lower()
    assert "Traceback" not in result.stderr


# -------------------------------------------------------------------------
# Waiting on run-all by progress instead of by elapsed time (J-0469).
#
# The old form gave the subprocess a fixed 120s wall-clock budget. That
# budget failed once in a loaded full-suite run (2026-09-14 at 0d7abe3,
# 927s suite) while the same test passed alone in 25.67s — a behaviour test
# losing to contention, which TESTING_POLICY rule 6 forbids depending on in
# the first place. Raising the number would only move the threshold.
#
# Measured solo 2026-09-15 at 93a7296: run-all takes ~24s, and ~22s of that
# is inside the nine scans, whose wall time is almost entirely spent waiting
# on the network or an external tool rather than computing — inventory 9.9s
# wall / 0.8s cpu, wifi 4.3s / 0.0s cpu, 2.4s cpu across all nine. Load
# inflates the computing and not the waiting, so total elapsed is the part
# of this that contention moves and the part the test never meant to assert.
#
# What a hang actually looks like is one scan that never returns. Each scan
# commits its perf_module_runs row as it finishes and those rows are visible
# to a second connection while the run is still going (verified: nine rows
# observed live, largest gap between two of them 10.2s, no lock contention),
# so a hung scan shows up as the absence of a new row. That is what this
# waits on.
# -------------------------------------------------------------------------

# 6x the largest gap between two finished scans measured solo (10.2s).
_SCAN_STALL_SECONDS = 60.0
# Backstop only: nine scans each finishing just inside the stall budget
# cannot reach this, so it fires only if the progress signal itself breaks.
_RUN_ALL_CEILING_SECONDS = 600.0


class _NoProgress(AssertionError):
    """The program under test stopped recording finished work."""


def _wait_for_progress(
    proc: subprocess.Popen,
    progress_count,
    stall_seconds: float,
    ceiling_seconds: float,
    poll_seconds: float = 0.5,
) -> int:
    """Wait for `proc`, judging it by progress rather than by elapsed time.

    `progress_count()` returns a non-decreasing count of work the program has
    durably recorded somewhere the test can read while it runs. Every increase
    resets the stall clock, so a slow machine only makes the program slower,
    never wrong. Returns the exit status; raises `_NoProgress` — after killing
    the process — if `stall_seconds` pass with the count unchanged, or if
    `ceiling_seconds` pass in total.

    Reusable wherever a subprocess under test writes durable progress: it is
    the only way to tell "hung" from "loaded" without asserting a speed.
    """
    started = time.monotonic()
    last_change = started
    seen = progress_count()
    while proc.poll() is None:
        time.sleep(poll_seconds)
        now = time.monotonic()
        current = progress_count()
        if current > seen:
            seen, last_change = current, now
        if now - last_change > stall_seconds:
            proc.kill()
            proc.wait()
            raise _NoProgress(
                f"no progress for {stall_seconds:.0f}s after {seen} completed"
                f" (killed {now - started:.0f}s in)"
            )
        if now - started > ceiling_seconds:
            proc.kill()
            proc.wait()
            raise _NoProgress(
                f"still running after {ceiling_seconds:.0f}s with {seen} completed"
            )
    return proc.wait()


def _finished_scan_count(db_path: Path) -> int:
    """How many scans have committed their perf_module_runs row so far.

    Never raises: before `init` the file is absent, and a read that loses a
    race with the writer is not evidence of a stall, so both report the count
    as unchanged and let the next poll decide.
    """
    if not db_path.exists():
        return 0
    try:
        conn = sqlite3.connect(db_path, timeout=0.2)
        try:
            return conn.execute("SELECT COUNT(*) FROM perf_module_runs").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def _run_secure_while_scans_progress(
    env: dict,
    args: list[str],
    cwd: Path,
    db_path: Path,
    out_dir: Path,
    stall_seconds: float = _SCAN_STALL_SECONDS,
    ceiling_seconds: float = _RUN_ALL_CEILING_SECONDS,
) -> subprocess.CompletedProcess:
    """`_run_secure`, but bounded by scan progress instead of by a deadline.

    Output goes to files rather than pipes for two reasons: a kill discards
    whatever a block-buffered pipe was holding, and a reader that is polling
    instead of draining the pipe would deadlock the child on a full buffer.
    """
    out_path, err_path = out_dir / "run_all.out", out_dir / "run_all.err"
    with open(out_path, "w") as out, open(err_path, "w") as err:
        proc = subprocess.Popen(
            [sys.executable, "-m", "secure", *args],
            stdout=out, stderr=err, env=env, cwd=str(cwd),
        )
        returncode = _wait_for_progress(
            proc, lambda: _finished_scan_count(db_path), stall_seconds, ceiling_seconds
        )
    return subprocess.CompletedProcess(
        proc.args, returncode, out_path.read_text(), err_path.read_text()
    )


def _sleeping_child(seconds: float) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})"])


def test_wait_for_progress_kills_a_run_that_stops_recording_finished_work():
    """The condition the budget is actually for: the program is alive and
    producing nothing. Killing it is what keeps a hang from becoming a
    suite-length wait, so this asserts the process is dead afterwards too.
    """
    proc = _sleeping_child(30)
    try:
        with pytest.raises(_NoProgress) as caught:
            _wait_for_progress(proc, lambda: 0, stall_seconds=1.0, ceiling_seconds=60.0, poll_seconds=0.1)
        assert "no progress for 1s" in str(caught.value)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:  # pragma: no cover - only if the assertion above fails
            proc.kill()


def test_wait_for_progress_lets_a_slow_but_progressing_run_finish():
    """The positive control, and the whole point of the change: this child
    runs three times the stall budget and is not killed, because every poll
    sees more work finished. A fixed elapsed-time budget fails it.
    """
    calls = iter(range(1000))
    proc = _sleeping_child(3)
    try:
        returncode = _wait_for_progress(
            proc, lambda: next(calls), stall_seconds=1.0, ceiling_seconds=60.0, poll_seconds=0.1
        )
        assert returncode == 0
    finally:
        if proc.poll() is None:  # pragma: no cover - only if the assertion above fails
            proc.kill()


def test_wait_for_progress_ceiling_fires_even_while_progress_keeps_arriving():
    """A progress signal that increments without the work advancing would
    otherwise let a run wait forever, so the backstop does not consult it.
    """
    calls = iter(range(1000))
    proc = _sleeping_child(30)
    try:
        with pytest.raises(_NoProgress) as caught:
            _wait_for_progress(
                proc, lambda: next(calls), stall_seconds=100.0, ceiling_seconds=1.0, poll_seconds=0.1
            )
        assert "still running after 1s" in str(caught.value)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:  # pragma: no cover - only if the assertion above fails
            proc.kill()


def test_finished_scan_count_reports_zero_rather_than_raising_on_an_absent_db(tmp_path: Path):
    """A stall is decided by the count not moving, so an unreadable database
    must read as "no new information" and never as an exception that would
    escape the waiter and be reported as some other failure.
    """
    assert _finished_scan_count(tmp_path / "nothing.db") == 0

    not_a_db = tmp_path / "garbage.db"
    not_a_db.write_bytes(b"this is not a sqlite file")
    assert _finished_scan_count(not_a_db) == 0


def _perf_rows_so_far(db_path: Path) -> str:
    """Which scans a killed run finished, with wall and CPU seconds each.

    Wall far above CPU is a scan waiting on the network or an external
    tool; the scan after the last one listed is the one that was running.
    """
    if not db_path.exists():
        return "no database, so no scan finished"
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT module, duration_seconds, cpu_time_seconds FROM perf_module_runs ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return "no scan finished"
    done = ", ".join(f"{module} {wall:.1f}s wall/{cpu or 0:.1f}s cpu" for module, wall, cpu in rows)
    return f"finished: {done}; killed during the scan after {rows[-1][0]}"


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


def test_no_source_file_uses_a_self_naming_tempfile_helper():
    """Static check covering ONE shape of invariant-12 leak: the
    tempfile helpers that pick their own path
    (NamedTemporaryFile/mkstemp/mkdtemp), which leave a file or
    directory the caller never named and so cannot be sure it removed.
    secure/validate/'s own sandbox uses TemporaryDirectory as a context
    manager instead, which self-cleans, and is excluded below.

    This check is deliberately narrow, and its name now says so. It
    does NOT establish the broader claim in SECURITY_INVARIANTS.md
    ("no write path outside cfg.app_dir_path()") — a module writing to
    a hardcoded absolute path passes it untouched. That broader claim
    is enforced by
    test_no_source_file_writes_to_a_hardcoded_path_outside_the_app_dir
    below, which is what actually fails when a write escapes.
    """
    root = _project_root() / "secure"
    offending = []
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "validate" in path.parts or path.name == "validate.py":
            continue  # secure/validate/'s own tempfile-sandboxed fixtures
        # Phase 47.5: parsed, not grepped. The previous version scanned
        # raw text including docstrings and comments, so a module that
        # merely EXPLAINED why it does not use these functions would
        # have failed the check. Detecting a real Call node keeps the
        # invariant while letting the code document itself.
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
        except SyntaxError:  # pragma: no cover — a syntax error is a different test's problem
            continue
        banned = {"NamedTemporaryFile", "mkstemp", "mkdtemp"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name in banned:
                offending.append(f"{path}:{node.lineno}: {name}()")

    assert offending == []


# A write-shaped call reached through a module: the argument index below
# is the thing being WRITTEN, never the source being read from, so
# shutil.copy("/var/log/x", app_dir / "y") is not flagged for its source.
_MODULE_WRITE_CALLS = {
    ("shutil", "copy"): 1,
    ("shutil", "copy2"): 1,
    ("shutil", "copytree"): 1,
    ("shutil", "move"): 1,
    ("shutil", "rmtree"): 0,
    ("os", "rename"): 1,
    ("os", "replace"): 1,
    ("os", "makedirs"): 0,
    ("os", "mkdir"): 0,
    ("os", "remove"): 0,
    ("os", "unlink"): 0,
}

# Path methods that write; the target is the Path they are called on.
_PATH_WRITE_METHODS = {"write_text", "write_bytes", "touch", "mkdir", "unlink", "rmdir"}

_MUTATING_MODE_CHARS = set("wax+")


def _is_mutating_mode(node: ast.Call, positional_index: int) -> bool:
    """True only when the mode argument is a literal containing w/a/x/+.

    A non-literal mode is treated as read-only on purpose: guessing at a
    computed mode would produce false positives, and this check is only
    useful if a failure is always a real one.
    """
    mode = None
    if len(node.args) > positional_index:
        mode = node.args[positional_index]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return bool(set(mode.value) & _MUTATING_MODE_CHARS)
    return False


def _write_targets(node: ast.Call) -> list[ast.AST]:
    """The expressions a call writes to, or [] if it writes nothing."""
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open" and _is_mutating_mode(node, 1):
        return node.args[:1]
    if isinstance(func, ast.Attribute):
        owner = getattr(func.value, "id", None)
        index = _MODULE_WRITE_CALLS.get((owner, func.attr))
        if index is not None:
            return node.args[index:index + 1]
        if func.attr in _PATH_WRITE_METHODS:
            return [func.value]
        if func.attr == "open" and _is_mutating_mode(node, 0):
            return [func.value]
    return []


def _escapes_app_dir(target: ast.AST) -> str | None:
    """Why this write target is not rooted at cfg.app_dir_path(), or None.

    Two shapes, both of which a `rm -rf ~/.secure` uninstall cannot
    reach: a literal absolute path, and a path built from the real home
    directory. Reads of either are fine and are never inspected — only
    expressions already identified as write targets get here.
    """
    for sub in ast.walk(target):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if sub.value.startswith("/") and len(sub.value) > 1:
                return f"absolute path literal {sub.value!r}"
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if sub.func.attr == "home":
                return "a path built from Path.home()"
            if sub.func.attr == "expanduser":
                return "a path built from expanduser()"
    return None


def _hardcoded_write_targets(source: str, filename: str) -> list[str]:
    """Every write in `source` aimed somewhere cfg.app_dir_path() isn't."""
    offending = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:  # pragma: no cover — a syntax error is a different test's problem
        return offending
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for target in _write_targets(node):
            reason = _escapes_app_dir(target)
            if reason:
                offending.append(f"{filename}:{node.lineno}: writes to {reason}")
    return offending


def test_no_source_file_writes_to_a_hardcoded_path_outside_the_app_dir():
    """The real invariant-12 structural check: no write in this codebase
    targets a hardcoded absolute path or a home-rooted path, because
    every one of those survives `rm -rf ~/.secure`.

    Note what is NOT banned: READING an absolute path. Sensors
    legitimately read ~/Library/LaunchAgents, /etc, and disk usage at
    Path.home() — secure/persistence/launch_items.py and
    secure/continuity.py do exactly that. Invariant 4 makes observation
    read-only, so a home-rooted path is only a violation when something
    writes to it, which is why this walks write targets rather than
    every path expression.

    Stated limit, so nobody reads more into a pass than it earns: the
    target expression is matched syntactically, so a write reached
    through a variable (`p = plist_path(); p.write_text(...)`) is
    invisible to it. It catches the direct shape, which is the one an
    edit actually introduces; it is not a proof of absence. The nearest
    live example is secure/agent/supervisor.py's launchd_plist_path(),
    whose two callers were read by hand and only stat and interpolate
    it.
    """
    root = _project_root() / "secure"
    offending = []
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if "validate" in path.parts or path.name == "validate.py":
            continue  # secure/validate/'s own tempfile-sandboxed fixtures
        offending.extend(
            _hardcoded_write_targets(path.read_text(encoding="utf-8", errors="ignore"), str(path))
        )

    assert offending == []


def test_the_hardcoded_write_path_check_detects_a_real_escape():
    """Positive control for the test above, which would otherwise be
    indistinguishable from a checker that never fires.

    The tree it scans is clean, so `offending == []` there passes
    whether the analysis works or is a no-op. This pins both
    directions against source it constructs itself: four real escapes
    are each caught, and read-only uses of the same paths are not.
    """
    escapes = [
        'open("/tmp/x.txt", "w").write("a")',
        'from pathlib import Path\n(Path.home() / ".other" / "r.json").write_text("{}")',
        'from pathlib import Path\nPath("/Library/LaunchDaemons/x.plist").write_bytes(b"")',
        'import shutil\nshutil.copy(src, "/Library/LaunchDaemons/x.plist")',
    ]
    for source in escapes:
        found = _hardcoded_write_targets(source, "probe.py")
        assert len(found) == 1, f"missed an escape in {source!r}: {found}"

    reads_only = (
        "import shutil\n"
        "from pathlib import Path\n"
        "open('/etc/hosts', 'r').read()\n"
        "(Path.home() / 'Library' / 'LaunchAgents').exists()\n"
        "list((Path.home() / 'Library' / 'LaunchAgents').glob('*.plist'))\n"
        "shutil.disk_usage(Path.home())\n"
    )
    assert _hardcoded_write_targets(reads_only, "probe.py") == []


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
