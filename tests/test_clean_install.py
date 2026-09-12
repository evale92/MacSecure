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
