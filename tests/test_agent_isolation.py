"""
Tests for Phase 35 (Part 2: Supervised Agentic Development & Self-Healing
— "Sandboxed Repair Workflow"). Phase 31 already built the isolation
mechanism this phase hardens (git worktrees, a throwaway agent-home
directory used as HOME for every subprocess); Phase 35's own job was to
close verification gaps in how thoroughly that isolation is proven,
not to build new isolation machinery — see docs/AGENT_FOUNDATION.md's
"Phase 35" section for the full rationale, including what this phase
deliberately does NOT claim to fix (there is still no OS-level sandbox
— see Phase 31's own documented limitation, repeated there on purpose).

Run with:  pytest
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from secure.agent import verify as verify_module
from secure.agent.verify import run_validate_in_worktree
from secure.agent.worktree import create_repair_worktree, remove_repair_worktree
from secure.config import default_config


# ---------- shared helpers (mirrors tests/test_agent.py's own) ----------


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    root = tmp_path / name
    root.mkdir()
    _git(["init", "-q"], root)
    _git(["config", "user.email", "t@t.com"], root)
    _git(["config", "user.name", "T"], root)
    (root / "README.md").write_text("hello\n")
    (root / "secure").mkdir()
    (root / "secure" / "config.py").write_text("# config\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    return root


def _cfg(tmp_path: Path):
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    return cfg


# ---------- HOME isolation symmetry (pytest already proven; validate wasn't) ----------


def test_run_validate_in_worktree_uses_isolated_home(tmp_path: Path, monkeypatch):
    """Mirrors tests/test_agent.py's own
    test_run_pytest_in_worktree_uses_isolated_home — Phase 31 already
    isolated BOTH verification subprocess calls via the same
    _isolated_env() helper, but only the pytest half had a dedicated
    adversarial proof. This closes that asymmetry for the
    `secure validate run` half."""
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("validatehome", app_dir=tmp_path / "appdir", repo_root=repo)

    captured = {}
    real_run = subprocess.run

    def fake_run(argv, **kwargs):
        if isinstance(argv, (list, tuple)) and str(argv[0]) == "git":
            return real_run(argv, **kwargs)
        captured["env_home"] = kwargs["env"]["HOME"]
        # Simulate a clean, zero-scenario validate run so
        # _read_latest_validation_verdict() (which reads a real sqlite
        # file under env["HOME"]) sees no database and returns None
        # rather than raising — this test is only about the HOME value
        # handed to the subprocess, not the verdict-reading path.
        return subprocess.CompletedProcess(argv, 0, stdout="validate output", stderr="")

    cfg = _cfg(tmp_path)
    monkeypatch.setattr(verify_module.subprocess, "run", fake_run)
    result = run_validate_in_worktree(wt, cfg)
    assert result.status == "ok"
    assert captured["env_home"] == str(wt.agent_home_path)

    real_home = os.environ.get("HOME", "")
    if real_home:
        assert captured["env_home"] != real_home

    monkeypatch.undo()
    remove_repair_worktree(wt, repo_root=repo)


# ---------- discard completeness ----------


def test_removed_worktree_leaves_no_git_worktree_list_residue(tmp_path: Path):
    """Adversarial: 'a failed repair must be completely discardable'
    means more than 'the directory is gone' — git itself must no
    longer consider the path a registered worktree of the live repo.
    A leftover registration (e.g. from a crash between `worktree
    remove` and `worktree prune`) would make git refuse to reuse that
    path and would show up in `git worktree list` forever, a persistent
    trace Phase 35's own acceptance criterion rules out."""
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("discardme", app_dir=tmp_path / "appdir", repo_root=repo)

    # Simulate a messy failed repair: extra files, a nested directory,
    # something that looks like a stray lock or cache file.
    (wt.worktree_path / "secure" / "junk.py").write_text("evil = True\n")
    (wt.worktree_path / "some_cache_dir").mkdir()
    (wt.worktree_path / "some_cache_dir" / "cache.bin").write_bytes(b"\x00\x01\x02")
    (wt.agent_home_path / ".secure").mkdir()
    (wt.agent_home_path / ".secure" / "secure.db").write_bytes(b"not a real db")

    before = _git(["worktree", "list"], repo).stdout
    assert str(wt.worktree_path) in before

    remove_repair_worktree(wt, repo_root=repo)

    after = _git(["worktree", "list"], repo).stdout
    assert str(wt.worktree_path) not in after
    assert not wt.worktree_path.exists()
    assert not wt.agent_home_path.exists()
    assert not wt.run_dir.exists()


def test_removed_worktree_permits_a_fresh_worktree_at_the_same_run_id(tmp_path: Path):
    """A stronger, behavioral proof of the same thing: if `git worktree
    remove` + `prune` left any registration behind, git would refuse to
    let a second worktree reuse the exact same path. Successfully
    creating a second one with the identical run_id right after removal
    is direct evidence the first left nothing behind."""
    repo = _init_repo(tmp_path)
    app_dir = tmp_path / "appdir"
    wt1 = create_repair_worktree("reuseid", app_dir=app_dir, repo_root=repo)
    remove_repair_worktree(wt1, repo_root=repo)

    wt2 = create_repair_worktree("reuseid", app_dir=app_dir, repo_root=repo)
    assert wt2.worktree_path.is_dir()
    remove_repair_worktree(wt2, repo_root=repo)


# ---------- the underlying OS/Python mechanism verify.py depends on ----------


def test_home_env_override_mechanism_is_honored_by_python_path_home(tmp_path: Path):
    """Real subprocess, no mocking: proves the actual mechanism
    secure/agent/verify.py's _isolated_env() relies on — that setting
    `env["HOME"]` on a subprocess.run() call genuinely changes what
    Path.home() resolves to INSIDE that subprocess, independent of this
    test process's own real HOME. This is what makes AppConfig's
    DEFAULT_APP_DIR (Path.home() / ".secure", resolved at import time
    inside the subprocess, never this process) land under the
    throwaway directory rather than the operator's real ~/.secure when
    `secure validate run` executes inside a repair worktree."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()

    env = dict(os.environ)
    env["HOME"] = str(fake_home)

    proc = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; print(Path.home())"],
        env=env, capture_output=True, text=True, timeout=10.0, shell=False,
    )
    assert proc.returncode == 0
    resolved = proc.stdout.strip()
    assert resolved == str(fake_home)

    real_home = os.environ.get("HOME", "")
    if real_home:
        assert resolved != real_home


def test_agent_home_path_is_never_the_real_operator_home_and_starts_empty(tmp_path: Path):
    """Structural, no subprocess: the throwaway agent_home_path must
    never literally BE the real operator HOME directory (otherwise
    HOME-overriding a subprocess would provide no isolation at all,
    regardless of how faithfully _isolated_env() sets the env var), and
    it must start out empty — never pre-seeded with anything from a
    real ~/.secure — so a subprocess pointed at it can never find an
    operator's real config/database sitting there already.

    Note: this deliberately does NOT assert agent_home_path is outside
    the real HOME directory tree — in this project's own CI/dev sandbox
    HOME is set to a broad umbrella directory that tmp_path fixtures
    also live under, so "not nested under HOME" is a sandbox-layout
    artifact, not a real isolation property. What actually matters, and
    what's asserted here, is that the two paths are never the SAME
    directory and that the throwaway one starts genuinely empty."""
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("homenotreal", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        real_home = os.environ.get("HOME", "")
        if real_home:
            assert wt.agent_home_path.resolve() != Path(real_home).resolve()
        assert list(wt.agent_home_path.iterdir()) == []
    finally:
        remove_repair_worktree(wt, repo_root=repo)
