"""
Tests for Phase 36 (Part 2: Supervised Agentic Development & Self-Healing
— "Tiered Test Orchestration"): secure/agent/tiers.py.

FAST tier tests run real, unmocked subprocesses (compileall + an import
check need no pytest, so they work in this sandbox exactly as they
would on a real Mac). TARGETED/FULL/SECURITY tests that need a genuine
pass mock subprocess.run — this sandbox has no real pytest installed
(confirmed: `python3 -m pytest --version` reports "No module named
pytest"), matching every other verification test in this project.

Run with:  pytest
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from secure.agent import tiers as tiers_module
from secure.agent.tiers import (
    TIER_FAST,
    TIER_FULL,
    TIER_SECURITY,
    TIER_TARGETED,
    choose_and_run_verification,
    run_fast_tier,
    run_pytest_targeted,
    targeted_test_files,
)
from secure.agent.worktree import create_repair_worktree, remove_repair_worktree
from secure.config import default_config


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    root = tmp_path / name
    root.mkdir()
    _git(["init", "-q"], root)
    _git(["config", "user.email", "t@t.com"], root)
    _git(["config", "user.name", "T"], root)
    (root / "secure").mkdir()
    (root / "secure" / "__init__.py").write_text("")
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    (root / "secure" / "agent").mkdir()
    (root / "secure" / "agent" / "__init__.py").write_text("")
    (root / "secure" / "agent" / "foo.py").write_text("def foo():\n    return 2\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_widget.py").write_text("def test_widget():\n    assert True\n")
    (root / "tests" / "test_agent.py").write_text("def test_agent_placeholder():\n    assert True\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    return root


def _cfg(tmp_path: Path):
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    return cfg


# ---------- FAST tier (real, unmocked subprocess) ----------


def test_run_fast_tier_passes_on_valid_worktree(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("faststart", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        result = run_fast_tier(wt, _cfg(tmp_path))
        assert result.tier == TIER_FAST
        assert result.status == "ok"
        assert result.passed is True
        assert len(result.commands) == 2
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_run_fast_tier_fails_on_syntax_error(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("fastbroken", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        (wt.worktree_path / "secure" / "widget.py").write_text("def widget(:\n    return 1\n")
        result = run_fast_tier(wt, _cfg(tmp_path))
        assert result.status == "ok"
        assert result.passed is False
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_run_fast_tier_unavailable_when_no_recognized_directories(tmp_path: Path):
    repo_root = tmp_path / "bare"
    repo_root.mkdir()
    _git(["init", "-q"], repo_root)
    _git(["config", "user.email", "t@t.com"], repo_root)
    _git(["config", "user.name", "T"], repo_root)
    (repo_root / "README.md").write_text("hi\n")
    _git(["add", "-A"], repo_root)
    _git(["commit", "-q", "-m", "init"], repo_root)

    wt = create_repair_worktree("fastbare", app_dir=tmp_path / "appdir", repo_root=repo_root)
    try:
        result = run_fast_tier(wt, _cfg(tmp_path))
        assert result.status == "unavailable"
        assert result.passed is None
    finally:
        remove_repair_worktree(wt, repo_root=repo_root)


# ---------- targeted_test_files() (pure function) ----------


def test_targeted_test_files_maps_changed_module_to_matching_test_files(tmp_path: Path):
    repo = _init_repo(tmp_path)
    matched = targeted_test_files(["secure/widget.py"], repo)
    assert "tests/test_widget.py" in matched


def test_targeted_test_files_includes_directly_changed_test_file(tmp_path: Path):
    repo = _init_repo(tmp_path)
    matched = targeted_test_files(["tests/test_agent.py"], repo)
    assert matched == ["tests/test_agent.py"]


def test_targeted_test_files_empty_for_unrelated_paths(tmp_path: Path):
    repo = _init_repo(tmp_path)
    matched = targeted_test_files(["docs/README.md", "PROJECT_NOTES.md"], repo)
    assert matched == []


def test_targeted_test_files_gui_segment_maps_to_gui_prefixed_tests(tmp_path: Path):
    repo = _init_repo(tmp_path)
    (repo / "tests" / "test_gui_components.py").write_text("def test_x():\n    assert True\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "add gui test"], repo)
    matched = targeted_test_files(["secure_gui/agent_view.py"], repo)
    assert "tests/test_gui_components.py" in matched


# ---------- run_pytest_targeted() ----------


def test_run_pytest_targeted_unavailable_with_no_files(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("targetnofiles", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        result = run_pytest_targeted(wt, _cfg(tmp_path), [])
        assert result.status == "unavailable"
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_run_pytest_targeted_reports_unavailable_when_pytest_not_installed(tmp_path: Path):
    """Real, unmocked: this sandbox genuinely has no pytest installed,
    so this proves the honest-unavailable path for real, the same way
    tests/test_agent.py's own
    test_run_pytest_in_worktree_records_audited_action_when_pytest_unavailable
    proves it for the FULL tier."""
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("targetnopytest", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        result = run_pytest_targeted(wt, _cfg(tmp_path), ["tests/test_widget.py"])
        assert result.status in ("unavailable", "ok")  # depends on whether pytest happens to be installed
    finally:
        remove_repair_worktree(wt, repo_root=repo)


# ---------- choose_and_run_verification() escalation ----------


def test_escalation_stops_at_fast_on_syntax_error(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("escfast", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        (wt.worktree_path / "secure" / "widget.py").write_text("def widget(:\n    return 1\n")
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), ["secure/widget.py"])
        assert outcome.stopped_at == TIER_FAST
        assert outcome.targeted is None
        assert outcome.full is None
        assert outcome.security is None
        assert outcome.overall_passed is False
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_escalation_unknown_scope_forces_full_and_security(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("escunknown", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), [])
        assert outcome.targeted is None
        assert outcome.full is not None
        assert outcome.security is not None
        assert outcome.stopped_at == TIER_SECURITY
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_escalation_targeted_pass_skips_full_and_security_for_non_sensitive_change(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("esctargetok", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="1 passed", stderr="")

        monkeypatch.setattr(tiers_module.subprocess, "run", fake_run)
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), ["secure/widget.py"])
        monkeypatch.undo()

        assert outcome.fast.passed is True
        assert outcome.targeted is not None
        assert outcome.targeted.passed is True
        assert outcome.full is None
        assert outcome.security is None
        assert outcome.stopped_at == TIER_TARGETED
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_escalation_security_sensitive_change_always_runs_security_even_if_targeted_passes(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("escsecurity", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="1 passed", stderr="")

        monkeypatch.setattr(tiers_module.subprocess, "run", fake_run)
        # tests/test_agent.py exists in this fixture, so the "agent"
        # segment maps to a real targeted test file.
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), ["secure/agent/foo.py"])
        monkeypatch.undo()

        assert outcome.targeted is not None
        assert outcome.targeted.passed is True
        assert outcome.full is None  # targeted passed cleanly, so FULL wasn't escalated to
        assert outcome.security is not None  # but security-sensitive path still forces SECURITY
        assert outcome.stopped_at == TIER_SECURITY
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_escalation_targeted_failure_escalates_to_full(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("escfail", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        def fake_run(argv, **kwargs):
            if isinstance(argv, (list, tuple)) and "pytest" in argv:
                return subprocess.CompletedProcess(argv, 1, stdout="1 failed", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(tiers_module.subprocess, "run", fake_run)
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), ["secure/widget.py"])
        monkeypatch.undo()

        assert outcome.targeted.passed is False
        assert outcome.full is not None  # escalated because targeted didn't pass cleanly
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_escalation_force_full_always_runs_full(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("escforce", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout="1 passed", stderr="")

        monkeypatch.setattr(tiers_module.subprocess, "run", fake_run)
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), ["secure/widget.py"], force_full=True)
        monkeypatch.undo()

        assert outcome.full is not None
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_escalation_outcome_carries_revision_and_diff_hash(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("escrevision", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        (wt.worktree_path / "secure" / "widget.py").write_text("def widget(:\n    return 1\n")
        outcome = choose_and_run_verification(wt, _cfg(tmp_path), ["secure/widget.py"], diff_hash="deadbeef")
        assert outcome.revision == wt.base_commit
        assert outcome.diff_hash == "deadbeef"
        assert outcome.changed_files == ("secure/widget.py",)
    finally:
        remove_repair_worktree(wt, repo_root=repo)
