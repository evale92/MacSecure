"""
Tests for Phase 33 (Part 2: Supervised Agentic Development & Self-Healing —
"mini-SWE-agent Repair Integration"): secure/agent/context.py, plus its
wiring into secure/agent/runner.py's task-text construction and
secure/agent/orchestrator.py's attempt_repair()/resume_repair_run().

Real `git` subprocesses are used for repo/history fixtures, matching
tests/test_agent.py's own convention.

Run with:  pytest
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from secure.agent import orchestrator as orch_module
from secure.agent.context import (
    RepairContext,
    build_repair_context,
    render_context_block,
)
from secure.agent.orchestrator import attempt_repair
from secure.agent.policy import (
    TRIGGER_DETECT_RULE_TEST_FAILURE,
    TRIGGER_PYTEST_FAILURE,
    RepairCandidate,
)
from secure.agent.runner import build_mini_argv, run_mini_swe_agent
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.config import AppConfig, default_config
from secure.storage.database import Database


# ---------- shared helpers ----------


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    root = tmp_path / name
    root.mkdir()
    _git(["init", "-q"], root)
    _git(["config", "user.email", "t@t.com"], root)
    _git(["config", "user.name", "T"], root)
    (root / "secure").mkdir()
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_widget.py").write_text("def test_widget():\n    assert True\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    # A second commit touching secure/widget.py, so it has real history
    # beyond the initial commit — used to prove _git_log_for_file()
    # returns more than one line when more than one exists.
    (root / "secure" / "widget.py").write_text("def widget():\n    return 2\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "bump widget"], root)
    return root


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


# ---------- _extract_affected_files() / build_repair_context() ----------


def test_build_repair_context_pytest_trigger_includes_the_failing_test_file(tmp_path: Path):
    repo = _init_repo(tmp_path)
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
    context = build_repair_context(candidate, root=repo)
    assert "tests/test_widget.py" in context.affected_files


def test_build_repair_context_extracts_traceback_file_paths_from_detail(tmp_path: Path):
    repo = _init_repo(tmp_path)
    detail = "secure/widget.py:12: in widget\n    raise ValueError('boom')\nE   ValueError: boom"
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", detail)
    context = build_repair_context(candidate, root=repo)
    assert "secure/widget.py" in context.affected_files


def test_build_repair_context_never_reports_a_nonexistent_file(tmp_path: Path):
    repo = _init_repo(tmp_path)
    detail = "secure/does_not_exist.py:3: in ghost\n    pass"
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/does_not_exist_either.py::t", detail)
    context = build_repair_context(candidate, root=repo)
    assert context.affected_files == ()


def test_build_repair_context_bounds_affected_files_to_max_five(tmp_path: Path):
    repo = _init_repo(tmp_path)
    for i in range(8):
        (repo / "secure" / f"mod{i}.py").write_text("x = 1\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "more files"], repo)
    detail = "\n".join(f"secure/mod{i}.py:1: in f" for i in range(8))
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", detail)
    context = build_repair_context(candidate, root=repo)
    assert len(context.affected_files) <= 5


def test_build_repair_context_non_pytest_trigger_has_no_fabricated_files(tmp_path: Path):
    repo = _init_repo(tmp_path)
    candidate = RepairCandidate(TRIGGER_DETECT_RULE_TEST_FAILURE, "family:rule_key", "fixture=x expected=y actual=z")
    context = build_repair_context(candidate, root=repo)
    # No traceback-shaped lines and no pytest node id to derive a file
    # from — honestly empty, not a guess.
    assert context.affected_files == ()


def test_build_repair_context_recent_changes_populated_for_files_with_history(tmp_path: Path):
    repo = _init_repo(tmp_path)
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "secure/widget.py:1: in f")
    context = build_repair_context(candidate, root=repo)
    assert "secure/widget.py" in context.recent_changes
    assert context.recent_changes["secure/widget.py"].strip() != ""


def test_build_repair_context_policy_excerpts_empty_when_no_policy_files_exist(tmp_path: Path):
    repo = _init_repo(tmp_path)
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
    context = build_repair_context(candidate, root=repo)
    assert context.policy_excerpts == {}


def test_build_repair_context_reads_policy_files_when_present_and_truncates_long_ones(tmp_path: Path):
    repo = _init_repo(tmp_path)
    (repo / "AGENTS.md").write_text("Rule: never weaken tests just to pass.\n")
    (repo / "ARCHITECTURE_RULES.md").write_text("x" * 5000)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "add policy files"], repo)

    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
    context = build_repair_context(candidate, root=repo)

    assert "AGENTS.md" in context.policy_excerpts
    assert "never weaken tests" in context.policy_excerpts["AGENTS.md"]
    assert "ARCHITECTURE_RULES.md" in context.policy_excerpts
    assert len(context.policy_excerpts["ARCHITECTURE_RULES.md"]) < 5000
    assert "more characters truncated" in context.policy_excerpts["ARCHITECTURE_RULES.md"]


def test_build_repair_context_workspace_note_always_present(tmp_path: Path):
    repo = _init_repo(tmp_path)
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
    context = build_repair_context(candidate, root=repo)
    assert "isolated" in context.workspace_note.lower()


# ---------- render_context_block() ----------


def test_render_context_block_omits_files_section_when_none_found():
    context = RepairContext(affected_files=(), recent_changes={}, policy_excerpts={}, workspace_note="note")
    rendered = render_context_block(context)
    assert "Relevant files" not in rendered
    assert "Recent relevant history" not in rendered
    assert "Engineering policy" not in rendered
    assert rendered == "note"


def test_render_context_block_includes_files_and_history_when_present():
    context = RepairContext(
        affected_files=("secure/widget.py",),
        recent_changes={"secure/widget.py": "abc123 bump widget"},
        policy_excerpts={},
        workspace_note="note",
    )
    rendered = render_context_block(context)
    assert "Relevant files:" in rendered
    assert "- secure/widget.py" in rendered
    assert "Recent relevant history" in rendered
    assert "abc123 bump widget" in rendered


def test_render_context_block_omits_history_subsection_when_no_file_has_log():
    context = RepairContext(
        affected_files=("secure/widget.py",), recent_changes={}, policy_excerpts={}, workspace_note="note",
    )
    rendered = render_context_block(context)
    assert "Relevant files:" in rendered
    assert "Recent relevant history" not in rendered


def test_render_context_block_includes_policy_excerpts_when_present():
    context = RepairContext(
        affected_files=(), recent_changes={}, policy_excerpts={"AGENTS.md": "never weaken tests"}, workspace_note="note",
    )
    rendered = render_context_block(context)
    assert "Engineering policy" in rendered
    assert "AGENTS.md" in rendered
    assert "never weaken tests" in rendered


# ---------- runner.py wiring ----------


def test_build_mini_argv_context_none_is_byte_identical_to_before_phase_33(tmp_path: Path):
    from secure.agent.worktree import create_repair_worktree, remove_repair_worktree

    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("ctxnone", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = "/bin/echo"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
        argv_without = build_mini_argv(cfg, wt, candidate)
        argv_explicit_none = build_mini_argv(cfg, wt, candidate, context=None)
        assert argv_without == argv_explicit_none
        task_text = argv_without[argv_without.index("-t") + 1]
        assert "Relevant files" not in task_text
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_build_mini_argv_with_context_appends_rendered_block_to_task_text(tmp_path: Path):
    from secure.agent.worktree import create_repair_worktree, remove_repair_worktree

    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("ctxsome", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = "/bin/echo"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
        context = build_repair_context(candidate, root=repo)
        argv = build_mini_argv(cfg, wt, candidate, context=context)
        task_text = argv[argv.index("-t") + 1]
        assert "Relevant files:" in task_text
        assert "tests/test_widget.py" in task_text
        assert "isolated" in task_text.lower()
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_run_mini_swe_agent_unavailable_ignores_context_gracefully(tmp_path: Path):
    from secure.agent.worktree import create_repair_worktree, remove_repair_worktree

    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("ctxunavail", app_dir=tmp_path / "appdir", repo_root=repo)
    try:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = ""
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")
        context = build_repair_context(candidate, root=repo)
        result = run_mini_swe_agent(cfg, wt, candidate, context=context)
        assert result.status == "unavailable"
    finally:
        remove_repair_worktree(wt, repo_root=repo)


# ---------- orchestrator.py wiring ----------


def test_attempt_repair_builds_and_passes_context_to_run_mini_swe_agent(tmp_path: Path, monkeypatch):
    """Integration proof that attempt_repair() actually builds a
    RepairContext for the candidate and threads it through to
    run_mini_swe_agent() — captured via monkeypatch rather than
    inspecting a real subprocess argv, since this is specifically about
    the orchestration wiring, not runner.py's own rendering (already
    covered above)."""
    repo = _init_repo(tmp_path)
    captured = {}

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        captured["context"] = context
        from secure.agent.runner import MiniRunResult

        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission=None,
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    def fake_verify(worktree, cfg_, **_kwargs):
        return VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok"))

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(orch_module, "verify_worktree", fake_verify)

    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.ollama_host = "http://127.0.0.1:11434"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "secure/widget.py:1: in f")
        attempt_repair(db.conn, cfg, candidate, repo_root=repo)

    assert "context" in captured
    assert captured["context"] is not None
    assert "tests/test_widget.py" in captured["context"].affected_files
    assert "secure/widget.py" in captured["context"].affected_files
