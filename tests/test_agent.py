"""
Tests for Phase 31 Agent Foundation (secure/agent/). Covers every
module (worktree, policy, runner, verify, changes, orchestrator) plus
explicit adversarial tests of the phase's own trust boundaries:

    - the external tool may modify only the isolated worktree, never
      the live repository
    - a path-denylist violation never produces a change request
    - an inconclusive or failing verification never produces a change
      request ("model confidence never equals success")
    - approval is bound to the exact diff hash, not just a text summary
    - bounded retries actually stop
    - resume never re-invokes the external tool

Real `git` subprocesses are used for worktree/orchestrator tests (git
is available in every environment this project runs in); pytest/mini
invocations are monkeypatched where the real binaries aren't
installed in this sandbox, matching tests/test_ai_verify.py's own
"mocked via monkeypatched subprocess.run" convention.

Run with:  pytest
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from pathlib import Path

from secure.agent import changes as changes_module
from secure.agent import orchestrator as orch_module
from secure.agent import policy as policy_module
from secure.agent import runner as runner_module
from secure.agent import verify as verify_module
from secure.agent import worktree as worktree_module
from secure.agent.changes import (
    DenylistCheck,
    RepairNotEligibleForChangeRequest,
    check_path_denylist,
    propose_repair_change_request,
)
from secure.agent.orchestrator import (
    RepairNotEligible,
    attempt_repair,
    resume_repair_run,
    revalidate_before_approval,
)
from secure.agent.policy import (
    PolicyDecision,
    RepairCandidate,
    TRIGGER_DETECT_RULE_TEST_FAILURE,
    TRIGGER_PYTEST_FAILURE,
    TRIGGER_VALIDATE_SCENARIO_FAILURE,
    evaluate_policy,
    find_pytest_failures,
)
from secure.agent.runner import MiniRunResult, build_mini_config, resolve_tool_binary, run_mini_swe_agent, tool_available
from secure.agent.verify import VerificationOutcome, VerifyResult, run_pytest_in_worktree, run_validate_in_worktree
from secure.agent.worktree import (
    RepairWorktree,
    WorktreeError,
    create_repair_worktree,
    current_commit,
    diff_and_changed_files,
    is_git_repository,
    remove_repair_worktree,
    worktree_exists,
)
from secure.ai.changes.workflow import approve_change
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import (
    add_agent_action,
    add_agent_repair_run,
    find_ai_change_request,
    list_agent_actions,
    list_agent_repair_runs,
)


# ---------- shared helpers ----------


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
    (root / "secure" / "validate").mkdir()
    (root / "secure" / "validate" / "runner.py").write_text("# validate runner\n")
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    return root


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


# ---------- worktree.py ----------


def test_is_git_repository_true_and_false(tmp_path: Path):
    repo = _init_repo(tmp_path)
    assert is_git_repository(repo) is True
    assert is_git_repository(tmp_path / "not_a_repo") is False


def test_current_commit_matches_git_rev_parse(tmp_path: Path):
    repo = _init_repo(tmp_path)
    expected = _git(["rev-parse", "HEAD"], repo).stdout.strip()
    assert current_commit(repo) == expected


def test_create_repair_worktree_refuses_existing_run_dir(tmp_path: Path):
    repo = _init_repo(tmp_path)
    app_dir = tmp_path / "appdir"
    wt = create_repair_worktree("slug1", app_dir=app_dir, repo_root=repo)
    try:
        create_repair_worktree("slug1", app_dir=app_dir, repo_root=repo)
        assert False, "should have raised WorktreeError"
    except WorktreeError:
        pass
    remove_repair_worktree(wt, repo_root=repo)


def test_worktree_roundtrip_and_diff_detection(tmp_path: Path):
    repo = _init_repo(tmp_path)
    app_dir = tmp_path / "appdir"
    wt = create_repair_worktree("slug2", app_dir=app_dir, repo_root=repo)
    assert worktree_exists(wt)

    (wt.worktree_path / "secure" / "widget.py").write_text("def widget():\n    return 2\n")
    (wt.worktree_path / "secure" / "newfile.py").write_text("x = 1\n")

    diff_text, changed = diff_and_changed_files(wt)
    assert "secure/widget.py" in changed
    assert "secure/newfile.py" in changed
    assert "widget()" in diff_text or "return 2" in diff_text

    remove_repair_worktree(wt, repo_root=repo)
    assert not wt.worktree_path.exists()


def test_worktree_changes_never_touch_the_live_repo(tmp_path: Path):
    """Adversarial: the whole point of worktree isolation. Modify a file
    inside the worktree and prove the live repo's own tracked file is
    byte-identical before and after."""
    repo = _init_repo(tmp_path)
    original = (repo / "secure" / "widget.py").read_text()

    app_dir = tmp_path / "appdir"
    wt = create_repair_worktree("slug3", app_dir=app_dir, repo_root=repo)
    (wt.worktree_path / "secure" / "widget.py").write_text("def widget():\n    return 999\n")
    (wt.worktree_path / "secure" / "brand_new.py").write_text("evil = True\n")

    assert (repo / "secure" / "widget.py").read_text() == original
    assert not (repo / "secure" / "brand_new.py").exists()

    remove_repair_worktree(wt, repo_root=repo)


# ---------- policy.py ----------


def test_find_pytest_failures_parses_failed_node_ids(tmp_path: Path, monkeypatch):
    fake_output = (
        "F.\n"
        "=================== short test summary info ===================\n"
        "FAILED tests/test_x.py::test_boom - assert 1 == 2\n"
    )

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout=fake_output, stderr="")

    (tmp_path / "tests").mkdir()
    monkeypatch.setattr(policy_module.subprocess, "run", fake_run)
    candidates = find_pytest_failures(root=tmp_path)
    assert len(candidates) == 1
    assert candidates[0].trigger_kind == TRIGGER_PYTEST_FAILURE
    assert candidates[0].trigger_ref == "tests/test_x.py::test_boom"


def test_find_pytest_failures_empty_when_all_pass(tmp_path: Path, monkeypatch):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="3 passed", stderr="")

    (tmp_path / "tests").mkdir()
    monkeypatch.setattr(policy_module.subprocess, "run", fake_run)
    assert find_pytest_failures(root=tmp_path) == []


def test_find_pytest_failures_no_tests_dir_returns_empty(tmp_path: Path):
    assert find_pytest_failures(root=tmp_path) == []


def test_evaluate_policy_rejects_disallowed_trigger_kind(tmp_path: Path):
    repo = _init_repo(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_allowed_trigger_kinds = [TRIGGER_PYTEST_FAILURE]
        candidate = RepairCandidate(TRIGGER_DETECT_RULE_TEST_FAILURE, "sigma:x", "detail")
        decision = evaluate_policy(db.conn, cfg, candidate, repo_root=repo)
        assert decision.allowed is False
        assert "agent_allowed_trigger_kinds" in decision.reason


def test_evaluate_policy_rejects_when_not_git_repo(tmp_path: Path):
    non_repo = tmp_path / "plain_dir"
    non_repo.mkdir()
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
        decision = evaluate_policy(db.conn, cfg, candidate, repo_root=non_repo)
        assert decision.allowed is False
        assert "git repository" in decision.reason


def test_evaluate_policy_rejects_after_max_attempts(tmp_path: Path):
    repo = _init_repo(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_max_attempts = 1
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
        add_agent_repair_run(
            db.conn, created_at="2026-01-01T00:00:00Z", attempt_number=1, max_attempts=1,
            trigger_kind=candidate.trigger_kind, trigger_ref=candidate.trigger_ref, trigger_detail="detail",
            base_commit="abc", worktree_path="/tmp/wt", agent_home_path="/tmp/home",
            tool_name="mini-swe-agent", model_name="ollama/x",
        )
        decision = evaluate_policy(db.conn, cfg, candidate, repo_root=repo)
        assert decision.allowed is False
        assert "agent_max_attempts" in decision.reason
        assert decision.attempts_so_far == 1


def test_evaluate_policy_allows_when_eligible(tmp_path: Path):
    repo = _init_repo(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
        decision = evaluate_policy(db.conn, cfg, candidate, repo_root=repo)
        assert decision.allowed is True
        assert decision.attempts_so_far == 0


# ---------- runner.py ----------


def test_resolve_tool_binary_prefers_configured_path():
    cfg = default_config()
    cfg.agent_tool_binary = "/usr/local/bin/mini"
    assert resolve_tool_binary(cfg) == "/usr/local/bin/mini"


def test_tool_available_false_when_unconfigured(monkeypatch):
    cfg = default_config()
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: None)
    assert tool_available(cfg) is False


def test_build_mini_config_shape(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("cfgtest", app_dir=tmp_path / "appdir", repo_root=repo)
    cfg = default_config()
    cfg.ollama_host = "http://127.0.0.1:11434"
    cfg.ollama_model = "llama3.1"
    cfg.agent_step_limit = 7
    config = build_mini_config(cfg, wt)
    assert config["model"]["model_name"] == "ollama/llama3.1"
    assert config["model"]["model_kwargs"]["api_base"] == "http://127.0.0.1:11434"
    assert config["environment"]["cwd"] == str(wt.worktree_path)
    assert config["agent"]["step_limit"] == 7
    assert config["agent"]["mode"] == "yolo"
    remove_repair_worktree(wt, repo_root=repo)


def test_run_mini_swe_agent_unavailable_when_no_binary(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("unavail", app_dir=tmp_path / "appdir", repo_root=repo)
    cfg = default_config()
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: None)
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
    result = run_mini_swe_agent(cfg, wt, candidate)
    assert result.status == "unavailable"
    remove_repair_worktree(wt, repo_root=repo)


def test_run_mini_swe_agent_home_is_isolated_not_real_home(tmp_path: Path):
    """Adversarial: proves the subprocess env's HOME is the throwaway
    agent-home directory, never this test process's own real HOME."""
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("homeiso", app_dir=tmp_path / "appdir", repo_root=repo)

    fake_bin = tmp_path / "fake_mini.py"
    fake_bin.write_text(
        "import sys, os, json\n"
        "args = sys.argv[1:]\n"
        "out = args[args.index('-o') + 1]\n"
        "marker = os.path.join(os.environ['HOME'], 'ran_here.txt')\n"
        "open(marker, 'w').write('yes')\n"
        "json.dump({'info': {'exit_status': 'Submitted', 'mini_version': 'fake'}}, open(out, 'w'))\n"
    )
    cfg = default_config()
    cfg.agent_tool_binary = f"python3"
    # simulate an executable wrapper by pointing agent_tool_binary at a
    # tiny shim script instead, since resolve_tool_binary expects one binary
    shim = tmp_path / "mini_shim"
    shim.write_text(f"#!/bin/sh\nexec python3 {fake_bin} \"$@\"\n")
    shim.chmod(0o755)
    cfg.agent_tool_binary = str(shim)
    cfg.ollama_host = "http://127.0.0.1:11434"

    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
    result = run_mini_swe_agent(cfg, wt, candidate)
    assert result.status == "completed"
    assert (wt.agent_home_path / "ran_here.txt").is_file()
    import os as _os

    real_home = _os.environ.get("HOME", "")
    if real_home:
        assert not (Path(real_home) / "ran_here.txt").is_file()
    remove_repair_worktree(wt, repo_root=repo)


def test_run_mini_swe_agent_timeout(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("timeouttest", app_dir=tmp_path / "appdir", repo_root=repo)
    shim = tmp_path / "slow_mini"
    shim.write_text("#!/bin/sh\nsleep 5\n")
    shim.chmod(0o755)
    cfg = default_config()
    cfg.agent_tool_binary = str(shim)
    cfg.agent_timeout_seconds = 0.2
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
    result = run_mini_swe_agent(cfg, wt, candidate)
    assert result.status == "timed_out"
    remove_repair_worktree(wt, repo_root=repo)


# ---------- verify.py ----------


def test_run_pytest_in_worktree_unavailable_when_no_tests_dir(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("notests", app_dir=tmp_path / "appdir", repo_root=repo)
    cfg = default_config()
    result = run_pytest_in_worktree(wt, cfg)
    assert result.status == "unavailable"
    remove_repair_worktree(wt, repo_root=repo)


def test_run_pytest_in_worktree_uses_isolated_home(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_x.py").write_text("def test_ok():\n    assert True\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "add tests"], repo)
    wt = create_repair_worktree("pytesthome", app_dir=tmp_path / "appdir", repo_root=repo)

    captured = {}
    real_run = subprocess.run

    def fake_run(argv, **kwargs):
        # subprocess is a single shared module object, so this patch
        # is visible to every importer (worktree.py's own git calls
        # included) — only intercept the pytest invocation itself and
        # pass everything else (e.g. `git worktree remove` during
        # cleanup below) straight through to the real subprocess.run.
        if isinstance(argv, (list, tuple)) and str(argv[0]) == "git":
            return real_run(argv, **kwargs)
        captured["env_home"] = kwargs["env"]["HOME"]
        return subprocess.CompletedProcess(argv, 0, stdout="1 passed", stderr="")

    cfg = default_config()
    monkeypatch.setattr(verify_module.subprocess, "run", fake_run)
    result = run_pytest_in_worktree(wt, cfg)
    assert result.status == "ok"
    assert result.passed is True
    assert captured["env_home"] == str(wt.agent_home_path)
    monkeypatch.undo()
    remove_repair_worktree(wt, repo_root=repo)


def test_run_validate_in_worktree_error_on_nonzero_returncode(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("validateerr", app_dir=tmp_path / "appdir", repo_root=repo)

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Traceback...")

    cfg = default_config()
    monkeypatch.setattr(verify_module.subprocess, "run", fake_run)
    result = run_validate_in_worktree(wt, cfg)
    assert result.status == "error"
    assert result.passed is None
    remove_repair_worktree(wt, repo_root=repo)


def test_verification_outcome_never_true_when_either_inconclusive():
    """Adversarial: a mechanism failure on either check must never be
    read as an overall pass."""
    outcome = VerificationOutcome(
        pytest_result=VerifyResult("unavailable", None, "pytest not installed"),
        validate_result=VerifyResult("ok", True, "12 scenarios ok"),
    )
    assert outcome.overall_passed is None

    outcome2 = VerificationOutcome(
        pytest_result=VerifyResult("ok", True, "ok"),
        validate_result=VerifyResult("timeout", None, "timed out"),
    )
    assert outcome2.overall_passed is None


def test_verification_outcome_true_only_when_both_pass():
    outcome = VerificationOutcome(
        pytest_result=VerifyResult("ok", True, "ok"),
        validate_result=VerifyResult("ok", True, "ok"),
    )
    assert outcome.overall_passed is True

    outcome_fail = VerificationOutcome(
        pytest_result=VerifyResult("ok", False, "1 failed"),
        validate_result=VerifyResult("ok", True, "ok"),
    )
    assert outcome_fail.overall_passed is False


# ---------- changes.py ----------


def test_check_path_denylist_directory_prefix():
    cfg = default_config()
    result = check_path_denylist(["secure/validate/runner.py"], cfg)
    assert result.violated is True


def test_check_path_denylist_exact_file():
    cfg = default_config()
    result = check_path_denylist(["secure/config.py"], cfg)
    assert result.violated is True


def test_check_path_denylist_clean():
    cfg = default_config()
    result = check_path_denylist(["secure/widget.py"], cfg)
    assert result.violated is False
    assert result.detail is None


def test_propose_repair_change_request_refuses_when_not_verified(tmp_path: Path):
    """Adversarial: the core Phase 31 rule — an unverified repair can
    never produce a change request, no matter what."""
    with Database(tmp_path / "secure.db") as db:
        cfg = default_config()
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
        mini_result = MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="x",
            mini_version="2.0.0", instance_cost=0.0, transcript_path=None, model_name="ollama/x",
        )
        for verification in (
            VerificationOutcome(VerifyResult("ok", False, ""), VerifyResult("ok", True, "")),
            VerificationOutcome(VerifyResult("unavailable", None, ""), VerifyResult("ok", True, "")),
        ):
            try:
                propose_repair_change_request(
                    db.conn, cfg, run_id="AR-1", candidate=candidate, diff_text="diff", diff_hash="h",
                    changed_files=["secure/widget.py"], verification=verification, mini_result=mini_result,
                )
                assert False, "should have refused"
            except RepairNotEligibleForChangeRequest:
                pass


def test_propose_repair_change_request_binds_approval_to_diff_hash(tmp_path: Path):
    """Adversarial: approving with the wrong diff hash must fail, and
    the diff's own hash must be embedded in the approved text."""
    with Database(tmp_path / "secure.db") as db:
        cfg = default_config()
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "detail")
        diff_text = "diff --git a/secure/widget.py b/secure/widget.py\n+fix\n"
        diff_hash = hashlib.sha256(diff_text.encode()).hexdigest()
        mini_result = MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="x",
            mini_version="2.0.0", instance_cost=0.0, transcript_path=None, model_name="ollama/x",
        )
        verification = VerificationOutcome(VerifyResult("ok", True, ""), VerifyResult("ok", True, ""))
        record = propose_repair_change_request(
            db.conn, cfg, run_id="AR-1", candidate=candidate, diff_text=diff_text, diff_hash=diff_hash,
            changed_files=["secure/widget.py"], verification=verification, mini_result=mini_result,
        )
        assert record.status == "pending"
        assert diff_hash in record.proposed_change

        from secure.ai.changes.workflow import RevisionMismatchError

        try:
            approve_change(db.conn, record.cr_id, revision_hash="not-the-real-hash", approved_by="tester")
            assert False, "should have raised RevisionMismatchError"
        except RevisionMismatchError:
            pass

        approved = approve_change(db.conn, record.cr_id, revision_hash=record.revision_hash, approved_by="tester")
        assert approved.status == "approved"


# ---------- orchestrator.py (full-pipeline + adversarial) ----------


def _fake_mini_shim(tmp_path: Path, *, mode: str) -> Path:
    script = tmp_path / "fake_mini.py"
    script.write_text(
        "import sys, os, json\n"
        "args = sys.argv[1:]\n"
        "out = args[args.index('-o') + 1]\n"
        "mode = os.environ.get('FAKE_MODE', 'good')\n"
        "cwd = os.getcwd()\n"
        "if mode == 'good':\n"
        "    p = os.path.join(cwd, 'secure', 'widget.py')\n"
        "    open(p, 'a').write('\\n# repaired\\n')\n"
        "elif mode == 'denylist':\n"
        "    p = os.path.join(cwd, 'secure', 'config.py')\n"
        "    open(p, 'a').write('\\n# bad\\n')\n"
        "json.dump({'info': {'exit_status': 'Submitted', 'mini_version': 'fake'}}, open(out, 'w'))\n"
    )
    shim = tmp_path / f"mini_shim_{mode}"
    shim.write_text(f"#!/bin/sh\nFAKE_MODE={mode} exec python3 {script} \"$@\"\n")
    shim.chmod(0o755)
    return shim


def test_attempt_repair_no_diff_records_status_and_no_change_request(tmp_path: Path):
    repo = _init_repo(tmp_path)
    shim = tmp_path / "mini_nodiff"
    shim.write_text(
        "#!/bin/sh\n"
        "python3 -c \"import sys,json; args=sys.argv[1:]; out=args[args.index('-o')+1]; "
        "json.dump({'info': {'exit_status': 'Submitted', 'mini_version': 'fake'}}, open(out,'w'))\" \"$@\"\n"
    )
    shim.chmod(0o755)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = str(shim)
        cfg.ollama_host = "http://127.0.0.1:11434"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "boom")
        record = attempt_repair(db.conn, cfg, candidate, repo_root=repo)
        assert record.status == "no_diff"
        assert record.change_request_id is None


def test_attempt_repair_denylist_violation_never_creates_change_request(tmp_path: Path):
    """Adversarial: a repair touching a denylisted path must be
    rejected before any change request exists."""
    repo = _init_repo(tmp_path)
    shim = _fake_mini_shim(tmp_path, mode="denylist")
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = str(shim)
        cfg.ollama_host = "http://127.0.0.1:11434"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "boom")
        record = attempt_repair(db.conn, cfg, candidate, repo_root=repo)
        assert record.status == "rejected_by_denylist"
        assert record.change_request_id is None
        assert "config.py" in record.denylist_violation


def test_attempt_repair_inconclusive_verification_never_creates_change_request(tmp_path: Path, monkeypatch):
    """Adversarial: verification that can't run cleanly must never be
    treated as a pass — the central 'model confidence never equals
    success' guarantee, exercised through the full orchestrator."""
    repo = _init_repo(tmp_path)
    shim = _fake_mini_shim(tmp_path, mode="good")

    def fake_verify(worktree, cfg, **_kwargs):
        return VerificationOutcome(
            pytest_result=VerifyResult("unavailable", None, "no pytest"),
            validate_result=VerifyResult("ok", True, "ok"),
        )

    monkeypatch.setattr(orch_module, "verify_worktree", fake_verify)

    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = str(shim)
        cfg.ollama_host = "http://127.0.0.1:11434"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "boom")
        record = attempt_repair(db.conn, cfg, candidate, repo_root=repo)
        assert record.status == "verification_inconclusive"
        assert record.change_request_id is None
        assert record.verification_passed is None


def test_attempt_repair_full_pass_creates_pending_change_request(tmp_path: Path, monkeypatch):
    """The success path, with verify_worktree monkeypatched to a clean
    pass (this sandbox has no real pytest) — proves the orchestrator's
    own sequencing wires diff -> denylist -> verification -> change
    request correctly end to end."""
    repo = _init_repo(tmp_path)
    shim = _fake_mini_shim(tmp_path, mode="good")

    def fake_verify(worktree, cfg, **_kwargs):
        return VerificationOutcome(
            pytest_result=VerifyResult("ok", True, "3 passed"),
            validate_result=VerifyResult("ok", True, "12 scenarios ok"),
        )

    monkeypatch.setattr(orch_module, "verify_worktree", fake_verify)

    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = str(shim)
        cfg.ollama_host = "http://127.0.0.1:11434"
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "boom")
        record = attempt_repair(db.conn, cfg, candidate, repo_root=repo)
        assert record.status == "verified"
        assert record.verification_passed is True
        assert record.change_request_id is not None

        cr = find_ai_change_request(db.conn, record.change_request_id)
        assert cr.status == "pending"
        assert record.diff_hash in cr.proposed_change


def test_attempt_repair_bounded_retries_stop(tmp_path: Path):
    repo = _init_repo(tmp_path)
    shim = tmp_path / "mini_nodiff2"
    shim.write_text(
        "#!/bin/sh\n"
        "python3 -c \"import sys,json; args=sys.argv[1:]; out=args[args.index('-o')+1]; "
        "json.dump({'info': {'exit_status': 'Submitted', 'mini_version': 'fake'}}, open(out,'w'))\" \"$@\"\n"
    )
    shim.chmod(0o755)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = str(shim)
        cfg.ollama_host = "http://127.0.0.1:11434"
        cfg.agent_max_attempts = 1
        candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/x.py::y", "boom")
        attempt_repair(db.conn, cfg, candidate, repo_root=repo)
        try:
            attempt_repair(db.conn, cfg, candidate, repo_root=repo)
            assert False, "should have refused a second attempt"
        except RepairNotEligible:
            pass
        runs = list_agent_repair_runs(db.conn)
        assert len(runs) == 1


def test_resume_repair_run_requires_running_status(tmp_path: Path):
    repo = _init_repo(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        run_id = add_agent_repair_run(
            db.conn, created_at="2026-01-01T00:00:00Z", attempt_number=1, max_attempts=2,
            trigger_kind=TRIGGER_PYTEST_FAILURE, trigger_ref="x", trigger_detail="d",
            base_commit="abc", worktree_path=str(repo), agent_home_path=str(tmp_path),
            tool_name="mini-swe-agent", model_name="ollama/x",
        )
        from secure.storage.models import complete_agent_repair_run

        complete_agent_repair_run(db.conn, run_id=run_id, completed_at="x", status="no_diff")
        try:
            resume_repair_run(db.conn, cfg, run_id)
            assert False, "should have raised"
        except ValueError as exc:
            assert "not 'running'" in str(exc)


def test_resume_repair_run_never_reinvokes_the_tool(tmp_path: Path, monkeypatch):
    """Adversarial: resuming a crashed run must reuse the diff already
    on disk, never call the external tool again."""
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("resumetest", app_dir=tmp_path / "appdir", repo_root=repo)
    (wt.worktree_path / "secure" / "widget.py").write_text("def widget():\n    return 42\n")

    transcript_path = wt.run_dir / "transcript.traj.json"
    transcript_path.write_text(json.dumps({"info": {"exit_status": "Submitted", "mini_version": "fake"}}))

    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)

        def boom(*args, **kwargs):
            raise AssertionError("run_mini_swe_agent must never be called during resume")

        monkeypatch.setattr(orch_module, "run_mini_swe_agent", boom)

        def fake_verify(worktree, cfg_, **_kwargs):
            return VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok"))

        monkeypatch.setattr(orch_module, "verify_worktree", fake_verify)

        run_id = add_agent_repair_run(
            db.conn, created_at="2026-01-01T00:00:00Z", attempt_number=1, max_attempts=2,
            trigger_kind=TRIGGER_PYTEST_FAILURE, trigger_ref="tests/x.py::y", trigger_detail="boom",
            base_commit=wt.base_commit, worktree_path=str(wt.worktree_path), agent_home_path=str(wt.agent_home_path),
            tool_name="mini-swe-agent", model_name="ollama/x",
        )
        record = resume_repair_run(db.conn, cfg, run_id)
        assert record.status == "verified"
        assert record.change_request_id is not None
    remove_repair_worktree(wt, repo_root=repo)


def test_agent_package_never_calls_approve_or_reject():
    """Adversarial, structural: proves — by parsing the actual source
    (ast, not a raw substring search, since the module docstrings
    legitimately *talk about* not calling these) — that no module
    under secure/agent/ ever imports or calls approve_change() or
    reject_change(). Rule 5 of Phase 28's five hard rules ("AI/agent
    code never authorizes its own change") is enforced by this being
    true of the code, not merely by these functions never being
    exercised in a given test run."""
    import ast

    import secure.agent as agent_pkg

    banned = {"approve_change", "reject_change"}
    agent_dir = Path(agent_pkg.__file__).resolve().parent
    offenders = []
    for py_file in agent_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
                offenders.append(f"{py_file}: imports {[a.name for a in node.names if a.name in banned]}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
                offenders.append(f"{py_file}: calls {node.func.id}()")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in banned:
                offenders.append(f"{py_file}: calls .{node.func.attr}()")
    assert offenders == [], f"secure/agent/ must never import/call approve_change()/reject_change(): {offenders}"


def test_resume_repair_run_errors_without_transcript(tmp_path: Path):
    repo = _init_repo(tmp_path)
    wt = create_repair_worktree("noresumetest", app_dir=tmp_path / "appdir", repo_root=repo)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        run_id = add_agent_repair_run(
            db.conn, created_at="2026-01-01T00:00:00Z", attempt_number=1, max_attempts=2,
            trigger_kind=TRIGGER_PYTEST_FAILURE, trigger_ref="tests/x.py::y", trigger_detail="boom",
            base_commit=wt.base_commit, worktree_path=str(wt.worktree_path), agent_home_path=str(wt.agent_home_path),
            tool_name="mini-swe-agent", model_name="ollama/x",
        )
        record = resume_repair_run(db.conn, cfg, run_id)
        assert record.status == "error"
        assert "transcript" in record.stop_reason
    remove_repair_worktree(wt, repo_root=repo)


# ---------- guardrail 2: pre-approval diff revalidation (explicit user instruction) ----------


def _full_verified_run(conn, cfg, repo, tmp_path: Path, monkeypatch, *, slug: str):
    """Shared setup: drive a repair all the way to 'verified' with a
    real pending change request, exactly like
    test_attempt_repair_full_pass_creates_pending_change_request above.
    Returns the completed AgentRepairRunRecord."""
    shim = _fake_mini_shim(tmp_path, mode="good")

    def fake_verify(worktree, cfg_, **_kwargs):
        return VerificationOutcome(
            pytest_result=VerifyResult("ok", True, "3 passed"),
            validate_result=VerifyResult("ok", True, "12 scenarios ok"),
        )

    monkeypatch.setattr(orch_module, "verify_worktree", fake_verify)
    cfg.agent_tool_binary = str(shim)
    cfg.ollama_host = "http://127.0.0.1:11434"
    candidate = RepairCandidate(TRIGGER_PYTEST_FAILURE, f"tests/{slug}.py::y", "boom")
    return attempt_repair(conn, cfg, candidate, repo_root=repo)


def test_revalidate_before_approval_passes_when_worktree_unchanged(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        record = _full_verified_run(db.conn, cfg, repo, tmp_path, monkeypatch, slug="clean")
        assert record.status == "verified"

        revalidation = revalidate_before_approval(db.conn, cfg, record.run_id)
        assert revalidation.diff_matches is True
        assert revalidation.new_cr_id is None

        cr = find_ai_change_request(db.conn, record.change_request_id)
        assert cr.status == "pending"  # untouched — still approvable normally


def test_revalidate_before_approval_deliberately_broken_diff_supersedes_and_regenerates(
    tmp_path: Path, monkeypatch
):
    """THE deliberately-broken test the user asked for: drive a repair
    to a normal 'verified' state with a real pending change request,
    then deliberately corrupt the worktree afterward (simulating a
    human — or anything else — touching it after the CR was proposed),
    and prove:

      1. the stale change request can never be approved as written —
         revalidate_before_approval() reports diff_matches=False
      2. the stale CR is marked 'superseded', not silently left
         'pending' (approve_change() already refuses non-pending, so
         this closes the loop completely)
      3. a REPLACEMENT change request is generated from the CURRENT,
         re-verified worktree state, with its own correct diff hash
      4. the replacement CR can be approved normally, and revalidating
         it again now reports diff_matches=True (proving the new CR's
         stored diff_hash actually matches what's on disk)
      5. attempting to approve the ORIGINAL cr_id directly (bypassing
         `secure agent approve`) still fails, because Phase 28's own
         approve_change() already requires status == 'pending'
    """
    repo = _init_repo(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        record = _full_verified_run(db.conn, cfg, repo, tmp_path, monkeypatch, slug="drift")
        assert record.status == "verified"
        old_cr_id = record.change_request_id
        old_cr = find_ai_change_request(db.conn, old_cr_id)
        assert old_cr.status == "pending"

        # Deliberately break it: touch the worktree AFTER the change
        # request was already proposed, so the diff on disk no longer
        # matches the diff_hash embedded in old_cr.proposed_change.
        (Path(record.worktree_path) / "secure" / "widget.py").write_text(
            "def widget():\n    return 'DELIBERATELY CORRUPTED AFTER PROPOSAL'\n"
        )

        def fake_verify_ok(worktree, cfg_, **_kwargs):
            return VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok"))

        monkeypatch.setattr(orch_module, "verify_worktree", fake_verify_ok)

        revalidation = revalidate_before_approval(db.conn, cfg, record.run_id)

        # 1. Must refuse.
        assert revalidation.diff_matches is False
        assert revalidation.old_cr_id == old_cr_id

        # 2. Old CR is superseded, never approvable again.
        old_cr_after = find_ai_change_request(db.conn, old_cr_id)
        assert old_cr_after.status == "superseded"
        try:
            approve_change(db.conn, old_cr_id, revision_hash=old_cr.revision_hash, approved_by="attacker")
            assert False, "a superseded change request must never be approvable"
        except ValueError as exc:
            assert "not pending" in str(exc)

        # 3. A replacement CR exists, with a genuinely different diff hash.
        assert revalidation.new_cr_id is not None
        assert revalidation.new_cr_id != old_cr_id
        new_cr = find_ai_change_request(db.conn, revalidation.new_cr_id)
        assert new_cr.status == "pending"
        assert "DELIBERATELY CORRUPTED" not in old_cr.proposed_change  # old CR text is untouched history
        assert new_cr.revision_hash != old_cr.revision_hash

        # 4. The replacement approves normally, and re-revalidating now matches.
        second_revalidation = revalidate_before_approval(db.conn, cfg, record.run_id)
        assert second_revalidation.diff_matches is True
        approved = approve_change(db.conn, new_cr.cr_id, revision_hash=new_cr.revision_hash, approved_by="tester")
        assert approved.status == "approved"


# ---------- Phase 31.5: Agent Action Audit ----------
#
# Two things this section proves, per the governing instruction:
#
#   1. STARTUP SAFETY. Ordinary `secure_gui.py` startup (SecureGUI.__init__
#      reaching the point where mainloop() would be called) cannot invoke
#      mini-SWE-agent, Aider, package managers, open/osascript, sudo,
#      system configuration tools, or agent repair execution — because it
#      cannot invoke ANY subprocess at all. Proven via AST reachability
#      analysis, not live instantiation: tkinter is unavailable in this
#      sandbox (an established, pre-existing project constraint — see
#      tests/test_gui_components.py's own docstring), and secure_gui.py
#      is syntax-checked only, never imported, for the same reason. The
#      key structural fact this relies on: Tkinter widget constructors
#      take callbacks as `command=`/`target=` keyword values — a bare
#      NAME or ATTRIBUTE reference, never wrapped in a Call — so they are
#      never invoked while building the widget, only later, in response
#      to a real user click or a queued/scheduled job. This distinguishes
#      an IMMEDIATE call (`self.method(...)`, an ast.Call node) from a
#      DEFERRED reference (`command=self.method`, an ast.Attribute/Name
#      passed as a value) when walking the construction-time call graph.
#
#   2. AUDIT BOUNDARY COVERAGE. Every function in secure/agent/ that
#      directly invokes subprocess.run/Popen accepts an `audit_trail`
#      parameter (structural proof), and a real attempt_repair() run
#      actually persists correctly-shaped, redacted agent_actions rows
#      for the worktree and tool-invocation subprocesses it makes
#      (functional proof) — see secure/agent/audit.py.


class _ImmediateCallVisitor(ast.NodeVisitor):
    """Collects callee names that execute IMMEDIATELY (unconditionally,
    as part of normal control flow) within a function body — as opposed
    to callables merely referenced for later, deferred invocation.

    `self.foo(...)` and `bar(...)` are immediate calls. `command=self.foo`,
    `target=self.foo`, and anything inside a `lambda` or nested `def` are
    NOT — they are references that only execute later, when something
    else (a user click, a Thread, a Tk `.after()` timer) explicitly
    invokes them. A keyword argument's value only counts as immediate if
    it is itself an ast.Call (e.g. `x=self.compute()` — compute() runs
    now, to produce the value passed in), never a bare Name/Attribute.
    """

    def __init__(self):
        self.self_methods: "set[str]" = set()
        self.other_names: "set[str]" = set()

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
            self.self_methods.add(f.attr)
        elif isinstance(f, ast.Name):
            self.other_names.add(f.id)
        self.visit(f)
        for a in node.args:
            self.visit(a)
        for kw in node.keywords:
            if isinstance(kw.value, ast.Call):
                self.visit(kw.value)
            # else: a deferred reference (Name/Attribute/Lambda/etc as a
            # keyword value) — intentionally NOT recursed into, since it
            # does not execute now.

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return  # a lambda's body never executes at definition time

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return  # a nested def's body never executes at definition time

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return


def _class_method_defs(tree: ast.Module, class_name: str) -> "dict[str, ast.FunctionDef]":
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                n.name: n for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    raise AssertionError(f"class {class_name!r} not found")


def _construction_reachable_methods(tree: ast.Module, class_name: str, entry: str = "__init__") -> "set[str]":
    """BFS over self.method(...) calls only, starting from `entry`,
    using ONLY immediate (non-deferred) calls at every hop — the set of
    method names that are guaranteed to run purely as a side effect of
    constructing the object, before any event loop, click, or scheduled
    callback ever fires."""
    methods = _class_method_defs(tree, class_name)
    assert entry in methods, f"{class_name}.{entry} not found"
    seen: "set[str]" = set()
    frontier = [entry]
    while frontier:
        name = frontier.pop()
        if name in seen or name not in methods:
            continue
        seen.add(name)
        visitor = _ImmediateCallVisitor()
        for stmt in methods[name].body:
            visitor.visit(stmt)
        for callee in visitor.self_methods:
            if callee not in seen:
                frontier.append(callee)
    return seen


def _secure_gui_tree() -> ast.Module:
    path = worktree_module.project_root() / "secure_gui.py"
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_secure_gui_startup_reaches_no_subprocess_call():
    """The core startup-safety proof: the transitive closure of methods
    reachable from SecureGUI.__init__ via IMMEDIATE self.method(...)
    calls contains zero functions whose own body directly invokes
    subprocess.run/Popen, os.system, or os.exec*. This is a STRICTER
    invariant than merely banning mini-SWE-agent/Aider/package managers/
    open/osascript/sudo by name — it proves ordinary app launch cannot
    invoke a subprocess AT ALL, which subsumes every name on that list."""
    tree = _secure_gui_tree()
    methods = _class_method_defs(tree, "SecureGUI")
    reachable = _construction_reachable_methods(tree, "SecureGUI")

    _BANNED_CALL_ATTRS = {("subprocess", "run"), ("subprocess", "Popen"), ("os", "system")}
    _BANNED_EXEC_PREFIXES = ("exec",)  # os.execv, os.execvp, os.execve, ...

    offenders = []
    for name in reachable:
        for node in ast.walk(methods[name]):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            f = node.func
            if not isinstance(f.value, ast.Name):
                continue
            if (f.value.id, f.attr) in _BANNED_CALL_ATTRS:
                offenders.append(f"{name}(): {f.value.id}.{f.attr}(...)")
            if f.value.id == "os" and f.attr.startswith(_BANNED_EXEC_PREFIXES):
                offenders.append(f"{name}(): os.{f.attr}(...)")
    assert offenders == [], (
        "SecureGUI.__init__'s construction-time call graph must never reach a subprocess "
        f"invocation, but found: {offenders}"
    )


def test_secure_gui_startup_never_reaches_named_dangerous_methods():
    """Belt-and-suspenders companion to the test above, phrased exactly
    against the instruction's own banned list: proves the specific
    methods known to invoke mini-SWE-agent / arbitrary `secure ...`
    subprocesses (including `agent run`/`agent approve`, which is how
    agent repair execution and Aider/package-manager/open/osascript/
    sudo/system-configuration-tool invocations would ever reach this
    process) are not in the construction-reachable set — i.e. they are
    only ever wired as deferred button `command=` callbacks."""
    tree = _secure_gui_tree()
    reachable = _construction_reachable_methods(tree, "SecureGUI")

    # _execute() is the single choke point where secure_gui.py spawns
    # `secure ...` as a real subprocess.Popen (including `agent run`,
    # `agent resume`, `agent approve`, `agent remove-worktree` — the
    # only way this GUI process can ever reach mini-SWE-agent, an
    # external package manager, sudo, or a system configuration tool).
    # _worker_loop() is what calls it, from a background thread that is
    # started but left blocked on an empty queue at construction time.
    # _open_agent_window()/_update_and_restart()/_do_relaunch() are the
    # only call sites that can enqueue an `agent ...` job or invoke
    # `open`/relaunch machinery at all.
    _DANGEROUS_METHODS = {
        "_execute", "_worker_loop", "_run_command",
        "_open_agent_window", "_update_and_restart", "_do_relaunch",
    }
    offenders = reachable & _DANGEROUS_METHODS
    assert offenders == set(), (
        f"SecureGUI.__init__ must never reach {sorted(offenders)} — these must only be "
        "wired as deferred button command= callbacks, never called during construction"
    )
    # Sanity check the analysis itself isn't vacuous (e.g. a rename
    # silently making every name in _DANGEROUS_METHODS obsolete): every
    # name above must still exist as a real method on the class.
    all_methods = set(_class_method_defs(tree, "SecureGUI").keys())
    missing = _DANGEROUS_METHODS - all_methods
    assert missing == set(), f"expected methods no longer exist on SecureGUI (rename?): {missing}"


def test_secure_gui_agent_window_only_reachable_via_deferred_command():
    """Confirms the mechanism this whole safety argument depends on: the
    "Agent — Repairs" button really is wired with `command=self.
    _open_agent_window` (a bare Attribute value, never a Call) rather
    than being invoked directly while the toolbar is being built."""
    tree = _secure_gui_tree()
    found_deferred_binding = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "command"
                    and isinstance(kw.value, ast.Attribute)
                    and kw.value.attr == "_open_agent_window"
                    and isinstance(kw.value.value, ast.Name)
                    and kw.value.value.id == "self"
                ):
                    found_deferred_binding = True
    assert found_deferred_binding, "expected a `command=self._open_agent_window` deferred binding somewhere"

    reachable = _construction_reachable_methods(tree, "SecureGUI")
    assert "_open_agent_window" not in reachable


def test_agent_subprocess_call_sites_all_accept_audit_trail_parameter():
    """Structural proof that every allowed agent subprocess call site
    goes through the audited execution boundary: for each of
    secure/agent/{worktree,runner,verify}.py, every function whose body
    directly calls subprocess.run(...)/subprocess.Popen(...) must accept
    an `audit_trail` parameter (positional or keyword-only) — the only
    way secure/agent/audit.py's record_action() can ever see that call."""
    agent_dir = worktree_module.project_root() / "secure" / "agent"
    checked_any = False
    offenders = []
    for filename in ("worktree.py", "runner.py", "verify.py"):
        path = agent_dir / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            has_subprocess_call = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"
                and n.func.attr in ("run", "Popen")
                for n in ast.walk(node)
            )
            if not has_subprocess_call:
                continue
            checked_any = True
            arg_names = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
            if "audit_trail" not in arg_names:
                offenders.append(f"{filename}::{node.name}")
    assert checked_any, "expected at least one subprocess.run/Popen call site in secure/agent/"
    assert offenders == [], f"these functions call subprocess.run/Popen without an audit_trail parameter: {offenders}"


def test_attempt_repair_persists_worktree_and_runner_audit_rows_with_redaction(tmp_path: Path, monkeypatch):
    """Functional proof: a real attempt_repair() call (real git
    subprocesses for the worktree, a real fake-mini shim subprocess for
    the tool invocation) actually lands rows in agent_actions, correctly
    shaped, and with a secret-shaped trigger detail never appearing
    verbatim anywhere in what got persisted."""
    repo = _init_repo(tmp_path)
    shim = _fake_mini_shim(tmp_path, mode="good")

    def fake_verify(worktree, cfg_, **_kwargs):
        return VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok"))

    monkeypatch.setattr(orch_module, "verify_worktree", fake_verify)

    secret = "hunter2_supersecret_password_XYZ"
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.agent_tool_binary = str(shim)
        cfg.ollama_host = "http://127.0.0.1:11434"
        candidate = RepairCandidate(
            TRIGGER_PYTEST_FAILURE, "tests/audit.py::y", f"boom — password={secret} in the traceback"
        )
        record = attempt_repair(db.conn, cfg, candidate, repo_root=repo)
        assert record.status in ("verified", "verification_failed", "verification_inconclusive")

        actions = list_agent_actions(db.conn, run_id=record.run_id)
        assert actions, "expected at least one audited action to be persisted"
        assert all(a.run_id == record.run_id for a in actions)

        components = {a.component for a in actions}
        assert "agent.worktree" in components
        assert "agent.runner" in components

        worktree_add = [a for a in actions if a.action == "git worktree add --detach"]
        assert len(worktree_add) == 1
        assert worktree_add[0].mutating is True
        assert worktree_add[0].exit_code == 0
        assert worktree_add[0].duration_seconds is not None and worktree_add[0].duration_seconds >= 0

        runner_rows = [a for a in actions if a.component == "agent.runner"]
        assert len(runner_rows) == 1
        assert runner_rows[0].mutating is True
        assert runner_rows[0].exit_code == 0

        # Redaction: the raw secret must never appear verbatim anywhere
        # in any persisted argv token or result_summary.
        everything = []
        for a in actions:
            everything.extend(a.argv)
            everything.append(a.result_summary or "")
        blob = "\n".join(everything)
        assert secret not in blob, "a secret-shaped token leaked into the persisted audit trail unredacted"
        # And the runner row's -t argument (which carries the trigger
        # detail) must show up redacted, not silently dropped.
        assert "[REDACTED]" in runner_rows[0].argv


def test_list_agent_actions_filters_by_run_id(tmp_path: Path):
    """Direct storage-layer proof of the run_id filter — independent of
    any orchestration, using add_agent_action()/list_agent_actions()
    directly against a real temp database."""
    with Database(tmp_path / "secure.db") as db:
        add_agent_action(
            db.conn, run_id="AR-1", timestamp="2026-01-01T00:00:00Z", component="agent.worktree",
            action="git rev-parse HEAD", argv=["git", "rev-parse", "HEAD"], cwd="/tmp/repo",
            target="/tmp/repo", mutating=False, approval_required=False, exit_code=0,
            result_summary="exit 0", duration_seconds=0.01,
        )
        add_agent_action(
            db.conn, run_id="AR-2", timestamp="2026-01-01T00:00:01Z", component="agent.worktree",
            action="git rev-parse HEAD", argv=["git", "rev-parse", "HEAD"], cwd="/tmp/repo2",
            target="/tmp/repo2", mutating=False, approval_required=False, exit_code=0,
            result_summary="exit 0", duration_seconds=0.02,
        )
        only_ar1 = list_agent_actions(db.conn, run_id="AR-1")
        assert len(only_ar1) == 1
        assert only_ar1[0].run_id == "AR-1"
        assert only_ar1[0].cwd == "/tmp/repo"

        everything = list_agent_actions(db.conn, run_id=None)
        assert len(everything) == 2

        nothing = list_agent_actions(db.conn, run_id="AR-999")
        assert nothing == []


def test_run_pytest_in_worktree_records_audited_action_when_pytest_unavailable(tmp_path: Path):
    """Direct unit test of verify.py's own audit wiring, without going
    through the full orchestrator: a real (not monkeypatched) subprocess
    call to `python3 -m pytest` against a worktree that has a tests/
    directory but no pytest installed (the actual, honest state of this
    sandbox) must still produce exactly one correctly-shaped audit row —
    proving the "unavailable" early-exit path is audited too, not just
    the success path."""
    repo = _init_repo(tmp_path)
    app_dir = tmp_path / "appdir"
    wt = create_repair_worktree("verifyaudit", app_dir=app_dir, repo_root=repo)
    try:
        (wt.worktree_path / "tests").mkdir()
        (wt.worktree_path / "tests" / "test_x.py").write_text("def test_x():\n    assert True\n")

        cfg = _cfg(tmp_path)
        audit_trail: list = []
        result = run_pytest_in_worktree(wt, cfg, audit_trail=audit_trail)
        assert result.status in ("ok", "unavailable")  # depends on whether pytest happens to be installed

        assert len(audit_trail) == 1
        entry = audit_trail[0]
        assert entry["component"] == "agent.verify"
        assert entry["mutating"] is False
        assert entry["approval_required"] is False
        assert entry["exit_code"] is not None
        assert entry["duration_seconds"] is not None and entry["duration_seconds"] >= 0
        assert entry["target"] == str(wt.worktree_path / "tests")
    finally:
        remove_repair_worktree(wt, repo_root=repo)


def test_worktree_and_runner_calls_are_silent_no_ops_when_audit_trail_omitted(tmp_path: Path):
    """Backward-compatibility guarantee this whole design depends on:
    every pre-existing call site (every test above this section, and
    every real caller before secure/agent/orchestrator.py was updated)
    omits `audit_trail` entirely — proves that still works identically,
    with no audit_trail argument required and nothing raised."""
    repo = _init_repo(tmp_path)
    app_dir = tmp_path / "appdir"
    wt = create_repair_worktree("noauditarg", app_dir=app_dir, repo_root=repo)
    assert is_git_repository(repo) is True
    assert current_commit(repo)
    diff_text, changed = diff_and_changed_files(wt)
    assert diff_text == ""
    assert changed == []
    remove_repair_worktree(wt, repo_root=repo)
    assert not wt.worktree_path.exists()
