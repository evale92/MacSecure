"""tests/test_agent_memory.py — Phase 45 ("Maintenance Memory").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "A later matching failure can retrieve relevant historical repair
    evidence while preserving revision/context differences and without
    automatically applying the old solution."

Three properties carry most of the weight here: signatures are stable
across occurrences of the same failure but distinct across different
ones (without which the table is unsearchable), differences from the
current situation are always stated (which is what makes a record
evidence rather than an instruction), and no replay mechanism exists
at all.
"""

from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import secure.agent.orchestrator as orch_module
from secure.agent.classify import CLASS_SAFE_PROJECT_CODE, CLASS_SYSTEM_CHANGE
from secure.agent.memory import (
    MATCH_COMPONENT,
    MATCH_SIGNATURE,
    OUTCOME_ESCALATED,
    OUTCOME_VERIFICATION_FAILED,
    OUTCOME_VERIFIED,
    describe_recall,
    failure_signature,
    recall,
    record_run,
)
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import (
    find_maintenance_memory_by_signature,
    find_maintenance_memory_for_run,
    link_regression,
    list_maintenance_memory,
)


@dataclass
class _Run:
    run_id: str = "AR-1"
    status: str = "verified"
    trigger_kind: str = TRIGGER_PYTEST_FAILURE
    trigger_ref: str = "tests/test_widget.py::test_widget"
    trigger_detail: str = "assert 1 == 2"
    base_commit: str = "aaaaaaaaaaaa"
    tool_name: str = "mini-swe-agent"
    model_name: str = "ollama/qwen"
    changed_files: list = field(default_factory=lambda: ["secure/widget.py"])
    diff_hash: "Optional[str]" = "d" * 64
    pytest_status: "Optional[str]" = "ok"
    validate_status: "Optional[str]" = "ok"
    verification_passed: "Optional[bool]" = True
    reproduced: "Optional[bool]" = True
    review_status: "Optional[str]" = "ok"
    review_provider: str = "ollama"
    review_model: str = "m"
    review_blocking: list = field(default_factory=list)
    classification: "Optional[str]" = CLASS_SAFE_PROJECT_CODE
    change_request_id: "Optional[str]" = "CR-1"
    denylist_violation: "Optional[str]" = None


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


# =====================================================================
# Failure signatures
# =====================================================================


def test_the_same_failure_produces_the_same_signature():
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "tests/test_x.py::test_y", "assert 1 == 2")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "tests/test_x.py::test_y", "assert 1 == 2")
    assert a == b


def test_different_failures_produce_different_signatures():
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "tests/test_x.py::test_y", "assert 1 == 2")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "tests/test_x.py::test_z", "assert 1 == 2")
    assert a != b


def test_a_signature_survives_a_changed_timestamp():
    """Without volatility stripping, every occurrence would be unique
    and the whole table would be unsearchable — which is the main way a
    'memory' quietly becomes useless."""
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "failed at 2026-08-22T10:00:00Z in handler")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "failed at 2026-01-01T23:59:59Z in handler")
    assert a == b


def test_a_signature_survives_a_changed_absolute_path():
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "error in /Users/erick/x/widget.py doing thing")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "error in /tmp/build9/widget.py doing thing")
    assert a == b


def test_a_signature_survives_a_changed_run_id_and_commit():
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "run AR-3 at commit abc1234 failed")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "run AR-99 at commit fed9876 failed")
    assert a == b


def test_a_signature_survives_a_changed_duration_and_line_number():
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "took 1.5s, line 42, boom")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "took 9.9s, line 7, boom")
    assert a == b


def test_a_signature_is_a_hex_digest_not_raw_text():
    """Safe to index, compare, and print without leaking a path or a
    payload."""
    sig = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "/Users/erick/secret/path.py")
    assert len(sig) == 64
    assert all(c in "0123456789abcdef" for c in sig)
    assert "erick" not in sig


def test_a_genuinely_different_message_changes_the_signature():
    a = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "AssertionError: expected 1")
    b = failure_signature(TRIGGER_PYTEST_FAILURE, "t::t", "TypeError: unsupported operand")
    assert a != b


# =====================================================================
# Recording
# =====================================================================


def test_a_completed_run_is_recorded(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        record_run(db.conn, _Run())
        stored = find_maintenance_memory_for_run(db.conn, "AR-1")
    assert stored is not None
    assert stored.outcome == OUTCOME_VERIFIED
    assert stored.files_changed == ["secure/widget.py"]
    assert stored.classification == CLASS_SAFE_PROJECT_CODE


def test_failures_are_remembered_too_not_just_successes(tmp_path: Path):
    """A memory that remembered only successes would systematically
    mislead whatever reads it."""
    with Database(tmp_path / "secure.db") as db:
        record_run(db.conn, _Run(run_id="AR-2", status="verification_failed", verification_passed=False))
        record_run(db.conn, _Run(run_id="AR-3", status="escalated_for_review",
                                 review_blocking=["tests_weakened"]))
        rows = list_maintenance_memory(db.conn)
    outcomes = {r.run_id: r.outcome for r in rows}
    assert outcomes["AR-2"] == OUTCOME_VERIFICATION_FAILED
    assert outcomes["AR-3"] == OUTCOME_ESCALATED


def test_the_recorded_outcome_cannot_disagree_with_the_run_status(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        record_run(db.conn, _Run(run_id="AR-9", status="rejected_by_denylist"))
        stored = find_maintenance_memory_for_run(db.conn, "AR-9")
    assert stored.outcome == "rejected_by_denylist"


def test_an_unrecognized_status_is_recorded_as_unknown_not_as_success(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        record_run(db.conn, _Run(run_id="AR-10", status="some_future_status"))
        stored = find_maintenance_memory_for_run(db.conn, "AR-10")
    assert stored.outcome == "unknown"


def test_no_transcript_or_model_prose_is_stored(tmp_path: Path):
    """"Do not use unrestricted chat history as the primary memory
    system." Everything stored is a structured fact established
    deterministically elsewhere."""
    with Database(tmp_path / "secure.db") as db:
        record_run(db.conn, _Run())
        row = dict(db.conn.execute("SELECT * FROM agent_maintenance_memory").fetchone())
    columns = set(row)
    for banned in ("transcript", "conversation", "chat", "model_output", "prompt", "raw_text"):
        assert not any(banned in c for c in columns), banned


def test_the_reviewer_assessment_stored_is_the_computed_blocking_list(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        record_run(db.conn, _Run(review_blocking=["security_weakened"]))
        stored = find_maintenance_memory_for_run(db.conn, "AR-1")
    assert "security_weakened" in stored.reviewer_assessment


# =====================================================================
# Recall — evidence with differences stated
# =====================================================================


def _seed(conn, **overrides):
    record_run(conn, _Run(**overrides))


def test_a_later_matching_failure_retrieves_the_prior_repair(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
        )
    assert len(results) == 1
    assert results[0].match_kind == MATCH_SIGNATURE
    assert results[0].record.run_id == "AR-1"


def test_an_unrelated_failure_retrieves_nothing(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_totally_different.py::test_other", trigger_detail="different failure",
        )
    assert results == []


def test_a_different_base_commit_is_reported_as_a_difference(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
            base_commit="bbbbbbbbbbbb",
        )
    diffs = results[0].differences
    assert any("different base commit" in d for d in diffs)
    assert any("may no longer exist as it was" in d for d in diffs)


def test_different_changed_files_are_reported_as_a_difference(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
            base_commit="aaaaaaaaaaaa", changed_files=["secure/other.py"],
        )
    assert any("different files" in d for d in results[0].differences)


def test_an_unverified_prior_repair_is_flagged_as_such(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn, status="verification_failed", verification_passed=False)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
            base_commit="aaaaaaaaaaaa",
        )
    assert any("did NOT reach a verified outcome" in d for d in results[0].differences)


def test_an_unapproved_prior_repair_is_flagged_as_such(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
            base_commit="aaaaaaaaaaaa",
        )
    assert any("never approved by a human" in d for d in results[0].differences)


def test_a_linked_regression_is_surfaced_in_recall(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        memory_id = record_run(db.conn, _Run())
        link_regression(db.conn, memory_id=memory_id, regression_run_id="AR-77", note="same test broke again")
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
            base_commit="aaaaaaaaaaaa",
        )
    assert any("AR-77" in d for d in results[0].differences)


def test_linking_a_regression_does_not_rewrite_the_original_record(tmp_path: Path):
    """A history that can be rewritten is not a history."""
    with Database(tmp_path / "secure.db") as db:
        memory_id = record_run(db.conn, _Run())
        before = find_maintenance_memory_for_run(db.conn, "AR-1")
        after = link_regression(db.conn, memory_id=memory_id, regression_run_id="AR-77", note="n")
    assert after.outcome == before.outcome
    assert after.failure_signature == before.failure_signature
    assert after.diff_hash == before.diff_hash
    assert after.regression_run_id == "AR-77"


def test_a_component_match_is_found_when_no_signature_matches(tmp_path: Path):
    """Looser fallback: nothing shares the exact signature, but prior
    work touched the same file."""
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn, trigger_ref="tests/test_widget.py::test_other", trigger_detail="a different failure",
              changed_files=["tests/test_widget.py"])
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
        )
    assert results
    assert results[0].match_kind == MATCH_COMPONENT


def test_recall_respects_its_limit(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        for i in range(8):
            _seed(db.conn, run_id=f"AR-{i}")
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2", limit=3,
        )
    assert len(results) == 3


# =====================================================================
# Evidence, not authority — and no replay mechanism exists
# =====================================================================


def test_recall_output_states_that_it_is_not_authority(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
        )
    text = describe_recall(results)
    assert "EVIDENCE, NOT AUTHORITY" in text
    assert "Do not re-apply an old patch" in text


def test_empty_recall_says_so_rather_than_inventing_something(tmp_path: Path):
    assert "No prior repair evidence" in describe_recall([])


def test_no_recalled_repair_is_ever_safe_to_replay(tmp_path: Path):
    with Database(tmp_path / "secure.db") as db:
        _seed(db.conn)
        results = recall(
            db.conn, trigger_kind=TRIGGER_PYTEST_FAILURE,
            trigger_ref="tests/test_widget.py::test_widget", trigger_detail="assert 1 == 2",
        )
    assert all(r.safe_to_replay is False for r in results)


def test_the_memory_module_ships_no_patch_replay_mechanism():
    """"Never blindly replay an old patch against changed code." The
    way to guarantee that is to ship no replay mechanism at all — the
    same enforced-by-absence reasoning Phase 42 applies to launchd
    installation."""
    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "memory.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    banned_calls = {"apply_patch", "run", "check_output", "Popen", "write_text", "write_bytes"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in banned_calls:
            offending.append(f"line {node.lineno}: .{node.attr}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned_calls:
            offending.append(f"line {node.lineno}: {node.func.id}()")
    assert offending == []


def test_the_memory_module_never_reads_the_stored_diff_text():
    """It records a diff HASH for identity, never diff content — so
    there is nothing here to re-apply even by accident."""
    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "memory.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    offending = [
        f"line {n.lineno}" for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr in ("diff_text", "diff_path")
    ]
    assert offending == []


# =====================================================================
# End-to-end through a real repair
# =====================================================================


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
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
    return root


def test_a_real_repair_writes_its_own_memory_row(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / "secure" / "widget.py").write_text("def widget():\n    return 2\n")
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="x",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok")),
    )
    with Database(tmp_path / "secure.db") as db:
        run = orch_module.attempt_repair(
            db.conn, _cfg(tmp_path),
            RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom"),
            repo_root=repo, providers={"ollama": None, "openai_compatible": None},
        )
        stored = find_maintenance_memory_for_run(db.conn, run.run_id)

    assert stored is not None
    assert stored.outcome == OUTCOME_VERIFIED
    assert stored.files_changed == ["secure/widget.py"]
    assert stored.diff_hash == run.diff_hash
    assert stored.base_commit == run.base_commit


def test_a_memory_write_failure_never_breaks_a_completed_repair(tmp_path: Path, monkeypatch):
    """Bookkeeping must not be able to turn a finished repair into a
    crashed one."""
    repo = _repo(tmp_path)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / "secure" / "widget.py").write_text("def widget():\n    return 2\n")
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="x",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    import secure.agent.memory as memory_module

    def _explode(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok")),
    )
    monkeypatch.setattr(memory_module, "record_run", _explode)

    with Database(tmp_path / "secure.db") as db:
        run = orch_module.attempt_repair(
            db.conn, _cfg(tmp_path),
            RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom"),
            repo_root=repo, providers={"ollama": None, "openai_compatible": None},
        )
    assert run.status == "verified"
