"""tests/test_agent_verified.py — Phase 44 ("Verified Self-Healing").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "Adversarial tests prove no candidate can reach VERIFIED by
    skipping required gates, changing its diff after verification,
    relying on model confidence, or failing required deterministic
    checks."

Those four attacks are the four test groups at the bottom of this
file. Everything above them establishes that a genuinely good repair
CAN reach VERIFIED — without which the adversarial tests would pass
trivially against a function that always says no.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.classify import (
    CLASS_PRIVILEGED_CHANGE,
    CLASS_SAFE_PROJECT_CODE,
    CLASS_SYSTEM_CHANGE,
)
from secure.agent.diagnose import REPRO_NOT_REPRODUCED, REPRO_REPRODUCED, REPRO_UNAVAILABLE
from secure.agent.policy import TRIGGER_PYTEST_FAILURE
from secure.agent.tiers import EscalationOutcome, TierResult
from secure.agent.verified import (
    ALL_CRITERIA,
    C1_REPRODUCED_BEFORE,
    C2_ISOLATED_ONLY,
    C3_FAILURE_GONE,
    C4_FAST,
    C5_TARGETED,
    C6_FULL,
    C7_VALIDATION,
    C8_PERFORMANCE,
    C9_REVIEW,
    C10_POLICY,
    C11_DIFF_HASH,
    CriterionResult,
    VerifiedAssessment,
    evaluate_verified,
    full_regression_required,
    security_validation_required,
)
from secure.agent.worktree import AGENT_RUNS_DIRNAME
from secure.config import AppConfig, default_config


# ---------------------------------------------------------------------
# A stand-in run record, plus a real on-disk worktree and diff
# ---------------------------------------------------------------------


@dataclass
class _Run:
    run_id: str = "AR-1"
    trigger_kind: str = TRIGGER_PYTEST_FAILURE
    trigger_ref: str = "tests/test_widget.py::test_widget"
    worktree_path: str = ""
    diff_path: "Optional[str]" = None
    diff_hash: "Optional[str]" = None
    changed_files: list = field(default_factory=lambda: ["secure/widget.py"])
    denylist_violation: "Optional[str]" = None
    classification: "Optional[str]" = CLASS_SAFE_PROJECT_CODE
    review_status: "Optional[str]" = "ok"
    review_blocking: list = field(default_factory=list)
    reproduction_status: "Optional[str]" = REPRO_REPRODUCED
    reproduced: "Optional[bool]" = True
    reproduction_command: str = "pytest tests/test_widget.py::test_widget"


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    return cfg


def _make_run(tmp_path: Path, **overrides) -> "_Run":
    """Builds a run whose worktree and diff really exist on disk, in
    the right place, with a real matching hash — so the criteria that
    look at the filesystem are exercised for real."""
    cfg = _cfg(tmp_path)
    worktree = cfg.app_dir_path() / AGENT_RUNS_DIRNAME / "run1" / "worktree"
    worktree.mkdir(parents=True, exist_ok=True)
    diff_path = worktree.parent / "diff.patch"
    diff_text = "--- a/secure/widget.py\n+++ b/secure/widget.py\n+    return 2\n"
    diff_path.write_text(diff_text)
    run = _Run(
        worktree_path=str(worktree),
        diff_path=str(diff_path),
        diff_hash=hashlib.sha256(diff_path.read_bytes()).hexdigest(),
    )
    for key, value in overrides.items():
        setattr(run, key, value)
    return run


def _tier(passed=True, status="ok"):
    return TierResult("t", status, passed, "summary", 0.1, ())


def _escalation(fast=True, targeted=True, full=True, security=True):
    """A full set of passing tiers. Any of them can be set to None
    (did not run) or False (failed) by a caller."""
    def _mk(v):
        if v is None:
            return None
        return _tier(passed=v) if isinstance(v, bool) else v

    return EscalationOutcome(
        fast=_mk(fast), targeted=_mk(targeted), full=_mk(full), security=_mk(security),
        stopped_at="security", revision="abc", changed_files=("secure/widget.py",), diff_hash="x",
    )


def _policy_root(tmp_path: Path) -> Path:
    """A root that has the Phase 37 policy files, so criterion 10 can
    be satisfied without depending on the real repository."""
    root = tmp_path / "policyroot"
    root.mkdir(exist_ok=True)
    for name in ("AGENTS.md", "ARCHITECTURE_RULES.md", "SECURITY_INVARIANTS.md", "TESTING_POLICY.md"):
        (root / name).write_text("1. **Rule.**\n")
    return root


def _evaluate(tmp_path, run, *, escalation=None, perf_warnings=None, monkeypatch=None, failure_gone=True):
    """Evaluates with criterion 3's subprocess re-check stubbed, since
    this sandbox has no pytest. Criterion 3 has its own dedicated tests
    below that exercise its real branches."""
    import secure.agent.verified as verified_module

    if monkeypatch is not None:
        result = CriterionResult(
            C3_FAILURE_GONE,
            True if failure_gone is True else (False if failure_gone is False else None),
            "stubbed re-check",
        )
        monkeypatch.setattr(verified_module, "_c3_failure_gone", lambda *a, **k: result)

    return evaluate_verified(
        run, _cfg(tmp_path),
        escalation=escalation if escalation is not None else _escalation(),
        perf_warnings=perf_warnings if perf_warnings is not None else [],
        root=_policy_root(tmp_path),
    )


# =====================================================================
# The shape of the definition
# =====================================================================


def test_there_are_exactly_eleven_criteria():
    assert len(ALL_CRITERIA) == 11


def test_every_criterion_is_numbered_to_match_the_governing_text():
    for index, key in enumerate(ALL_CRITERIA, start=1):
        assert key.startswith(f"{index}_"), key


def test_an_assessment_missing_a_criterion_is_never_verified():
    """Defensive: a partially-built assessment must not read as a pass
    just because nothing in it happens to be False."""
    partial = VerifiedAssessment(criteria=(CriterionResult(C1_REPRODUCED_BEFORE, True, "ok"),))
    assert partial.verified is False


def test_unknown_blocks_exactly_as_false_does():
    unknown = CriterionResult(C4_FAST, None, "could not tell")
    false = CriterionResult(C4_FAST, False, "failed")
    assert unknown.blocks is True
    assert false.blocks is True


def test_a_not_applicable_criterion_does_not_block():
    skipped = CriterionResult(C6_FULL, True, "not required", applicable=False)
    assert skipped.blocks is False


# =====================================================================
# A genuinely good repair can reach VERIFIED
# =====================================================================


def test_a_good_repair_reaches_verified(tmp_path: Path, monkeypatch):
    assessment = _evaluate(tmp_path, _make_run(tmp_path), monkeypatch=monkeypatch)
    assert assessment.verified is True, assessment.describe()
    assert assessment.blocking == ()


def test_a_verified_safe_change_is_a_promotion_candidate(tmp_path: Path, monkeypatch):
    assessment = _evaluate(tmp_path, _make_run(tmp_path), monkeypatch=monkeypatch)
    assert assessment.promotion_candidate is True


def test_a_verified_consequential_change_is_not_a_promotion_candidate(tmp_path: Path, monkeypatch):
    """"Only VERIFIED SAFE_PROJECT_CODE changes may become candidates
    for automatic promotion." Being verified is not enough."""
    for cls in (CLASS_SYSTEM_CHANGE, CLASS_PRIVILEGED_CHANGE):
        run = _make_run(tmp_path, classification=cls)
        assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
        assert assessment.verified is True
        assert assessment.promotion_candidate is False


# =====================================================================
# ATTACK 1 — skipping a required gate
# =====================================================================


def test_skipping_fast_verification_blocks_verified(tmp_path: Path, monkeypatch):
    assessment = _evaluate(tmp_path, _make_run(tmp_path), escalation=_escalation(fast=None), monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C4_FAST in assessment.blocking


def test_skipping_targeted_tests_blocks_verified(tmp_path: Path, monkeypatch):
    assessment = _evaluate(tmp_path, _make_run(tmp_path), escalation=_escalation(targeted=None), monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C5_TARGETED in assessment.blocking


def test_skipping_full_regression_blocks_when_it_was_required(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, changed_files=["secure/a.py", "secure/b.py"])  # >1 file => full required
    assert full_regression_required(run) is True
    assessment = _evaluate(tmp_path, run, escalation=_escalation(full=None), monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C6_FULL in assessment.blocking


def test_skipping_security_validation_blocks_when_security_was_touched(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, changed_files=["secure/detect/rules.py"])
    assert security_validation_required(run) is True
    assessment = _evaluate(tmp_path, run, escalation=_escalation(security=None), monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C7_VALIDATION in assessment.blocking


def test_providing_no_escalation_at_all_blocks_every_tier_criterion(tmp_path: Path, monkeypatch):
    """The bluntest version of the attack: run no tiers and ask to be
    called verified anyway."""
    assessment = evaluate_verified(
        _make_run(tmp_path), _cfg(tmp_path), escalation=None, perf_warnings=[], root=_policy_root(tmp_path),
    )
    assert assessment.verified is False
    for key in (C4_FAST, C5_TARGETED):
        assert key in assessment.blocking


def test_unknown_scope_requires_both_full_and_security(tmp_path: Path):
    run = _make_run(tmp_path, changed_files=[])
    assert full_regression_required(run) is True
    assert security_validation_required(run) is True


def test_a_test_file_change_always_requires_full_regression(tmp_path: Path):
    run = _make_run(tmp_path, changed_files=["tests/test_widget.py"])
    assert full_regression_required(run) is True


def test_skipping_reproduction_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, reproduction_status=None, reproduced=None)
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C1_REPRODUCED_BEFORE in assessment.blocking


def test_a_failure_that_never_reproduced_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, reproduction_status=REPRO_NOT_REPRODUCED, reproduced=False)
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C1_REPRODUCED_BEFORE in assessment.blocking


def test_an_inconclusive_reproduction_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, reproduction_status=REPRO_UNAVAILABLE, reproduced=None)
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False


# =====================================================================
# ATTACK 2 — changing the diff after verification
# =====================================================================


def test_editing_the_diff_after_verification_blocks_verified(tmp_path: Path, monkeypatch):
    """The named attack. Everything else about the run is perfect; only
    the diff file changed on disk after its hash was recorded."""
    run = _make_run(tmp_path)
    Path(run.diff_path).write_text("a completely different patch\n")
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C11_DIFF_HASH in assessment.blocking
    assert "CHANGED" in assessment.result_for(C11_DIFF_HASH).detail


def test_deleting_the_diff_after_verification_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path)
    Path(run.diff_path).unlink()
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C11_DIFF_HASH in assessment.blocking


def test_a_run_with_no_recorded_diff_hash_cannot_be_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, diff_hash=None)
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C11_DIFF_HASH in assessment.blocking


def test_the_hash_check_reads_the_file_now_not_a_cached_value(tmp_path: Path, monkeypatch):
    """Proves the check is a live measurement: the same record object
    verifies before the edit and fails after, with nothing else
    changed."""
    run = _make_run(tmp_path)
    assert _evaluate(tmp_path, run, monkeypatch=monkeypatch).verified is True
    Path(run.diff_path).write_text("tampered\n")
    assert _evaluate(tmp_path, run, monkeypatch=monkeypatch).verified is False


# =====================================================================
# ATTACK 3 — relying on model confidence
# =====================================================================


def test_a_glowing_review_cannot_supply_a_missing_gate(tmp_path: Path, monkeypatch):
    """The reviewer says everything is wonderful; FAST never ran.
    VERIFIED must still be withheld."""
    run = _make_run(tmp_path, review_status="ok", review_blocking=[])
    assessment = _evaluate(tmp_path, run, escalation=_escalation(fast=None), monkeypatch=monkeypatch)
    assert assessment.verified is False


def test_a_blocking_review_finding_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, review_blocking=["tests_weakened"])
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C9_REVIEW in assessment.blocking


def test_an_unusable_review_blocks_verified(tmp_path: Path, monkeypatch):
    for status in ("error", "unparseable"):
        run = _make_run(tmp_path, review_status=status, review_blocking=[])
        assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
        assert assessment.verified is False, status


def test_the_module_never_reads_any_free_text_model_field(tmp_path: Path):
    """Structural. `review_summary`, `coder_assessment`, and
    `model_*_opinion` are all fields a model writes freely into. None
    of them may influence VERIFIED, so none of them is ever read."""
    import ast

    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "verified.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)

    banned = {"review_summary", "coder_assessment", "model_a_opinion", "model_b_opinion", "raw_text"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in banned:
            offending.append(f"line {node.lineno}: .{node.attr}")
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value not in docstrings:
            if node.value in banned:
                offending.append(f"line {node.lineno}: {node.value!r}")
    assert offending == []


# =====================================================================
# ATTACK 4 — failing a required deterministic check
# =====================================================================


def test_a_failing_fast_tier_blocks_verified(tmp_path: Path, monkeypatch):
    assessment = _evaluate(tmp_path, _make_run(tmp_path), escalation=_escalation(fast=False), monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C4_FAST in assessment.blocking


def test_a_failing_full_regression_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, changed_files=["secure/a.py", "secure/b.py"])
    assessment = _evaluate(tmp_path, run, escalation=_escalation(full=False), monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C6_FULL in assessment.blocking


def test_a_tier_whose_mechanism_did_not_run_cleanly_is_not_a_pass(tmp_path: Path, monkeypatch):
    """status='unavailable' with passed=None is inconclusive, and
    inconclusive is never a pass."""
    unavailable = TierResult("t", "unavailable", None, "pytest missing", 0.0, ())
    assessment = _evaluate(
        tmp_path, _make_run(tmp_path), escalation=_escalation(fast=unavailable), monkeypatch=monkeypatch
    )
    assert assessment.verified is False


def test_the_original_failure_still_failing_blocks_verified(tmp_path: Path, monkeypatch):
    """A repair whose tests pass but whose original failure still
    occurs has not fixed anything."""
    assessment = _evaluate(tmp_path, _make_run(tmp_path), monkeypatch=monkeypatch, failure_gone=False)
    assert assessment.verified is False
    assert C3_FAILURE_GONE in assessment.blocking


def test_being_unable_to_recheck_the_original_failure_blocks_verified(tmp_path: Path, monkeypatch):
    assessment = _evaluate(tmp_path, _make_run(tmp_path), monkeypatch=monkeypatch, failure_gone=None)
    assert assessment.verified is False


def test_a_performance_regression_blocks_verified(tmp_path: Path, monkeypatch):
    from secure.diagnostics.budgets import PerfWarning

    warning = PerfWarning("scan_duration", "widget scan took 90s, above the 30s budget")
    assessment = _evaluate(tmp_path, _make_run(tmp_path), perf_warnings=[warning], monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C8_PERFORMANCE in assessment.blocking


def test_absent_performance_data_is_not_applicable_rather_than_a_pass(tmp_path: Path, monkeypatch):
    assessment = evaluate_verified(
        _make_run(tmp_path), _cfg(tmp_path), escalation=_escalation(), perf_warnings=None,
        root=_policy_root(tmp_path),
    )
    perf = assessment.result_for(C8_PERFORMANCE)
    assert perf.applicable is False
    assert "not applicable" in perf.detail


def test_a_denylist_violation_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, denylist_violation="'secure/agent/x.py' is under denylisted path 'secure/agent/'")
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C10_POLICY in assessment.blocking


def test_an_unclassified_change_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, classification=None)
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C10_POLICY in assessment.blocking


def test_missing_engineering_policy_files_block_verified(tmp_path: Path, monkeypatch):
    import secure.agent.verified as verified_module

    monkeypatch.setattr(
        verified_module, "_c3_failure_gone",
        lambda *a, **k: CriterionResult(C3_FAILURE_GONE, True, "stubbed"),
    )
    empty_root = tmp_path / "no-policy"
    empty_root.mkdir()
    assessment = evaluate_verified(
        _make_run(tmp_path), _cfg(tmp_path), escalation=_escalation(), perf_warnings=[], root=empty_root,
    )
    assert assessment.verified is False
    assert C10_POLICY in assessment.blocking


def test_a_patch_outside_the_isolated_workspace_blocks_verified(tmp_path: Path, monkeypatch):
    """Criterion 2: the patch must have existed only in isolation. A
    worktree path pointing at the live checkout is the failure this
    catches."""
    run = _make_run(tmp_path, worktree_path=str(tmp_path / "not-an-agent-workspace"))
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C2_ISOLATED_ONLY in assessment.blocking


def test_a_run_with_no_worktree_recorded_blocks_verified(tmp_path: Path, monkeypatch):
    run = _make_run(tmp_path, worktree_path="")
    assessment = _evaluate(tmp_path, run, monkeypatch=monkeypatch)
    assert assessment.verified is False
    assert C2_ISOLATED_ONLY in assessment.blocking


# =====================================================================
# The module promotes nothing
# =====================================================================


def test_the_module_contains_no_promotion_or_approval_action():
    """Eligibility is not permission: `promotion_candidate` is a
    predicate, and there is no function here that applies a patch,
    approves a change request, or changes a status."""
    import ast

    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "verified.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    banned = {"approve_change", "reject_change", "set_ai_change_request_status",
              "complete_agent_repair_run", "propose_change"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
            offending.append(f"import line {node.lineno}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
            offending.append(f"call line {node.lineno}")
        if isinstance(node, ast.Attribute) and node.attr in ("write_text", "write_bytes"):
            offending.append(f"write line {node.lineno}")
    assert offending == []


# =====================================================================
# Criterion 3's own implementation
#
# The tests above stub `_c3_failure_gone` so they can vary one thing at
# a time without needing a real pytest. That would leave the real
# function untested, so these exercise it directly.
# =====================================================================


def test_c3_reports_unknown_when_the_worktree_is_gone(tmp_path: Path):
    from secure.agent.verified import _c3_failure_gone

    run = _make_run(tmp_path, worktree_path=str(tmp_path / "vanished"))
    result = _c3_failure_gone(run, _cfg(tmp_path), timeout=10)
    assert result.satisfied is None
    assert "no longer exists" in result.detail
    assert result.blocks is True


def test_c3_reports_unknown_for_a_trigger_kind_it_cannot_recheck(tmp_path: Path):
    from secure.agent.policy import TRIGGER_VALIDATE_SCENARIO_FAILURE
    from secure.agent.verified import _c3_failure_gone

    run = _make_run(tmp_path, trigger_kind=TRIGGER_VALIDATE_SCENARIO_FAILURE)
    result = _c3_failure_gone(run, _cfg(tmp_path), timeout=10)
    assert result.satisfied is None
    assert result.blocks is True


def test_c3_treats_a_missing_pytest_as_unknown_not_as_success(tmp_path: Path, monkeypatch):
    """The same trap Phase 43 guards in reproduction, on the other end
    of the pipeline: "the checker could not run" must never read as
    "the failure is gone"."""
    import secure.agent.verified as verified_module
    from secure.agent.verified import _c3_failure_gone

    class _Proc:
        returncode = 1
        stdout = "No module named pytest"
        stderr = ""

    monkeypatch.setattr(verified_module.subprocess, "run", lambda *a, **k: _Proc())
    result = _c3_failure_gone(_make_run(tmp_path), _cfg(tmp_path), timeout=10)
    assert result.satisfied is None
    assert "unavailable" in result.detail


def test_c3_is_satisfied_when_the_original_test_now_passes(tmp_path: Path, monkeypatch):
    import secure.agent.verified as verified_module
    from secure.agent.verified import _c3_failure_gone

    class _Proc:
        returncode = 0
        stdout = "1 passed"
        stderr = ""

    monkeypatch.setattr(verified_module.subprocess, "run", lambda *a, **k: _Proc())
    result = _c3_failure_gone(_make_run(tmp_path), _cfg(tmp_path), timeout=10)
    assert result.satisfied is True


def test_c3_fails_when_the_original_test_still_fails(tmp_path: Path, monkeypatch):
    import secure.agent.verified as verified_module
    from secure.agent.verified import _c3_failure_gone

    class _Proc:
        returncode = 1
        stdout = "1 failed"
        stderr = ""

    monkeypatch.setattr(verified_module.subprocess, "run", lambda *a, **k: _Proc())
    result = _c3_failure_gone(_make_run(tmp_path), _cfg(tmp_path), timeout=10)
    assert result.satisfied is False
    assert "still fails" in result.detail


def test_c3_reruns_inside_the_worktree_with_an_isolated_home(tmp_path: Path, monkeypatch):
    """It must re-check in the ISOLATED worktree, not the live
    checkout, and with HOME pinned so a test that writes to ~/.secure
    cannot touch the operator's real one."""
    import os

    import secure.agent.verified as verified_module
    from secure.agent.verified import _c3_failure_gone

    captured = {}

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def _run(argv, **kwargs):
        captured["argv"] = argv
        captured["cwd"] = kwargs.get("cwd")
        captured["env"] = kwargs.get("env")
        return _Proc()

    monkeypatch.setattr(verified_module.subprocess, "run", _run)
    run = _make_run(tmp_path)
    _c3_failure_gone(run, _cfg(tmp_path), timeout=10)

    assert captured["cwd"] == run.worktree_path
    assert run.trigger_ref in captured["argv"]
    assert captured["env"]["HOME"] != os.environ.get("HOME")


def test_c3_reports_unknown_when_the_recheck_times_out(tmp_path: Path, monkeypatch):
    import subprocess as sp

    import secure.agent.verified as verified_module
    from secure.agent.verified import _c3_failure_gone

    def _raise(*a, **k):
        raise sp.TimeoutExpired(cmd="pytest", timeout=1)

    monkeypatch.setattr(verified_module.subprocess, "run", _raise)
    result = _c3_failure_gone(_make_run(tmp_path), _cfg(tmp_path), timeout=1)
    assert result.satisfied is None
