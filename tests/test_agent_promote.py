"""tests/test_agent_promote.py — Phase 47.5
("Close the Verified Safe-Code Loop").

Governing text: `docs/PHASE_47_5.md`. Required adversarial proofs:

    - fully verified SAFE_PROJECT_CODE can auto-promote
    - UNKNOWN blocks promotion
    - failed tests block promotion
    - stale diff blocks promotion
    - changed live base blocks promotion
    - dirty live checkout blocks unsafe promotion
    - reviewer blocker blocks promotion
    - consequential classifications never auto-promote
    - failed post-promotion verification safely rolls back when possible

**Every test here operates on a DISPOSABLE git repository created in
`tmp_path`. None of them touches the real Secure checkout.** That
matters more than usual in this phase: `secure/agent/promote.py` is the
first module permitted to write to a live working tree, and a test
that pointed it at the real repository would be writing to Erick's
project. `test_no_test_in_this_file_targets_the_real_checkout` asserts
that structurally.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.classify import (
    CLASS_DEPENDENCY_CHANGE,
    CLASS_PRIVILEGED_CHANGE,
    CLASS_SAFE_PROJECT_CODE,
    CLASS_SECURITY_SEMANTIC_CHANGE,
    CLASS_SYSTEM_CHANGE,
)
from secure.agent.diagnose import REPRO_REPRODUCED, REPRO_UNAVAILABLE
from secure.agent.policy import TRIGGER_PYTEST_FAILURE
from secure.agent.promote import (
    PROMOTION_ESCALATED,
    PROMOTION_PROMOTED,
    PROMOTION_REFUSED,
    PROMOTION_ROLLED_BACK,
    STATUS_PROMOTED_AUTOMATICALLY,
    describe,
    evaluate_promotion_gate,
    live_dirty_paths,
    live_head,
    promote,
)
from secure.agent.tiers import EscalationOutcome, TierResult
from secure.agent.verified import CriterionResult, C3_FAILURE_GONE, evaluate_verified
from secure.config import AppConfig, default_config
from secure.storage.database import Database


# ---------------------------------------------------------------------
# A disposable live checkout, and a real patch against it
# ---------------------------------------------------------------------


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _live_repo(tmp_path: Path) -> Path:
    """A throwaway stand-in for "the live checkout". Real git, real
    commit, real clean tree — never the actual Secure repository."""
    root = tmp_path / "live"
    root.mkdir()
    _git(["init", "-q"], root)
    _git(["config", "user.email", "t@t.com"], root)
    _git(["config", "user.name", "T"], root)
    (root / "secure").mkdir()
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_widget.py").write_text(
        "from secure.widget import widget\n\n\ndef test_widget():\n    assert widget() == 2\n"
    )
    for name in ("AGENTS.md", "ARCHITECTURE_RULES.md", "SECURITY_INVARIANTS.md", "TESTING_POLICY.md"):
        (root / name).write_text("1. **Rule.**\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "baseline"], root)
    return root


_PATCH = """--- a/secure/widget.py
+++ b/secure/widget.py
@@ -1,2 +1,2 @@
 def widget():
-    return 1
+    return 2
"""


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    return cfg


@dataclass
class _Run:
    run_id: str = "AR-1"
    status: str = "verified"
    trigger_kind: str = TRIGGER_PYTEST_FAILURE
    trigger_ref: str = "tests/test_widget.py::test_widget"
    base_commit: str = ""
    worktree_path: str = ""
    diff_path: "Optional[str]" = None
    diff_hash: "Optional[str]" = None
    changed_files: list = field(default_factory=lambda: ["secure/widget.py"])
    denylist_violation: "Optional[str]" = None
    classification: "Optional[str]" = CLASS_SAFE_PROJECT_CODE
    review_status: "Optional[str]" = "ok"
    review_blocking: list = field(default_factory=list)
    review_disagreement: "Optional[bool]" = False
    reproduction_status: "Optional[str]" = REPRO_REPRODUCED
    reproduced: "Optional[bool]" = True
    change_request_id: "Optional[str]" = None
    pytest_status: "Optional[str]" = "ok"
    validate_status: "Optional[str]" = "ok"
    verification_passed: "Optional[bool]" = True


@dataclass
class _CR:
    cr_id: str = "CR-1"
    status: str = "pending"
    classification: "Optional[str]" = CLASS_SAFE_PROJECT_CODE


def _make_run(tmp_path: Path, live: Path, *, patch: str = _PATCH, **overrides) -> "_Run":
    cfg = _cfg(tmp_path)
    worktree = cfg.app_dir_path() / "agent_runs" / "run1" / "repo"
    worktree.mkdir(parents=True, exist_ok=True)
    diff_path = worktree.parent / "diff.patch"
    diff_path.write_text(patch)
    run = _Run(
        base_commit=_git(["rev-parse", "HEAD"], live).stdout.strip(),
        worktree_path=str(worktree),
        diff_path=str(diff_path),
        diff_hash=hashlib.sha256(diff_path.read_bytes()).hexdigest(),
    )
    for k, v in overrides.items():
        setattr(run, k, v)
    return run


def _tier(passed=True, status="ok"):
    return TierResult("t", status, passed, "summary", 0.1, ())


def _escalation(fast=True, targeted=True, full=True, security=True):
    def _mk(v):
        if v is None:
            return None
        return _tier(passed=v) if isinstance(v, bool) else v

    return EscalationOutcome(
        fast=_mk(fast), targeted=_mk(targeted), full=_mk(full), security=_mk(security),
        stopped_at="security", revision="abc", changed_files=("secure/widget.py",), diff_hash="x",
    )


def _assessment(tmp_path, live, run, monkeypatch, *, escalation=None, failure_gone=True):
    """A REAL Phase 44 assessment. Only criterion 3's subprocess
    re-check is stubbed (this sandbox has no pytest); every other
    criterion is evaluated for real against the real run and the real
    files on disk."""
    import secure.agent.verified as verified_module

    result = CriterionResult(
        C3_FAILURE_GONE,
        True if failure_gone is True else (False if failure_gone is False else None),
        "stubbed re-check",
    )
    monkeypatch.setattr(verified_module, "_c3_failure_gone", lambda *a, **k: result)
    return evaluate_verified(
        run, _cfg(tmp_path),
        escalation=escalation if escalation is not None else _escalation(),
        perf_warnings=[], root=live,
    )


def _stub_post_verification(monkeypatch, ok: bool, notes=("stubbed",)):
    import secure.agent.promote as promote_module

    monkeypatch.setattr(promote_module, "verify_after_promotion", lambda *a, **k: (ok, tuple(notes)))


# =====================================================================
# 1 — fully verified SAFE_PROJECT_CODE can auto-promote
# =====================================================================


def test_a_fully_verified_safe_change_promotes(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    _stub_post_verification(monkeypatch, True)

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_PROMOTED, describe(result)
    assert result.applied is True
    assert result.rolled_back is False
    assert result.live_checkout_modified is True
    assert (live / "secure" / "widget.py").read_text() == "def widget():\n    return 2\n"


def test_promotion_leaves_the_change_uncommitted_for_the_operator(tmp_path: Path, monkeypatch):
    """Nothing commits on the operator's behalf, and HEAD does not
    move."""
    live = _live_repo(tmp_path)
    head_before = _git(["rev-parse", "HEAD"], live).stdout.strip()
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    _stub_post_verification(monkeypatch, True)

    with Database(tmp_path / "s.db") as db:
        promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert _git(["rev-parse", "HEAD"], live).stdout.strip() == head_before
    assert _git(["log", "--oneline"], live).stdout.strip().count("\n") == 0
    assert live_dirty_paths(live) == ["secure/widget.py"]


def test_a_promoted_change_request_is_never_marked_approved(tmp_path: Path, monkeypatch):
    """Phase 28 reserves 'approved' for a human CLI action. Automatic
    promotion records a distinct terminal state instead."""
    from secure.ai.changes.workflow import propose_change
    from secure.storage.models import find_ai_change_request

    live = _live_repo(tmp_path)
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "s.db") as db:
        cr = propose_change(
            db.conn, cfg, title="t", proposed_change="p", reason="r", affected_component="c",
            risks="risk", model_a_opinion="a", model_b_opinion="b", notify=False,
        )
        run = _make_run(tmp_path, live, change_request_id=cr.cr_id)
        assessment = _assessment(tmp_path, live, run, monkeypatch)
        _stub_post_verification(monkeypatch, True)
        result = promote(db.conn, run, assessment, cfg, root=live, change_request=cr)
        after = find_ai_change_request(db.conn, cr.cr_id)

    assert result.outcome == PROMOTION_PROMOTED
    assert after.status == STATUS_PROMOTED_AUTOMATICALLY
    assert after.status != "approved"


def test_promotion_records_every_git_action_in_the_audit_trail(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    _stub_post_verification(monkeypatch, True)
    audit: list = []

    with Database(tmp_path / "s.db") as db:
        promote(db.conn, run, assessment, _cfg(tmp_path), root=live,
                change_request=_CR(), audit_trail=audit)

    assert audit
    assert all(a["component"] == "agent.promote" for a in audit)
    assert any(a["mutating"] for a in audit), "the apply itself must be recorded as mutating"
    assert any("apply" in a["action"] for a in audit)


# =====================================================================
# 2 — UNKNOWN blocks promotion
# =====================================================================


def test_an_unknown_criterion_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch, failure_gone=None)  # UNKNOWN
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("UNKNOWN is never a pass" in r for r in gate.refusals)


def test_missing_tiers_are_unknown_and_block_promotion(tmp_path: Path, monkeypatch):
    """The exact gap Phase 47.5 was written to close: no tiers run
    means UNKNOWN, and UNKNOWN must not become PASS."""
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = evaluate_verified(run, _cfg(tmp_path), escalation=None, perf_warnings=[], root=live)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False


def test_no_assessment_at_all_blocks_promotion(tmp_path: Path):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    gate = evaluate_promotion_gate(run, None, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("no Phase 44 assessment" in r for r in gate.refusals)


def test_an_unknown_criterion_actually_prevents_the_write(tmp_path: Path, monkeypatch):
    """Not just the gate — the file on disk is untouched."""
    live = _live_repo(tmp_path)
    before = (live / "secure" / "widget.py").read_text()
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch, failure_gone=None)

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_REFUSED
    assert result.applied is False
    assert (live / "secure" / "widget.py").read_text() == before


# =====================================================================
# 3 — failed tests block promotion
# =====================================================================


def test_a_failed_tier_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch, escalation=_escalation(full=False))
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False


def test_a_run_that_is_not_verified_status_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, status="verification_failed")
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("not 'verified'" in r for r in gate.refusals)


def test_an_unreproduced_failure_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, reproduced=None, reproduction_status=REPRO_UNAVAILABLE)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("not confirmed to have been reproduced" in r for r in gate.refusals)


def test_a_denylist_violation_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, denylist_violation="'secure/agent/x.py' is denylisted")
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False


# =====================================================================
# 4 — stale diff blocks promotion
# =====================================================================


def test_a_diff_edited_after_verification_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    Path(run.diff_path).write_text("a completely different patch\n")

    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("the diff has changed since verification" in r for r in gate.refusals)


def test_a_deleted_diff_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    Path(run.diff_path).unlink()
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False


def test_a_run_with_no_diff_hash_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, diff_hash=None)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False


def test_a_stale_diff_actually_prevents_the_write(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    before = (live / "secure" / "widget.py").read_text()
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    Path(run.diff_path).write_text("--- a/secure/widget.py\n+++ b/secure/widget.py\n@@ -1,2 +1,2 @@\n def widget():\n-    return 1\n+    return 99\n")

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_REFUSED
    assert (live / "secure" / "widget.py").read_text() == before


# =====================================================================
# 5 — changed live base blocks promotion
# =====================================================================


def test_a_moved_live_head_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)

    (live / "unrelated.txt").write_text("someone else committed\n")
    _git(["add", "-A"], live)
    _git(["commit", "-q", "-m", "unrelated work"], live)

    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("the live checkout has moved since the repair" in r for r in gate.refusals)


def test_a_run_with_no_base_commit_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, base_commit="")
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False


def test_a_non_git_root_blocks_promotion(tmp_path: Path, monkeypatch):
    """If HEAD cannot be read, refuse rather than assume."""
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=not_a_repo, change_request=_CR())
    assert gate.allowed is False
    assert live_head(not_a_repo) is None


# =====================================================================
# 6 — dirty live checkout blocks unsafe promotion
# =====================================================================


def test_an_uncommitted_change_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)

    (live / "secure" / "other.py").write_text("operator was mid-edit\n")

    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("uncommitted change" in r for r in gate.refusals)


def test_a_dirty_checkout_actually_prevents_the_write(tmp_path: Path, monkeypatch):
    """The operator's in-progress edit survives untouched."""
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    (live / "secure" / "other.py").write_text("operator was mid-edit\n")
    widget_before = (live / "secure" / "widget.py").read_text()

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_REFUSED
    assert (live / "secure" / "widget.py").read_text() == widget_before
    assert (live / "secure" / "other.py").read_text() == "operator was mid-edit\n"


def test_an_unanswerable_cleanliness_question_blocks_promotion(tmp_path: Path, monkeypatch):
    import secure.agent.promote as promote_module

    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    monkeypatch.setattr(promote_module, "live_dirty_paths", lambda *a, **k: None)

    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("refusing rather than assuming" in r for r in gate.refusals)


# =====================================================================
# 7 — reviewer blocker blocks promotion
# =====================================================================


def test_a_reviewer_blocking_finding_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, review_blocking=["tests_weakened"])
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("tests_weakened" in r for r in gate.refusals)


def test_a_coder_reviewer_disagreement_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, review_disagreement=True)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("materially disagreed" in r for r in gate.refusals)


def test_an_unusable_review_blocks_promotion(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    for status in ("error", "unparseable"):
        run = _make_run(tmp_path, live, review_status=status)
        assessment = _assessment(tmp_path, live, run, monkeypatch)
        gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
        assert gate.allowed is False, status


# =====================================================================
# 8 — consequential classifications never auto-promote
# =====================================================================


def test_no_consequential_classification_can_ever_promote(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    for cls in (
        CLASS_DEPENDENCY_CHANGE, CLASS_SECURITY_SEMANTIC_CHANGE,
        CLASS_SYSTEM_CHANGE, CLASS_PRIVILEGED_CHANGE,
    ):
        run = _make_run(tmp_path, live, classification=cls)
        assessment = _assessment(tmp_path, live, run, monkeypatch)
        gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR(classification=cls))
        assert gate.allowed is False, cls
        assert any("never auto-promotes" in r for r in gate.refusals), cls


def test_an_unclassified_change_never_promotes(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live, classification=None)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    gate = evaluate_promotion_gate(run, assessment, _cfg(tmp_path), root=live, change_request=_CR())
    assert gate.allowed is False
    assert any("ambiguous classification never auto-promotes" in r for r in gate.refusals)


def test_a_change_request_already_acted_on_by_a_human_is_not_overridden(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    for status in ("approved", "rejected", "superseded"):
        run = _make_run(tmp_path, live)
        assessment = _assessment(tmp_path, live, run, monkeypatch)
        gate = evaluate_promotion_gate(
            run, assessment, _cfg(tmp_path), root=live, change_request=_CR(status=status)
        )
        assert gate.allowed is False, status
        assert any("not this module's to override" in r for r in gate.refusals), status


# =====================================================================
# 9 — failed post-promotion verification safely rolls back
# =====================================================================


def test_failed_post_verification_rolls_back(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    before = (live / "secure" / "widget.py").read_text()
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    _stub_post_verification(monkeypatch, False, notes=("FAST: failed",))

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_ROLLED_BACK
    assert result.applied is True
    assert result.rolled_back is True
    assert result.live_checkout_modified is False
    assert (live / "secure" / "widget.py").read_text() == before
    assert live_dirty_paths(live) == []


def test_rollback_is_refused_when_something_else_also_changed(tmp_path: Path, monkeypatch):
    """A rollback that might destroy unrelated work is worse than
    leaving the patch in place with a loud message."""
    import secure.agent.promote as promote_module

    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)

    def _verify_and_meddle(*a, **k):
        # Simulate a concurrent writer touching an unrelated file
        # between the apply and the rollback decision.
        (live / "secure" / "concurrent.py").write_text("someone else's work\n")
        return False, ("FAST: failed",)

    monkeypatch.setattr(promote_module, "verify_after_promotion", _verify_and_meddle)

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_ESCALATED
    assert result.rolled_back is False
    assert "could not be proven safe" in result.detail
    assert (live / "secure" / "concurrent.py").read_text() == "someone else's work\n"


def test_a_failed_rollback_escalates_rather_than_retrying(tmp_path: Path, monkeypatch):
    import secure.agent.promote as promote_module

    live = _live_repo(tmp_path)
    run = _make_run(tmp_path, live)
    assessment = _assessment(tmp_path, live, run, monkeypatch)
    _stub_post_verification(monkeypatch, False)

    real_git = promote_module._git

    def _git_failing_revert(args, **kwargs):
        if args[:2] == ["apply", "-R"]:
            class _P:
                returncode = 1
                stdout = ""
                stderr = "patch does not apply"

            return _P()
        return real_git(args, **kwargs)

    monkeypatch.setattr(promote_module, "_git", _git_failing_revert)

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_ESCALATED
    assert "rollback itself failed" in result.detail
    assert "git apply -R" in result.detail


def test_a_patch_that_does_not_apply_is_refused_before_any_write(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    before = (live / "secure" / "widget.py").read_text()
    bad_patch = (
        "--- a/secure/widget.py\n+++ b/secure/widget.py\n@@ -1,2 +1,2 @@\n"
        " def widget():\n-    return 999\n+    return 2\n"
    )
    run = _make_run(tmp_path, live, patch=bad_patch)
    assessment = _assessment(tmp_path, live, run, monkeypatch)

    with Database(tmp_path / "s.db") as db:
        result = promote(db.conn, run, assessment, _cfg(tmp_path), root=live, change_request=_CR())

    assert result.outcome == PROMOTION_REFUSED
    assert result.applied is False
    assert (live / "secure" / "widget.py").read_text() == before


# =====================================================================
# The module's own guarantees
# =====================================================================


def test_the_gate_collects_refusals_rather_than_approvals(tmp_path: Path):
    """Polarity matters: an empty refusal list is the only thing that
    permits promotion, so a condition nobody checked cannot read as
    satisfied."""
    from secure.agent.promote import PromotionGate

    assert PromotionGate(refusals=()).allowed is True
    assert PromotionGate(refusals=("anything",)).allowed is False


def test_the_module_never_commits_amends_or_touches_git_config():
    """The operator owns their history."""
    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "promote.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    literals = [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value not in docstrings
    ]
    forbidden_subcommands = {"commit", "config", "push", "reset", "checkout", "branch", "rebase", "tag"}
    assert not (set(literals) & forbidden_subcommands), (
        f"forbidden git subcommand used as an argv token: {set(literals) & forbidden_subcommands}"
    )


def test_the_module_never_calls_approve_change():
    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "promote.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    banned = {"approve_change", "reject_change"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
            offending.append(node.lineno)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
            offending.append(node.lineno)
    assert offending == []


def test_no_test_in_this_file_targets_the_real_checkout():
    """This phase's tests drive the first module that can write to a
    live working tree. A test that pointed it at the real repository
    would be writing to Erick's project, so every `root=` here must be
    a tmp_path-derived repo."""
    source = Path(__file__)
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords or []:
                if kw.arg == "root" and isinstance(kw.value, ast.Call):
                    func = kw.value.func
                    name = getattr(func, "id", None) or getattr(func, "attr", None)
                    if name == "project_root":
                        offending.append(node.lineno)
    assert offending == []

    # Deliberately AST-only. A substring belt-and-braces line here
    # ("project_root()" not in text) fails against this very test's own
    # source, which has to name the thing it forbids — the same
    # substring-vs-structure trap that has bitten this project five
    # times already. The AST check is the real one.


# =====================================================================
# 10/11 — forbidden commands are detected; prose mentioning them is not
#
# Phase 47.5's governing text asks for structural checks that catch a
# real executable command shape while leaving documentation alone.
# These two tests exercise the detection logic itself, so the property
# is proven rather than assumed each time a module is checked.
# =====================================================================


def _argv_tokens(source: str, binaries: set) -> list:
    tree = ast.parse(source)
    literals = [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    return [lit for lit in literals if lit.strip() in binaries]


def _banned_calls(source: str, banned: set) -> list:
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name in banned:
                found.append(name)
    return found


def test_an_actual_forbidden_command_is_detected():
    real_invocation = 'import subprocess\nsubprocess.run(["launchctl", "load", path])\n'
    assert _argv_tokens(real_invocation, {"launchctl", "launchd"}) == ["launchctl"]

    real_pip = 'import subprocess\nsubprocess.run(["pip", "install", "requests"])\n'
    assert _argv_tokens(real_pip, {"pip", "pip3", "brew", "npm"}) == ["pip"]

    real_tempfile = "import tempfile\nd = tempfile.mkdtemp()\n"
    assert _banned_calls(real_tempfile, {"mkdtemp", "mkstemp", "NamedTemporaryFile"}) == ["mkdtemp"]


def test_prose_merely_mentioning_a_forbidden_command_is_not_detected():
    """The failure mode this project hit five separate times. A safety
    check that fires on the sentence explaining the safety property
    will eventually be deleted or silenced, and a silenced check
    protects nothing."""
    prose = (
        'MSG = "Secure never invokes launchctl to install itself, and does not install, '
        'update, or remove packages with pip or brew."\n'
    )
    assert _argv_tokens(prose, {"launchctl", "launchd"}) == []
    assert _argv_tokens(prose, {"pip", "pip3", "brew", "npm"}) == []

    docstring_prose = (
        '"""This module never calls tempfile.mkdtemp() or NamedTemporaryFile(); '
        'it uses TemporaryDirectory instead."""\nx = 1\n'
    )
    assert _banned_calls(docstring_prose, {"mkdtemp", "mkstemp", "NamedTemporaryFile"}) == []
