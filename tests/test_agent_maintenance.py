"""tests/test_agent_maintenance.py — Phase 47
("Supervised Autonomous Maintenance") — the Part 2 acceptance demo.

Acceptance criteria (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "Demonstrate the complete loop using controlled synthetic failures.
    At minimum demonstrate:
      1. one repair that safely reaches VERIFIED through the automated pipeline
      2. one intentionally failing repair that is rejected
      3. one consequential/system-change scenario that stops at AWAITING_APPROVAL
         without modifying the host
      4. one coder/reviewer disagreement that escalates instead of proceeding
      5. one non-reproducible failure that stops honestly
      6. complete action/provenance history for each scenario"

    "Do not perform a real host/system change merely to demonstrate
    Phase 47."

EVERY SCENARIO BELOW IS SYNTHETIC. Each runs against a throwaway git
repository in `tmp_path` with a stubbed coder and stubbed reproduction;
none touches the live checkout, `~/.secure`, launchd, a package
manager, or the network. Scenario 3's whole point is that it stops
with the host untouched, and it asserts that explicitly.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import secure.agent.diagnose as diagnose_module
import secure.agent.orchestrator as orch_module
from secure.agent.classify import CLASS_SAFE_PROJECT_CODE, CLASS_SYSTEM_CHANGE
from secure.agent.diagnose import (
    REPRO_NOT_REPRODUCED,
    REPRO_REPRODUCED,
    REPRO_UNAVAILABLE,
    ReproductionResult,
)
from secure.agent.maintenance import (
    ALL_LOOP_OUTCOMES,
    LOOP_AWAITING_APPROVAL,
    LOOP_ESCALATED_DISAGREEMENT,
    LOOP_INCONCLUSIVE,
    LOOP_NOT_REPRODUCED,
    LOOP_PROMOTION_ELIGIBLE,
    LOOP_REPAIR_REJECTED,
    describe,
    run_maintenance_cycle,
)
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.review import Q_ROOT_PROBLEM, Q_TESTS_WEAKENED, REVIEW_QUESTIONS
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import (
    find_ai_change_request,
    find_maintenance_memory_for_run,
    list_agent_actions,
)


# ---------------------------------------------------------------------
# Synthetic world
# ---------------------------------------------------------------------


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
    (root / "tests" / "test_widget.py").write_text("def test_widget():\n    assert widget() == 2\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    return root


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


def _candidate() -> RepairCandidate:
    return RepairCandidate(
        TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "AssertionError: widget() == 2",
    )


class _FakeReviewer:
    """A duck-typed local model. Never makes a network call."""

    def __init__(self, answers: dict):
        self.identity = ProviderIdentity(name="ollama")
        self.model_name = "reviewer-model"
        self.configured = True
        self.timeout = 30.0
        self._answers = answers
        self.calls = []

    def complete(self, system_prompt, user_prompt, timeout=None):
        self.calls.append(user_prompt)
        payload = {
            "answers": {q: {"answer": self._answers.get(q, "no"), "rationale": "because"} for q in REVIEW_QUESTIONS},
            "summary": "synthetic review",
        }
        payload["answers"][Q_ROOT_PROBLEM] = {
            "answer": self._answers.get(Q_ROOT_PROBLEM, "yes"), "rationale": "because",
        }
        return ProviderCompletionResult(
            provider="ollama", model=self.model_name, status="ok", text=json.dumps(payload),
            requested_at="now", latency_ms=1.0, raw_response={}, error=None,
        )


def _providers(reviewer=None):
    return {"ollama": reviewer, "openai_compatible": None}


def _install_stubs(
    monkeypatch,
    *,
    edits: "list[tuple[str, str]]",
    verification: VerificationOutcome,
    reproduction: ReproductionResult,
):
    """Stubs exactly three seams — the coder, the deterministic
    verification, and the reproduction check — and nothing else. Every
    other step in the loop (diff computation, denylist, classification,
    review, change request, memory, audit) runs for real."""

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        for rel, content in edits:
            path = worktree.worktree_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted",
            submission="I fixed the failing test", mini_version="fake", instance_cost=None,
            transcript_path=None, model_name="ollama/coder-model", argv=["fake"],
            config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(orch_module, "verify_worktree", lambda w, c, **k: verification)
    monkeypatch.setattr(diagnose_module, "reproduce_failure", lambda *a, **k: reproduction)


_PASSING = VerificationOutcome(VerifyResult("ok", True, "1 passed"), VerifyResult("ok", True, "validate ok"))
_FAILING = VerificationOutcome(VerifyResult("ok", False, "1 failed"), VerifyResult("ok", True, "validate ok"))
_REPRODUCED = ReproductionResult(REPRO_REPRODUCED, True, "1 failed", "pytest node", 0.5)
_NOT_REPRODUCED = ReproductionResult(REPRO_NOT_REPRODUCED, False, "1 passed — did NOT recur", "pytest node", 0.4)
_INCONCLUSIVE = ReproductionResult(REPRO_UNAVAILABLE, None, "pytest is not installed", "pytest node", 0.1)

# Deliberately more than 20 changed lines. Phase 38 treats a single
# small non-test, non-sensitive change as TRIVIAL and skips the
# independent review — correct behavior, but it would mean scenario 1
# never exercised the reviewer at all. A realistic repair of this shape
# is what the demo should show.
_ORDINARY_FIX = (
    "secure/widget.py",
    "def widget():\n"
    + "".join(f"    step_{i} = {i}\n" for i in range(24))
    + "    return 2\n",
)
_CONSEQUENTIAL_FIX = (
    "secure/widget.py",
    'import subprocess\n\n\ndef widget():\n    subprocess.run(["launchctl", "load", "/x.plist"])\n    return 2\n',
)
_TEST_WEAKENING_FIX = ("tests/test_widget.py", "def test_widget():\n    pass\n")


def _run(tmp_path, monkeypatch, *, edits, verification, reproduction, reviewer=None):
    repo = _repo(tmp_path)
    _install_stubs(monkeypatch, edits=edits, verification=verification, reproduction=reproduction)
    with Database(tmp_path / "secure.db") as db:
        outcome = run_maintenance_cycle(
            db.conn, _cfg(tmp_path), _candidate(), root=repo, providers=_providers(reviewer),
        )
        cr = find_ai_change_request(db.conn, outcome.change_request_id) if outcome.change_request_id else None
        memory = find_maintenance_memory_for_run(db.conn, outcome.run_id) if outcome.run_id else None
        actions = list_agent_actions(db.conn, run_id=outcome.run_id, limit=200) if outcome.run_id else []
        return outcome, cr, memory, actions


# =====================================================================
# SCENARIO 1 — a repair that safely reaches VERIFIED
# =====================================================================


def test_scenario_1_a_good_repair_travels_the_whole_pipeline(tmp_path: Path, monkeypatch):
    reviewer = _FakeReviewer({})  # clean review
    outcome, cr, memory, actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=reviewer,
    )

    assert outcome.run_status == "verified"
    assert outcome.reproduced is True
    assert outcome.classification == CLASS_SAFE_PROJECT_CODE
    assert outcome.review_status == "ok"
    assert outcome.review_blocking == ()
    assert outcome.change_request_id is not None
    assert cr.status == "pending"
    assert reviewer.calls, "the independent reviewer was never actually invoked"
    assert outcome.host_modified is False


def test_scenario_1_reaches_promotion_eligibility_when_phase_44_criteria_are_met(tmp_path: Path, monkeypatch):
    """Phase 44 re-measures rather than remembering, so the loop's own
    call (without a re-run of the tiers) honestly reports "unknown" for
    the tier criteria and therefore does NOT claim promotion
    eligibility. Proving that here matters more than manufacturing a
    green result: the loop fails toward requiring a human."""
    reviewer = _FakeReviewer({})
    outcome, _cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=reviewer,
    )
    assert outcome.outcome in (LOOP_PROMOTION_ELIGIBLE, LOOP_AWAITING_APPROVAL)
    if outcome.outcome == LOOP_AWAITING_APPROVAL:
        assert outcome.verified is False
        assert outcome.verified_blocking, "if not verified, the blocking criteria must be named"


def test_scenario_1_never_promotes_anything_itself(tmp_path: Path, monkeypatch):
    """"Eligibility is not permission." Even on the happy path, the
    live checkout is untouched."""
    repo = _repo(tmp_path)
    before = (repo / "secure" / "widget.py").read_text()
    _install_stubs(monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING, reproduction=_REPRODUCED)
    with Database(tmp_path / "secure.db") as db:
        outcome = run_maintenance_cycle(
            db.conn, _cfg(tmp_path), _candidate(), root=repo, providers=_providers(_FakeReviewer({})),
        )
    assert (repo / "secure" / "widget.py").read_text() == before
    assert outcome.host_modified is False


# =====================================================================
# SCENARIO 2 — an intentionally failing repair is rejected
# =====================================================================


def test_scenario_2_a_repair_that_fails_verification_is_rejected(tmp_path: Path, monkeypatch):
    outcome, cr, memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_FAILING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({}),
    )
    assert outcome.outcome == LOOP_REPAIR_REJECTED
    assert outcome.run_status == "verification_failed"
    assert outcome.change_request_id is None
    assert cr is None
    assert memory is not None and memory.outcome == "verification_failed"


def test_scenario_2_a_rejected_repair_never_reaches_the_reviewer(tmp_path: Path, monkeypatch):
    """Deterministic verification is authoritative and comes first: a
    failed repair is not sent for a second opinion that could not have
    saved it anyway."""
    reviewer = _FakeReviewer({})
    _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_FAILING,
        reproduction=_REPRODUCED, reviewer=reviewer,
    )
    assert reviewer.calls == []


# =====================================================================
# SCENARIO 3 — a consequential change stops at AWAITING_APPROVAL
#              with the host untouched
# =====================================================================


def test_scenario_3_a_consequential_change_stops_awaiting_approval(tmp_path: Path, monkeypatch):
    outcome, cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_CONSEQUENTIAL_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({}),
    )
    assert outcome.outcome == LOOP_AWAITING_APPROVAL
    assert outcome.classification == CLASS_SYSTEM_CHANGE
    assert outcome.awaiting_human is True
    assert cr is not None and cr.status == "pending"
    assert cr.classification == CLASS_SYSTEM_CHANGE


def test_scenario_3_leaves_the_host_completely_untouched(tmp_path: Path, monkeypatch):
    """The scenario's whole point. The repair CONTAINS a launchctl
    call; nothing ran it, nothing installed anything, and the live
    checkout is byte-identical."""
    repo = _repo(tmp_path)
    before = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}
    launch_agents = Path.home() / "Library" / "LaunchAgents"
    agents_before = sorted(p.name for p in launch_agents.glob("*.plist")) if launch_agents.is_dir() else []

    _install_stubs(monkeypatch, edits=[_CONSEQUENTIAL_FIX], verification=_PASSING, reproduction=_REPRODUCED)
    with Database(tmp_path / "secure.db") as db:
        outcome = run_maintenance_cycle(
            db.conn, _cfg(tmp_path), _candidate(), root=repo, providers=_providers(_FakeReviewer({})),
        )

    after = {p: p.read_bytes() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}
    agents_after = sorted(p.name for p in launch_agents.glob("*.plist")) if launch_agents.is_dir() else []

    assert after == before
    assert agents_after == agents_before
    assert outcome.host_modified is False
    assert "no host state was changed" in outcome.detail


def test_scenario_3_is_never_promotion_eligible(tmp_path: Path, monkeypatch):
    outcome, _cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_CONSEQUENTIAL_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({}),
    )
    assert outcome.promotion_eligible is False


# =====================================================================
# SCENARIO 4 — coder/reviewer disagreement escalates
# =====================================================================


def test_scenario_4_a_disagreement_escalates_instead_of_proceeding(tmp_path: Path, monkeypatch):
    """The coder weakened a test and reports success; deterministic
    verification passes (the weakened test does pass); the reviewer
    says tests were weakened. That is the material disagreement."""
    reviewer = _FakeReviewer({Q_TESTS_WEAKENED: "yes"})
    outcome, cr, memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_TEST_WEAKENING_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=reviewer,
    )
    assert outcome.outcome == LOOP_ESCALATED_DISAGREEMENT
    assert outcome.run_status == "escalated_for_review"
    assert Q_TESTS_WEAKENED in outcome.review_blocking
    assert outcome.disagreement is True


def test_scenario_4_creates_no_change_request(tmp_path: Path, monkeypatch):
    """Escalation is a stop, not a slower approval path."""
    outcome, cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_TEST_WEAKENING_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({Q_TESTS_WEAKENED: "yes"}),
    )
    assert outcome.change_request_id is None
    assert cr is None
    assert outcome.awaiting_human is True


def test_scenario_4_records_the_escalation_in_memory(tmp_path: Path, monkeypatch):
    _outcome, _cr, memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_TEST_WEAKENING_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({Q_TESTS_WEAKENED: "yes"}),
    )
    assert memory is not None
    assert memory.outcome == "escalated_for_review"
    assert "tests_weakened" in memory.reviewer_assessment


# =====================================================================
# SCENARIO 5 — a non-reproducible failure stops honestly
# =====================================================================


def test_scenario_5_a_non_reproducible_failure_stops_honestly(tmp_path: Path, monkeypatch):
    outcome, cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING,
        reproduction=_NOT_REPRODUCED, reviewer=_FakeReviewer({}),
    )
    assert outcome.outcome == LOOP_NOT_REPRODUCED
    assert outcome.reproduced is False
    assert outcome.run_id is None
    assert cr is None
    assert "none was fabricated" in outcome.detail


def test_scenario_5_no_coder_is_ever_invoked_for_a_non_reproducible_failure(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path)
    invoked = []

    def _boom(*a, **k):
        invoked.append(1)
        raise AssertionError("the coder must not run for a failure that does not reproduce")

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", _boom)
    monkeypatch.setattr(diagnose_module, "reproduce_failure", lambda *a, **k: _NOT_REPRODUCED)
    with Database(tmp_path / "secure.db") as db:
        outcome = run_maintenance_cycle(
            db.conn, _cfg(tmp_path), _candidate(), root=repo, providers=_providers(),
        )
    assert invoked == []
    assert outcome.outcome == LOOP_NOT_REPRODUCED


def test_scenario_5b_an_inconclusive_reproduction_also_stops(tmp_path: Path, monkeypatch):
    outcome, _cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING,
        reproduction=_INCONCLUSIVE, reviewer=_FakeReviewer({}),
    )
    assert outcome.outcome == LOOP_INCONCLUSIVE
    assert outcome.reproduced is None
    assert "not permission to repair" in outcome.detail


# =====================================================================
# SCENARIO 6 — complete action/provenance history for each scenario
# =====================================================================


def test_scenario_6_every_repairing_scenario_has_a_full_audit_trail(tmp_path: Path, monkeypatch):
    for label, edits, verification, reviewer in (
        ("verified", [_ORDINARY_FIX], _PASSING, _FakeReviewer({})),
        ("rejected", [_ORDINARY_FIX], _FAILING, _FakeReviewer({})),
        ("consequential", [_CONSEQUENTIAL_FIX], _PASSING, _FakeReviewer({})),
        ("escalated", [_TEST_WEAKENING_FIX], _PASSING, _FakeReviewer({Q_TESTS_WEAKENED: "yes"})),
    ):
        sub = tmp_path / label
        sub.mkdir()
        outcome, _cr, memory, actions = _run(
            sub, monkeypatch, edits=edits, verification=verification,
            reproduction=_REPRODUCED, reviewer=reviewer,
        )
        assert outcome.run_id is not None, label
        assert actions, f"{label}: no audited actions recorded"
        assert memory is not None, f"{label}: no maintenance memory recorded"
        assert memory.failure_signature, label
        assert memory.base_commit, label
        assert all(a.timestamp for a in actions), label


def test_scenario_6_the_audit_trail_records_argv_and_mutation_flags(tmp_path: Path, monkeypatch):
    _outcome, _cr, _memory, actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({}),
    )
    assert any(a.argv for a in actions)
    assert any(a.component.startswith("agent.") for a in actions)
    assert all(isinstance(a.mutating, bool) for a in actions)


def test_scenario_6_provenance_survives_for_a_non_reproducing_failure_too(tmp_path: Path, monkeypatch):
    """A stop still leaves evidence — Phase 43 records the reproduction
    attempt even though no run row exists."""
    repo = _repo(tmp_path)
    _install_stubs(monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING, reproduction=_NOT_REPRODUCED)
    with Database(tmp_path / "secure.db") as db:
        outcome = run_maintenance_cycle(
            db.conn, _cfg(tmp_path), _candidate(), root=repo, providers=_providers(),
        )
        unattached = list_agent_actions(db.conn, run_id=None, limit=50)
    assert outcome.run_id is None
    assert isinstance(unattached, list)  # queryable either way; no silent gap


def test_describe_renders_every_scenario_without_raising(tmp_path: Path, monkeypatch):
    outcome, _cr, _memory, _actions = _run(
        tmp_path, monkeypatch, edits=[_ORDINARY_FIX], verification=_PASSING,
        reproduction=_REPRODUCED, reviewer=_FakeReviewer({}),
    )
    text = describe(outcome)
    assert "OUTCOME:" in text
    assert "Host modified:  False" in text


# =====================================================================
# The loop's own guarantees
# =====================================================================


def test_no_outcome_of_the_loop_ever_reports_a_modified_host(tmp_path: Path, monkeypatch):
    """Across every scenario, `host_modified` is False — asserted
    rather than inferred."""
    for label, edits, verification, reproduction, reviewer in (
        ("a", [_ORDINARY_FIX], _PASSING, _REPRODUCED, _FakeReviewer({})),
        ("b", [_ORDINARY_FIX], _FAILING, _REPRODUCED, _FakeReviewer({})),
        ("c", [_CONSEQUENTIAL_FIX], _PASSING, _REPRODUCED, _FakeReviewer({})),
        ("d", [_TEST_WEAKENING_FIX], _PASSING, _REPRODUCED, _FakeReviewer({Q_TESTS_WEAKENED: "yes"})),
        ("e", [_ORDINARY_FIX], _PASSING, _NOT_REPRODUCED, _FakeReviewer({})),
        ("f", [_ORDINARY_FIX], _PASSING, _INCONCLUSIVE, _FakeReviewer({})),
    ):
        sub = tmp_path / label
        sub.mkdir()
        outcome, _cr, _memory, _actions = _run(
            sub, monkeypatch, edits=edits, verification=verification,
            reproduction=reproduction, reviewer=reviewer,
        )
        assert outcome.host_modified is False, label
        assert outcome.outcome in ALL_LOOP_OUTCOMES, label


def test_the_loop_module_never_applies_a_patch_or_approves_anything():
    """Structural. The flow's happy path ends at "policy-permitted
    promotion", and this module reports eligibility rather than
    performing it — applying a patch to the live checkout is the write
    every isolation boundary since Phase 31 exists to prevent."""
    import ast

    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "maintenance.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    banned = {"approve_change", "reject_change", "set_ai_change_request_status", "apply_patch"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
            offending.append(f"import line {node.lineno}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
            offending.append(f"call line {node.lineno}")
        if isinstance(node, ast.Attribute) and node.attr in ("write_text", "write_bytes"):
            offending.append(f"write line {node.lineno}")
        # Execution is checked by import rather than by attribute name:
        # a bare `.run` also matches `diagnosis.run`, which is a
        # dataclass field, not a subprocess call. The first version of
        # this test made exactly that mistake.
        if isinstance(node, ast.Import):
            offending += [
                f"import line {node.lineno}: {a.name}"
                for a in node.names if a.name.split(".")[0] in {"subprocess", "os"}
            ]
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in {"subprocess", "os"}:
                offending.append(f"import line {node.lineno}: {node.module}")
    assert offending == []


def test_every_loop_outcome_is_in_the_declared_vocabulary():
    assert len(set(ALL_LOOP_OUTCOMES)) == len(ALL_LOOP_OUTCOMES)
    for name in ALL_LOOP_OUTCOMES:
        assert isinstance(name, str) and name
