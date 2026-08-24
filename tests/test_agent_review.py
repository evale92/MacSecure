"""tests/test_agent_review.py — Phase 38 ("Independent Reviewer").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "A non-trivial candidate repair can be independently reviewed, its
    assessment is persisted/auditable, deterministic test results
    remain authoritative, and material disagreement prevents automatic
    progression."

The four adversarial tests that matter most are grouped under
"deterministic verification remains authoritative" below: a maximally
positive review must not rescue a failed or inconclusive verification,
and the reviewer must not even be consulted on those branches.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import secure.agent.orchestrator as orch_module
from secure.agent.changes import _model_b_opinion, _review_risk_sentence
from secure.agent.orchestrator import attempt_repair
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.review import (
    ANSWER_NO,
    ANSWER_UNKNOWN,
    ANSWER_YES,
    BLOCKING_QUESTIONS,
    GATE_ESCALATE,
    GATE_PROCEED,
    REVIEW_ERROR,
    REVIEW_NOT_REQUIRED,
    REVIEW_OK,
    REVIEW_QUESTIONS,
    REVIEW_UNAVAILABLE,
    REVIEW_UNPARSEABLE,
    Q_ARCHITECTURE,
    Q_DEPENDENCIES,
    Q_NEEDS_APPROVAL,
    Q_ROOT_PROBLEM,
    Q_TESTS_WEAKENED,
    Q_TOO_BROAD,
    ReviewAnswer,
    ReviewAssessment,
    build_review_prompt,
    compute_blocking,
    is_non_trivial,
    parse_review_response,
    review_gate,
    review_repair,
)
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import find_agent_repair_run, find_ai_change_request


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
    return root


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


def _candidate() -> RepairCandidate:
    return RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::test_widget", "boom")


def _passing_verification() -> VerificationOutcome:
    return VerificationOutcome(VerifyResult("ok", True, "5 passed"), VerifyResult("ok", True, "validate ok"))


def _failing_verification() -> VerificationOutcome:
    return VerificationOutcome(VerifyResult("ok", False, "1 failed"), VerifyResult("ok", True, "validate ok"))


def _inconclusive_verification() -> VerificationOutcome:
    return VerificationOutcome(VerifyResult("unavailable", None, "no pytest"), VerifyResult("ok", True, "ok"))


def _answers(**overrides) -> dict:
    """A fully clean set of answers, with individual questions
    overridable — so each test states only the one thing it is about."""
    base = {q: ANSWER_NO for q in REVIEW_QUESTIONS}
    base[Q_ROOT_PROBLEM] = ANSWER_YES  # "yes it addresses the root problem" is the clean answer
    base.update(overrides)
    return {"answers": {q: {"answer": a, "rationale": "because"} for q, a in base.items()},
            "summary": "looks fine"}


def _assessment(status: str = REVIEW_OK, **overrides) -> ReviewAssessment:
    payload = _answers(**overrides)
    answers, summary, err = parse_review_response(json.dumps(payload))
    return ReviewAssessment(
        status=status, provider="ollama", model="m", answers=answers,
        blocking=compute_blocking(answers), summary=summary,
    )


class _FakeProvider:
    """Duck-typed stand-in for a Phase 28 provider. Deliberately not a
    subclass — secure/ai/model_roles.py's invoke_role() docstring says
    it works identically for a real provider or a test stub, and this
    test proves that claim rather than assuming it."""

    def __init__(self, name: str, text=None, *, configured: bool = True, raises: bool = False, status: str = "ok"):
        self.identity = ProviderIdentity(name=name)
        self.model_name = f"{name}-model"
        self.configured = configured
        self.timeout = 30.0
        self._text = text
        self._raises = raises
        self._status = status
        self.calls = []

    def complete(self, system_prompt, user_prompt, timeout=None):
        self.calls.append((system_prompt, user_prompt, timeout))
        if self._raises:
            raise RuntimeError("provider exploded")
        if self._status != "ok":
            return ProviderCompletionResult(
                provider=self.identity.name, model=self.model_name, status=self._status, text=None,
                requested_at="now", latency_ms=None, raw_response=None, error="backend down",
            )
        return ProviderCompletionResult(
            provider=self.identity.name, model=self.model_name, status="ok", text=self._text,
            requested_at="now", latency_ms=1.0, raw_response={}, error=None,
        )


def _providers(reviewer: "_FakeProvider | None") -> dict:
    return {"ollama": reviewer, "openai_compatible": None}


# =====================================================================
# Triviality — which repairs get reviewed at all
# =====================================================================


def test_single_small_ordinary_file_change_is_trivial():
    assert is_non_trivial("+x = 1\n-x = 0\n", ["secure/widget.py"]) is False


def test_any_change_to_a_test_file_is_never_trivial():
    """A one-line edit deleting an assertion is small but is exactly
    the failure mode AGENTS.md rule 3 exists to prevent."""
    assert is_non_trivial("-    assert result == 5\n", ["tests/test_widget.py"]) is True


def test_security_sensitive_path_is_never_trivial():
    assert is_non_trivial("+x = 1\n", ["secure/detect/rules.py"]) is True


def test_multiple_files_is_never_trivial():
    assert is_non_trivial("+x = 1\n", ["secure/widget.py", "secure/other.py"]) is True


def test_large_diff_is_never_trivial():
    big = "\n".join(f"+line{i}" for i in range(40))
    assert is_non_trivial(big, ["secure/widget.py"]) is True


def test_unknown_scope_escalates_toward_review_not_away_from_it():
    assert is_non_trivial("", []) is True


# =====================================================================
# Parsing
# =====================================================================


def test_parses_a_well_formed_response():
    answers, summary, err = parse_review_response(json.dumps(_answers()))
    assert err is None
    assert len(answers) == len(REVIEW_QUESTIONS)
    assert summary == "looks fine"


def test_parses_a_response_wrapped_in_a_markdown_fence():
    body = json.dumps(_answers())
    answers, _summary, err = parse_review_response("Sure!\n```json\n" + body + "\n```\nHope that helps.")
    assert err is None
    assert len(answers) == len(REVIEW_QUESTIONS)


def test_a_missing_question_becomes_unknown_rather_than_disappearing():
    payload = _answers()
    del payload["answers"][Q_TESTS_WEAKENED]
    answers, _summary, err = parse_review_response(json.dumps(payload))
    assert err is None
    assert [a.answer for a in answers if a.question == Q_TESTS_WEAKENED] == [ANSWER_UNKNOWN]


def test_an_invalid_answer_value_becomes_unknown_rather_than_being_trusted():
    payload = _answers()
    payload["answers"][Q_TESTS_WEAKENED] = {"answer": "definitely not!", "rationale": ""}
    answers, _summary, err = parse_review_response(json.dumps(payload))
    assert err is None
    assert [a.answer for a in answers if a.question == Q_TESTS_WEAKENED] == [ANSWER_UNKNOWN]


def test_a_flat_answer_shape_is_tolerated():
    payload = {"answers": {q: ANSWER_NO for q in REVIEW_QUESTIONS}, "summary": "s"}
    payload["answers"][Q_ROOT_PROBLEM] = ANSWER_YES
    answers, _summary, err = parse_review_response(json.dumps(payload))
    assert err is None
    assert compute_blocking(answers) == ()


def test_non_json_output_is_an_error_not_an_empty_review():
    answers, _summary, err = parse_review_response("I think this patch looks great, ship it!")
    assert err is not None
    assert answers == ()


def test_json_with_no_recognizable_answers_is_an_error():
    answers, _summary, err = parse_review_response(json.dumps({"answers": {"nonsense": "yes"}}))
    assert err is not None
    assert answers == ()


# =====================================================================
# Blocking findings
# =====================================================================


def test_a_clean_review_has_no_blocking_findings():
    assert _assessment().blocking == ()


def test_tests_weakened_blocks():
    assert Q_TESTS_WEAKENED in _assessment(**{Q_TESTS_WEAKENED: ANSWER_YES}).blocking


def test_not_addressing_the_root_problem_blocks():
    assert Q_ROOT_PROBLEM in _assessment(**{Q_ROOT_PROBLEM: ANSWER_NO}).blocking


def test_unknown_on_a_blocking_question_blocks():
    """The gate exists to obtain an assurance; a reviewer that cannot
    give it has not given it — the same "inconclusive is never a pass"
    rule deterministic verification already follows."""
    assert Q_ARCHITECTURE in _assessment(**{Q_ARCHITECTURE: ANSWER_UNKNOWN}).blocking


def test_breadth_and_needs_approval_are_recorded_but_do_not_block():
    assessment = _assessment(**{Q_TOO_BROAD: ANSWER_YES, Q_NEEDS_APPROVAL: ANSWER_YES})
    assert assessment.blocking == ()
    assert assessment.answer_for(Q_TOO_BROAD).answer == ANSWER_YES
    assert assessment.answer_for(Q_NEEDS_APPROVAL).answer == ANSWER_YES


def test_blocking_is_computed_from_answers_not_from_what_the_model_claims_about_itself():
    """A model asserting `"blocking": []` alongside a `tests_weakened:
    yes` answer must not be able to clear itself."""
    payload = _answers(**{Q_TESTS_WEAKENED: ANSWER_YES})
    payload["blocking"] = []
    payload["verdict"] = "approve"
    answers, _summary, err = parse_review_response(json.dumps(payload))
    assert err is None
    assert Q_TESTS_WEAKENED in compute_blocking(answers)


def test_every_blocking_question_is_one_of_the_nine_governing_questions():
    assert set(BLOCKING_QUESTIONS).issubset(set(REVIEW_QUESTIONS))


# =====================================================================
# The gate — deterministic verification remains authoritative
# =====================================================================


def test_gate_has_no_representation_for_verification_success():
    """Structural: the gate's vocabulary is exactly {proceed, escalate}.
    There is no third value a reviewer could return that means "tests
    passed," which is what makes it impossible for the reviewer to
    manufacture one."""
    assert {GATE_PROCEED, GATE_ESCALATE} == {"proceed", "escalate"}


def test_unavailable_reviewer_proceeds_without_claiming_a_review_happened():
    decision = review_gate(
        ReviewAssessment(status=REVIEW_UNAVAILABLE, provider="", model="", summary="none configured"),
        coder_claimed_success=True,
    )
    assert decision.decision == GATE_PROCEED
    assert decision.disagreement is False


def test_trivial_change_proceeds_without_a_review():
    decision = review_gate(
        ReviewAssessment(status=REVIEW_NOT_REQUIRED, provider="", model="", summary="trivial"),
        coder_claimed_success=True,
    )
    assert decision.decision == GATE_PROCEED


def test_a_reviewer_that_ran_and_errored_escalates_rather_than_being_ignored():
    decision = review_gate(
        ReviewAssessment(status=REVIEW_ERROR, provider="ollama", model="m", error="backend down"),
        coder_claimed_success=True,
    )
    assert decision.decision == GATE_ESCALATE


def test_unparseable_review_is_not_treated_as_approval():
    decision = review_gate(
        ReviewAssessment(status=REVIEW_UNPARSEABLE, provider="ollama", model="m", error="not json"),
        coder_claimed_success=True,
    )
    assert decision.decision == GATE_ESCALATE


def test_blocking_finding_plus_coder_success_claim_is_material_disagreement():
    decision = review_gate(_assessment(**{Q_TESTS_WEAKENED: ANSWER_YES}), coder_claimed_success=True)
    assert decision.decision == GATE_ESCALATE
    assert decision.disagreement is True
    assert Q_TESTS_WEAKENED in decision.reason


def test_clean_review_proceeds():
    decision = review_gate(_assessment(), coder_claimed_success=True)
    assert decision.decision == GATE_PROCEED
    assert decision.disagreement is False


# =====================================================================
# review_repair() against duck-typed providers
# =====================================================================


def test_no_configured_reviewer_reports_unavailable_honestly(tmp_path: Path):
    assessment = review_repair(
        _providers(None), _candidate(), coder_assessment="", diff_text="+x\n",
        changed_files=["tests/test_widget.py"], verification=_passing_verification(), root=tmp_path,
    )
    assert assessment.status == REVIEW_UNAVAILABLE
    assert assessment.blocking == ()


def test_a_real_review_round_trip_produces_answers(tmp_path: Path):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    assessment = review_repair(
        _providers(provider), _candidate(), coder_assessment="I fixed it", diff_text="+x\n",
        changed_files=["tests/test_widget.py"], verification=_passing_verification(), root=tmp_path,
    )
    assert assessment.status == REVIEW_OK
    assert len(assessment.answers) == len(REVIEW_QUESTIONS)
    assert assessment.blocking == ()
    assert provider.calls, "the reviewer provider was never actually invoked"


def test_a_provider_that_raises_is_reported_not_propagated(tmp_path: Path):
    provider = _FakeProvider("ollama", raises=True)
    assessment = review_repair(
        _providers(provider), _candidate(), coder_assessment="", diff_text="+x\n",
        changed_files=["tests/test_widget.py"], verification=_passing_verification(), root=tmp_path,
    )
    assert assessment.status == REVIEW_ERROR
    assert "provider exploded" in (assessment.error or "")


def test_a_provider_returning_prose_is_unparseable(tmp_path: Path):
    provider = _FakeProvider("ollama", text="Looks good to me!")
    assessment = review_repair(
        _providers(provider), _candidate(), coder_assessment="", diff_text="+x\n",
        changed_files=["tests/test_widget.py"], verification=_passing_verification(), root=tmp_path,
    )
    assert assessment.status == REVIEW_UNPARSEABLE


def test_a_trivial_change_never_reaches_the_provider(tmp_path: Path):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    assessment = review_repair(
        _providers(provider), _candidate(), coder_assessment="", diff_text="+x = 1\n",
        changed_files=["secure/widget.py"], verification=_passing_verification(), root=tmp_path,
    )
    assert assessment.status == REVIEW_NOT_REQUIRED
    assert provider.calls == []


# =====================================================================
# The prompt carries everything the governing text requires
# =====================================================================


def test_review_prompt_contains_all_seven_required_inputs(tmp_path: Path):
    prompt = build_review_prompt(
        _candidate(), coder_assessment="I changed the widget", diff_text="--- a/x\n+++ b/x\n+changed line\n",
        changed_files=["secure/widget.py"], verification=_passing_verification(), root=tmp_path,
    )
    assert "Original failure" in prompt                 # original failure
    assert "tests/test_widget.py::test_widget" in prompt
    assert "I changed the widget" in prompt             # diagnosis
    assert "+changed line" in prompt                    # actual git diff
    assert "- secure/widget.py" in prompt               # files changed
    assert "5 passed" in prompt                         # tests run + results
    assert "validate ok" in prompt
    assert "AUTHORITATIVE" in prompt                    # results framed as fact, not opinion


def test_review_prompt_labels_the_coder_account_as_an_unverified_claim(tmp_path: Path):
    prompt = build_review_prompt(
        _candidate(), coder_assessment="trust me", diff_text="+x\n", changed_files=[],
        verification=_passing_verification(), root=tmp_path,
    )
    assert "UNVERIFIED CLAIM" in prompt


def test_review_prompt_includes_engineering_policy_from_the_live_checkout():
    """Phase 37's files feed the reviewer too, not just the coder."""
    prompt = build_review_prompt(
        _candidate(), coder_assessment="", diff_text="+x\n", changed_files=[],
        verification=_passing_verification(),
    )
    assert "Engineering policy" in prompt
    assert "AGENTS.md" in prompt


# =====================================================================
# Orchestrator integration
# =====================================================================


def _fake_mini_that_edits(repo_relative: str = "secure/widget.py", content: str = "def widget():\n    return 99\n"):
    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / repo_relative).write_text(content)
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted",
            submission="I rewrote widget()", mini_version="fake", instance_cost=None,
            transcript_path=None, model_name="ollama/x", argv=["fake"], config_yaml="",
            transcript_hash=None,
        )

    return fake_run_mini


def _run_attempt(tmp_path, monkeypatch, *, verification, providers, edits="secure/widget.py"):
    repo = _init_repo(tmp_path)
    monkeypatch.setattr(orch_module, "run_mini_swe_agent", _fake_mini_that_edits(edits))
    monkeypatch.setattr(orch_module, "verify_worktree", lambda worktree, cfg_, **_kw: verification)
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        cfg.ollama_host = "http://127.0.0.1:11434"
        record = attempt_repair(db.conn, cfg, _candidate(), repo_root=repo, providers=providers)
        cr = find_ai_change_request(db.conn, record.change_request_id) if record.change_request_id else None
        return record, cr


def test_clean_review_still_produces_a_change_request(tmp_path: Path, monkeypatch):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_passing_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    assert record.status == "verified"
    assert record.change_request_id is not None
    assert record.review_status == REVIEW_OK
    assert record.review_blocking == []
    assert record.review_disagreement is False
    assert cr is not None


def test_blocking_review_escalates_and_creates_no_change_request(tmp_path: Path, monkeypatch):
    provider = _FakeProvider("ollama", text=json.dumps(_answers(**{Q_TESTS_WEAKENED: ANSWER_YES})))
    record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_passing_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    assert record.status == "escalated_for_review"
    assert record.change_request_id is None
    assert cr is None
    assert Q_TESTS_WEAKENED in record.review_blocking
    assert record.review_disagreement is True


def test_both_assessments_are_persisted_and_auditable(tmp_path: Path, monkeypatch):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    record, _cr = _run_attempt(
        tmp_path, monkeypatch, verification=_passing_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    # "Record BOTH assessments" — the coder's own account is stored
    # verbatim (and still never trusted; the diff above is what is
    # believed), alongside the reviewer's structured answers.
    assert record.coder_assessment == "I rewrote widget()"
    assert record.review_provider == "ollama"
    assert record.review_model == "ollama-model"
    questions_recorded = {a["question"] for a in record.review_answers}
    assert questions_recorded == set(REVIEW_QUESTIONS)


# ---------- adversarial: the reviewer can never rescue a bad result ----------


def test_a_glowing_review_cannot_rescue_a_failed_verification(tmp_path: Path, monkeypatch):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_failing_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    assert record.status == "verification_failed"
    assert record.verification_passed is False
    assert record.change_request_id is None
    assert cr is None


def test_a_glowing_review_cannot_rescue_an_inconclusive_verification(tmp_path: Path, monkeypatch):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_inconclusive_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    assert record.status == "verification_inconclusive"
    assert record.verification_passed is None
    assert cr is None


def test_the_reviewer_is_never_even_consulted_when_verification_did_not_pass(tmp_path: Path, monkeypatch):
    """Stronger than checking the outcome: the model is not called at
    all, so there is no path by which its opinion could have mattered."""
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    record, _cr = _run_attempt(
        tmp_path, monkeypatch, verification=_failing_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    # Guard against a vacuous pass: the run really did get far enough to
    # produce a reviewable diff, so "the reviewer was not called" means
    # the verification branch excluded it — not that there was nothing
    # to review.
    assert record.diff_hash is not None
    assert record.changed_files == ["tests/test_widget.py"]
    assert provider.calls == []


def test_no_configured_reviewer_behaves_exactly_as_before_phase_38(tmp_path: Path, monkeypatch):
    """The honest-absence path: an operator with no local model still
    gets Phase 31's behavior, with the absence recorded rather than a
    fabricated clean review."""
    record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_passing_verification(), providers=_providers(None),
        edits="tests/test_widget.py",
    )
    assert record.status == "verified"
    assert record.change_request_id is not None
    assert record.review_status == REVIEW_UNAVAILABLE
    assert record.review_blocking == []
    assert cr is not None


# ---------- what the human actually reads ----------


def test_change_request_model_b_opinion_carries_the_real_review(tmp_path: Path, monkeypatch):
    provider = _FakeProvider("ollama", text=json.dumps(_answers()))
    _record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_passing_verification(), providers=_providers(provider),
        edits="tests/test_widget.py",
    )
    assert "INDEPENDENT_REVIEWER" in cr.model_b_opinion
    assert Q_TESTS_WEAKENED in cr.model_b_opinion
    assert "Blocking findings: (none)" in cr.model_b_opinion


def test_change_request_still_says_plainly_when_nothing_reviewed_it(tmp_path: Path, monkeypatch):
    _record, cr = _run_attempt(
        tmp_path, monkeypatch, verification=_passing_verification(), providers=_providers(None),
        edits="tests/test_widget.py",
    )
    assert "no independent second-model review" in cr.model_b_opinion.lower()


def test_a_clean_review_is_never_described_as_authorization():
    sentence = _review_risk_sentence(_assessment())
    assert "NOT an approval" in sentence


def test_an_unusable_review_is_described_as_unreviewed_not_as_passing():
    unusable = ReviewAssessment(status=REVIEW_ERROR, provider="ollama", model="m", error="backend down")
    assert "unreviewed" in _review_risk_sentence(unusable)
    assert "unusable" in _model_b_opinion(unusable)
