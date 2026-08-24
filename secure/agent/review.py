"""
secure/agent/review.py — Phase 38 (Part 2: Supervised Agentic
Development & Self-Healing — "Independent Reviewer").

Makes the second local model an independent reviewer of non-trivial
repairs. Governing text, verbatim (docs/ROADMAP_PART2_PHASES_38_47.md):

    "Make the second local model an independent reviewer of non-trivial
    repairs... The reviewer does not determine test success.
    Deterministic verification remains authoritative. If coder and
    reviewer materially disagree: STOP AND ESCALATE. Record both
    assessments."

WHAT THIS MODULE CAN AND CANNOT DO — the whole point of the phase:

- It can turn a PASSING deterministic verification into a STOP
  (escalation). A blocking review finding prevents automatic
  progression to a change request.
- It can NEVER turn a failing, inconclusive, or unavailable
  deterministic verification into a pass. `review_gate()` is only ever
  consulted on the `verification.overall_passed is True` branch of
  secure/agent/orchestrator.py, and returns only PROCEED or ESCALATE —
  there is no return value that means "verification succeeded." The
  reviewer's influence is strictly one-directional: it can restrict,
  never permit. `test_agent_review.py` proves this adversarially.

Reuse, not reinvention (ARCHITECTURE_RULES.md rule 10):

- Role assignment and model invocation are Phase 32's
  `secure/ai/model_roles.py` (`ROLE_INDEPENDENT_REVIEWER`,
  `resolve_maintenance_roles()`, `invoke_role()`), used unmodified.
  No new provider, no new HTTP client, no new inference path.
- The architecture/security policy the reviewer is shown is Phase 37's
  four root policy files, read by Phase 33's own
  `secure/agent/context.py` loader — not a second copy of that logic.
- "Is this change security-relevant?" reuses Phase 36's
  `secure/agent/tiers.py` SECURITY_SENSITIVE_PREFIXES rather than
  defining a second, drifting list.
- JSON extraction from a model's prose reuses Phase 28's own
  `secure/ai/response.py` helper, which already handles markdown
  fences and surrounding chatter.

HONEST ABSENCE, AND THE ASYMMETRY THAT MATTERS:

- Reviewer NOT CONFIGURED (no local model backend) -> status
  `unavailable`, no blocking, the run proceeds exactly as it did in
  Phase 31. That is an operator's deliberate configuration choice, and
  Phase 31's own change-request text already says in plain words that
  no second model reviewed the change.
- Reviewer CONFIGURED BUT MALFUNCTIONING (provider error, or output
  that cannot be parsed into the required answers) -> status `error` /
  `unparseable`, which IS blocking. A review that ran and could not be
  understood must never be counted as an approval. Silence from a
  disabled reviewer is honest; noise from a broken one is not
  assurance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.context import _load_policy_excerpts
from secure.agent.policy import RepairCandidate
from secure.agent.tiers import SECURITY_SENSITIVE_PREFIXES
from secure.agent.verify import VerificationOutcome
# Reusing Phase 28's fence/prose-tolerant JSON extraction rather than
# writing a second one that would drift from it. It is underscore-named
# there only because Phase 28 had a single caller; this is the second.
from secure.ai.response import _extract_json_object as extract_json_object
from secure.ai.base import STATUS_OK
from secure.ai.model_roles import ROLE_INDEPENDENT_REVIEWER, invoke_role, resolve_maintenance_roles

# ---------------------------------------------------------------------
# The nine questions, verbatim from the governing text
# ---------------------------------------------------------------------

Q_ROOT_PROBLEM = "addresses_root_problem"
Q_TESTS_WEAKENED = "tests_weakened"
Q_DATA_LOSS = "data_loss_possible"
Q_SECURITY_WEAKENED = "security_weakened"
Q_PROVENANCE = "provenance_affected"
Q_ARCHITECTURE = "architecture_boundaries_violated"
Q_TOO_BROAD = "unnecessarily_broad"
Q_DEPENDENCIES = "unexplained_dependencies"
Q_NEEDS_APPROVAL = "requires_human_approval"

REVIEW_QUESTIONS = (
    Q_ROOT_PROBLEM,
    Q_TESTS_WEAKENED,
    Q_DATA_LOSS,
    Q_SECURITY_WEAKENED,
    Q_PROVENANCE,
    Q_ARCHITECTURE,
    Q_TOO_BROAD,
    Q_DEPENDENCIES,
    Q_NEEDS_APPROVAL,
)

ANSWER_YES = "yes"
ANSWER_NO = "no"
ANSWER_UNKNOWN = "unknown"
VALID_ANSWERS = (ANSWER_YES, ANSWER_NO, ANSWER_UNKNOWN)

# For each question, the answer that indicates a problem. Note
# Q_ROOT_PROBLEM is inverted: "no, this does not address the root
# problem" is the concerning answer.
CONCERNING_ANSWER = {
    Q_ROOT_PROBLEM: ANSWER_NO,
    Q_TESTS_WEAKENED: ANSWER_YES,
    Q_DATA_LOSS: ANSWER_YES,
    Q_SECURITY_WEAKENED: ANSWER_YES,
    Q_PROVENANCE: ANSWER_YES,
    Q_ARCHITECTURE: ANSWER_YES,
    Q_TOO_BROAD: ANSWER_YES,
    Q_DEPENDENCIES: ANSWER_YES,
    Q_NEEDS_APPROVAL: ANSWER_YES,
}

# Questions whose concerning answer stops automatic progression. The
# two omissions are deliberate and are recorded rather than escalated:
# Q_TOO_BROAD is a quality judgment, not a disagreement about
# correctness, and escalating on breadth alone would make the gate
# noisy enough to be ignored; Q_NEEDS_APPROVAL is already true of
# EVERY repair in this system (Phase 31 routes all of them to a human
# change request), so treating it as blocking would escalate
# unconditionally and mean nothing. Phase 39 gives that question real
# teeth by turning it into a deterministic classification.
BLOCKING_QUESTIONS = (
    Q_ROOT_PROBLEM,
    Q_TESTS_WEAKENED,
    Q_DATA_LOSS,
    Q_SECURITY_WEAKENED,
    Q_PROVENANCE,
    Q_ARCHITECTURE,
    Q_DEPENDENCIES,
)

# Review statuses.
REVIEW_OK = "ok"                    # ran, parsed, answers available
REVIEW_UNAVAILABLE = "unavailable"  # no reviewer configured — not blocking
REVIEW_NOT_REQUIRED = "not_required"  # trivial change — not blocking
REVIEW_ERROR = "error"              # provider failed — blocking
REVIEW_UNPARSEABLE = "unparseable"  # ran, output unusable — blocking

# Gate decisions. Deliberately only two: there is no value here that
# means "verification passed."
GATE_PROCEED = "proceed"
GATE_ESCALATE = "escalate"

_MAX_DIFF_CHARS_FOR_REVIEW = 12000
_MAX_DETAIL_CHARS = 3000
_MAX_SUMMARY_CHARS = 2000

# A repair is treated as trivial (review not required) only when it is
# small AND touches nothing sensitive. Anything uncertain is
# non-trivial — the conservative direction.
_TRIVIAL_MAX_FILES = 1
_TRIVIAL_MAX_CHANGED_LINES = 20


@dataclass(frozen=True)
class ReviewAnswer:
    question: str
    answer: str
    rationale: str


@dataclass(frozen=True)
class ReviewAssessment:
    """One independent review of one candidate repair.

    `blocking` is computed from `answers` by this module, never taken
    from the model's own text — a model cannot mark its own finding
    non-blocking, and cannot declare itself blocking-free by asserting
    it in prose.
    """

    status: str
    provider: str
    model: str
    answers: "tuple[ReviewAnswer, ...]" = field(default_factory=tuple)
    blocking: "tuple[str, ...]" = field(default_factory=tuple)
    summary: str = ""
    error: "Optional[str]" = None
    raw_text: str = ""

    @property
    def has_blocking_finding(self) -> bool:
        return bool(self.blocking)

    def answer_for(self, question: str) -> "Optional[ReviewAnswer]":
        for a in self.answers:
            if a.question == question:
                return a
        return None

    def to_json(self) -> str:
        return json.dumps(
            {
                "status": self.status,
                "provider": self.provider,
                "model": self.model,
                "answers": [
                    {"question": a.question, "answer": a.answer, "rationale": a.rationale}
                    for a in self.answers
                ],
                "blocking": list(self.blocking),
                "summary": self.summary,
                "error": self.error,
            },
            sort_keys=True,
        )


# ---------------------------------------------------------------------
# Triviality
# ---------------------------------------------------------------------


def _changed_line_count(diff_text: str) -> int:
    return sum(
        1
        for line in diff_text.splitlines()
        if (line.startswith("+") or line.startswith("-"))
        and not line.startswith("+++")
        and not line.startswith("---")
    )


def is_non_trivial(diff_text: str, changed_files: "list[str]") -> bool:
    """Deterministic, no model call. A repair is non-trivial — and so
    requires independent review — when it touches more than one file,
    changes more than `_TRIVIAL_MAX_CHANGED_LINES` lines, touches a
    security-sensitive path, or touches anything under `tests/`.

    The `tests/` clause matters more than its size suggests: deleting a
    single assertion is a one-line, one-file change that would
    otherwise read as trivial, and it is exactly the failure mode
    AGENTS.md rule 3 and TESTING_POLICY.md rule 1 exist to prevent. A
    change to a test is never trivial here.

    An empty/unknown diff returns True — uncertainty escalates toward
    more review, never less.
    """
    if not changed_files:
        return True
    if len(changed_files) > _TRIVIAL_MAX_FILES:
        return True
    if any(f.startswith("tests/") for f in changed_files):
        return True
    if any(f.startswith(prefix) for f in changed_files for prefix in SECURITY_SENSITIVE_PREFIXES):
        return True
    if _changed_line_count(diff_text) > _TRIVIAL_MAX_CHANGED_LINES:
        return True
    return False


# ---------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------

REVIEW_SYSTEM_PROMPT = (
    "You are an INDEPENDENT REVIEWER of a proposed automated code repair. A different "
    "model wrote the patch; your job is to scrutinize it, not to agree with it. You do "
    "NOT decide whether tests passed — deterministic test results are given to you as "
    "fact and are authoritative. You cannot approve anything; a human does that. "
    "Answer only the questions asked, as strict JSON, with no text outside the JSON "
    "object. Every answer must be exactly \"yes\", \"no\", or \"unknown\". Use "
    "\"unknown\" honestly when the material you were given does not let you tell — a "
    "guess is worse than an admission."
)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[{len(text) - limit} more characters truncated]"


def build_review_prompt(
    candidate: RepairCandidate,
    *,
    coder_assessment: str,
    diff_text: str,
    changed_files: "list[str]",
    verification: VerificationOutcome,
    root: "Optional[Path]" = None,
) -> str:
    """Assembles exactly the seven inputs the governing text requires:
    original failure, diagnosis, actual Git diff, files changed, tests
    run, results, and relevant architecture/security policies.

    The coder's own account is included but explicitly labelled as an
    unverified claim — Secure never trusts a tool's self-report (that
    is why `diff_text` here is always the diff Secure computed itself),
    and the reviewer should not either.
    """
    parts: "list[str]" = []

    parts.append(
        "## Original failure\n"
        f"Trigger kind: {candidate.trigger_kind}\n"
        f"Trigger ref: {candidate.trigger_ref}\n"
        f"Detail:\n{_truncate(candidate.trigger_detail, _MAX_DETAIL_CHARS)}"
    )

    parts.append(
        "## The coder model's own account of what it did (UNVERIFIED CLAIM — treat with suspicion)\n"
        + (_truncate(coder_assessment.strip(), _MAX_DETAIL_CHARS) if coder_assessment.strip()
           else "(the coder model provided no account)")
    )

    parts.append(
        "## Actual Git diff (computed independently by Secure, not reported by the coder)\n"
        + _truncate(diff_text, _MAX_DIFF_CHARS_FOR_REVIEW)
    )

    parts.append(
        "## Files changed\n"
        + ("\n".join(f"- {f}" for f in changed_files) if changed_files else "(none)")
    )

    parts.append(
        "## Tests run, and their results (AUTHORITATIVE — these are facts, not opinions)\n"
        f"pytest: status={verification.pytest_result.status} passed={verification.pytest_result.passed}\n"
        f"{_truncate(verification.pytest_result.summary, _MAX_SUMMARY_CHARS)}\n\n"
        f"secure validate: status={verification.validate_result.status} "
        f"passed={verification.validate_result.passed}\n"
        f"{_truncate(verification.validate_result.summary, _MAX_SUMMARY_CHARS)}"
    )

    policy = _load_policy_excerpts(root) if root is not None else _load_policy_excerpts(_default_root())
    if policy:
        parts.append(
            "## Engineering policy this repository is held to\n"
            + "\n\n".join(f"--- {name} ---\n{text}" for name, text in policy.items())
        )

    parts.append(
        "## Answer with this exact JSON shape and nothing else\n"
        "{\n"
        '  "answers": {\n'
        + ",\n".join(f'    "{q}": {{"answer": "yes|no|unknown", "rationale": "one or two sentences"}}'
                     for q in REVIEW_QUESTIONS)
        + "\n  },\n"
        '  "summary": "a short overall assessment"\n'
        "}\n\n"
        "Question meanings:\n"
        f"- {Q_ROOT_PROBLEM}: does the patch address the ROOT problem (not just silence the symptom)?\n"
        f"- {Q_TESTS_WEAKENED}: are tests being weakened, deleted, skipped, or loosened?\n"
        f"- {Q_DATA_LOSS}: could this cause data loss?\n"
        f"- {Q_SECURITY_WEAKENED}: could this weaken security?\n"
        f"- {Q_PROVENANCE}: is provenance (evidence identity, audit trail, citations) affected?\n"
        f"- {Q_ARCHITECTURE}: are architecture boundaries violated?\n"
        f"- {Q_TOO_BROAD}: is the change unnecessarily broad for the failure it fixes?\n"
        f"- {Q_DEPENDENCIES}: were unexplained dependencies introduced?\n"
        f"- {Q_NEEDS_APPROVAL}: does anything here require human approval?"
    )

    return "\n\n".join(parts)


def _default_root() -> Path:
    from secure.agent.worktree import project_root

    return project_root()


# ---------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------


def parse_review_response(raw_text: str) -> "tuple[tuple[ReviewAnswer, ...], str, Optional[str]]":
    """Returns (answers, summary, error). `error` is non-None when the
    response could not be understood well enough to be a review.

    A missing or malformed individual answer is coerced to
    ANSWER_UNKNOWN rather than dropped — an absent answer must not read
    as reassurance. If NO question could be answered at all, that is an
    error, not nine polite unknowns.
    """
    parsed = extract_json_object(raw_text or "")
    if parsed is None:
        return (), "", "response was not parseable as a JSON object"

    raw_answers = parsed.get("answers")
    if not isinstance(raw_answers, dict):
        return (), "", "response JSON had no 'answers' object"

    answers: "list[ReviewAnswer]" = []
    recognized = 0
    for question in REVIEW_QUESTIONS:
        entry = raw_answers.get(question)
        answer = ANSWER_UNKNOWN
        rationale = ""
        if isinstance(entry, dict):
            candidate_answer = entry.get("answer")
            if isinstance(candidate_answer, str) and candidate_answer.strip().lower() in VALID_ANSWERS:
                answer = candidate_answer.strip().lower()
                recognized += 1
            raw_rationale = entry.get("rationale")
            if isinstance(raw_rationale, str):
                rationale = raw_rationale.strip()
        elif isinstance(entry, str) and entry.strip().lower() in VALID_ANSWERS:
            # Tolerate the flatter {"tests_weakened": "no"} shape.
            answer = entry.strip().lower()
            recognized += 1
        answers.append(ReviewAnswer(question=question, answer=answer, rationale=rationale))

    if recognized == 0:
        return (), "", "response JSON contained no recognizable answers"

    summary = parsed.get("summary")
    summary = summary.strip() if isinstance(summary, str) else ""
    return tuple(answers), _truncate(summary, _MAX_SUMMARY_CHARS), None


def compute_blocking(answers: "tuple[ReviewAnswer, ...]") -> "tuple[str, ...]":
    """Which questions block automatic progression.

    An ANSWER_UNKNOWN on a blocking question blocks. The gate exists to
    obtain an assurance; a reviewer that cannot give it has not given
    it. This is the same "inconclusive is never a pass" rule
    VerificationOutcome.overall_passed already applies to deterministic
    verification, applied here to the review.
    """
    blocking: "list[str]" = []
    for answer in answers:
        if answer.question not in BLOCKING_QUESTIONS:
            continue
        if answer.answer in (CONCERNING_ANSWER[answer.question], ANSWER_UNKNOWN):
            blocking.append(answer.question)
    return tuple(blocking)


# ---------------------------------------------------------------------
# Running a review
# ---------------------------------------------------------------------


def review_repair(
    providers: dict,
    candidate: RepairCandidate,
    *,
    coder_assessment: str,
    diff_text: str,
    changed_files: "list[str]",
    verification: VerificationOutcome,
    root: "Optional[Path]" = None,
    timeout: "Optional[float]" = None,
) -> ReviewAssessment:
    """Runs one independent review. Never raises for a provider
    problem — every failure mode is reported as a status on the
    returned assessment, the same discipline every optional-signal
    function in this project follows.

    `providers` is `secure.ai.registry.build_providers()`'s own dict,
    exactly as Phase 32's `resolve_maintenance_roles()` expects it.
    """
    if not is_non_trivial(diff_text, changed_files):
        return ReviewAssessment(
            status=REVIEW_NOT_REQUIRED, provider="", model="",
            summary="change is trivial (single small non-test, non-sensitive file) — independent review not required",
        )

    bindings = resolve_maintenance_roles(providers)
    binding = bindings[ROLE_INDEPENDENT_REVIEWER]
    if not binding.configured:
        return ReviewAssessment(
            status=REVIEW_UNAVAILABLE, provider=binding.provider_name, model=binding.model,
            summary="no independent reviewer model is configured", error="reviewer not configured",
        )

    provider = _provider_for_binding(providers, binding)
    if provider is None:
        return ReviewAssessment(
            status=REVIEW_UNAVAILABLE, provider=binding.provider_name, model=binding.model,
            summary="independent reviewer model could not be resolved to a provider instance",
            error="reviewer provider not resolvable",
        )

    user_prompt = build_review_prompt(
        candidate, coder_assessment=coder_assessment, diff_text=diff_text,
        changed_files=changed_files, verification=verification, root=root,
    )

    try:
        invocation = invoke_role(
            ROLE_INDEPENDENT_REVIEWER, provider, REVIEW_SYSTEM_PROMPT, user_prompt,
            timeout=timeout if timeout is not None else binding.timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — a provider fault must not crash a repair run
        return ReviewAssessment(
            status=REVIEW_ERROR, provider=binding.provider_name, model=binding.model,
            summary="independent reviewer raised an exception", error=f"{type(exc).__name__}: {exc}",
        )

    completion = invocation.completion
    if completion.status != STATUS_OK or not completion.text:
        return ReviewAssessment(
            status=REVIEW_ERROR, provider=completion.provider or binding.provider_name,
            model=completion.model or binding.model,
            summary="independent reviewer did not return a usable completion",
            error=completion.error or f"provider status {completion.status}",
        )

    answers, summary, parse_error = parse_review_response(completion.text)
    if parse_error is not None:
        return ReviewAssessment(
            status=REVIEW_UNPARSEABLE, provider=completion.provider, model=completion.model,
            summary="independent reviewer output could not be parsed into answers",
            error=parse_error, raw_text=_truncate(completion.text, _MAX_SUMMARY_CHARS),
        )

    return ReviewAssessment(
        status=REVIEW_OK, provider=completion.provider, model=completion.model,
        answers=answers, blocking=compute_blocking(answers), summary=summary,
        raw_text=_truncate(completion.text, _MAX_SUMMARY_CHARS),
    )


def _provider_for_binding(providers: dict, binding) -> "Optional[object]":
    """Finds the provider instance whose identity matches the binding
    Phase 32 already produced, so the same instance is used rather than
    resolved a second time by a different route."""
    for provider in providers.values():
        if provider is None:
            continue
        identity = getattr(provider, "identity", None)
        name = identity.name if identity is not None else ""
        if name == binding.provider_name and getattr(provider, "model_name", "") == binding.model:
            return provider
    return None


# ---------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewGateDecision:
    """PROCEED or ESCALATE — deliberately not a pass/fail. This type
    has no representation for "verification succeeded," which is why a
    reviewer can never manufacture one."""

    decision: str
    reason: str
    disagreement: bool


def review_gate(assessment: ReviewAssessment, *, coder_claimed_success: bool) -> ReviewGateDecision:
    """Decides whether a repair whose DETERMINISTIC VERIFICATION HAS
    ALREADY PASSED may progress automatically to a change request.

    Callers must only reach this on the verification-passed branch. It
    is not a second verification and cannot substitute for one.

    "Material disagreement" is concrete rather than a vibe: the coder
    asserted a successful repair (it exited successfully and produced a
    diff that passed deterministic verification) while the reviewer
    reports at least one blocking finding, or a review that actually
    ran could not be understood. Both are cases where two independent
    assessments of the same patch point in opposite directions, which
    the governing text says must stop and escalate rather than proceed.
    """
    if assessment.status in (REVIEW_NOT_REQUIRED, REVIEW_UNAVAILABLE):
        return ReviewGateDecision(
            decision=GATE_PROCEED,
            reason=assessment.summary or "no independent review was performed",
            disagreement=False,
        )

    if assessment.status in (REVIEW_ERROR, REVIEW_UNPARSEABLE):
        return ReviewGateDecision(
            decision=GATE_ESCALATE,
            reason=(
                "an independent reviewer was configured but did not produce a usable "
                f"assessment ({assessment.status}: {assessment.error}) — a review that ran "
                "and could not be understood is not an approval"
            ),
            disagreement=False,
        )

    if assessment.has_blocking_finding:
        detail = ", ".join(
            f"{q}={(assessment.answer_for(q).answer if assessment.answer_for(q) else ANSWER_UNKNOWN)}"
            for q in assessment.blocking
        )
        return ReviewGateDecision(
            decision=GATE_ESCALATE,
            reason=f"independent reviewer raised blocking findings ({detail})",
            disagreement=bool(coder_claimed_success),
        )

    return ReviewGateDecision(
        decision=GATE_PROCEED,
        reason="independent reviewer raised no blocking findings",
        disagreement=False,
    )
