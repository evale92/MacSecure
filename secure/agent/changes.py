"""
secure/agent/changes.py — Phase 31: turns a verified repair into a
normal Phase 28 change request.

This module calls secure.ai.changes.workflow's own propose_change()
literally, unmodified — no new approval mechanism, no new status, and
this module never itself calls approve_change()/reject_change() (see
secure/agent/__init__.py's hard rules 1-4, inherited unchanged from
secure/ai/changes/__init__.py's own five). A verified repair still
only ever produces a PENDING change request; a human decides
everything from there.

Two things this module is specifically responsible for, both BEFORE
propose_change() is ever called:

1. PATH DENYLIST ENFORCEMENT. Every file in the diff Secure computed
   itself (secure/agent/worktree.py's diff_and_changed_files() —
   never the tool's self-reported text) is checked against
   AppConfig.agent_path_denylist. A single denylisted path anywhere
   means no change request is ever created at all — the repair stops
   as 'rejected_by_denylist'. This protects the exact things that
   grade a repair (secure/validate/, secure/ai/verify/, secure/ai/
   changes/, secure/agent/ itself, config.py, the schema) from being
   rewritten by the thing they're grading.

2. THE DIFF'S HASH IS BOUND INTO THE APPROVAL REVISION HASH. Phase
   28's approve_change() already refuses to approve unless the
   caller's revision_hash exactly matches what propose_change()
   computed over (title, proposed_change, reason, affected_component,
   risks) at creation time. This module embeds the diff's own SHA-256
   directly inside `proposed_change`'s text, so that existing check
   transitively pins the exact diff content too — a human approving
   CR-N is provably approving the diff whose hash they saw, without a
   single line of workflow.py changing.

Only ever called after verification has already run — see
secure/agent/orchestrator.py — and refuses to propose anything unless
verification.overall_passed is exactly True (not None, not False) as
its own independent safety check, not just a caller's promise.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from secure.agent.audit import record_and_persist_one
from secure.agent.policy import RepairCandidate
from secure.agent.runner import MiniRunResult
from secure.agent.verify import VerificationOutcome
from secure.agent.worktree import RepairWorktree, diff_and_changed_files
from secure.ai.changes.workflow import propose_change
from secure.config import AppConfig
from secure.storage.models import (
    find_ai_change_request,
    set_ai_change_request_classification,
    set_ai_change_request_status,
)
from secure.storage.models.ai import AiChangeRequestRecord

# A change request's third terminal state — distinct from Phase 28's
# human-only 'pending'/'approved'/'rejected'. Set exactly once, by
# supersede_change_request() below, and only as the automatic result
# of revalidate_worktree_diff() finding the worktree has drifted since
# a change request was proposed. This is NOT a disguised rejection: no
# judgment is made about the change's merits, only an objective fact
# ("the diff on disk no longer matches what was proposed") that makes
# the original proposal text stale and therefore unsafe to approve as
# written. A human still decides everything about whatever change
# request (if any) replaces it.
STATUS_SUPERSEDED = "superseded"

_MAX_DIFF_PREVIEW_CHARS = 6000


@dataclass(frozen=True)
class DenylistCheck:
    violated: bool
    detail: "Optional[str]"


def check_path_denylist(changed_files: "list[str]", cfg: AppConfig) -> DenylistCheck:
    """Prefix match against AppConfig.agent_path_denylist — a
    denylisted entry ending in "/" matches anything under that
    directory; one that doesn't (e.g. "secure/config.py") matches that
    exact file. Returns the FIRST violation found, not all of them —
    one is enough to stop."""
    for changed in changed_files:
        for denied in cfg.agent_path_denylist:
            if denied.endswith("/"):
                if changed.startswith(denied):
                    return DenylistCheck(violated=True, detail=f"{changed!r} is under denylisted path {denied!r}")
            elif changed == denied:
                return DenylistCheck(violated=True, detail=f"{changed!r} is a denylisted path")
    return DenylistCheck(violated=False, detail=None)


@dataclass(frozen=True)
class DiffRevalidation:
    matches: bool
    current_diff_hash: "Optional[str]"
    current_diff_text: str
    current_changed_files: "list[str]"
    detail: str


def revalidate_worktree_diff(
    worktree: RepairWorktree, expected_diff_hash: "Optional[str]", *, audit_trail: "Optional[list]" = None
) -> DiffRevalidation:
    """Guardrail 2 (explicit user instruction): before a human approves
    an agent-originated change request, re-run Secure's OWN diff
    computation against the worktree RIGHT NOW and compare its hash to
    the one embedded in the change request at proposal time.

    Phase 28's approve_change() already refuses unless the caller's
    revision_hash matches the hash of the proposal TEXT — that catches
    someone approving against a stale copy of the CR's title/reason/
    risks. It says nothing about whether the worktree's actual `git
    diff` still matches what that text describes. If a human edited
    files in the worktree after the CR was proposed, ran a second tool
    pass, or the worktree was otherwise touched, the text hash would
    still match (nothing edited proposed_change itself) even though
    the code it describes is no longer what's actually there. This
    closes that gap by treating the worktree's live diff, not just the
    CR's stored text, as part of what "the exact revision" means.
    """
    diff_text, changed_files = diff_and_changed_files(worktree, audit_trail=audit_trail)
    current_hash = hashlib.sha256(diff_text.encode("utf-8")).hexdigest() if diff_text.strip() else None
    matches = current_hash == expected_diff_hash
    detail = (
        "worktree diff is unchanged since the change request was proposed" if matches else
        f"worktree diff has changed since the change request was proposed (expected diff "
        f"SHA-256 {expected_diff_hash!r}, found {current_hash!r}) — the change request no "
        "longer accurately describes what is in the worktree"
    )
    return DiffRevalidation(
        matches=matches, current_diff_hash=current_hash, current_diff_text=diff_text,
        current_changed_files=changed_files, detail=detail,
    )


def supersede_change_request(
    conn: sqlite3.Connection, cr_id: str, *, detail: str, run_id: "Optional[str]" = None
) -> "Optional[AiChangeRequestRecord]":
    """Marks a change request 'superseded'. Called only by
    secure/agent/orchestrator.py's revalidate_before_approval() after
    revalidate_worktree_diff() finds a mismatch — never called for any
    other reason, and never a substitute for reject_change() (which
    remains the only way a human rejects a change request on its
    merits; see this module's own docstring and
    secure/ai/changes/workflow.py's five hard rules). Uses the raw
    set_ai_change_request_status() storage primitive directly — the
    same one secure/ai/changes/workflow.py's approve_change()/
    reject_change() wrap — which its own docstring says does not
    itself gate WHO may call it or WHEN; this is a second, narrower,
    deterministic-integrity caller of that same primitive, not a
    bypass of Phase 28's approval policy (a superseded CR can never be
    approved: approve_change() already requires status == 'pending').

    `run_id` (Phase 31.5, optional): when supplied, this action — an
    automatic, no-human-judgment proposed system change (superseding a
    change request) — is recorded via secure/agent/audit.py's
    record_and_persist_one(), the same as propose_repair_change_request()
    below. `mutating=True` (it changes ai_change_requests' status);
    `approval_required=False` (this itself is not something a human
    approves — it's a deterministic integrity finding, not a proposal
    awaiting review)."""
    result = set_ai_change_request_status(
        conn, cr_id=cr_id, status=STATUS_SUPERSEDED,
        approved_at=datetime.now(timezone.utc).isoformat(),
        approved_by=f"secure/agent (automatic diff-integrity check): {detail}",
    )
    record_and_persist_one(
        conn, run_id=run_id, component="agent.changes", action="supersede_change_request",
        target=cr_id, mutating=True, approval_required=False, result_summary=detail,
    )
    return result


def invalidate_change_request_if_content_changed(
    conn: sqlite3.Connection, cr_id: str, *, run_id: "Optional[str]" = None
):
    """Phase 40. "If proposed content changes after approval:
    INVALIDATE/SUPERSEDE THE REQUEST. Never silently transfer approval
    to changed content."

    Phase 28's `approve_change()` guards the moment of approval and
    Phase 31's `revalidate_before_approval()` guards the instant
    before it. Neither covers the window AFTER approval, where a diff
    file on disk or a change request's own stored text could change
    while an approval that was granted for the OLD content remains
    recorded. This closes that window: on any mismatch, the request is
    superseded, which makes it un-approvable (Phase 28's
    `approve_change()` already requires status == 'pending') and marks
    it plainly stale for anything downstream.

    Returns (integrity, record). `record` is the possibly-superseded
    change request, or None when there is no such request. Superseding
    only ever moves a request AWAY from approvability — this function
    has no branch that can advance one toward it.
    """
    from secure.agent.center import approval_integrity

    integrity = approval_integrity(conn, cr_id)
    if integrity is None:
        return None, None
    if integrity.intact:
        return integrity, find_ai_change_request(conn, cr_id)
    record = supersede_change_request(
        conn, cr_id,
        detail=f"content changed after proposal/approval: {integrity.detail}",
        run_id=run_id,
    )
    return integrity, record


def _notify_operator(conn: sqlite3.Connection, cfg: AppConfig, *, cr_id: str, run_id: "Optional[str]") -> None:
    """Phase 41. Builds the Phase 40 view of the freshly-created change
    request and hands it to secure/agent/notify.py, which decides
    whether the class warrants an email and, if so, sends a sanitized
    one. Records the outcome on the change request's own
    notify_status column.

    Wrapped in a broad except on purpose: a repair that has already
    been verified, hashed, classified, and persisted must not be
    turned into a failure by an email problem.
    """
    from secure.agent.center import build_change_request_view
    from secure.agent.notify import notify_if_consequential
    from secure.storage.models import mark_ai_change_request_notified

    try:
        view = build_change_request_view(conn, cr_id)
        if view is None:
            return
        status, detail = notify_if_consequential(cfg, view)
        mark_ai_change_request_notified(
            conn, cr_id=cr_id, notified_at=datetime.now(timezone.utc).isoformat(), notify_status=status
        )
        record_and_persist_one(
            conn, run_id=run_id, component="agent.notify", action="notify_change_request",
            target=cr_id, mutating=False, approval_required=False, result_summary=f"{status}: {detail}",
        )
    except Exception as exc:  # noqa: BLE001
        record_and_persist_one(
            conn, run_id=run_id, component="agent.notify", action="notify_change_request",
            target=cr_id, mutating=False, approval_required=False,
            result_summary=f"notification failed: {type(exc).__name__}: {exc}",
        )


def _diff_preview(diff_text: str) -> str:
    if len(diff_text) <= _MAX_DIFF_PREVIEW_CHARS:
        return diff_text
    return diff_text[:_MAX_DIFF_PREVIEW_CHARS] + f"\n...[{len(diff_text) - _MAX_DIFF_PREVIEW_CHARS} more characters truncated — see secure agent show for the full diff]"


def _review_risk_sentence(review) -> str:
    """Phase 38. Replaces Phase 31's hardcoded "nothing was reviewed by
    a second model" sentence with whatever actually happened — including,
    still, an honest statement that no review occurred when none did."""
    if review is None or getattr(review, "status", None) in (None, "unavailable", "not_required"):
        detail = getattr(review, "summary", "") if review is not None else ""
        return (
            "No independent second-model review was performed for this repair"
            + (f" ({detail})" if detail else "")
            + " — the deterministic pytest + secure validate run above is the only automated check."
        )
    if getattr(review, "status", None) != "ok":
        return (
            "An independent reviewer was invoked but did not produce a usable assessment "
            f"(status={review.status!r}, error={getattr(review, 'error', None)!r}). Treat this "
            "change as unreviewed by a second model."
        )
    if getattr(review, "blocking", ()):  # pragma: no cover — orchestrator escalates before proposing
        return (
            f"An independent reviewer ({review.provider}/{review.model}) raised blocking findings: "
            f"{', '.join(review.blocking)}."
        )
    return (
        f"An independent reviewer ({review.provider}/{review.model}) reviewed this patch and "
        "raised no blocking findings. That is a second opinion, NOT an approval — a model "
        "agreeing with another model is explicitly not authorization (see "
        "secure/ai/changes/workflow.py's hard rules)."
    )


def _model_b_opinion(review) -> str:
    """What goes in ai_change_requests.model_b_opinion — the column
    Phase 28 created for exactly this and Phase 31 could only fill with
    a placeholder because no second model was involved yet."""
    if review is None or getattr(review, "status", None) in (None, "unavailable", "not_required"):
        summary = getattr(review, "summary", "") if review is not None else ""
        return (
            "(no independent second-model review"
            + (f": {summary}" if summary else "")
            + ")"
        )
    if getattr(review, "status", None) != "ok":
        return f"(independent reviewer unusable: status={review.status!r}, error={getattr(review, 'error', None)!r})"
    answer_lines = "\n".join(
        f"- {a.question}: {a.answer}" + (f" — {a.rationale}" if a.rationale else "")
        for a in review.answers
    )
    blocking = ", ".join(review.blocking) if review.blocking else "(none)"
    return (
        f"INDEPENDENT_REVIEWER {review.provider}/{review.model}\n"
        f"Blocking findings: {blocking}\n"
        f"Summary: {review.summary}\n"
        f"{answer_lines}"
    )


def _classification_risk_text(classification) -> str:
    """Phase 39. The classification is embedded in `risks`, which
    Phase 28's compute_revision_hash() already covers — so a human
    approving CR-N is provably approving the class they were shown,
    with no change to the hash computation itself. This is the same
    trick Phase 31 used to bind the diff's SHA-256 into the approval.
    """
    if classification is None:
        return ""
    described = getattr(classification, "describe", None)
    body = described() if callable(described) else str(classification)
    return "\n\n" + body


class RepairNotEligibleForChangeRequest(RuntimeError):
    """Raised when propose_repair_change_request() is called for a
    repair that hasn't actually passed verification — a programming
    error in the caller, not a normal outcome; the orchestrator should
    never reach this call unless verification.overall_passed is True."""


def propose_repair_change_request(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    run_id: str,
    candidate: RepairCandidate,
    diff_text: str,
    diff_hash: str,
    changed_files: "list[str]",
    verification: VerificationOutcome,
    mini_result: MiniRunResult,
    review: "Optional[object]" = None,
    classification: "Optional[object]" = None,
) -> AiChangeRequestRecord:
    if verification.overall_passed is not True:
        raise RepairNotEligibleForChangeRequest(
            f"refusing to propose a change request for {run_id}: verification.overall_passed "
            f"is {verification.overall_passed!r}, not True"
        )

    title = f"Autonomous repair for {candidate.trigger_kind}: {candidate.trigger_ref}"

    proposed_change = (
        f"Diff SHA-256: {diff_hash}\n"
        f"Repair run: {run_id}\n"
        f"Files changed: {', '.join(changed_files) or '(none)'}\n\n"
        f"--- diff ---\n{_diff_preview(diff_text)}"
    )

    reason = (
        f"Trigger: {candidate.trigger_kind} ({candidate.trigger_ref}).\n\n"
        f"Failure detail:\n{candidate.trigger_detail}"
    )

    affected_component = ", ".join(changed_files) if changed_files else "(unknown)"

    risks = (
        "Automatically generated by secure/agent/ (Phase 31) via mini-SWE-agent, model "
        f"{mini_result.model_name}. Verified in an isolated git worktree: pytest "
        f"status={verification.pytest_result.status} passed={verification.pytest_result.passed}; "
        f"secure validate status={verification.validate_result.status} "
        f"passed={verification.validate_result.passed}. A passing verification result is NOT "
        "authorization — review the diff yourself before approving. "
        + _review_risk_sentence(review)
        + _classification_risk_text(classification)
    )

    model_a_opinion = f"mini-SWE-agent ({mini_result.model_name}) exit_status={mini_result.exit_status}"
    model_b_opinion = _model_b_opinion(review)

    cr = propose_change(
        conn, cfg,
        title=title,
        proposed_change=proposed_change,
        reason=reason,
        affected_component=affected_component,
        risks=risks,
        model_a_opinion=model_a_opinion,
        model_b_opinion=model_b_opinion,
        verification_run_id=None,
        verification_summary=(
            f"pytest: {verification.pytest_result.status}/{verification.pytest_result.passed}\n"
            f"secure validate: {verification.validate_result.status}/{verification.validate_result.passed}"
        ),
        # Phase 41: this path sends its own sanitized notification
        # below. An agent-authored `proposed_change` embeds raw diff
        # text, and a notification must never carry secrets or
        # sensitive model context — so the operator gets exactly one
        # email about this change request, and it is the safe one.
        notify=False,
    )
    # Phase 39: denormalize the class onto the change request for
    # querying (Phase 40's UI, Phase 41's notification rules). The copy
    # a human actually approves is the classification text embedded in
    # `risks` above, which IS covered by revision_hash — this column is
    # for filtering, never for deciding.
    if classification is not None:
        set_ai_change_request_classification(
            conn, cr_id=cr.cr_id,
            classification=getattr(classification, "classification", str(classification)),
        )
        cr = find_ai_change_request(conn, cr.cr_id) or cr

    # Phase 41: the sanitized consequential-change notification. Sent
    # AFTER the classification is denormalized above, so the email can
    # state the class. Never raises and never blocks — a notification
    # failure leaves a fully-persisted, fully-approvable change
    # request behind, exactly as an SMTP-less install always has.
    _notify_operator(conn, cfg, cr_id=cr.cr_id, run_id=run_id)

    # Phase 31.5: the proposal of a system change is itself an audited
    # action — approval_required=True since this row's whole purpose is
    # to represent something that now requires (and, until a human acts,
    # is awaiting) human approval; see secure/agent/audit.py.
    record_and_persist_one(
        conn, run_id=run_id, component="agent.changes", action="propose_repair_change_request",
        target=cr.cr_id, mutating=True, approval_required=True,
        result_summary=f"proposed {cr.cr_id} ({len(changed_files)} file(s) changed)",
    )
    return cr
