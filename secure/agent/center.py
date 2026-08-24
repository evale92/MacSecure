"""
secure/agent/center.py — Phase 40 (Part 2: Supervised Agentic
Development & Self-Healing — "Change Request Center").

Assembles the complete, read-only view of one pending change request:
every field the governing text requires a human to see before deciding,
gathered from the rows that already hold them. Governing text, verbatim
(docs/ROADMAP_PART2_PHASES_38_47.md):

    "Extend Secure's existing change-request workflow rather than
    replacing it... Approval must remain bound to the exact reviewed
    revision/diff. If proposed content changes after approval:
    INVALIDATE/SUPERSEDE THE REQUEST. Never silently transfer approval
    to changed content."

WHAT THIS MODULE IS NOT

It is not a second approval mechanism, and it contains no code path
that can move a change request toward approval. It is a READER. Every
function here opens with a `SELECT` and returns a frozen dataclass.
The only writer this phase adds anything to is the existing
supersede path, and that only ever moves a request AWAY from
approvability. `secure/agent/__init__.py`'s hard rules and the
AST-based test that no file under `secure/agent/` may import or call
`approve_change()`/`reject_change()` both cover this file unchanged.

WHERE EACH REQUIRED FIELD ACTUALLY COMES FROM

Nothing new is stored for this phase except the rollback strategy,
which is not stored at all — it is derived, because it is a pure
function of facts already recorded (was it applied? is the worktree
still there? what is the diff's hash?). Storing a derived sentence
would just create a second copy that could go stale.

    request ID              ai_change_requests.cr_id
    requesting run          agent_repair_runs.run_id (joined by
                            change_request_id, never copied)
    requesting model/       agent_repair_runs.tool_name/.model_name
      framework
    reason                  ai_change_requests.reason
    exact proposed action   ai_change_requests.proposed_change
    actual diff             agent_repair_runs.diff_path (read on
                            demand, never duplicated into the DB)
    diff/revision hash      .diff_hash / .revision_hash
    affected files/settings .changed_files / .affected_component
    risk classification     .classification            (Phase 39)
    commands involved       agent_actions.argv_json    (Phase 31.5)
    tests performed         .pytest_status/.validate_status
    test results            .pytest_summary/.validate_summary
    reviewer assessment     .review_* columns          (Phase 38)
    rollback strategy       derived — see rollback_strategy()
    status                  ai_change_requests.status
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.storage.models import (
    find_agent_repair_run,
    find_ai_change_request,
    list_agent_actions,
    list_agent_repair_runs,
    list_ai_change_requests,
)

# Statuses at which a change request is still awaiting a human. Phase
# 28 created 'pending'; the roadmap's own vocabulary for this state is
# AWAITING_APPROVAL, which is the same thing under a different name —
# this module does NOT introduce a second status column to hold a
# synonym.
AWAITING_APPROVAL_STATUSES = ("pending",)

_MAX_DIFF_CHARS = 200_000


@dataclass(frozen=True)
class ChangeRequestView:
    """One change request, fully assembled for human review. Frozen:
    a view object that could be mutated would eventually be mutated."""

    cr_id: str
    status: str
    created_at: str
    title: str
    reason: str
    proposed_action: str
    revision_hash: str
    affected_component: str
    risks: str
    classification: "Optional[str]"
    model_a_opinion: str
    model_b_opinion: str
    approved_at: "Optional[str]"
    approved_by: "Optional[str]"

    # Joined from the requesting repair run, when there is one. A change
    # request proposed by a non-agent path (Phase 46) legitimately has
    # none of these, and they stay None/empty rather than being faked.
    run_id: "Optional[str]" = None
    requesting_tool: str = ""
    requesting_model: str = ""
    diff_path: "Optional[str]" = None
    diff_hash: "Optional[str]" = None
    changed_files: list = field(default_factory=list)
    pytest_status: "Optional[str]" = None
    pytest_summary: str = ""
    validate_status: "Optional[str]" = None
    validate_summary: str = ""
    verification_passed: "Optional[bool]" = None
    review_status: "Optional[str]" = None
    review_provider: str = ""
    review_model: str = ""
    review_blocking: list = field(default_factory=list)
    review_summary: str = ""
    commands: list = field(default_factory=list)
    rollback: str = ""

    @property
    def awaiting_approval(self) -> bool:
        return self.status in AWAITING_APPROVAL_STATUSES

    @property
    def requires_human_approval(self) -> bool:
        from secure.agent.classify import requires_human_approval

        # An unclassified request is treated as requiring approval, not
        # as safe — same direction as everything else in this phase.
        return requires_human_approval(self.classification or "")


def rollback_strategy(
    *, status: str, diff_hash: "Optional[str]", diff_path: "Optional[str]", worktree_path: "Optional[str]"
) -> str:
    """Derived, never stored. A rollback strategy that is written down
    once at proposal time and then read back later is a sentence that
    can quietly stop being true; this recomputes it from current facts
    every time it is displayed.

    The honest headline for the common case is that there is nothing to
    roll back: an agent repair lives in an isolated worktree and is
    never applied to the live checkout until a human does it by hand,
    so an un-approved request is discarded simply by deleting the
    worktree.
    """
    if status in AWAITING_APPROVAL_STATUSES:
        where = f" ({worktree_path})" if worktree_path else ""
        return (
            "Nothing to roll back — this change has NOT been applied to the live checkout. "
            f"It exists only inside its isolated worktree{where}. Rejecting the request, or "
            "running `secure agent remove-worktree <run_id>`, discards it completely."
        )
    if status == "superseded":
        return (
            "Nothing to roll back — this request was superseded before approval because the "
            "content it described changed. It can never be approved as written."
        )
    if status == "rejected":
        return "Nothing to roll back — this request was rejected and was never applied."
    if status == "approved":
        if diff_hash:
            return (
                "This request was approved. If the diff was subsequently applied by hand, revert "
                f"it with `git apply -R {diff_path or '<diff.patch>'}` and confirm the reverted "
                f"patch's SHA-256 is {diff_hash}. Approval alone does not apply anything — check "
                "whether it was actually applied before reverting."
            )
        return (
            "This request was approved but records no diff, so it describes an action rather than "
            "a patch. There is no automatic rollback; read the proposed action and undo it "
            "deliberately."
        )
    return (
        f"Unrecognized status {status!r} — treat rollback as unknown and inspect the run by hand "
        "rather than assuming this change is inert."
    )


def _commands_for_run(conn: sqlite3.Connection, run_id: "Optional[str]") -> list:
    """The exact commands this change's run actually executed, from
    Phase 31.5's audit trail. Already redacted at write time by
    secure/agent/audit.py — this function does no filtering of its own
    and adds nothing that was not already recorded."""
    if not run_id:
        return []
    rows = list_agent_actions(conn, run_id=run_id, limit=500)
    return [
        {
            "timestamp": a.timestamp,
            "component": a.component,
            "action": a.action,
            "argv": a.argv,
            "mutating": a.mutating,
            "exit_code": a.exit_code,
            "duration_seconds": a.duration_seconds,
            "result_summary": a.result_summary,
        }
        for a in rows
    ]


def _run_for_change_request(conn: sqlite3.Connection, cr_id: str):
    """Finds the repair run that proposed `cr_id`, if any. Looked up by
    scanning recent runs rather than by a new index: the link is
    already stored on the run (change_request_id), and adding a second
    index for a screen a human opens a few times a day would be paying
    schema cost for nothing."""
    for run in list_agent_repair_runs(conn, limit=500):
        if run.change_request_id == cr_id:
            return run
    return None


def build_change_request_view(conn: sqlite3.Connection, cr_id: str) -> "Optional[ChangeRequestView]":
    cr = find_ai_change_request(conn, cr_id)
    if cr is None:
        return None
    run = _run_for_change_request(conn, cr_id)

    return ChangeRequestView(
        cr_id=cr.cr_id,
        status=cr.status,
        created_at=cr.created_at,
        title=cr.title,
        reason=cr.reason,
        proposed_action=cr.proposed_change,
        revision_hash=cr.revision_hash,
        affected_component=cr.affected_component,
        risks=cr.risks,
        classification=cr.classification,
        model_a_opinion=cr.model_a_opinion,
        model_b_opinion=cr.model_b_opinion,
        approved_at=cr.approved_at,
        approved_by=cr.approved_by,
        run_id=run.run_id if run else None,
        requesting_tool=run.tool_name if run else "",
        requesting_model=run.model_name if run else "",
        diff_path=run.diff_path if run else None,
        diff_hash=run.diff_hash if run else None,
        changed_files=list(run.changed_files) if run else [],
        pytest_status=run.pytest_status if run else None,
        pytest_summary=run.pytest_summary if run else "",
        validate_status=run.validate_status if run else None,
        validate_summary=run.validate_summary if run else "",
        verification_passed=run.verification_passed if run else None,
        review_status=run.review_status if run else None,
        review_provider=run.review_provider if run else "",
        review_model=run.review_model if run else "",
        review_blocking=list(run.review_blocking) if run else [],
        review_summary=run.review_summary if run else "",
        commands=_commands_for_run(conn, run.run_id if run else None),
        rollback=rollback_strategy(
            status=cr.status,
            diff_hash=run.diff_hash if run else None,
            diff_path=run.diff_path if run else None,
            worktree_path=run.worktree_path if run else None,
        ),
    )


def list_pending_change_requests(conn: sqlite3.Connection, limit: int = 50) -> "list[ChangeRequestView]":
    """Every change request still awaiting a human, newest first,
    fully assembled."""
    views = []
    for cr in list_ai_change_requests(conn, limit=limit):
        if cr.status not in AWAITING_APPROVAL_STATUSES:
            continue
        view = build_change_request_view(conn, cr.cr_id)
        if view is not None:
            views.append(view)
    return views


@dataclass(frozen=True)
class ApprovalIntegrity:
    """Whether the content a change request currently holds is still
    the content its `revision_hash` was computed over, and whether the
    diff on disk is still the diff the run recorded.

    Pure: computes and compares, writes nothing. The writer that acts
    on a mismatch is `invalidate_change_request_if_content_changed()`
    in secure/agent/changes.py, kept separate so this check can be run
    for display without any risk of a side effect.
    """

    intact: bool
    content_hash_matches: bool
    diff_hash_matches: "Optional[bool]"  # None when there is no diff to check
    detail: str


def approval_integrity(conn: sqlite3.Connection, cr_id: str) -> "Optional[ApprovalIntegrity]":
    """Recomputes the approval hash from the change request's own
    stored content and, when a diff file is recorded, re-hashes it on
    disk.

    Phase 28's `approve_change()` already refuses unless the caller's
    hash matches at approval time, and Phase 31's
    `revalidate_before_approval()` re-derives the worktree diff
    immediately BEFORE approval. Neither says anything about the window
    AFTER approval, which is exactly what the governing text's
    "if proposed content changes after approval" clause is about. This
    closes that window: an approved request whose content or diff no
    longer hashes the same is detectably stale, and nothing downstream
    may treat its approval as still covering what is now there.
    """
    import hashlib

    from secure.ai.changes.model import ProposedChangeContent, compute_revision_hash

    cr = find_ai_change_request(conn, cr_id)
    if cr is None:
        return None

    recomputed = compute_revision_hash(
        ProposedChangeContent(
            title=cr.title, proposed_change=cr.proposed_change, reason=cr.reason,
            affected_component=cr.affected_component, risks=cr.risks,
        )
    )
    content_ok = recomputed == cr.revision_hash

    run = _run_for_change_request(conn, cr_id)
    diff_ok: "Optional[bool]" = None
    diff_detail = "no diff file is recorded for this change request"
    if run is not None and run.diff_path and run.diff_hash:
        path = Path(run.diff_path)
        if not path.is_file():
            diff_ok = False
            diff_detail = f"the recorded diff file no longer exists at {run.diff_path}"
        else:
            try:
                current = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                diff_ok = False
                diff_detail = f"the recorded diff file could not be read: {exc}"
            else:
                diff_ok = current == run.diff_hash
                diff_detail = (
                    "the diff on disk still matches the hash recorded at proposal time"
                    if diff_ok else
                    f"the diff on disk has changed (recorded {run.diff_hash}, found {current})"
                )

    intact = content_ok and diff_ok is not False
    detail = (
        ("the approved content still hashes to its recorded revision_hash" if content_ok else
         f"the change request's content no longer hashes to its recorded revision_hash "
         f"(recorded {cr.revision_hash}, recomputed {recomputed})")
        + "; " + diff_detail
    )
    return ApprovalIntegrity(
        intact=intact, content_hash_matches=content_ok, diff_hash_matches=diff_ok, detail=detail
    )


def read_diff(view: ChangeRequestView) -> str:
    """VIEW DIFF. Reads the diff from the path recorded on the run,
    right now — never from a copy cached at proposal time, so a diff
    file that has been altered or deleted on disk since is visible as
    what it actually is rather than as what was once true."""
    if not view.diff_path:
        return "(this change request records no diff — it describes an action, not a patch)"
    path = Path(view.diff_path)
    if not path.is_file():
        return f"(the recorded diff file no longer exists at {view.diff_path})"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"(could not read the recorded diff at {view.diff_path}: {exc})"
    if len(text) > _MAX_DIFF_CHARS:
        return text[:_MAX_DIFF_CHARS] + f"\n...[{len(text) - _MAX_DIFF_CHARS} more characters truncated]"
    return text


def tests_report(view: ChangeRequestView) -> str:
    """VIEW TESTS. Deterministic results only — no model's opinion
    about them appears in this function's output."""
    if view.run_id is None:
        return "(no repair run is linked to this change request, so no tests were recorded)"
    lines = [
        f"Run:             {view.run_id}",
        f"pytest:          {view.pytest_status or '(not run)'}",
        f"  {view.pytest_summary or '(no output recorded)'}",
        f"secure validate: {view.validate_status or '(not run)'}",
        f"  {view.validate_summary or '(no output recorded)'}",
        "",
        f"Overall deterministic verification passed: {view.verification_passed}",
        "",
        "Deterministic test results are authoritative. A passing result is NOT authorization.",
    ]
    return "\n".join(lines)


def reviewer_report(view: ChangeRequestView) -> str:
    """The Phase 38 independent reviewer's assessment, stated as an
    opinion — never as a verdict on whether the tests passed."""
    if not view.review_status:
        return "(no independent review was recorded for this change request)"
    lines = [
        f"Reviewer:        {view.review_provider or '(none)'}/{view.review_model or '(none)'}",
        f"Review status:   {view.review_status}",
        f"Blocking:        {', '.join(view.review_blocking) if view.review_blocking else '(none)'}",
        f"Summary:         {view.review_summary or '(none)'}",
        "",
        "A second model raising no blocking findings is a second opinion, not an approval.",
    ]
    return "\n".join(lines)
