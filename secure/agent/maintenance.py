"""
secure/agent/maintenance.py — Phase 47 (Part 2: Supervised Agentic
Development & Self-Healing — "Supervised Autonomous Maintenance").

The single bounded loop that integrates everything Part 2 built.
Governing flow, verbatim (docs/ROADMAP_PART2_PHASES_38_47.md):

    HEALTH / TESTS -> FAILURE DETECTED -> REPRODUCE -> PRIMARY CODER ->
    ISOLATED REPAIR -> ACTUAL GIT DIFF -> DETERMINISTIC TESTS ->
    SECURITY VALIDATION WHEN RELEVANT -> INDEPENDENT REVIEW ->
    CHANGE CLASSIFICATION

    Then: VERIFIED SAFE_PROJECT_CODE -> policy-permitted promotion
    OR:   CONSEQUENTIAL CHANGE -> CHANGE REQUEST -> SECURE UI ->
          EMAIL NOTIFICATION -> HUMAN APPROVAL -> APPLY -> POST-VERIFY

    Finally: AUDIT / MAINTENANCE MEMORY

THIS MODULE IS A SEQUENCER, NOT A NEW CAPABILITY

Every box above already exists and is already tested in its own phase.
This module calls them in order and reports what happened. It adds no
detection logic, no verification logic, no approval logic, and — most
importantly — no way to do any of those things differently from how
the owning phase does them.

"POLICY-PERMITTED PROMOTION" (updated by Phase 47.5)

Phase 47 originally stopped at REPORTING promotion eligibility, because
nothing in the Part 2 roadmap authorized writing to the live checkout.
Phase 47.5 (docs/PHASE_47_5.md) narrowly authorizes it for fully
VERIFIED SAFE_PROJECT_CODE repairs only.

Two things about that authorization are load-bearing:

- It is OPT-IN. `run_maintenance_cycle()` promotes nothing unless the
  caller passes `allow_promotion=True`. The default is still report-
  only, so every pre-47.5 caller behaves exactly as it did.
- It is narrow. Everything else — DEPENDENCY_CHANGE,
  SECURITY_SEMANTIC_CHANGE, SYSTEM_CHANGE, PRIVILEGED_CHANGE, anything
  ambiguous, any reviewer blocker, any UNKNOWN criterion — still stops
  at AWAITING_APPROVAL, and `secure agent approve` (human-triggered,
  hash-revalidated, unchanged since Phase 31) remains the manual path.

The gate and the write itself live in `secure/agent/promote.py`, which
refuses by default and collects refusal reasons rather than approval
evidence.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.classify import CLASS_SAFE_PROJECT_CODE, requires_human_approval
from secure.agent.diagnose import (
    DIAGNOSIS_REPAIRED,
    DIAGNOSIS_STOPPED_INCONCLUSIVE,
    DIAGNOSIS_STOPPED_NOT_REPRODUCED,
    diagnose_failure,
)
from secure.agent.policy import RepairCandidate
from secure.config import AppConfig

# Terminal states of one maintenance pass. These are outcomes of the
# LOOP, distinct from Phase 42's supervisor state vocabulary (which
# describes what the supervisor is doing at a moment in time).
LOOP_NOT_REPRODUCED = "stopped_not_reproduced"
LOOP_INCONCLUSIVE = "stopped_inconclusive_reproduction"
LOOP_REPAIR_REJECTED = "repair_rejected"
LOOP_ESCALATED_DISAGREEMENT = "escalated_coder_reviewer_disagreement"
LOOP_AWAITING_APPROVAL = "awaiting_human_approval"
LOOP_PROMOTION_ELIGIBLE = "verified_promotion_eligible"
# Phase 47.5 — only reachable when the caller opted in to promotion.
LOOP_PROMOTED = "promoted"
LOOP_PROMOTION_ROLLED_BACK = "promotion_rolled_back"
LOOP_PROMOTION_ESCALATED = "promotion_escalated"
LOOP_ERROR = "error"

ALL_LOOP_OUTCOMES = (
    LOOP_NOT_REPRODUCED,
    LOOP_INCONCLUSIVE,
    LOOP_REPAIR_REJECTED,
    LOOP_ESCALATED_DISAGREEMENT,
    LOOP_AWAITING_APPROVAL,
    LOOP_PROMOTION_ELIGIBLE,
    LOOP_PROMOTED,
    LOOP_PROMOTION_ROLLED_BACK,
    LOOP_PROMOTION_ESCALATED,
    LOOP_ERROR,
)

# Run statuses that mean the repair itself did not survive its own
# deterministic gates. Distinct from an escalation, which means it
# passed them and a reviewer objected.
_REJECTED_STATUSES = (
    "verification_failed",
    "verification_inconclusive",
    "rejected_by_denylist",
    "no_diff",
    "timed_out",
    "error",
)


@dataclass(frozen=True)
class MaintenanceOutcome:
    """One full pass of the loop, and everything a human needs to
    understand it without re-deriving anything."""

    outcome: str
    candidate: RepairCandidate
    reproduction_status: "Optional[str]" = None
    reproduced: "Optional[bool]" = None
    run_id: "Optional[str]" = None
    run_status: "Optional[str]" = None
    classification: "Optional[str]" = None
    change_request_id: "Optional[str]" = None
    verified: "Optional[bool]" = None
    verified_blocking: "tuple[str, ...]" = field(default_factory=tuple)
    review_status: "Optional[str]" = None
    review_blocking: "tuple[str, ...]" = field(default_factory=tuple)
    disagreement: bool = False
    detail: str = ""
    # Phase 47.5: True only when a patch was actually applied to the
    # live working tree and not rolled back. A field rather than a
    # hardcoded False, because as of 47.5 it can genuinely be True —
    # a property that always returned False would now be a lie.
    live_checkout_modified: bool = False
    promotion_refusals: "tuple[str, ...]" = field(default_factory=tuple)
    post_verification: "tuple[str, ...]" = field(default_factory=tuple)

    @property
    def promotion_eligible(self) -> bool:
        """Reports eligibility. Never performs a promotion — see this
        module's docstring for why that distinction is the point."""
        return self.outcome == LOOP_PROMOTION_ELIGIBLE

    @property
    def host_modified(self) -> bool:
        """Whether this pass wrote to the live working tree. False for
        every outcome except a successful, non-rolled-back promotion —
        and promotion only happens when the caller opted in."""
        return self.live_checkout_modified

    @property
    def awaiting_human(self) -> bool:
        return self.outcome in (LOOP_AWAITING_APPROVAL, LOOP_ESCALATED_DISAGREEMENT)


def run_maintenance_cycle(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    candidate: RepairCandidate,
    *,
    root: "Optional[Path]" = None,
    providers: "Optional[dict]" = None,
    allow_promotion: bool = False,
) -> MaintenanceOutcome:
    """One candidate, all the way through.

    `allow_promotion` (Phase 47.5) defaults to False. When False this
    function writes nothing to the live checkout and behaves exactly as
    it did before 47.5 — it reports eligibility and stops.

    Phase 43's `diagnose_failure()` already sequences reproduce ->
    bounded context -> primary coder -> isolated repair -> actual git
    diff -> tiered deterministic tests -> security validation ->
    independent review -> classification -> change request, and Phase
    45's memory write already happens inside `attempt_repair()`. This
    function adds the branch AFTER that: rejected, escalated, awaiting
    approval, or eligible for promotion.
    """
    diagnosis = diagnose_failure(conn, cfg, candidate, root=root, providers=providers)

    if diagnosis.status == DIAGNOSIS_STOPPED_NOT_REPRODUCED:
        return MaintenanceOutcome(
            outcome=LOOP_NOT_REPRODUCED, candidate=candidate,
            reproduction_status=diagnosis.reproduction.status,
            reproduced=diagnosis.reproduction.reproduced,
            detail="The failure did not recur. No repair was attempted and none was fabricated.",
        )
    if diagnosis.status == DIAGNOSIS_STOPPED_INCONCLUSIVE:
        return MaintenanceOutcome(
            outcome=LOOP_INCONCLUSIVE, candidate=candidate,
            reproduction_status=diagnosis.reproduction.status,
            reproduced=diagnosis.reproduction.reproduced,
            detail="Reproduction was inconclusive. An inconclusive check is not permission to repair.",
        )
    if diagnosis.status != DIAGNOSIS_REPAIRED or diagnosis.run is None:
        return MaintenanceOutcome(
            outcome=LOOP_ERROR, candidate=candidate,
            reproduction_status=diagnosis.reproduction.status,
            detail=f"unexpected diagnosis status {diagnosis.status!r}",
        )

    run = diagnosis.run
    common = dict(
        candidate=candidate,
        reproduction_status=diagnosis.reproduction.status,
        reproduced=diagnosis.reproduction.reproduced,
        run_id=run.run_id,
        run_status=run.status,
        classification=run.classification,
        change_request_id=run.change_request_id,
        review_status=run.review_status,
        review_blocking=tuple(run.review_blocking or ()),
        disagreement=bool(run.review_disagreement),
    )

    if run.status == "escalated_for_review":
        return MaintenanceOutcome(
            outcome=LOOP_ESCALATED_DISAGREEMENT,
            detail=(
                "Deterministic verification passed, but the independent reviewer raised a blocking "
                "finding while the coder reported success. Material disagreement stops automatic "
                "progression — no change request was created, and a human must look at this."
            ),
            **common,
        )

    if run.status in _REJECTED_STATUSES:
        return MaintenanceOutcome(
            outcome=LOOP_REPAIR_REJECTED,
            detail=f"The repair did not survive its own deterministic gates ({run.status}): {run.stop_reason}",
            **common,
        )

    if run.status != "verified":
        return MaintenanceOutcome(
            outcome=LOOP_ERROR, detail=f"unrecognized run status {run.status!r}", **common
        )

    # Verified by Phase 31's own gates and holding a pending change
    # request. Now apply Phase 44's authoritative eleven-criterion
    # definition, which is stricter and re-measures rather than
    # remembering.
    #
    # Phase 47.5: the Phase 36 tiers are run here, for real, ONLY on
    # the path where promotion is actually being considered. A
    # consequential change goes to a human regardless, so paying for a
    # full regression to tell it so would be waste; those paths report
    # UNKNOWN honestly instead.
    consider_promotion = run.classification == CLASS_SAFE_PROJECT_CODE
    escalation = _run_authoritative_tiers(run, cfg) if consider_promotion else None
    assessment = _evaluate_verified(run, cfg, root=root, escalation=escalation)

    if run.classification is not None and requires_human_approval(run.classification):
        return MaintenanceOutcome(
            outcome=LOOP_AWAITING_APPROVAL,
            verified=assessment.verified if assessment else None,
            verified_blocking=tuple(assessment.blocking) if assessment else (),
            detail=(
                f"Classified {run.classification}, which requires human approval. A change request is "
                "pending in Secure and the operator has been notified. Nothing has been applied to the "
                "live checkout, and no host state was changed."
            ),
            **common,
        )

    if assessment is not None and assessment.promotion_candidate:
        if not allow_promotion:
            return MaintenanceOutcome(
                outcome=LOOP_PROMOTION_ELIGIBLE,
                verified=True,
                detail=(
                    "VERIFIED against all eleven Phase 44 criteria and classified SAFE_PROJECT_CODE, so "
                    "this is ELIGIBLE for policy-permitted promotion. Nothing was promoted: this caller "
                    "did not opt in (`allow_promotion=False`), and eligibility is not permission."
                ),
                **common,
            )
        return _promote(conn, cfg, run, assessment, root=root, common=common)

    return MaintenanceOutcome(
        outcome=LOOP_AWAITING_APPROVAL,
        verified=assessment.verified if assessment else None,
        verified_blocking=tuple(assessment.blocking) if assessment else (),
        detail=(
            "The repair passed Phase 31's gates and has a pending change request, but did not meet "
            "every Phase 44 VERIFIED criterion"
            + (f" (blocking: {', '.join(assessment.blocking)})" if assessment and assessment.blocking else "")
            + ". A human decides from here."
        ),
        **common,
    )


def _run_authoritative_tiers(run, cfg: AppConfig, *, audit_trail: "Optional[list]" = None):
    """Phase 47.5: OBTAIN the authoritative Phase 36 tiers.

    Phase 36 built `choose_and_run_verification()` but deliberately did
    not rewire Phase 31's `_finish_repair_run()`, which still runs
    `verify_worktree()` (pytest + `secure validate`). The consequence
    was that Phase 36's tier runner had no production caller at all, so
    Phase 44's FAST/TARGETED/FULL/SECURITY criteria could never be
    satisfied by anything and always answered UNKNOWN.

    This closes that gap the smallest way: run the real tiers against
    the repair's own still-existing worktree, here, and hand the real
    `EscalationOutcome` to Phase 44. Phase 31's flow is untouched.

    Returns None when the tiers could not be run — which makes Phase
    44 answer UNKNOWN, which blocks. **Nothing here manufactures a
    PASS, and nothing translates UNKNOWN into PASS.**
    """
    from secure.agent.tiers import choose_and_run_verification
    from secure.agent.worktree import RepairWorktree, worktree_exists

    worktree_path = Path(getattr(run, "worktree_path", "") or "")
    if not worktree_path:
        return None
    worktree = RepairWorktree(
        run_dir=worktree_path.parent,
        worktree_path=worktree_path,
        agent_home_path=worktree_path.parent / "home",
        base_commit=getattr(run, "base_commit", "") or "",
    )
    if not worktree_exists(worktree):
        return None
    try:
        return choose_and_run_verification(
            worktree, cfg, list(getattr(run, "changed_files", []) or []),
            diff_hash=getattr(run, "diff_hash", None), audit_trail=audit_trail,
        )
    except Exception:  # noqa: BLE001 — an unavailable tier runner is UNKNOWN, never a pass
        return None


def _evaluate_verified(run, cfg: AppConfig, *, root: "Optional[Path]" = None, escalation=None):
    """Phase 44's evaluation.

    When `escalation` is None the tier criteria answer "unknown", which
    BLOCKS — the honest result for a caller that did not re-measure,
    failing toward requiring a human rather than toward promotion.
    """
    try:
        from secure.agent.verified import evaluate_verified

        return evaluate_verified(run, cfg, escalation=escalation, perf_warnings=None, root=root)
    except Exception:  # noqa: BLE001 — an assessment failure must not crash the loop
        return None


def describe(outcome: MaintenanceOutcome) -> str:
    lines = [
        f"Trigger:        {outcome.candidate.trigger_kind}  {outcome.candidate.trigger_ref}",
        f"Reproduction:   {outcome.reproduction_status} (reproduced={outcome.reproduced})",
        f"Run:            {outcome.run_id or '(none)'}  status={outcome.run_status or '(none)'}",
        f"Classification: {outcome.classification or '(none)'}",
        f"Reviewer:       {outcome.review_status or '(none)'}  "
        f"blocking={', '.join(outcome.review_blocking) or '(none)'}",
        f"Phase 44:       verified={outcome.verified}  "
        f"blocking={', '.join(outcome.verified_blocking) or '(none)'}",
        f"Change request: {outcome.change_request_id or '(none)'}",
        "",
        f"OUTCOME:        {outcome.outcome}",
        f"  {outcome.detail}",
        "",
        f"Host modified:  {outcome.host_modified}",
    ]
    return "\n".join(lines)


def _promote(conn, cfg: AppConfig, run, assessment, *, root: "Optional[Path]", common: dict) -> MaintenanceOutcome:
    """Phase 47.5. Hands off to secure/agent/promote.py, which owns the
    gate and the only write to the live checkout in this project.

    This function makes no safety decision of its own — it does not
    re-check anything, relax anything, or override a refusal. It
    translates one PromotionResult into one MaintenanceOutcome.
    """
    from secure.agent.audit import persist_audit_trail
    from secure.agent.promote import (
        PROMOTION_ESCALATED,
        PROMOTION_PROMOTED,
        PROMOTION_REFUSED,
        PROMOTION_ROLLED_BACK,
        promote,
    )
    from secure.agent.worktree import project_root
    from secure.storage.models import find_ai_change_request

    live_root = Path(root) if root is not None else project_root()
    change_request = (
        find_ai_change_request(conn, run.change_request_id) if run.change_request_id else None
    )

    audit_trail: list = []
    result = promote(
        conn, run, assessment, cfg, root=live_root,
        change_request=change_request, audit_trail=audit_trail,
    )
    persist_audit_trail(conn, run_id=run.run_id, audit_trail=audit_trail)

    outcome_map = {
        PROMOTION_PROMOTED: LOOP_PROMOTED,
        PROMOTION_ROLLED_BACK: LOOP_PROMOTION_ROLLED_BACK,
        PROMOTION_ESCALATED: LOOP_PROMOTION_ESCALATED,
        PROMOTION_REFUSED: LOOP_AWAITING_APPROVAL,
    }
    return MaintenanceOutcome(
        outcome=outcome_map.get(result.outcome, LOOP_ERROR),
        verified=True,
        live_checkout_modified=result.live_checkout_modified,
        promotion_refusals=result.gate.refusals,
        post_verification=result.post_verification,
        detail=result.detail,
        **common,
    )
