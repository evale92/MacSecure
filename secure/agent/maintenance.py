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

"POLICY-PERMITTED PROMOTION" IS DELIBERATELY NOT AUTOMATIC EXECUTION

The flow's happy path ends at "policy-permitted promotion." Phase 44
defines what is ELIGIBLE (VERIFIED and SAFE_PROJECT_CODE); this module
reports that eligibility and stops there. It does not apply a patch to
the live checkout.

That is a deliberate reading of the roadmap rather than an omission,
and the FINAL AUTHORITY MODEL in the same document is why:

    "LLMs do NOT independently establish: authorization ... permission
    for consequential host changes."
    "Human approval authorizes consequential system changes."

Applying a patch to the live checkout is a write to the operator's
working tree — the thing every isolation boundary since Phase 31 exists
to prevent. Nothing in Part 2 ever asked for that write to happen
without a human, and this project's whole argument rests on it not
happening. So `MaintenanceOutcome.promotion_eligible` is a report, and
`secure agent approve` (human-triggered, hash-revalidated, unchanged
since Phase 31) remains the only path by which anything reaches the
live checkout.
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
LOOP_ERROR = "error"

ALL_LOOP_OUTCOMES = (
    LOOP_NOT_REPRODUCED,
    LOOP_INCONCLUSIVE,
    LOOP_REPAIR_REJECTED,
    LOOP_ESCALATED_DISAGREEMENT,
    LOOP_AWAITING_APPROVAL,
    LOOP_PROMOTION_ELIGIBLE,
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

    @property
    def promotion_eligible(self) -> bool:
        """Reports eligibility. Never performs a promotion — see this
        module's docstring for why that distinction is the point."""
        return self.outcome == LOOP_PROMOTION_ELIGIBLE

    @property
    def host_modified(self) -> bool:
        """Always False. No path through this loop writes to the live
        checkout or changes host state; the property exists so a caller
        can assert it rather than infer it."""
        return False

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
) -> MaintenanceOutcome:
    """One candidate, all the way through.

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
    assessment = _evaluate_verified(run, cfg, root=root)

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
        return MaintenanceOutcome(
            outcome=LOOP_PROMOTION_ELIGIBLE,
            verified=True,
            detail=(
                "VERIFIED against all eleven Phase 44 criteria and classified SAFE_PROJECT_CODE, so "
                "this is ELIGIBLE for policy-permitted promotion. Secure has not promoted it: applying "
                "a patch to the live checkout is a human action (`secure agent approve <run_id>`), and "
                "eligibility is not permission."
            ),
            **common,
        )

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


def _evaluate_verified(run, cfg: AppConfig, *, root: "Optional[Path]" = None):
    """Phase 44's evaluation, called without a re-run of the tiers.

    The tier criteria will therefore answer "unknown", which BLOCKS —
    that is the honest result for a caller that did not re-measure, and
    it fails toward requiring a human rather than toward promotion. A
    caller that has a real `EscalationOutcome` should evaluate with it
    directly.
    """
    try:
        from secure.agent.verified import evaluate_verified

        return evaluate_verified(run, cfg, escalation=None, perf_warnings=None, root=root)
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
