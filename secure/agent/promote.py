"""
secure/agent/promote.py — Phase 47.5 ("Close the Verified Safe-Code
Loop"). Governing text: docs/PHASE_47_5.md.

**This is the first module in the project permitted to write to the
live checkout.** Every isolation boundary since Phase 31 existed to
prevent exactly that write, so the burden here is higher than anywhere
else in the codebase, and the standing instruction is explicit:

    "Prefer refusing to promote over promoting wrongly, in every
    ambiguous case."

That is implemented literally. `evaluate_promotion_gate()` collects
REFUSAL REASONS rather than approval evidence, and promotion proceeds
only when that list is empty. Every unknown, every missing value, and
every unrecognized state adds a reason. There is no branch that
promotes because nothing objected — something must affirmatively
establish each condition.

WHAT THIS MODULE MAY PROMOTE

Only a repair that is VERIFIED against all eleven Phase 44 criteria AND
classified exactly SAFE_PROJECT_CODE. DEPENDENCY_CHANGE,
SECURITY_SEMANTIC_CHANGE, SYSTEM_CHANGE, PRIVILEGED_CHANGE, anything
ambiguous or unclassified, anything with a reviewer blocker, and
anything with an UNKNOWN criterion all remain AWAITING_APPROVAL and are
refused here.

`secure agent approve` is untouched and remains the manual promotion
path for everything else.

STANDARD GIT MECHANISMS ONLY

Base-revision verification is `git rev-parse HEAD`. Dirty-checkout
protection is `git status --porcelain`. Application is `git apply`
(preceded by `git apply --check`). Rollback is `git apply -R` of the
exact same patch file. No bespoke snapshot framework, per the standing
rule to prefer standard Git/worktree mechanisms.

The patch is applied to the WORKING TREE only. Nothing here commits,
amends, moves HEAD, creates a branch, or touches git config — the
operator owns their history. After a successful promotion the change
sits as an uncommitted working-tree modification for them to inspect
and commit themselves.

ROLLBACK IS ONLY ATTEMPTED WHEN IT CAN BE PROVEN SAFE

After applying, the working tree must contain changes to EXACTLY the
files the patch touches and nothing else. If anything else changed —
another process, the operator, a concurrent tool — rollback could
destroy work that is not ours, so this module refuses to roll back and
escalates instead. A rollback that might eat someone else's edit is
worse than a patch left in place with a loud message.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure.agent.audit import now_iso, record_action
from secure.agent.classify import CLASS_SAFE_PROJECT_CODE
from secure.agent.policy import TRIGGER_PYTEST_FAILURE
from secure.config import AppConfig

# Outcomes.
PROMOTION_REFUSED = "refused"
PROMOTION_PROMOTED = "promoted"
PROMOTION_ROLLED_BACK = "rolled_back"
PROMOTION_ESCALATED = "escalated"

ALL_PROMOTION_OUTCOMES = (
    PROMOTION_REFUSED, PROMOTION_PROMOTED, PROMOTION_ROLLED_BACK, PROMOTION_ESCALATED,
)

# A change request resolved by automatic promotion. Deliberately NOT
# 'approved' — Phase 28's hard rule 4 reserves that word for a human
# CLI action, and nothing here may produce it. This is a fourth
# terminal state in the same spirit as Phase 31's 'superseded': set
# only by deterministic machinery, recording an objective fact rather
# than a judgment, and permanently un-approvable afterwards (Phase
# 28's approve_change() already requires status == 'pending').
STATUS_PROMOTED_AUTOMATICALLY = "promoted_automatically"

_GIT_TIMEOUT_SECONDS = 60.0
_VERIFY_TIMEOUT_SECONDS = 600.0


@dataclass(frozen=True)
class PromotionGate:
    """Why a repair may NOT be promoted. An empty `refusals` tuple is
    the only thing that permits promotion — see this module's docstring
    for why the polarity matters."""

    refusals: "tuple[str, ...]" = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return not self.refusals

    def describe(self) -> str:
        if self.allowed:
            return "All promotion conditions are satisfied."
        return "Promotion refused:\n" + "\n".join(f"  - {r}" for r in self.refusals)


@dataclass(frozen=True)
class PromotionResult:
    outcome: str
    gate: PromotionGate
    applied: bool = False
    rolled_back: bool = False
    detail: str = ""
    changed_files: "tuple[str, ...]" = field(default_factory=tuple)
    base_commit: "Optional[str]" = None
    diff_hash: "Optional[str]" = None
    post_verification: "tuple[str, ...]" = field(default_factory=tuple)

    @property
    def live_checkout_modified(self) -> bool:
        """True only when a patch was applied and NOT rolled back."""
        return self.applied and not self.rolled_back


# ---------------------------------------------------------------------
# Audited git seam
# ---------------------------------------------------------------------


def _git(
    args: "list[str]",
    *,
    cwd: Path,
    audit_trail: "Optional[list]" = None,
    mutating: bool = False,
    action: str = "",
    timeout: float = _GIT_TIMEOUT_SECONDS,
) -> "subprocess.CompletedProcess":
    """The one seam every git call in this module goes through, so that
    requirement 4 ("record every filesystem/Git action through the
    Phase 31.5 audit boundary") holds by construction rather than by
    remembering to call `record_action()` at each site.

    Mirrors secure/agent/worktree.py's own `_run_git()` shape rather
    than importing it, for the reason that module's docstring gives
    about narrow safety boundaries: this caller needs a different
    contract (it must audit unconditionally), and widening the other
    one to serve both would loosen it.
    """
    argv = ["git", *args]
    started_at = now_iso()
    started = _monotonic()
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, shell=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        record_action(
            audit_trail, component="agent.promote", action=action or " ".join(args[:2]),
            argv=argv, cwd=str(cwd), target=str(cwd), mutating=mutating, started_at=started_at,
            exit_code=None, result_summary=f"{type(exc).__name__}", duration_seconds=_monotonic() - started,
        )
        raise
    record_action(
        audit_trail, component="agent.promote", action=action or " ".join(args[:2]),
        argv=argv, cwd=str(cwd), target=str(cwd), mutating=mutating, started_at=started_at,
        exit_code=proc.returncode, result_summary=f"exit {proc.returncode}",
        duration_seconds=_monotonic() - started,
    )
    return proc


def _monotonic() -> float:
    import time

    return time.monotonic()


def live_head(root: Path, *, audit_trail: "Optional[list]" = None) -> "Optional[str]":
    try:
        proc = _git(["rev-parse", "HEAD"], cwd=root, audit_trail=audit_trail, action="rev-parse HEAD")
    except Exception:  # noqa: BLE001
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def live_dirty_paths(root: Path, *, audit_trail: "Optional[list]" = None) -> "Optional[list[str]]":
    """Returns the list of paths git reports as changed, or None when
    the question could not be answered. None is never treated as
    clean."""
    try:
        proc = _git(["status", "--porcelain"], cwd=root, audit_trail=audit_trail, action="status --porcelain")
    except Exception:  # noqa: BLE001
        return None
    if proc.returncode != 0:
        return None
    paths = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        # Porcelain v1: two status chars, a space, then the path.
        paths.append(line[3:].strip().strip('"'))
    return paths


# ---------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------


def evaluate_promotion_gate(
    record,
    assessment,
    cfg: AppConfig,
    *,
    root: Path,
    change_request=None,
    audit_trail: "Optional[list]" = None,
) -> PromotionGate:
    """Every condition from the governing text, evaluated as a refusal
    list. `assessment` is Phase 44's `VerifiedAssessment`, built with a
    REAL Phase 36 `EscalationOutcome` — never one this module
    manufactured.
    """
    refusals: "list[str]" = []

    # --- Phase 44: every applicable criterion satisfied, none UNKNOWN.
    if assessment is None:
        refusals.append("no Phase 44 assessment was produced — nothing established that this repair is verified")
    else:
        if not assessment.verified:
            refusals.append(
                "not VERIFIED against all eleven Phase 44 criteria"
                + (f" (blocking: {', '.join(assessment.blocking)})" if assessment.blocking else "")
            )
        unknown = [c.key for c in assessment.criteria if c.applicable and c.satisfied is None]
        if unknown:
            refusals.append(
                f"criteria could not be determined and UNKNOWN is never a pass: {', '.join(unknown)}"
            )

    # --- Classification must be exactly SAFE_PROJECT_CODE.
    classification = getattr(record, "classification", None)
    if classification is None:
        refusals.append("the change is unclassified — an ambiguous classification never auto-promotes")
    elif classification != CLASS_SAFE_PROJECT_CODE:
        refusals.append(
            f"classified {classification}, which always requires human approval and never auto-promotes"
        )

    # --- Reviewer must have raised no blocker.
    review_blocking = list(getattr(record, "review_blocking", []) or [])
    if review_blocking:
        refusals.append(f"the independent reviewer raised blocking findings: {', '.join(review_blocking)}")
    if getattr(record, "review_disagreement", None):
        refusals.append("coder and reviewer materially disagreed")
    if getattr(record, "review_status", None) in ("error", "unparseable"):
        refusals.append(
            f"the independent reviewer produced no usable assessment ({record.review_status}) — "
            "a review that ran and could not be understood is not a pass"
        )

    # --- Reproduction.
    if getattr(record, "reproduced", None) is not True:
        refusals.append("the original failure was not confirmed to have been reproduced before the repair")

    # --- Run status and denylist.
    if getattr(record, "status", None) != "verified":
        refusals.append(f"the repair run status is {getattr(record, 'status', None)!r}, not 'verified'")
    if getattr(record, "denylist_violation", None):
        refusals.append(f"path denylist violation: {record.denylist_violation}")

    # --- Diff must be known, hash-bound, and unchanged right now.
    diff_path = getattr(record, "diff_path", None)
    diff_hash = getattr(record, "diff_hash", None)
    if not diff_path or not diff_hash:
        refusals.append("no diff path or diff hash was recorded — the exact patch is not identifiable")
    else:
        path = Path(diff_path)
        if not path.is_file():
            refusals.append(f"the recorded diff file no longer exists at {diff_path}")
        else:
            try:
                current = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                refusals.append(f"the recorded diff could not be read: {exc}")
            else:
                if current != diff_hash:
                    refusals.append(
                        f"the diff has changed since verification (recorded {diff_hash}, found {current})"
                    )

    # --- Changed files must be known.
    changed_files = list(getattr(record, "changed_files", []) or [])
    if not changed_files:
        refusals.append("no changed files were recorded — the patch's scope is unknown")

    # --- No approval request pending a human decision.
    if change_request is not None:
        cr_status = getattr(change_request, "status", None)
        if cr_status != "pending":
            refusals.append(
                f"the linked change request is {cr_status!r}, not 'pending' — a human has already acted "
                "on it and that decision is not this module's to override"
            )
        cr_class = getattr(change_request, "classification", None)
        if cr_class is not None and cr_class != CLASS_SAFE_PROJECT_CODE:
            refusals.append(f"the linked change request is classified {cr_class}, which requires approval")

    # --- Live checkout: base revision and cleanliness.
    head = live_head(root, audit_trail=audit_trail)
    base = getattr(record, "base_commit", None)
    if head is None:
        refusals.append("could not read the live checkout's HEAD — cannot confirm the base revision")
    elif not base:
        refusals.append("the repair recorded no base commit — cannot confirm the live checkout matches it")
    elif head != base:
        refusals.append(
            f"the live checkout has moved since the repair (repair based on {base}, HEAD is now {head})"
        )

    dirty = live_dirty_paths(root, audit_trail=audit_trail)
    if dirty is None:
        refusals.append("could not determine whether the live checkout is clean — refusing rather than assuming")
    elif dirty:
        refusals.append(
            f"the live checkout has {len(dirty)} uncommitted change(s) that could be overwritten: "
            + ", ".join(sorted(dirty)[:5])
            + ("..." if len(dirty) > 5 else "")
        )

    return PromotionGate(refusals=tuple(refusals))


# ---------------------------------------------------------------------
# Post-promotion verification
# ---------------------------------------------------------------------


def _live_target(root: Path, home: Path):
    """Adapts the live checkout into the shape Phase 36's tier runners
    expect, so post-promotion verification reuses the exact same
    FAST/TARGETED implementations rather than a second copy that could
    drift from them. `home` is a throwaway directory used as HOME, the
    same isolation every subprocess in this package gets."""
    from secure.agent.worktree import RepairWorktree

    return RepairWorktree(
        run_dir=home.parent, worktree_path=root, agent_home_path=home, base_commit=""
    )


def verify_after_promotion(
    record, cfg: AppConfig, *, root: Path, audit_trail: "Optional[list]" = None
) -> "tuple[bool, tuple[str, ...]]":
    """Runs FAST and TARGETED against the live checkout, plus the
    ORIGINAL failing test, which must now pass.

    Returns (ok, notes). `ok` is True only when every check that ran
    definitely passed — an unavailable or inconclusive check makes it
    False, because after writing to the operator's working tree the
    burden of proof is on the promotion, not on the doubt.
    """
    from secure.agent.tiers import run_fast_tier, run_pytest_targeted, targeted_test_files

    notes: "list[str]" = []
    ok = True

    with tempfile.TemporaryDirectory(prefix="secure-postpromo-home-") as home:
        target = _live_target(root, Path(home))

        fast = run_fast_tier(target, cfg, audit_trail=audit_trail)
        notes.append(f"FAST: status={fast.status} passed={fast.passed}")
        if not (fast.status == "ok" and fast.passed is True):
            ok = False

        test_files = targeted_test_files(list(getattr(record, "changed_files", []) or []), root)
        if test_files:
            targeted = run_pytest_targeted(target, cfg, test_files, audit_trail=audit_trail)
            notes.append(f"TARGETED: status={targeted.status} passed={targeted.passed} ({len(test_files)} file(s))")
            if not (targeted.status == "ok" and targeted.passed is True):
                ok = False
        else:
            notes.append("TARGETED: no test files map to the changed files")
            ok = False

        if getattr(record, "trigger_kind", None) == TRIGGER_PYTEST_FAILURE:
            argv = [sys.executable, "-m", "pytest", record.trigger_ref, "-q", "--tb=short"]
            import os

            env = dict(os.environ)
            env["HOME"] = home
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            started_at = now_iso()
            started = _monotonic()
            try:
                proc = subprocess.run(
                    argv, cwd=str(root), capture_output=True, text=True,
                    timeout=_VERIFY_TIMEOUT_SECONDS, shell=False, env=env,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                notes.append(f"ORIGINAL FAILURE re-check: could not run ({type(exc).__name__})")
                ok = False
            else:
                record_action(
                    audit_trail, component="agent.promote", action="post-promotion original-failure re-check",
                    argv=argv, cwd=str(root), target=record.trigger_ref, mutating=False,
                    started_at=started_at, exit_code=proc.returncode,
                    result_summary=f"exit {proc.returncode}", duration_seconds=_monotonic() - started,
                )
                output = (proc.stdout or "") + (proc.stderr or "")
                if "No module named pytest" in output:
                    notes.append("ORIGINAL FAILURE re-check: pytest unavailable — cannot confirm")
                    ok = False
                elif proc.returncode == 0:
                    notes.append(f"ORIGINAL FAILURE re-check: {record.trigger_ref} now passes")
                else:
                    notes.append(f"ORIGINAL FAILURE re-check: {record.trigger_ref} STILL FAILS")
                    ok = False

    return ok, tuple(notes)


# ---------------------------------------------------------------------
# Promotion
# ---------------------------------------------------------------------


def _rollback_is_safe(root: Path, expected: "list[str]", *, audit_trail) -> "tuple[bool, str]":
    """Rollback is safe only when the working tree contains changes to
    EXACTLY the files the patch touches and nothing else.

    Anything extra means something outside this promotion also wrote to
    the tree, and `git apply -R` could then destroy work that is not
    ours. A rollback that might eat someone else's edit is worse than a
    patch left in place with a loud message.
    """
    dirty = live_dirty_paths(root, audit_trail=audit_trail)
    if dirty is None:
        return False, "could not determine what the working tree currently contains"
    unexpected = sorted(set(dirty) - set(expected))
    if unexpected:
        return False, (
            "the working tree contains changes this promotion did not make "
            f"({', '.join(unexpected[:5])}) — rolling back could destroy them"
        )
    return True, "the working tree contains only this promotion's own changes"


def promote(
    conn,
    record,
    assessment,
    cfg: AppConfig,
    *,
    root: Path,
    change_request=None,
    audit_trail: "Optional[list]" = None,
) -> PromotionResult:
    """The eight-step procedure from the governing text. Refuses by
    default; applies only the exact verified patch; verifies
    immediately; rolls back only when provably safe; escalates
    otherwise.
    """
    audit_trail = audit_trail if audit_trail is not None else []
    gate = evaluate_promotion_gate(
        record, assessment, cfg, root=root, change_request=change_request, audit_trail=audit_trail
    )
    changed_files = tuple(getattr(record, "changed_files", []) or [])
    base = getattr(record, "base_commit", None)
    diff_hash = getattr(record, "diff_hash", None)

    if not gate.allowed:
        return PromotionResult(
            outcome=PROMOTION_REFUSED, gate=gate, detail=gate.describe(),
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash,
        )

    diff_path = Path(record.diff_path)

    # Step 3 — apply ONLY the exact verified patch, dry-run first.
    check = _git(
        ["apply", "--check", str(diff_path)], cwd=root, audit_trail=audit_trail,
        action="apply --check", mutating=False,
    )
    if check.returncode != 0:
        return PromotionResult(
            outcome=PROMOTION_REFUSED,
            gate=PromotionGate(refusals=(f"the patch does not apply cleanly: {check.stderr.strip()}",)),
            detail="`git apply --check` refused the patch; nothing was written.",
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash,
        )

    applied = _git(
        ["apply", str(diff_path)], cwd=root, audit_trail=audit_trail,
        action="apply (PROMOTION)", mutating=True,
    )
    if applied.returncode != 0:
        return PromotionResult(
            outcome=PROMOTION_REFUSED,
            gate=PromotionGate(refusals=(f"git apply failed: {applied.stderr.strip()}",)),
            detail="The patch failed to apply after passing --check; the tree may be unchanged, "
                   "but verify it by hand.",
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash,
        )

    # Step 5 — verify immediately.
    ok, notes = verify_after_promotion(record, cfg, root=root, audit_trail=audit_trail)
    if ok:
        _resolve_change_request(conn, change_request, record, audit_trail=audit_trail)
        return PromotionResult(
            outcome=PROMOTION_PROMOTED, gate=gate, applied=True, rolled_back=False,
            detail=(
                "Promoted. The patch is applied to the live working tree as an UNCOMMITTED change — "
                "nothing was committed on your behalf. Review it with `git diff` and commit it yourself."
            ),
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash, post_verification=notes,
        )

    # Steps 6/7/8 — verification failed. Roll back only if provably safe.
    safe, why = _rollback_is_safe(root, list(changed_files), audit_trail=audit_trail)
    if not safe:
        return PromotionResult(
            outcome=PROMOTION_ESCALATED, gate=gate, applied=True, rolled_back=False,
            detail=(
                "Post-promotion verification FAILED and rollback could not be proven safe "
                f"({why}). The patch is still applied. Nothing was reverted, deliberately — "
                "a rollback that might destroy unrelated work is worse than leaving this for you. "
                f"Revert by hand with: git apply -R {diff_path}"
            ),
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash, post_verification=notes,
        )

    reverted = _git(
        ["apply", "-R", str(diff_path)], cwd=root, audit_trail=audit_trail,
        action="apply -R (ROLLBACK)", mutating=True,
    )
    if reverted.returncode != 0:
        return PromotionResult(
            outcome=PROMOTION_ESCALATED, gate=gate, applied=True, rolled_back=False,
            detail=(
                "Post-promotion verification FAILED and the rollback itself failed "
                f"({reverted.stderr.strip()}). The live checkout may still contain the patch — "
                f"inspect it now. Revert by hand with: git apply -R {diff_path}"
            ),
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash, post_verification=notes,
        )

    after = live_dirty_paths(root, audit_trail=audit_trail)
    if after is None or after:
        return PromotionResult(
            outcome=PROMOTION_ESCALATED, gate=gate, applied=True, rolled_back=True,
            detail=(
                "Post-promotion verification failed and the patch was reverted, but the working tree "
                f"is not clean afterwards ({after}). Inspect it by hand."
            ),
            changed_files=changed_files, base_commit=base, diff_hash=diff_hash, post_verification=notes,
        )

    return PromotionResult(
        outcome=PROMOTION_ROLLED_BACK, gate=gate, applied=True, rolled_back=True,
        detail=(
            "Post-promotion verification failed, so the patch was rolled back. The live checkout is "
            "back at its previous state and the working tree is clean. Nothing was committed."
        ),
        changed_files=changed_files, base_commit=base, diff_hash=diff_hash, post_verification=notes,
    )


def _resolve_change_request(conn, change_request, record, *, audit_trail) -> None:
    """Marks the run's pending change request resolved by automatic
    promotion.

    Deliberately NOT 'approved': Phase 28's hard rule 4 reserves that
    word for an explicit human CLI action, and nothing in this module
    may produce it. Leaving it 'pending' would be worse than either —
    an operator would see a change request awaiting their decision for
    something already applied, and might approve or reject it again.
    """
    if change_request is None or conn is None:
        return
    try:
        from secure.agent.audit import record_and_persist_one
        from secure.storage.models import set_ai_change_request_status

        set_ai_change_request_status(
            conn, cr_id=change_request.cr_id, status=STATUS_PROMOTED_AUTOMATICALLY,
            approved_at=datetime.now(timezone.utc).isoformat(),
            approved_by=(
                "secure/agent/promote.py (automatic promotion of a VERIFIED SAFE_PROJECT_CODE repair "
                "— NOT a human approval)"
            ),
        )
        record_and_persist_one(
            conn, run_id=getattr(record, "run_id", None), component="agent.promote",
            action="resolve_change_request_as_promoted", target=change_request.cr_id,
            mutating=True, approval_required=False,
            result_summary=f"{change_request.cr_id} -> {STATUS_PROMOTED_AUTOMATICALLY}",
        )
    except Exception:  # noqa: BLE001 — bookkeeping never undoes a completed promotion
        pass


def describe(result: PromotionResult) -> str:
    lines = [
        f"OUTCOME:              {result.outcome}",
        f"Live checkout written: {result.live_checkout_modified}",
        f"Base commit:          {result.base_commit or '(none)'}",
        f"Diff SHA-256:         {result.diff_hash or '(none)'}",
        f"Files:                {', '.join(result.changed_files) or '(none)'}",
    ]
    if result.post_verification:
        lines.append("Post-promotion verification:")
        lines += [f"  {n}" for n in result.post_verification]
    lines.append("")
    lines.append(result.detail)
    return "\n".join(lines)
