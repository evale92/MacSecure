"""
secure/agent/verified.py — Phase 44 (Part 2: Supervised Agentic
Development & Self-Healing — "Verified Self-Healing").

The authoritative definition of a VERIFIED repair. Governing text,
verbatim (docs/ROADMAP_PART2_PHASES_38_47.md):

    A repair may be VERIFIED only when:
      1. original failure was reproduced before repair
      2. candidate patch was applied only in isolation
      3. original failure disappears
      4. FAST verification passes
      5. TARGETED tests pass
      6. FULL regression passes when required
      7. Phase 27 validation passes when security behavior is affected
      8. performance diagnostics show no unacceptable regression where relevant
      9. independent review reports no blocking issue
     10. architecture/security policy remains satisfied
     11. actual final diff still matches its recorded hash

    "Only VERIFIED SAFE_PROJECT_CODE changes may become candidates for
    automatic promotion... Never define success from model confidence
    or textual self-assessment."

THREE PROPERTIES THIS MODULE IS BUILT AROUND

1. **Nothing here consults a model.** Not the reviewer's prose, not the
   coder's self-report, not a confidence score. Criterion 9 reads only
   the reviewer's COMPUTED blocking list (Phase 38 derives that from
   parsed answers, never from what the model says about itself), and
   even that can only subtract. There is no input to this module that a
   model could write freely into.

2. **Unknown is never satisfied.** Every criterion answers True, False,
   or None, and a required criterion that answers None blocks VERIFIED
   exactly as a False does. This is the same rule Phase 31's
   verification, Phase 36's escalation, Phase 38's review gate, and
   Phase 43's reproduction gate all already follow. It is the single
   most load-bearing line in the file.

3. **Measured now, not remembered.** Criteria 3 and 11 re-run and
   re-hash at evaluation time rather than trusting what was recorded
   earlier. A diff that changed after verification is the specific
   attack the acceptance criterion names, and the only way to catch it
   is to look again.

THIS MODULE PROMOTES NOTHING

`promotion_candidate` is a predicate, not an action. Phase 44 defines
what would be eligible; it does not apply anything, and there is no
function here that writes to the live checkout, approves a change
request, or changes a status. Eligibility is not permission.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.classify import CLASS_SAFE_PROJECT_CODE
from secure.agent.diagnose import REPRO_REPRODUCED
from secure.agent.policy import TRIGGER_PYTEST_FAILURE
from secure.agent.tiers import (
    TIER_FAST,
    TIER_FULL,
    TIER_SECURITY,
    TIER_TARGETED,
    SECURITY_SENSITIVE_PREFIXES,
)
from secure.agent.worktree import AGENT_RUNS_DIRNAME
from secure.config import AppConfig

# Criterion keys, numbered to match the governing text exactly so a
# reader can check them off against it one for one.
C1_REPRODUCED_BEFORE = "1_original_failure_reproduced_before_repair"
C2_ISOLATED_ONLY = "2_patch_applied_only_in_isolation"
C3_FAILURE_GONE = "3_original_failure_disappears"
C4_FAST = "4_fast_verification_passes"
C5_TARGETED = "5_targeted_tests_pass"
C6_FULL = "6_full_regression_passes_when_required"
C7_VALIDATION = "7_phase27_validation_passes_when_security_affected"
C8_PERFORMANCE = "8_no_unacceptable_performance_regression"
C9_REVIEW = "9_independent_review_reports_no_blocking_issue"
C10_POLICY = "10_architecture_and_security_policy_satisfied"
C11_DIFF_HASH = "11_final_diff_still_matches_recorded_hash"

ALL_CRITERIA = (
    C1_REPRODUCED_BEFORE, C2_ISOLATED_ONLY, C3_FAILURE_GONE, C4_FAST, C5_TARGETED,
    C6_FULL, C7_VALIDATION, C8_PERFORMANCE, C9_REVIEW, C10_POLICY, C11_DIFF_HASH,
)

_RECHECK_TIMEOUT_SECONDS = 300.0


@dataclass(frozen=True)
class CriterionResult:
    """`satisfied` is three-state. None means "could not determine",
    and for a required criterion that blocks VERIFIED exactly as False
    does — see `VerifiedAssessment.verified`."""

    key: str
    satisfied: "Optional[bool]"
    detail: str
    applicable: bool = True

    @property
    def blocks(self) -> bool:
        if not self.applicable:
            return False
        return self.satisfied is not True


@dataclass(frozen=True)
class VerifiedAssessment:
    criteria: "tuple[CriterionResult, ...]" = field(default_factory=tuple)
    classification: "Optional[str]" = None

    @property
    def verified(self) -> bool:
        """True only when every applicable criterion is definitely
        True. One None anywhere is enough to withhold VERIFIED."""
        if len(self.criteria) != len(ALL_CRITERIA):
            return False
        return not any(c.blocks for c in self.criteria)

    @property
    def blocking(self) -> "tuple[str, ...]":
        return tuple(c.key for c in self.criteria if c.blocks)

    @property
    def promotion_candidate(self) -> bool:
        """"Only VERIFIED SAFE_PROJECT_CODE changes may become
        CANDIDATES for automatic promotion." A candidate, not a
        promotion — nothing in this module applies anything."""
        return self.verified and self.classification == CLASS_SAFE_PROJECT_CODE

    def result_for(self, key: str) -> "Optional[CriterionResult]":
        for c in self.criteria:
            if c.key == key:
                return c
        return None

    def describe(self) -> str:
        lines = [f"VERIFIED: {self.verified}    classification: {self.classification or '(unclassified)'}"]
        lines.append(f"Eligible as an automatic-promotion candidate: {self.promotion_candidate}")
        for c in self.criteria:
            mark = "ok  " if c.satisfied is True else ("FAIL" if c.satisfied is False else "????")
            scope = "" if c.applicable else "  (not applicable)"
            lines.append(f"  [{mark}] {c.key}{scope}")
            lines.append(f"         {c.detail}")
        return "\n".join(lines)


# ---------------------------------------------------------------------
# Individual criteria
# ---------------------------------------------------------------------


def _c1_reproduced(record) -> CriterionResult:
    status = getattr(record, "reproduction_status", None)
    reproduced = getattr(record, "reproduced", None)
    if reproduced is True and status == REPRO_REPRODUCED:
        return CriterionResult(C1_REPRODUCED_BEFORE, True,
                               f"the original failure was confirmed to still occur before any repair "
                               f"({getattr(record, 'reproduction_command', '') or 'command not recorded'})")
    if reproduced is False:
        return CriterionResult(C1_REPRODUCED_BEFORE, False,
                               "the original failure did not recur when checked — there was nothing to repair")
    return CriterionResult(C1_REPRODUCED_BEFORE, None,
                           "no reproduction evidence was recorded for this run (a repair started outside "
                           "`secure agent diagnose` records none) — cannot confirm the failure was real")


def _c2_isolated(record, cfg: AppConfig) -> CriterionResult:
    worktree_path = getattr(record, "worktree_path", "") or ""
    if not worktree_path:
        return CriterionResult(C2_ISOLATED_ONLY, None, "no worktree path was recorded for this run")
    expected_root = cfg.app_dir_path() / AGENT_RUNS_DIRNAME
    try:
        Path(worktree_path).resolve().relative_to(expected_root.resolve())
    except (ValueError, OSError):
        return CriterionResult(
            C2_ISOLATED_ONLY, False,
            f"the recorded worktree {worktree_path!r} is not inside {expected_root} — the patch was "
            "not confined to an agent-owned isolated workspace",
        )
    return CriterionResult(C2_ISOLATED_ONLY, True,
                           f"the patch exists only inside the isolated worktree at {worktree_path}")


def _c3_failure_gone(record, cfg: AppConfig, *, timeout: float) -> CriterionResult:
    """Re-runs the ORIGINAL failing thing inside the worktree and
    requires it to pass now. Measured, not remembered: a repair whose
    tests pass but whose original failure still occurs has not fixed
    anything."""
    if getattr(record, "trigger_kind", None) != TRIGGER_PYTEST_FAILURE:
        return CriterionResult(
            C3_FAILURE_GONE, None,
            f"no re-check is defined for trigger kind {getattr(record, 'trigger_kind', None)!r} — "
            "cannot confirm the original failure disappeared",
        )
    worktree = Path(getattr(record, "worktree_path", "") or "")
    if not worktree.is_dir():
        return CriterionResult(C3_FAILURE_GONE, None,
                               f"the worktree at {worktree} no longer exists — cannot re-check the failure")

    argv = [sys.executable, "-m", "pytest", record.trigger_ref, "-q", "--tb=short"]
    with tempfile.TemporaryDirectory(prefix="secure-verified-home-") as home:
        import os

        env = dict(os.environ)
        env["HOME"] = home
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            proc = subprocess.run(
                argv, cwd=str(worktree), capture_output=True, text=True,
                timeout=timeout, shell=False, env=env,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return CriterionResult(C3_FAILURE_GONE, None,
                                   f"could not re-check the original failure: {type(exc).__name__}")

    output = (proc.stdout or "") + (proc.stderr or "")
    if "No module named pytest" in output:
        return CriterionResult(C3_FAILURE_GONE, None,
                               "pytest is unavailable — cannot confirm the original failure disappeared")
    if proc.returncode == 0:
        return CriterionResult(C3_FAILURE_GONE, True,
                               f"{record.trigger_ref} passes inside the worktree after the repair")
    return CriterionResult(C3_FAILURE_GONE, False,
                           f"{record.trigger_ref} still fails inside the worktree after the repair")


def _tier_criterion(key: str, tier_result, *, applicable: bool, why_not: str = "") -> CriterionResult:
    if not applicable:
        # Phase 47.5 correction. "Not required" means its ABSENCE is
        # acceptable — it must never mean its FAILURE is acceptable. A
        # tier that was not required but ran anyway and definitively
        # failed is real evidence of breakage, and treating it as
        # satisfied would let a repair with a red full regression reach
        # VERIFIED simply because policy did not demand that tier. Found
        # by a Phase 47.5 promotion test that expected a failing
        # unrequired FULL run to block and discovered it did not.
        if tier_result is not None and getattr(tier_result, "passed", None) is False:
            return CriterionResult(
                key, False,
                "this tier was not required for this change, but it ran and FAILED — a failing "
                "result is evidence of breakage regardless of whether policy demanded the tier",
            )
        return CriterionResult(key, True, why_not or "not required for this change", applicable=False)
    if tier_result is None:
        return CriterionResult(key, None, "this tier did not run — cannot confirm it passed")
    if getattr(tier_result, "status", None) != "ok":
        return CriterionResult(key, None,
                               f"tier status {getattr(tier_result, 'status', None)!r} — the mechanism did "
                               "not run cleanly, which is not a pass")
    passed = getattr(tier_result, "passed", None)
    if passed is True:
        return CriterionResult(key, True, "passed")
    if passed is False:
        return CriterionResult(key, False, "did not pass")
    return CriterionResult(key, None, "tier reported no definite result")


def _c8_performance(cfg: AppConfig, warnings) -> CriterionResult:
    """Phase 30's own budget evaluation, reused unchanged. `warnings`
    is None when no measurements were available — which is honest
    absence, not a clean bill of health, so it is treated as not
    applicable rather than as satisfied."""
    if warnings is None:
        return CriterionResult(
            C8_PERFORMANCE, True,
            "no performance measurements were available for this repair, so no regression could be "
            "assessed — recorded as not applicable rather than as a pass",
            applicable=False,
        )
    if not warnings:
        return CriterionResult(C8_PERFORMANCE, True, "no performance budget was exceeded")
    detail = "; ".join(getattr(w, "message", str(w)) for w in warnings)
    return CriterionResult(C8_PERFORMANCE, False, f"performance budget exceeded: {detail}")


def _c9_review(record) -> CriterionResult:
    """Reads only the COMPUTED blocking list. Phase 38 derives that
    from parsed answers, never from the model's own claim about itself,
    so there is nothing here a model could write freely into."""
    status = getattr(record, "review_status", None)
    blocking = list(getattr(record, "review_blocking", []) or [])
    if blocking:
        return CriterionResult(C9_REVIEW, False,
                               f"the independent reviewer raised blocking findings: {', '.join(blocking)}")
    if status in ("error", "unparseable"):
        return CriterionResult(C9_REVIEW, None,
                               f"an independent reviewer was configured but produced no usable assessment "
                               f"({status}) — a review that ran and could not be understood is not a pass")
    if status in ("unavailable", "not_required", None):
        return CriterionResult(
            C9_REVIEW, True,
            f"no independent review was performed ({status or 'none recorded'}) — no blocking issue was "
            "reported because no review ran",
            applicable=False,
        )
    return CriterionResult(C9_REVIEW, True, "the independent reviewer raised no blocking findings")


def _c10_policy(record, cfg: AppConfig, *, root: "Optional[Path]" = None) -> CriterionResult:
    """Deterministic policy satisfaction: no denylisted path was
    touched, the change was classified at all, and Phase 37's policy
    files still exist to have been satisfied against."""
    from secure.agent.context import _POLICY_FILENAMES
    from secure.agent.worktree import project_root

    violation = getattr(record, "denylist_violation", None)
    if violation:
        return CriterionResult(C10_POLICY, False, f"path denylist violation: {violation}")

    classification = getattr(record, "classification", None)
    if not classification:
        return CriterionResult(C10_POLICY, None,
                               "the change was never classified — cannot confirm policy is satisfied")

    root = root or project_root()
    missing = [name for name in _POLICY_FILENAMES if not (root / name).is_file()]
    if missing:
        return CriterionResult(C10_POLICY, None,
                               f"engineering-policy files are missing ({', '.join(missing)}) — cannot "
                               "confirm the change was held to them")
    return CriterionResult(C10_POLICY, True,
                           f"no denylisted path was touched, the change is classified {classification}, "
                           "and every engineering-policy file is present")


def _c11_diff_hash(record) -> CriterionResult:
    """Re-hashes the diff file on disk RIGHT NOW. This is the criterion
    that catches "changing its diff after verification" — the specific
    attack the acceptance text names."""
    diff_path = getattr(record, "diff_path", None)
    recorded = getattr(record, "diff_hash", None)
    if not diff_path or not recorded:
        return CriterionResult(C11_DIFF_HASH, None,
                               "no diff path or hash was recorded — cannot confirm the diff is unchanged")
    path = Path(diff_path)
    if not path.is_file():
        return CriterionResult(C11_DIFF_HASH, False,
                               f"the recorded diff file no longer exists at {diff_path}")
    try:
        current = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return CriterionResult(C11_DIFF_HASH, None, f"could not read the recorded diff: {exc}")
    if current != recorded:
        return CriterionResult(C11_DIFF_HASH, False,
                               f"the diff has CHANGED since verification (recorded {recorded}, found {current})")
    return CriterionResult(C11_DIFF_HASH, True, f"the diff still hashes to {recorded}")


# ---------------------------------------------------------------------
# The evaluation
# ---------------------------------------------------------------------


def full_regression_required(record) -> bool:
    """"when required" — required whenever scope is unknown, or the
    change touches more than one file, or it touches anything under
    tests/. Conservative: when uncertain, require it."""
    changed = list(getattr(record, "changed_files", []) or [])
    if not changed:
        return True
    if len(changed) > 1:
        return True
    return any(f.startswith("tests/") for f in changed)


def security_validation_required(record) -> bool:
    """"when security behavior is affected" — reuses Phase 36's own
    sensitivity prefixes rather than defining a second list. Unknown
    scope requires it."""
    changed = list(getattr(record, "changed_files", []) or [])
    if not changed:
        return True
    return any(f.startswith(p) for f in changed for p in SECURITY_SENSITIVE_PREFIXES)


def evaluate_verified(
    record,
    cfg: AppConfig,
    *,
    escalation=None,
    perf_warnings=None,
    root: "Optional[Path]" = None,
    recheck_timeout: float = _RECHECK_TIMEOUT_SECONDS,
) -> VerifiedAssessment:
    """Evaluates all eleven criteria for one repair run.

    `escalation` is Phase 36's `EscalationOutcome` for this repair. It
    is passed in rather than re-derived so a caller that already ran
    the tiers does not run them twice; when it is None, the tier
    criteria answer None (unknown), which blocks — never a pass.

    `perf_warnings` is Phase 30's `evaluate_budgets()` output, or None
    when no measurements were available.
    """
    def _tier(name):
        return getattr(escalation, name, None) if escalation is not None else None

    needs_full = full_regression_required(record)
    needs_security = security_validation_required(record)

    criteria = (
        _c1_reproduced(record),
        _c2_isolated(record, cfg),
        _c3_failure_gone(record, cfg, timeout=recheck_timeout),
        _tier_criterion(C4_FAST, _tier("fast"), applicable=True),
        _tier_criterion(C5_TARGETED, _tier("targeted"), applicable=True),
        _tier_criterion(
            C6_FULL, _tier("full"), applicable=needs_full,
            why_not="full regression was not required for this single-file, non-test change",
        ),
        _tier_criterion(
            C7_VALIDATION, _tier("security"), applicable=needs_security,
            why_not="no security-relevant path was touched, so Phase 27 validation was not required",
        ),
        _c8_performance(cfg, perf_warnings),
        _c9_review(record),
        _c10_policy(record, cfg, root=root),
        _c11_diff_hash(record),
    )
    return VerifiedAssessment(criteria=criteria, classification=getattr(record, "classification", None))
