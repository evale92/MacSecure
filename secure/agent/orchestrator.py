"""
secure/agent/orchestrator.py — Phase 31: the one place that sequences
policy -> worktree -> tool run -> diff -> denylist -> verification ->
change request, in that fixed order, always. Every step's result is
persisted to `agent_repair_runs` before the next one starts, so a
crash at any point leaves an honest, resumable record instead of
nothing — see resume_repair_run() below.

This module contains no policy logic of its own (secure/agent/policy.py
owns that), no tool-invocation logic of its own
(secure/agent/runner.py owns that), no verification logic of its own
(secure/agent/verify.py owns that), and no approval logic of its own
(secure/ai/changes/workflow.py owns that, called unchanged through
secure/agent/changes.py). It only sequences them and persists what
happened at each step.
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure.agent.audit import persist_audit_trail
from secure.agent.changes import (
    check_path_denylist,
    propose_repair_change_request,
    revalidate_worktree_diff,
    supersede_change_request,
)
from secure.agent.classify import classify_change
from secure.agent.context import build_repair_context
from secure.agent.policy import PolicyDecision, RepairCandidate, evaluate_policy
from secure.agent.review import (
    GATE_ESCALATE,
    REVIEW_UNAVAILABLE,
    ReviewAssessment,
    review_gate,
    review_repair,
)
from secure.agent.runner import (
    MINI_CONFIG_FILENAME,
    TRANSCRIPT_FILENAME,
    MiniRunResult,
    build_mini_argv,
    hash_transcript,
    run_mini_swe_agent,
)
from secure.agent.verify import verify_worktree
from secure.agent.worktree import (
    RepairWorktree,
    create_repair_worktree,
    diff_and_changed_files,
    worktree_exists,
)
from secure.config import AppConfig
from secure.storage.models import (
    AgentRepairRunRecord,
    add_agent_repair_run,
    complete_agent_repair_run,
    find_agent_repair_run,
    find_ai_change_request,
    set_agent_repair_run_change_request,
)


class RepairNotEligible(RuntimeError):
    """Raised by attempt_repair() when called for a candidate
    evaluate_policy() would refuse — callers are expected to check
    eligibility themselves first (see secure/cli/agent.py) and this
    exception exists as a defense-in-depth backstop, not the primary
    UX."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _remember(conn: sqlite3.Connection, record) -> None:
    """Phase 45: write one maintenance-memory row for a run that has
    reached a terminal status. Records EVERY outcome, not just
    successes — a memory that remembered only successes would
    systematically mislead whatever reads it.

    Never raises: a bookkeeping failure must not turn a completed
    repair into a crashed one, and the run row itself is already
    persisted by the time this is called.
    """
    if record is None:
        return
    try:
        from secure.agent.memory import record_run

        record_run(conn, record)
    except Exception:  # noqa: BLE001
        pass


def attempt_repair(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    candidate: RepairCandidate,
    *,
    repo_root: "Optional[Path]" = None,
    providers: "Optional[dict]" = None,
    reproduction: "Optional[object]" = None,
) -> AgentRepairRunRecord:
    """Runs exactly ONE repair attempt for `candidate`: creates a fresh
    isolated worktree, invokes the configured external tool once,
    computes the diff independently, enforces the path denylist,
    verifies, and — only on a full pass — proposes a change request.
    Always returns the completed AgentRepairRunRecord; never raises for
    an ordinary tool/verification failure (those are recorded as a
    terminal status, not an exception)."""
    decision = evaluate_policy(conn, cfg, candidate, repo_root=repo_root)
    if not decision.allowed:
        raise RepairNotEligible(decision.reason)

    # Phase 31.5: a single audit_trail list, created here and threaded
    # through every subprocess/worktree/verification call this attempt
    # makes, persisted once at the very end (or at each early-return
    # point below) via persist_audit_trail(). See secure/agent/audit.py.
    audit_trail: list = []

    worktree_slug = uuid.uuid4().hex[:12]
    worktree = create_repair_worktree(
        worktree_slug, app_dir=cfg.app_dir_path(), repo_root=repo_root, audit_trail=audit_trail
    )

    run_id = add_agent_repair_run(
        conn,
        created_at=_now(),
        attempt_number=decision.attempts_so_far + 1,
        max_attempts=cfg.agent_max_attempts,
        trigger_kind=candidate.trigger_kind,
        trigger_ref=candidate.trigger_ref,
        trigger_detail=candidate.trigger_detail,
        base_commit=worktree.base_commit,
        worktree_path=str(worktree.worktree_path),
        agent_home_path=str(worktree.agent_home_path),
        tool_name=cfg.agent_tool,
        model_name=f"ollama/{cfg.ollama_model}",
    )

    # Phase 33: a bounded repair context (relevant files, recent
    # history for them, engineering-policy excerpts once Phase 37 adds
    # any) built deterministically from `candidate` and the live
    # checkout — see secure/agent/context.py. Built here, not inside
    # run_mini_swe_agent(), so the exact same context object could in
    # principle be reused for review/audit without recomputing it.
    context = build_repair_context(candidate, root=repo_root)

    mini_result = run_mini_swe_agent(cfg, worktree, candidate, audit_trail=audit_trail, context=context)

    if mini_result.status == "unavailable":
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="error",
            agent_exit_status=None, stop_reason=f"tool unavailable: {mini_result.error}",
            tool_argv=mini_result.argv, mini_config_yaml=mini_result.config_yaml or "",
            transcript_hash=mini_result.transcript_hash,
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        _remember(conn, result)
        return result

    result = _finish_repair_run(
        conn, cfg, run_id, worktree, candidate, mini_result, audit_trail=audit_trail,
        providers=providers, reproduction=reproduction,
    )
    _remember(conn, result)
    return result


def resume_repair_run(
    conn: sqlite3.Connection, cfg: AppConfig, run_id: str, *, providers: "Optional[dict]" = None
) -> AgentRepairRunRecord:
    """Resumes a run left in status='running' by a Secure process that
    crashed or was killed mid-attempt. Never re-invokes the external
    tool (there is no safe way to reattach to a possibly-still-running
    or half-finished LLM session) — it only re-derives the diff from
    whatever is currently on disk in the worktree and, if a transcript
    file exists, re-runs denylist/verification/proposal from there. If
    no transcript was ever written, the tool invocation itself never
    completed and this reports status='error' rather than guessing."""
    record = find_agent_repair_run(conn, run_id)
    if record is None:
        raise ValueError(f"no repair run {run_id!r}")
    if record.status != "running":
        raise ValueError(f"{run_id} is not 'running' (current status: {record.status!r}) — nothing to resume")

    audit_trail: list = []

    worktree = RepairWorktree(
        run_dir=Path(record.worktree_path).parent,
        worktree_path=Path(record.worktree_path),
        agent_home_path=Path(record.agent_home_path),
        base_commit=record.base_commit,
    )
    if not worktree_exists(worktree):
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="error",
            stop_reason="worktree no longer exists on disk — cannot resume; start a fresh attempt instead",
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    transcript_path = worktree.run_dir / TRANSCRIPT_FILENAME
    if not transcript_path.is_file():
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="error",
            stop_reason="no transcript found — the tool invocation itself never completed; "
            "resuming is only possible after the tool has finished running",
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    import json

    try:
        transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        transcript = {}
    info = transcript.get("info", {}) if transcript else {}

    candidate = RepairCandidate(record.trigger_kind, record.trigger_ref, record.trigger_detail)

    # Reproducibility fields, reconstructed from what's still on disk
    # rather than re-invoked: build_mini_argv() is a pure function of
    # (cfg, worktree, candidate) so it reproduces the same argv a fresh
    # run would use (assuming cfg hasn't changed since); the config
    # YAML is read back verbatim from the same file
    # run_mini_swe_agent() wrote originally; the transcript hash is
    # computed fresh from the same transcript file _finish_repair_run()
    # is about to read the diff/verification tail from — authentic,
    # not reconstructed.
    config_path = worktree.run_dir / MINI_CONFIG_FILENAME
    config_yaml_text = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""

    # Phase 33: rebuilt fresh from the live checkout, same as
    # attempt_repair() — an honest approximation of the original run's
    # context when repo history has advanced since (see
    # build_mini_argv()'s own docstring for why this is acceptable).
    context = build_repair_context(candidate)

    mini_result = MiniRunResult(
        status="completed", returncode=None, exit_status=info.get("exit_status"),
        submission=info.get("submission"), mini_version=info.get("mini_version"),
        instance_cost=(info.get("model_stats") or {}).get("instance_cost"),
        transcript_path=transcript_path, model_name=record.model_name,
        argv=build_mini_argv(cfg, worktree, candidate, context=context),
        config_yaml=config_yaml_text,
        transcript_hash=hash_transcript(transcript_path),
    )
    return _finish_repair_run(
        conn, cfg, run_id, worktree, candidate, mini_result, audit_trail=audit_trail, providers=providers
    )


def _run_independent_review(
    cfg: AppConfig,
    candidate: RepairCandidate,
    *,
    coder_assessment: str,
    diff_text: str,
    changed_files: "list[str]",
    verification,
    providers: "Optional[dict]" = None,
) -> ReviewAssessment:
    """Phase 38. `providers` is injectable so a test can supply a
    duck-typed reviewer without a live model; when it is None the real
    Phase 28 registry is used, which returns unconfigured providers on a
    machine with no local model set up — the honest-absence path.

    Never raises: a failure to even build the provider registry is
    reported as an unavailable review, not as a crashed repair run.
    """
    if providers is None:
        try:
            from secure.ai.registry import build_providers

            providers = build_providers(cfg)
        except Exception as exc:  # noqa: BLE001
            return ReviewAssessment(
                status=REVIEW_UNAVAILABLE, provider="", model="",
                summary="could not build the local-model provider registry",
                error=f"{type(exc).__name__}: {exc}",
            )
    return review_repair(
        providers, candidate, coder_assessment=coder_assessment, diff_text=diff_text,
        changed_files=changed_files, verification=verification,
    )


def _review_meta(assessment: ReviewAssessment, gate, *, coder_assessment: str) -> dict:
    """The persistence payload for BOTH assessments — the phase's own
    "record both assessments" requirement. `coder_assessment` is the
    coder tool's own account, stored verbatim and never trusted;
    `review_blocking` comes from the assessment's own computed tuple
    (secure/agent/review.py derives it from the answers), never from
    anything the model asserted about itself."""
    return dict(
        coder_assessment=coder_assessment,
        review_status=assessment.status,
        review_provider=assessment.provider,
        review_model=assessment.model,
        review_answers=[
            {"question": a.question, "answer": a.answer, "rationale": a.rationale}
            for a in assessment.answers
        ],
        review_blocking=list(assessment.blocking),
        review_summary=assessment.summary or gate.reason,
        review_error=assessment.error,
        review_disagreement=gate.disagreement,
    )


def _finish_repair_run(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    run_id: str,
    worktree: RepairWorktree,
    candidate: RepairCandidate,
    mini_result: MiniRunResult,
    *,
    audit_trail: "Optional[list]" = None,
    providers: "Optional[dict]" = None,
    reproduction: "Optional[object]" = None,
) -> AgentRepairRunRecord:
    """Shared tail used by both attempt_repair() (right after a fresh
    tool invocation) and resume_repair_run() (after re-reading an
    already-written transcript): diff -> denylist -> verification ->
    (only on a full pass) change request proposal.

    `audit_trail` (Phase 31.5, optional): the SAME list the caller
    started collecting into (attempt_repair()'s worktree-creation and
    tool-invocation actions, or resume_repair_run()'s empty list) —
    threaded through this function's own diff/verification calls, then
    persisted via persist_audit_trail() at every return point below, so
    exactly one batch of rows lands in agent_actions per attempt/resume
    call regardless of which status it ends in."""
    diff_text, changed_files = diff_and_changed_files(worktree, audit_trail=audit_trail)
    diff_hash = hashlib.sha256(diff_text.encode("utf-8")).hexdigest() if diff_text.strip() else None
    transcript_path_str = str(mini_result.transcript_path) if mini_result.transcript_path else None

    # Reproducibility fields (argv/config YAML/transcript hash) —
    # spread into every terminal complete_agent_repair_run() call below
    # so they're recorded regardless of which status this run ends in,
    # not just on a full pass.
    mini_meta = dict(
        tool_argv=mini_result.argv, mini_config_yaml=mini_result.config_yaml or "",
        transcript_hash=mini_result.transcript_hash,
    )

    # Phase 43: the reproduction evidence gathered BEFORE this repair
    # was attempted, recorded on every terminal branch below so Phase
    # 44 can read it as its first VERIFIED criterion. None when this
    # repair was started directly rather than through
    # secure/agent/diagnose.py — recorded as honest absence, never as
    # a confirmed reproduction.
    if reproduction is not None:
        mini_meta.update(
            reproduction_status=getattr(reproduction, "status", None),
            reproduced=getattr(reproduction, "reproduced", None),
            reproduction_detail=getattr(reproduction, "detail", ""),
            reproduction_command=getattr(reproduction, "command", ""),
        )

    if not diff_text.strip():
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="no_diff",
            tool_version=mini_result.mini_version or "", transcript_path=transcript_path_str,
            agent_exit_status=mini_result.exit_status, changed_files=[],
            stop_reason="the tool produced no detectable changes in the worktree "
            f"(exit_status={mini_result.exit_status!r})",
            **mini_meta,
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    denylist = check_path_denylist(changed_files, cfg)
    if denylist.violated:
        diff_path = worktree.run_dir / "diff.patch"
        diff_path.write_text(diff_text, encoding="utf-8")
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="rejected_by_denylist",
            tool_version=mini_result.mini_version or "", transcript_path=transcript_path_str,
            agent_exit_status=mini_result.exit_status, diff_path=str(diff_path), diff_hash=diff_hash,
            changed_files=changed_files, denylist_violation=denylist.detail,
            stop_reason=f"path denylist violation: {denylist.detail}",
            **mini_meta,
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    diff_path = worktree.run_dir / "diff.patch"
    diff_path.write_text(diff_text, encoding="utf-8")

    if mini_result.status == "timed_out":
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="timed_out",
            tool_version=mini_result.mini_version or "", transcript_path=transcript_path_str,
            agent_exit_status=mini_result.exit_status, diff_path=str(diff_path), diff_hash=diff_hash,
            changed_files=changed_files, stop_reason=mini_result.error or "the tool run timed out",
            **mini_meta,
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    verification = verify_worktree(worktree, cfg, audit_trail=audit_trail)
    common = dict(
        tool_version=mini_result.mini_version or "", transcript_path=transcript_path_str,
        agent_exit_status=mini_result.exit_status, diff_path=str(diff_path), diff_hash=diff_hash,
        changed_files=changed_files, pytest_status=verification.pytest_result.status,
        pytest_summary=verification.pytest_result.summary, validate_status=verification.validate_result.status,
        validate_summary=verification.validate_result.summary,
        **mini_meta,
    )

    if verification.overall_passed is True:
        # Phase 38: the independent review happens ONLY here, on the
        # branch where deterministic verification has already passed on
        # its own. The reviewer is therefore structurally incapable of
        # rescuing a failed or inconclusive verification — the two
        # branches below never consult it. Its only power is to turn
        # this pass into a stop.
        coder_assessment = mini_result.submission or ""
        assessment = _run_independent_review(
            cfg, candidate, coder_assessment=coder_assessment, diff_text=diff_text,
            changed_files=changed_files, verification=verification, providers=providers,
        )
        gate = review_gate(
            assessment,
            coder_claimed_success=mini_result.status == "completed" and bool(diff_text.strip()),
        )
        review_meta = _review_meta(assessment, gate, coder_assessment=coder_assessment)

        # Phase 39: deterministic classification of what this change
        # actually is. Computed from the changed paths and the diff's
        # own added lines — never from the reviewer's opinion, and
        # never from the coder's. Recorded on every branch below,
        # including the escalation branch, so a human triaging an
        # escalated run can see what class of change they are looking
        # at without re-deriving it.
        classification = classify_change(changed_files, diff_text)
        classification_meta = dict(
            classification=classification.classification,
            classification_reasons=classification.describe(),
        )

        if gate.decision == GATE_ESCALATE:
            result = complete_agent_repair_run(
                conn, run_id=run_id, completed_at=_now(),
                status="escalated_for_review", verification_passed=True,
                stop_reason=(
                    "deterministic verification passed, but the independent reviewer stopped "
                    f"automatic progression: {gate.reason}. No change request was created; a "
                    "human must review this run before anything proceeds."
                ),
                **common, **review_meta, **classification_meta,
            )
            persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
            return result

        complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="verified", verification_passed=True,
            stop_reason="verification passed", **common, **review_meta, **classification_meta,
        )
        cr = propose_repair_change_request(
            conn, cfg, run_id=run_id, candidate=candidate, diff_text=diff_text, diff_hash=diff_hash,
            changed_files=changed_files, verification=verification, mini_result=mini_result,
            review=assessment, classification=classification,
        )
        set_agent_repair_run_change_request(conn, run_id=run_id, change_request_id=cr.cr_id)
        result = find_agent_repair_run(conn, run_id)
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    if verification.overall_passed is False:
        result = complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="verification_failed", verification_passed=False,
            stop_reason="pytest and/or secure validate did not pass in the worktree", **common,
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return result

    result = complete_agent_repair_run(
        conn, run_id=run_id, completed_at=_now(), status="verification_inconclusive", verification_passed=None,
        stop_reason="verification mechanism did not run cleanly (unavailable/timeout/error) — "
        "see pytest_status/validate_status for which one",
        **common,
    )
    persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
    return result


@dataclass(frozen=True)
class ApprovalRevalidation:
    """Result of revalidate_before_approval() below — never itself an
    approval. `diff_matches=True` means it's safe to proceed to the
    real, human-triggered `secure ai changes approve <cr_id>
    <revision_hash>` (which `secure agent approve <run_id>` does next,
    unchanged). `diff_matches=False` means the worktree drifted since
    proposal: the old CR is now 'superseded' and, if re-verification of
    the CURRENT worktree state still passes, `new_cr_id` names a fresh
    pending change request describing what's actually there now — a
    human must review and approve THAT one; nothing here approves
    anything automatically, ever."""

    run_id: str
    old_cr_id: str
    diff_matches: bool
    new_cr_id: "Optional[str]"
    detail: str


def revalidate_before_approval(conn: sqlite3.Connection, cfg: AppConfig, run_id: str) -> ApprovalRevalidation:
    """Guardrail 2 (explicit user instruction): must be called — and
    must report diff_matches=True — before approving any agent-
    originated change request. See secure/agent/changes.py's
    revalidate_worktree_diff()/supersede_change_request() for the
    mechanism this wraps; this function is the one place that sequences
    it against a specific run_id and, on a mismatch, tries to produce a
    replacement change request from the worktree's current state.

    Called from `secure agent approve <run_id>` (secure/cli/agent.py)
    and secure_gui/agent_view.py's Approve button — never anywhere
    else. Neither of those callers approves anything themselves when
    this reports diff_matches=False; they only report the outcome.
    """
    record = find_agent_repair_run(conn, run_id)
    if record is None:
        raise ValueError(f"no repair run {run_id!r}")
    if not record.change_request_id:
        raise ValueError(f"{run_id} has no change request to revalidate")
    old_cr_id = record.change_request_id

    audit_trail: list = []

    old_cr = find_ai_change_request(conn, old_cr_id)
    if old_cr is None:
        raise ValueError(f"{run_id}'s change request {old_cr_id} no longer exists")
    if old_cr.status != "pending":
        return ApprovalRevalidation(
            run_id=run_id, old_cr_id=old_cr_id, diff_matches=False, new_cr_id=None,
            detail=f"{old_cr_id} is not pending (current status: {old_cr.status!r}) — nothing to revalidate",
        )

    worktree = RepairWorktree(
        run_dir=Path(record.worktree_path).parent, worktree_path=Path(record.worktree_path),
        agent_home_path=Path(record.agent_home_path), base_commit=record.base_commit,
    )
    if not worktree_exists(worktree):
        raise ValueError(
            f"{run_id}'s worktree no longer exists on disk — cannot revalidate before approval; "
            "do not approve this change request without independently reviewing the diff yourself"
        )

    revalidation = revalidate_worktree_diff(worktree, record.diff_hash, audit_trail=audit_trail)
    if revalidation.matches:
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return ApprovalRevalidation(
            run_id=run_id, old_cr_id=old_cr_id, diff_matches=True, new_cr_id=None, detail=revalidation.detail,
        )

    # Stale: the old CR can never be approved again (superseding sets
    # its status away from 'pending', and approve_change() already
    # requires 'pending'). Re-verify the CURRENT worktree state before
    # trying to propose a replacement — the OLD verification result
    # described the OLD diff, not this one, and Phase 31's own rule
    # ("tests and validation decide whether a repair technically
    # passes") applies just as much to a revalidated diff as a fresh
    # one.
    supersede_change_request(conn, old_cr_id, detail=revalidation.detail, run_id=run_id)

    candidate = RepairCandidate(record.trigger_kind, record.trigger_ref, record.trigger_detail)
    verification = verify_worktree(worktree, cfg, audit_trail=audit_trail)

    diff_path = worktree.run_dir / "diff.patch"
    diff_path.write_text(revalidation.current_diff_text, encoding="utf-8")

    if verification.overall_passed is not True:
        complete_agent_repair_run(
            conn, run_id=run_id, completed_at=_now(), status="verification_failed",
            verification_passed=(False if verification.overall_passed is False else None),
            diff_path=str(diff_path), diff_hash=revalidation.current_diff_hash,
            changed_files=revalidation.current_changed_files,
            pytest_status=verification.pytest_result.status, pytest_summary=verification.pytest_result.summary,
            validate_status=verification.validate_result.status, validate_summary=verification.validate_result.summary,
            stop_reason=f"diff revalidation found drift ({revalidation.detail}); re-verification of the "
            "current worktree state did not pass either — no replacement change request was created",
        )
        persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
        return ApprovalRevalidation(
            run_id=run_id, old_cr_id=old_cr_id, diff_matches=False, new_cr_id=None,
            detail=revalidation.detail + "; re-verification of current worktree state also did not pass",
        )

    mini_result = MiniRunResult(
        status="completed", returncode=None, exit_status=record.agent_exit_status,
        submission=None, mini_version=record.tool_version, instance_cost=None,
        transcript_path=(Path(record.transcript_path) if record.transcript_path else None),
        model_name=record.model_name, argv=record.tool_argv, config_yaml=record.mini_config_yaml,
        transcript_hash=record.transcript_hash,
    )
    new_cr = propose_repair_change_request(
        conn, cfg, run_id=run_id, candidate=candidate, diff_text=revalidation.current_diff_text,
        diff_hash=revalidation.current_diff_hash, changed_files=revalidation.current_changed_files,
        verification=verification, mini_result=mini_result,
    )
    set_agent_repair_run_change_request(conn, run_id=run_id, change_request_id=new_cr.cr_id)
    complete_agent_repair_run(
        conn, run_id=run_id, completed_at=_now(), status="verified", verification_passed=True,
        diff_path=str(diff_path), diff_hash=revalidation.current_diff_hash,
        changed_files=revalidation.current_changed_files,
        pytest_status=verification.pytest_result.status, pytest_summary=verification.pytest_result.summary,
        validate_status=verification.validate_result.status, validate_summary=verification.validate_result.summary,
        stop_reason=f"diff revalidation found drift ({revalidation.detail}); {old_cr_id} superseded and "
        f"{new_cr.cr_id} proposed from the current, re-verified worktree state",
    )
    persist_audit_trail(conn, run_id=run_id, audit_trail=audit_trail)
    return ApprovalRevalidation(
        run_id=run_id, old_cr_id=old_cr_id, diff_matches=False, new_cr_id=new_cr.cr_id, detail=revalidation.detail,
    )
