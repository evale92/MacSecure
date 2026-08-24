"""
cli/agent.py — `secure agent ...` (Phase 31: Agent Foundation).

Thin on purpose, same split every other secure/cli/*.py module keeps:
this file only parses arguments, opens the real database, and formats
output. Every actual policy/isolation/verification/approval decision
lives in secure/agent/ and secure/ai/changes/ — this file makes none
of its own.

`secure agent run` and `secure agent resume` can, at most, leave a
PENDING row in ai_change_requests — they never approve anything.

`secure agent approve <run_id>` (added as a second guardrail, per
explicit user instruction) is the one exception, and it still never
approves anything itself in the sense of inventing new authority: it
first re-derives the worktree's CURRENT diff and refuses to proceed
unless it still matches the diff the change request was proposed from
(secure/agent/orchestrator.py's revalidate_before_approval()) — only
once that passes does it call the real, unchanged `secure ai changes
approve <cr_id> <revision_hash>` machinery. A human still has to type
this command themselves; nothing here runs on its own. Plain `secure
ai changes approve` still works too and is unaffected — this command
is a stricter path specifically for agent-originated change requests,
not a replacement for the general one.
"""

from __future__ import annotations

import argparse

from secure.agent.audit import persist_audit_trail
from secure.agent.orchestrator import attempt_repair, resume_repair_run, revalidate_before_approval
from secure.agent.policy import evaluate_policy, find_repair_candidates
from secure.agent.runner import tool_available
from secure.agent.worktree import RepairWorktree, is_git_repository, remove_repair_worktree
from secure.ai.changes.workflow import RevisionMismatchError, approve_change
from secure.storage.database import Database
from secure.storage.models import (
    find_agent_repair_run,
    find_ai_change_request,
    list_agent_actions,
    list_agent_repair_runs,
)
from secure.cli import _bootstrap, logger


def cmd_agent_status(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    git_ok = is_git_repository()
    tool_ok = tool_available(cfg)
    ollama_ok = bool(cfg.ollama_host)

    print("Agent Foundation (Phase 31) status:")
    print(f"  Live checkout is a git repository: {'yes' if git_ok else 'NO — git worktree isolation is not possible'}")
    print(f"  Tool: {cfg.agent_tool} ({'available' if tool_ok else 'NOT CONFIGURED / not on PATH'})")
    print(f"  Ollama configured: {'yes (' + cfg.ollama_host + ', model ' + cfg.ollama_model + ')' if ollama_ok else 'no — set ollama_host/ollama_model in config.json'}")
    print(f"  Allowed trigger kinds: {', '.join(cfg.agent_allowed_trigger_kinds) or '(none)'}")
    print(f"  Max attempts per trigger: {cfg.agent_max_attempts}")
    print(f"  Path denylist: {len(cfg.agent_path_denylist)} entries")
    if not (git_ok and tool_ok and ollama_ok):
        print("\n  `secure agent run` will not be able to complete a repair until every item above is ready.")
    return 0


def cmd_agent_discover(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        candidates = find_repair_candidates(db.conn, cfg)
        if not candidates:
            print("No deterministic test/validation failures found.")
            return 0
        print(f"{len(candidates)} candidate(s):")
        for c in candidates:
            decision = evaluate_policy(db.conn, cfg, c)
            print(f"  [{c.trigger_kind}] {c.trigger_ref}  ({'eligible' if decision.allowed else 'NOT eligible: ' + decision.reason})")
    return 0


def cmd_agent_run(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    if bool(args.trigger_kind) != bool(args.trigger_ref):
        print("--trigger-kind and --trigger-ref must be given together, or neither (to auto-discover).")
        return 2

    with Database(cfg.database_path()) as db:
        if args.trigger_kind and args.trigger_ref:
            from secure.agent.policy import RepairCandidate

            candidates = [RepairCandidate(args.trigger_kind, args.trigger_ref, args.trigger_detail or "")]
        else:
            candidates = find_repair_candidates(db.conn, cfg)

        attempted = 0
        for candidate in candidates:
            if attempted >= args.limit:
                break
            decision = evaluate_policy(db.conn, cfg, candidate)
            if not decision.allowed:
                print(f"Skipping [{candidate.trigger_kind}] {candidate.trigger_ref}: {decision.reason}")
                continue
            print(f"Attempting repair for [{candidate.trigger_kind}] {candidate.trigger_ref} ...")
            record = attempt_repair(db.conn, cfg, candidate)
            attempted += 1
            logger.info(f"Attempted an autonomous repair ({record.run_id}, status={record.status})")
            _print_run_summary(record)
    if attempted == 0:
        print("No eligible candidates were attempted.")
    return 0


def cmd_agent_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        runs = list_agent_repair_runs(db.conn, status=args.status, limit=args.limit)
        if not runs:
            print("No repair runs recorded.")
            return 0
        for r in runs:
            print(f"{r.run_id}  {r.status:<24} {r.trigger_kind:<24} {r.trigger_ref}  (attempt {r.attempt_number}/{r.max_attempts})")
    return 0


def cmd_agent_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = find_agent_repair_run(db.conn, args.run_id)
        if record is None:
            print(f"No repair run {args.run_id!r}.")
            return 1
        _print_run_summary(record, full=True)
    return 0


def cmd_agent_resume(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = resume_repair_run(db.conn, cfg, args.run_id)
        logger.info(f"Resumed an autonomous repair run ({record.run_id}, status={record.status})")
        _print_run_summary(record, full=True)
    return 0


def cmd_agent_approve(args: argparse.Namespace) -> int:
    """Guardrail 2 (explicit user instruction): revalidate the
    worktree's current diff against the change request BEFORE
    approving it, and only call the real, unchanged `approve_change()`
    if that still matches. On a mismatch, this never approves anything
    — it reports that the old CR is now superseded and, if
    re-verification of the current worktree state passed, names the
    new replacement CR for the human to separately review and approve
    (by running this same command again with a fresh run_id lookup, or
    `secure ai changes approve <new_cr_id> <its revision_hash>`)."""
    cfg = _bootstrap()
    approved_by = args.approved_by or "cli-user"
    with Database(cfg.database_path()) as db:
        try:
            revalidation = revalidate_before_approval(db.conn, cfg, args.run_id)
        except ValueError as exc:
            print(f"Cannot revalidate/approve: {exc}")
            return 1
        logger.info(
            f"Revalidated an agent repair's diff before approval ({args.run_id}, "
            f"matches={revalidation.diff_matches})",
            extra={"event": "agent_revalidate_before_approval", "component": "cli", "run_id": args.run_id},
        )

        if not revalidation.diff_matches:
            print(f"NOT approving {revalidation.old_cr_id}: {revalidation.detail}")
            print(f"{revalidation.old_cr_id} has been marked 'superseded' and can no longer be approved.")
            if revalidation.new_cr_id:
                new_cr = find_ai_change_request(db.conn, revalidation.new_cr_id)
                print(f"A replacement change request was created from the current worktree state: {revalidation.new_cr_id}")
                if new_cr is not None:
                    print(f"Review it, then approve it explicitly:")
                    print(f"  secure ai changes show {new_cr.cr_id}")
                    print(f"  secure agent approve {args.run_id}   (will now revalidate against {new_cr.cr_id})")
            else:
                print("Re-verification of the current worktree state did not pass either — "
                      "no replacement change request was created. Investigate manually.")
            return 1

        cr = find_ai_change_request(db.conn, revalidation.old_cr_id)
        if cr is None:
            print(f"Could not re-load {revalidation.old_cr_id} after revalidation.")
            return 1
        try:
            approved = approve_change(db.conn, cr.cr_id, revision_hash=cr.revision_hash, approved_by=approved_by)
        except (ValueError, RevisionMismatchError) as exc:
            print(f"Cannot approve: {exc}")
            return 1

        logger.info(
            f"Approved an agent-originated AI change request ({approved.cr_id})",
            extra={"event": "agent_changes_approve", "component": "cli", "cr_id": approved.cr_id},
        )
        print(f"{approved.cr_id} approved by {approved.approved_by} at {approved.approved_at}.")
        print("Approval recorded. Applying the diff to the live repository is still a separate, manual step.")
    return 0


def cmd_agent_remove_worktree(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = find_agent_repair_run(db.conn, args.run_id)
        if record is None:
            print(f"No repair run {args.run_id!r}.")
            return 1
        if record.status == "running":
            print(f"{args.run_id} is still 'running' — resume or wait for it to finish before removing its worktree.")
            return 1
        from pathlib import Path

        worktree = RepairWorktree(
            run_dir=Path(record.worktree_path).parent, worktree_path=Path(record.worktree_path),
            agent_home_path=Path(record.agent_home_path), base_commit=record.base_commit,
        )
        audit_trail: list = []
        remove_repair_worktree(worktree, audit_trail=audit_trail)
        persist_audit_trail(db.conn, run_id=args.run_id, audit_trail=audit_trail)
        logger.info(f"Removed a repair worktree ({args.run_id})")
        print(f"Removed the worktree for {args.run_id}. The database record is kept.")
    return 0


def cmd_agent_actions(args: argparse.Namespace) -> int:
    """Phase 31.5: `secure agent actions [--run-id ID]` — every
    audited subprocess/git/filesystem/proposed-system-change action
    secure/agent/ has recorded, optionally filtered to one run. Every
    field printed here is already redacted at write time by
    secure/agent/audit.py — this command does no filtering of its own,
    it only formats what list_agent_actions() returns."""
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        actions = list_agent_actions(db.conn, run_id=args.run_id, limit=args.limit)
        if not actions:
            scope = f" for {args.run_id}" if args.run_id else ""
            print(f"No audited agent actions recorded{scope}.")
            return 0
        print(f"{len(actions)} audited action(s){' for ' + args.run_id if args.run_id else ''}:")
        for a in actions:
            kind = "MUTATING" if a.mutating else "read-only"
            approval = ", approval-required" if a.approval_required else ""
            print(f"  [{a.timestamp}] {a.run_id or '(none)':<8} {a.component:<16} {a.action}")
            print(f"      {kind}{approval}  exit={a.exit_code}  duration={a.duration_seconds}")
            if a.cwd:
                print(f"      cwd: {a.cwd}")
            if a.target:
                print(f"      target: {a.target}")
            if a.argv:
                print(f"      argv: {' '.join(a.argv)}")
            if a.result_summary:
                print(f"      result: {a.result_summary}")
    return 0


def _print_run_summary(record, *, full: bool = False) -> None:
    print(f"  {record.run_id}  status={record.status}  trigger={record.trigger_kind}:{record.trigger_ref}")
    print(f"    verification: pytest={record.pytest_status} validate={record.validate_status} passed={record.verification_passed}")
    if record.change_request_id:
        print(f"    change request: {record.change_request_id} (see `secure ai changes show {record.change_request_id}`)")
    print(f"    stop reason: {record.stop_reason}")
    if full:
        print(f"    worktree: {record.worktree_path}")
        print(f"    diff: {record.diff_path} (sha256 {record.diff_hash})")
        print(f"    transcript: {record.transcript_path}")
        print(f"    changed files: {', '.join(record.changed_files) or '(none)'}")
        if record.denylist_violation:
            print(f"    DENYLIST VIOLATION: {record.denylist_violation}")


# ---------------------------------------------------------------------
# Phase 40 — Change Request Center (CLI half)
# ---------------------------------------------------------------------


def _print_center_view(view, *, full: bool = False) -> None:
    """Every field the Phase 40 governing text requires, in one place.
    Prints only what is recorded — a change request with no linked
    repair run shows empty values rather than invented ones."""
    print(f"  {view.cr_id}  status={view.status}  classification={view.classification or '(unclassified)'}")
    print(f"    title:            {view.title}")
    print(f"    requesting run:   {view.run_id or '(none)'}")
    print(f"    requesting model: {view.requesting_tool or '(none)'} / {view.requesting_model or '(none)'}")
    print(f"    revision hash:    {view.revision_hash}")
    print(f"    diff hash:        {view.diff_hash or '(none)'}")
    print(f"    affected:         {view.affected_component}")
    print(f"    changed files:    {', '.join(view.changed_files) or '(none)'}")
    print(f"    tests:            pytest={view.pytest_status} validate={view.validate_status} passed={view.verification_passed}")
    print(f"    reviewer:         {view.review_status or '(none)'} blocking={', '.join(view.review_blocking) or '(none)'}")
    print(f"    requires approval:{view.requires_human_approval}")
    print(f"    rollback:         {view.rollback}")
    if full:
        print(f"    reason:\n      {view.reason}")
        print(f"    proposed action:\n      {view.proposed_action}")
        print(f"    risks:\n      {view.risks}")
        print(f"    commands involved: {len(view.commands)} recorded "
              f"(see `secure agent actions --run-id {view.run_id}`)" if view.run_id else "    commands involved: (none)")


def cmd_agent_center_list(args: argparse.Namespace) -> int:
    """Phase 40: `secure agent center` — every change request still
    awaiting a human, fully assembled. Read-only; this command cannot
    approve, reject, or supersede anything."""
    from secure.agent.center import list_pending_change_requests

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        views = list_pending_change_requests(db.conn, limit=args.limit)
        if not views:
            print("No change requests are awaiting approval.")
            return 0
        print(f"{len(views)} change request(s) awaiting approval:")
        for view in views:
            _print_center_view(view)
    return 0


def cmd_agent_center_show(args: argparse.Namespace) -> int:
    """Phase 40: `secure agent center show <cr_id>` — VIEW DETAILS,
    plus VIEW DIFF / VIEW TESTS via --diff / --tests."""
    from secure.agent.center import build_change_request_view, read_diff, reviewer_report, tests_report

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        view = build_change_request_view(db.conn, args.cr_id)
        if view is None:
            print(f"No change request {args.cr_id!r}.")
            return 1
        _print_center_view(view, full=True)
        if args.tests:
            print("\n--- tests ---")
            print(tests_report(view))
            print("\n--- independent review ---")
            print(reviewer_report(view))
        if args.diff:
            print("\n--- diff ---")
            print(read_diff(view))
        print("\nA passing verification result is NOT authorization, and a second model raising")
        print("no blocking findings is not an approval. Approve with:")
        print(f"  secure ai changes approve {view.cr_id} {view.revision_hash}")
    return 0


def cmd_agent_center_check(args: argparse.Namespace) -> int:
    """Phase 40: `secure agent center check <cr_id>` — re-verify that
    the content this change request holds still hashes to its recorded
    revision, and that the diff on disk still matches. On a mismatch
    the request is SUPERSEDED, because approval must never silently
    transfer to changed content. Superseding only ever makes a request
    less approvable; nothing here can approve anything."""
    from secure.agent.changes import invalidate_change_request_if_content_changed

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        integrity, record = invalidate_change_request_if_content_changed(db.conn, args.cr_id)
        if integrity is None:
            print(f"No change request {args.cr_id!r}.")
            return 1
        print(f"{args.cr_id}: {integrity.detail}")
        if integrity.intact:
            print("Content integrity intact — approval (if any) still covers exactly what is recorded.")
            return 0
        print(f"CONTENT CHANGED — change request superseded (status is now {record.status if record else 'unknown'}).")
        print("A superseded change request can never be approved; propose a fresh one describing")
        print("what is actually there now.")
    return 1


# ---------------------------------------------------------------------
# Phase 42 — Background Supervisor (CLI half)
# ---------------------------------------------------------------------


def cmd_agent_supervise(args: argparse.Namespace) -> int:
    """Phase 42: `secure agent supervise` — one bounded supervision
    pass. Observes only: it runs read-only CLI jobs, records each one
    in the Phase 31.5 audit trail, and reports a state. It cannot
    start a repair, approve anything, or run the full regression
    suite; secure/agent/supervisor.py's validate_jobs() refuses any job
    that would.

    This is the command a launchd job WOULD run. Nothing about running
    it here installs anything.
    """
    from secure.agent.audit import persist_audit_trail
    from secure.agent.supervisor import STATE_HEALTHY, run_supervisor_cycle

    cfg = _bootstrap()
    audit_trail: list = []
    cycle = run_supervisor_cycle(cfg, audit_trail=audit_trail)
    with Database(cfg.database_path()) as db:
        persist_audit_trail(db.conn, run_id=None, audit_trail=audit_trail)

    print(f"Supervisor cycle {cycle.started_at} -> {cycle.completed_at}: {cycle.state}")
    for result in cycle.results:
        print(f"  {result.name:<26} {result.status:<8} exit={result.exit_code} "
              f"{result.duration_seconds:.2f}s")
        if args.verbose and result.summary:
            for line in result.summary.splitlines():
                print(f"      {line}")
    return 0 if cycle.state == STATE_HEALTHY else 1


def cmd_agent_supervisor_plist(args: argparse.Namespace) -> int:
    """Phase 42: print the launchd plist that WOULD schedule the
    supervisor, and say plainly that Secure will not install it."""
    from secure.agent.supervisor import (
        build_launchd_plist,
        installation_instructions,
        installation_status,
    )

    cfg = _bootstrap()
    installed, detail = installation_status(args.label)
    print(f"# {detail}")
    print("#")
    for line in installation_instructions(args.label).splitlines():
        print(f"# {line}")
    print()
    print(build_launchd_plist(cfg, label=args.label, interval_seconds=args.interval))
    return 0 if not installed else 0


def cmd_agent_supervisor_propose(args: argparse.Namespace) -> int:
    """Phase 42: raise the approval-gated change request for installing
    the supervisor as a launchd job. Creates a PENDING change request
    and STOPS. Installs nothing."""
    from secure.agent.supervisor import propose_supervisor_installation

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        cr = propose_supervisor_installation(
            db.conn, cfg, label=args.label, interval_seconds=args.interval
        )
    print(f"Created change request {cr.cr_id} (status={cr.status}, classification={cr.classification}).")
    print("Nothing has been installed. Review it with:")
    print(f"  secure agent center show {cr.cr_id}")
    print("If you approve it, you perform the installation yourself — Secure ships no code that does.")
    return 0


# ---------------------------------------------------------------------
# Phase 43 — Automated Failure Diagnosis (CLI half)
# ---------------------------------------------------------------------


def cmd_agent_diagnose(args: argparse.Namespace) -> int:
    """Phase 43: `secure agent diagnose` — the full required sequence
    for the first eligible failure found: DETECT -> REPRODUCE ->
    bounded context -> diagnosis -> sandbox repair -> targeted tests ->
    broader tests -> independent review.

    Stops honestly, and repairs nothing, when the failure does not
    reproduce or when reproduction is inconclusive.
    """
    from secure.agent.diagnose import describe, diagnose_failure
    from secure.agent.policy import find_repair_candidates

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        candidates = find_repair_candidates(db.conn, cfg)
        if not candidates:
            print("No eligible failures found. Nothing to diagnose.")
            return 0

        selected = candidates
        if args.trigger_ref:
            selected = [c for c in candidates if c.trigger_ref == args.trigger_ref]
            if not selected:
                print(f"No eligible failure with trigger ref {args.trigger_ref!r}.")
                return 1
        if not args.all:
            selected = selected[:1]

        exit_code = 0
        for candidate in selected:
            if args.reproduce_only:
                from secure.agent.diagnose import reproduce_failure

                repro = reproduce_failure(candidate, cfg)
                print(f"{candidate.trigger_kind}  {candidate.trigger_ref}")
                print(f"  reproduction: {repro.status} (reproduced={repro.reproduced})")
                print(f"  command:      {repro.command}")
                if repro.reproduced is not True:
                    exit_code = 1
                continue

            result = diagnose_failure(db.conn, cfg, candidate)
            print(describe(result))
            print()
            if not result.repair_attempted:
                exit_code = 1
    return exit_code


# ---------------------------------------------------------------------
# Phase 44 — Verified Self-Healing (CLI half)
# ---------------------------------------------------------------------


def cmd_agent_verified(args: argparse.Namespace) -> int:
    """Phase 44: `secure agent verified <run_id>` — evaluate all eleven
    VERIFIED criteria for one repair run and print the checklist.

    Read-only. This command promotes nothing, approves nothing, and
    changes no status; VERIFIED is a measurement, and eligibility is
    not permission.
    """
    from secure.agent.verified import evaluate_verified

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = find_agent_repair_run(db.conn, args.run_id)
        if record is None:
            print(f"No repair run {args.run_id!r}.")
            return 1
        assessment = evaluate_verified(record, cfg)
        print(assessment.describe())
        if not assessment.verified:
            print()
            print("Not VERIFIED. Blocking criteria: " + ", ".join(assessment.blocking))
    return 0 if assessment.verified else 1


# ---------------------------------------------------------------------
# Phase 45 — Maintenance Memory (CLI half)
# ---------------------------------------------------------------------


def cmd_agent_memory(args: argparse.Namespace) -> int:
    """Phase 45: `secure agent memory` — the structured repair history,
    or (with --trigger-ref) the prior evidence relevant to a failure
    happening now.

    Read-only, and it returns evidence rather than instructions: there
    is no command here, and no function in secure/agent/memory.py, that
    re-applies an old patch.
    """
    from secure.agent.memory import describe_recall, recall
    from secure.storage.models import list_maintenance_memory

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        if args.trigger_ref:
            results = recall(
                db.conn,
                trigger_kind=args.trigger_kind or "pytest_failure",
                trigger_ref=args.trigger_ref,
                trigger_detail=args.detail or "",
                limit=args.limit,
            )
            print(describe_recall(results))
            return 0

        rows = list_maintenance_memory(db.conn, limit=args.limit)
        if not rows:
            print("No maintenance history recorded yet.")
            return 0
        print(f"{len(rows)} maintenance record(s):")
        for m in rows:
            print(f"  {m.run_id}  {m.recorded_at}  outcome={m.outcome}  verified={m.verified}")
            print(f"    trigger:        {m.trigger_kind}  {m.trigger_ref}")
            print(f"    component:      {m.affected_component or '(none)'}")
            print(f"    classification: {m.classification or '(unclassified)'}  approval={m.approval_decision}")
            print(f"    signature:      {m.failure_signature[:16]}...")
            if m.regression_run_id:
                print(f"    REGRESSION LINKED: {m.regression_run_id}  {m.regression_note}")
    return 0


# ---------------------------------------------------------------------
# Phase 46 — Dependency & Security Tool Maintenance (CLI half)
# ---------------------------------------------------------------------


def cmd_agent_toolchain(args: argparse.Namespace) -> int:
    """Phase 46: `secure agent toolchain [--propose]` — survey external
    tooling and dependencies for maintenance situations, and optionally
    raise an approval-gated change request for each.

    Installs nothing, updates nothing, and writes no manifest. Secure
    ships no code that runs a package manager.
    """
    from secure.agent.toolchain import describe, propose_maintenance, survey

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        situations = survey(db.conn, cfg)
        print(describe(situations))
        if not situations:
            return 0
        if args.propose:
            print()
            for situation in situations:
                cr = propose_maintenance(db.conn, cfg, situation)
                print(f"  {situation.component}: created {cr.cr_id} "
                      f"(status={cr.status}, classification={cr.classification})")
            print()
            print("Nothing was installed or updated. Review with `secure agent center`.")
    return 1 if situations else 0


# ---------------------------------------------------------------------
# Phase 47 — Supervised Autonomous Maintenance (CLI half)
# ---------------------------------------------------------------------


def cmd_agent_maintain(args: argparse.Namespace) -> int:
    """Phase 47: `secure agent maintain` — one full pass of the bounded
    maintenance loop for the first eligible failure.

    Health/tests -> failure -> reproduce -> primary coder -> isolated
    repair -> actual git diff -> deterministic tests -> security
    validation when relevant -> independent review -> classification ->
    (eligible for promotion | change request awaiting a human |
    escalated | rejected | stopped honestly).

    Applies nothing to the live checkout and changes no host state. A
    verified SAFE_PROJECT_CODE repair is reported as ELIGIBLE for
    promotion; promoting it is still `secure agent approve <run_id>`,
    typed by a human.
    """
    from secure.agent.maintenance import describe, run_maintenance_cycle
    from secure.agent.policy import find_repair_candidates

    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        candidates = find_repair_candidates(db.conn, cfg)
        if not candidates:
            print("No eligible failures found. Nothing to maintain.")
            return 0

        selected = candidates if args.all else candidates[:1]
        worst = 0
        for candidate in selected:
            outcome = run_maintenance_cycle(db.conn, cfg, candidate)
            print(describe(outcome))
            print()
            if not outcome.promotion_eligible:
                worst = 1
    return worst
