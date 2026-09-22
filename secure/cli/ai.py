"""
secure/cli/ai.py — Phase 28: `secure ai ...`, the CLI front end for
secure/ai/. Thin on purpose, same split every other secure/cli/*.py
module keeps: this file only parses arguments, opens the REAL database,
and formats output — every actual provider/context/orchestration/
verification/change-request decision lives in secure/ai/ itself.
"""

from __future__ import annotations

import argparse

from secure.ai.analyst import STATUS_OK, STATUS_PARTIAL, ask
from secure.ai.changes.workflow import RevisionMismatchError, approve_change, propose_simplification, reject_change
from secure.ai.model_roles import ALL_MAINTENANCE_ROLES, resolve_maintenance_roles
from secure.ai.registry import build_providers
from secure.ai.verify.operations import VALID_OPERATIONS, VerificationOperation
from secure.ai.verify.runner import run_default_verification_suite, run_operations
from secure.investigate.entity import EntityRef
from secure.storage.database import Database
from secure.storage.models import (
    find_agent_repair_run_for_change_request,
    find_ai_analyst_query,
    find_ai_change_request,
    find_ai_verification_run,
    list_ai_analyst_queries,
    list_ai_change_requests,
    list_ai_verification_runs,
)
from secure.cli import _bootstrap, logger


def cmd_ai_status(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    providers = build_providers(cfg)

    print("Registered local AI providers (both always shown, whether configured or not):")
    for name, provider in providers.items():
        reachable, detail = provider.check_reachable()
        state = "REACHABLE" if reachable else "not configured/unreachable"
        print(f"  - {name} [{provider.identity.name}] model={_configured_model(cfg, name)!r}: {state} — {detail}")

    print()
    print(f"Change-request notification email: {cfg.ai_notify_email or '(not set)'}")
    smtp_state = "configured" if cfg.smtp_host else "not configured (notifications will be skipped, never blocking)"
    print(f"SMTP relay: {smtp_state}")

    return 0


def cmd_ai_roles(args: argparse.Namespace) -> int:
    """Phase 32 (Part 2 — Local Model Routing): shows which provider is
    currently assigned to each engineering-maintenance role
    (PRIMARY_CODER, INDEPENDENT_REVIEWER) and whether that assignment
    is actually usable right now — read-only, invokes nothing."""
    cfg = _bootstrap()
    providers = build_providers(cfg)
    bindings = resolve_maintenance_roles(providers)

    print("Engineering-maintenance model roles (Phase 32):")
    for role in ALL_MAINTENANCE_ROLES:
        binding = bindings[role]
        if not binding.configured:
            print(f"  - {role}: NOT CONFIGURED — no provider available for this role yet")
            continue
        reachable, detail = providers[binding.provider_name].check_reachable()
        state = "REACHABLE" if reachable else "configured but unreachable"
        timeout_text = f"{binding.timeout_seconds:g}s" if binding.timeout_seconds is not None else "(default)"
        print(
            f"  - {role}: provider={binding.provider_name!r} model={binding.model!r} "
            f"timeout={timeout_text} — {state} ({detail})"
        )

    same_provider = bindings[ALL_MAINTENANCE_ROLES[0]].provider_name == bindings[ALL_MAINTENANCE_ROLES[1]].provider_name
    both_configured = all(bindings[r].configured for r in ALL_MAINTENANCE_ROLES)
    if both_configured and same_provider:
        print(
            "\n  Note: both roles are currently using the same provider — configure a second "
            "backend (ollama_host or local_llm_host) so review is not merely the same model "
            "agreeing with itself."
        )
    return 0


def _configured_model(cfg, provider_name: str) -> str:
    if provider_name == "ollama":
        return cfg.ollama_model
    if provider_name == "openai_compatible":
        return cfg.local_llm_model
    return ""


def _print_claims(claims, indent: str = "    ") -> None:
    for claim in claims:
        cite = f" [{claim.citation}]" if claim.citation else ""
        valid_note = ""
        if claim.citation_valid is False:
            valid_note = "  *** CITATION INVALID/NOT FOUND IN CONTEXT ***"
        print(f"{indent}[{claim.kind}]{cite}{valid_note} {claim.text}")


def cmd_ai_ask(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    entity = None
    if args.entity_type or args.entity_key:
        if not (args.entity_type and args.entity_key):
            print("Both --entity-type and --entity-key are required together.")
            return 1
        try:
            entity = EntityRef(entity_type=args.entity_type, entity_key=args.entity_key)
        except ValueError as exc:
            print(f"Invalid entity: {exc}")
            return 1

    with Database(cfg.database_path()) as db:
        outcome = ask(db.conn, cfg, args.question, entity=entity)

    print(f"Query #{outcome.query_id} — status: {outcome.status}")
    for note in outcome.notes:
        print(f"  note: {note}")

    if outcome.analyst is None:
        print("No provider was available to answer this question.")
        print("Run `secure ai status` to see what's configured.")
        return 1

    print()
    print(f"Model A (Analyst) — {outcome.analyst.completion.provider}/{outcome.analyst.completion.model}:")
    if outcome.analyst.answer.parse_ok:
        print(f"  {outcome.analyst.answer.summary}")
        _print_claims(outcome.analyst.answer.claims)
        for step in outcome.analyst.answer.suggested_next_steps:
            print(f"    -> suggested next step: {step}")
    else:
        print(f"  (could not parse a structured answer: {outcome.analyst.answer.parse_error})")
        print(f"  raw: {outcome.analyst.answer.raw_text[:500]!r}")

    if outcome.verifier is not None:
        print()
        print(f"Model B (Verifier) — independent pass:")
        _print_claims(outcome.verifier.independent_answer.claims)
        print()
        print(f"Model B (Verifier) — review of Model A ({outcome.verifier.review_answer.agreement or 'unknown'}):")
        if outcome.verifier.review_answer.contradictions_found:
            print("  contradictions found:")
            for c in outcome.verifier.review_answer.contradictions_found:
                print(f"    - {c}")
        if outcome.verifier.review_answer.unsupported_assumptions:
            print("  unsupported assumptions:")
            for a in outcome.verifier.review_answer.unsupported_assumptions:
                print(f"    - {a}")
        _print_claims(outcome.verifier.review_answer.claims)
    else:
        print()
        print("(No verifier pass ran — configure a second provider for cross-checked answers.)")

    logger.info(
        "Asked the AI analyst a question", extra={"event": "ai_ask", "component": "cli", "status": outcome.status},
    )
    return 0 if outcome.status in (STATUS_OK, STATUS_PARTIAL) else 1


def cmd_ai_history(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        queries = list_ai_analyst_queries(db.conn, limit=args.limit)

    if not queries:
        print("No AI analyst queries yet. Run `secure ai ask \"<question>\"` first.")
        return 0

    for q in queries:
        target = f"{q.entity_type}:{q.entity_key}" if q.entity_type else "(free-form)"
        second = f" + {q.provider_b}" if q.provider_b else ""
        print(
            f"#{q.id:<4} [{q.status:<12}] {q.asked_at}  {target}  "
            f"({q.provider_a or '?'}{second})  citations {q.citation_valid_count}ok/{q.citation_invalid_count}bad"
        )
        print(f"      {q.question}")
    return 0


def cmd_ai_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = find_ai_analyst_query(db.conn, args.query_id)

    if record is None:
        print(f"No AI analyst query found with id {args.query_id}.")
        return 1

    print(f"Query #{record.id} — status: {record.status}")
    print(f"  asked:     {record.asked_at}")
    print(f"  completed: {record.completed_at or '(incomplete)'}")
    print(f"  mode:      {record.mode}")
    if record.entity_type:
        print(f"  entity:    {record.entity_type}:{record.entity_key}")
    print(f"  question:  {record.question}")
    print(f"  provider A: {record.provider_a or '(none)'} / {record.model_a or ''}")
    print(f"  provider B: {record.provider_b or '(none)'} / {record.model_b or ''}")
    print(f"  citations:  {record.citation_valid_count} valid, {record.citation_invalid_count} invalid")
    print(f"  latency:    {record.latency_ms:.1f}ms" if record.latency_ms is not None else "  latency:    (n/a)")
    print(f"  context evidence ids shown to the model: {record.context_manifest}")
    if record.analyst_answer:
        print()
        print("  Analyst answer:")
        print(f"    summary: {record.analyst_answer.get('summary', '')}")
        for claim in record.analyst_answer.get("claims", []):
            print(f"    [{claim.get('kind')}] [{claim.get('citation')}] {claim.get('text')}")
    if record.verifier_answer:
        print()
        print("  Verifier review:")
        review = record.verifier_answer.get("review", {})
        print(f"    agreement: {review.get('agreement')}")
        for claim in review.get("claims", []):
            print(f"    [{claim.get('kind')}] [{claim.get('citation')}] {claim.get('text')}")
    return 0


# ---------- secure ai verify ... ----------
#
# The constrained verification mode (secure/ai/verify/) — a FIXED,
# allowlisted set of read-only-plus-deterministic-test operations. No
# free-text command ever reaches a shell here; see
# secure/ai/verify/__init__.py's own hard rules for the full reasoning.
# These CLI commands let a human run exactly the same operations an
# LLM will eventually be allowed to request (Stage 7's change-request
# workflow) — nothing here is more privileged than what the AI gets.


def _print_op_result(result) -> None:
    print(f"  [{result.status}] {result.op} {result.args or ''}".rstrip())
    if result.error:
        print(f"      error: {result.error}")
    if result.output is not None:
        print(f"      output: {_short(result.output)}")


def _short(obj, limit: int = 400) -> str:
    text = str(obj)
    return text if len(text) <= limit else text[:limit] + f"... [{len(text)} chars total]"


def cmd_ai_verify_list_ops(args: argparse.Namespace) -> int:
    print("Allowed verification operations (fixed set — nothing else can ever run):")
    for op in VALID_OPERATIONS:
        print(f"  - {op}")
    return 0


def cmd_ai_verify_run(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    if args.op not in VALID_OPERATIONS:
        print(f"{args.op!r} is not an allowed operation. Run `secure ai verify list-ops` to see the full set.")
        return 1

    op_args = {}
    if args.path:
        op_args["path"] = args.path
    if args.scenario_id:
        op_args["scenario_id"] = args.scenario_id
    if args.test_path:
        op_args["test_path"] = args.test_path
    if args.timeout:
        op_args["timeout"] = args.timeout

    with Database(cfg.database_path()) as db:
        summary = run_operations(db.conn, cfg, [VerificationOperation(args.op, op_args)])

    print(f"Verification run #{summary.run_id} — overall: {summary.overall_status}")
    for result in summary.results:
        _print_op_result(result)
    logger.info(
        "Ran a single AI verification operation",
        extra={"event": "ai_verify_run", "component": "cli", "op": args.op, "status": summary.overall_status},
    )
    return 0 if summary.overall_status in ("ok", "partial") else 1


def cmd_ai_verify_suite(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        summary = run_default_verification_suite(db.conn, cfg)

    print(f"Verification run #{summary.run_id} — overall: {summary.overall_status}")
    for result in summary.results:
        _print_op_result(result)
    logger.info(
        "Ran the default AI verification suite",
        extra={"event": "ai_verify_suite", "component": "cli", "status": summary.overall_status},
    )
    return 0 if summary.overall_status in ("ok", "partial") else 1


def cmd_ai_verify_history(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        runs = list_ai_verification_runs(db.conn, limit=args.limit)

    if not runs:
        print("No AI verification runs yet. Run `secure ai verify suite` first.")
        return 0

    for run in runs:
        print(f"#{run.id:<4} [{run.overall_status:<8}] {run.started_at}  ops={len(run.operations)}")
    return 0


def cmd_ai_verify_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        run = find_ai_verification_run(db.conn, args.run_id)

    if run is None:
        print(f"No AI verification run found with id {args.run_id}.")
        return 1

    print(f"Verification run #{run.id} — overall: {run.overall_status}")
    print(f"  started:   {run.started_at}")
    print(f"  completed: {run.completed_at or '(incomplete)'}")
    if run.query_id:
        print(f"  triggered by query: #{run.query_id}")
    for result_dict in run.results:
        status = result_dict.get("status")
        op = result_dict.get("op")
        print(f"  [{status}] {op} {result_dict.get('args') or ''}".rstrip())
        if result_dict.get("error"):
            print(f"      error: {result_dict['error']}")
        if result_dict.get("output") is not None:
            print(f"      output: {_short(result_dict['output'])}")
    return 0


# ---------- secure ai changes ... ----------
#
# The change-request workflow (secure/ai/changes/). Every command here
# except `propose` is a thin wrapper around a deterministic state
# transition; `propose` runs the full Model A -> Model B -> deterministic
# tests -> PENDING change request pipeline. Nothing here can ever
# execute a change — see secure/ai/changes/__init__.py's own hard rules.


def cmd_ai_changes_propose(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    entity = None
    if args.entity_type or args.entity_key:
        if not (args.entity_type and args.entity_key):
            print("Both --entity-type and --entity-key are required together.")
            return 1
        try:
            entity = EntityRef(entity_type=args.entity_type, entity_key=args.entity_key)
        except ValueError as exc:
            print(f"Invalid entity: {exc}")
            return 1

    with Database(cfg.database_path()) as db:
        outcome = propose_simplification(
            db.conn, cfg, title=args.title, topic=args.topic,
            affected_component=args.affected_component, entity=entity,
        )

    for note in outcome.notes:
        print(f"note: {note}")

    if outcome.change_request is None:
        print("No change request was created (see notes above).")
        return 1

    cr = outcome.change_request
    print()
    print(f"{cr.cr_id} — status: {cr.status} — notification: {cr.notify_status}")
    print(f"  revision hash: {cr.revision_hash}")
    print(f"  title:         {cr.title}")
    print(f"  proposed change: {cr.proposed_change}")
    print(f"  risks:           {cr.risks}")
    print()
    print("THIS IS NOT APPROVED. Nothing has been changed. To act on it, a human must run:")
    print(f"  secure ai changes approve {cr.cr_id} {cr.revision_hash}")
    logger.info(
        "Proposed an AI change request",
        extra={"event": "ai_changes_propose", "component": "cli", "cr_id": cr.cr_id},
    )
    return 0


def cmd_ai_changes_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        crs = list_ai_change_requests(db.conn, status=args.status, limit=args.limit)

    if not crs:
        print("No change requests found." + (f" (status={args.status})" if args.status else ""))
        return 0

    for cr in crs:
        print(f"{cr.cr_id:<8} [{cr.status:<10}] {cr.created_at}  {cr.title}")
        print(f"         component={cr.affected_component}  notify={cr.notify_status}")
    return 0


def cmd_ai_changes_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        cr = find_ai_change_request(db.conn, args.cr_id)

    if cr is None:
        print(f"No change request found with id {args.cr_id!r}.")
        return 1

    print(f"{cr.cr_id} — status: {cr.status}")
    print(f"  created:        {cr.created_at}")
    print(f"  revision hash:  {cr.revision_hash}")
    print(f"  title:          {cr.title}")
    print(f"  affected:       {cr.affected_component}")
    print(f"  notify:         {cr.notify_status} ({cr.notified_at or 'not yet'})")
    if cr.status != "pending":
        print(f"  approved_at:    {cr.approved_at}")
        print(f"  approved_by:    {cr.approved_by}")
    print()
    print("Proposed change:")
    print(f"  {cr.proposed_change}")
    print()
    print("Reason:")
    print(f"  {cr.reason}")
    print()
    print("Risks:")
    print(f"  {cr.risks}")
    print()
    print("Model A opinion:")
    print(f"  {cr.model_a_opinion}")
    print()
    print("Model B opinion:")
    print(f"  {cr.model_b_opinion}")
    if cr.verification_run_id:
        print()
        print(f"Verification run: #{cr.verification_run_id} (see `secure ai verify show {cr.verification_run_id}`)")
    if cr.status == "pending":
        print()
        print(f"To approve: secure ai changes approve {cr.cr_id} {cr.revision_hash}")
        print(f"To reject:  secure ai changes reject {cr.cr_id}")
    return 0


def _resolve_approved_by(args: argparse.Namespace) -> str:
    if args.approved_by:
        return args.approved_by
    import getpass

    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def cmd_ai_changes_approve(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    approved_by = _resolve_approved_by(args)
    with Database(cfg.database_path()) as db:
        # A change request a repair run proposed must be approved through
        # `secure agent approve <run_id>`, which first re-checks that the
        # worktree diff still matches (revalidate_before_approval). This
        # path only compares the revision hash, so it refuses them.
        run = find_agent_repair_run_for_change_request(db.conn, args.cr_id)
        if run is not None:
            print(
                f"REFUSED: {args.cr_id} was proposed by agent repair run {run.run_id}. "
                f"Approve it with `secure agent approve {run.run_id} --cr-id {args.cr_id}`, which re-checks "
                "the worktree diff before approving."
            )
            return 1
        try:
            cr = approve_change(db.conn, args.cr_id, revision_hash=args.revision_hash, approved_by=approved_by)
        except RevisionMismatchError as exc:
            print(f"REFUSED: {exc}")
            return 1
        except ValueError as exc:
            print(f"Cannot approve: {exc}")
            return 1

    print(f"{cr.cr_id} approved by {cr.approved_by} at {cr.approved_at}.")
    print("This is a record of approval only — Secure does not execute changes automatically.")
    logger.info(
        "Approved an AI change request",
        extra={"event": "ai_changes_approve", "component": "cli", "cr_id": cr.cr_id},
    )
    return 0


def cmd_ai_changes_reject(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    approved_by = _resolve_approved_by(args)
    with Database(cfg.database_path()) as db:
        try:
            cr = reject_change(db.conn, args.cr_id, approved_by=approved_by)
        except ValueError as exc:
            print(f"Cannot reject: {exc}")
            return 1

    print(f"{cr.cr_id} rejected by {cr.approved_by} at {cr.approved_at}.")
    logger.info(
        "Rejected an AI change request",
        extra={"event": "ai_changes_reject", "component": "cli", "cr_id": cr.cr_id},
    )
    return 0
