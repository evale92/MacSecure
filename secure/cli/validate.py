"""
secure/cli/validate.py — Phase 27: `secure validate ...`, the CLI
front end for secure/validate/. Thin on purpose, same split every
other secure/cli/*.py module keeps: this file only parses arguments,
opens the REAL database, and formats output — every actual scenario/
scoring/persistence decision lives in secure/validate/ and
secure/storage/models/validate.py.

`secure validate run` is the one command that actually DOES anything;
`list`/`show` are read-only history browsing over rows `run` already
wrote, the same list/show shape secure/cli/detect.py established.
Markdown/JSON report generation is Stage 6 (secure/validate/report.py)
and is deliberately not referenced here yet.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import find_validation_run, list_validation_runs, list_validation_scenario_results
from secure.validate import VALID_OUTCOMES
from secure.validate.report import write_report
from secure.validate.runner import run_validation_suite
from secure.cli import _bootstrap, logger


def cmd_validate_run(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        summary = run_validation_suite(db.conn)

    print(f"Validation run {summary.run_id} (Secure {summary.secure_version})")
    print(f"  {summary.total_count} scenario(s) evaluated:")
    for outcome in VALID_OUTCOMES:
        print(f"    {outcome:<19} {summary.count(outcome)}")

    misses = [r for r in summary.results if r.outcome not in ("PASS", "NOT_EVALUABLE", "SENSOR_UNAVAILABLE")]
    if misses:
        print()
        print("  MISS/PARTIAL detail (never hidden — see governing instruction):")
        for r in misses:
            print(f"    [{r.outcome}] {r.scenario_id}: {r.notes or r.expected_result}")

    print()
    print(f"  Run `secure validate show {summary.run_id}` for the full per-scenario table.")

    logger.info(
        "Ran the security validation suite",
        extra={"event": "validate_run", "component": "cli", "run_id": summary.run_id},
    )
    return 0 if summary.count("MISS") == 0 else 1


def cmd_validate_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        runs = list_validation_runs(db.conn, limit=args.limit)

    if not runs:
        print("No validation runs yet. Run `secure validate run` first.")
        return 0

    for run in runs:
        status = "complete" if run.completed_at else "incomplete"
        print(f"{run.run_id}  [{status}]  {run.started_at}  {run.scenario_count} scenario(s)  {run.detail}")
    return 0


def cmd_validate_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        run = find_validation_run(db.conn, args.run_id)
        if run is None:
            print(f"No validation run found with id {args.run_id!r}. Run `secure validate list`.")
            return 1
        results = list_validation_scenario_results(db.conn, args.run_id)

    print(f"Validation run {run.run_id} (Secure {run.secure_version})")
    print(f"  started:   {run.started_at}")
    print(f"  completed: {run.completed_at or '(incomplete)'}")
    print(f"  {run.scenario_count} scenario(s) — {run.detail}")
    print()
    for r in results:
        technique = f"[{r.technique_id}] {r.technique_name}" if r.technique_id else (r.technique_name or "—")
        print(f"  {r.outcome:<19} {r.scenario_id}")
        print(f"      category:    {r.category}")
        print(f"      technique:   {technique}")
        print(f"      description: {r.description}")
        print(f"      expected:    {r.expected_result}")
        print(f"      sensors:     {r.sensors_observed or '(none observed)'}")
        if r.correlation_result:
            print(f"      correlation: {r.correlation_result}")
        if r.dedup_result:
            print(f"      dedup:       {r.dedup_result}")
        if r.explanation_checklist:
            print(f"      explanation: {r.explanation_checklist}")
        if r.latency_ms is not None:
            print(f"      latency:     {r.latency_ms:.1f}ms (framework overhead, not real dwell time)")
        if r.notes:
            print(f"      notes:       {r.notes}")
        print()
    return 0


def cmd_validate_report(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    output_dir = Path(args.output_dir) if args.output_dir else None
    with Database(cfg.database_path()) as db:
        try:
            md_path, json_path = write_report(
                db.conn, run_id=args.run_id, output_dir=output_dir, write_json=not args.no_json
            )
        except ValueError as exc:
            print(str(exc))
            return 1

    print(f"Wrote {md_path}")
    if json_path is not None:
        print(f"Wrote {json_path}")

    logger.info(
        "Generated a security validation report",
        extra={"event": "validate_report", "component": "cli"},
    )
    return 0
