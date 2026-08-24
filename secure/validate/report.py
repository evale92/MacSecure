"""
secure/validate/report.py — Stage 6: turns one persisted validation
run (secure/storage/models/validate.py) into the portfolio-facing
Markdown report plus an optional machine-readable JSON twin. Pure
formatting only — no scenario logic, no scoring, no DB writes; this
module's only inputs are already-decided records, its only outputs
are strings/dicts and, via write_report(), files on disk.

Governing instruction, verbatim, and how this module honors it:

    "Never calculate a misleading overall 'security percentage' that
    hides misses or unavailable sensors."

This module has NO function anywhere that reduces a run to a single
score. The only aggregate numbers it ever prints are the per-outcome
COUNTS (how many PASS, how many MISS, how many NOT_EVALUABLE, how many
SENSOR_UNAVAILABLE, how many PARTIAL) — never a ratio, percentage, or
letter grade. list_validation_scenario_results() itself never accepts
an outcome filter (see that module's own docstring), so every scenario
this run recorded — including every MISS — appears in this report; the
report generator has no filtering knob to remove one even if it wanted
to.

    "make failures highly visible"

MISS and PARTIAL rows are called out in their own "Failures and Gaps"
section near the top of the report, ahead of the full per-scenario
detail, in addition to appearing in the full table.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from secure.storage.models import find_latest_validation_run, find_validation_run, list_validation_scenario_results
from secure.storage.models.validate import ValidationRunRecord, ValidationScenarioResultRecord
from secure.validate import VALID_OUTCOMES

_DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent.parent / "docs" / "generated"

_LATENCY_NOTE = (
    "Latency figures measure in-process framework overhead (fixture injection, the real scan "
    "pass, and any explain() call) timed by secure/validate/scenario.py's timed() helper — they "
    "are NOT a measurement of real-world attacker dwell time or detection latency against a live "
    "adversary. See docs/SECURITY_VALIDATION.md."
)

_SANDBOX_NOTE = (
    "Every scenario below ran against a throwaway, temp-file sandbox database and AppConfig "
    "(secure/validate/sandbox.py) with synthetic fixtures injected at real scanner/integration "
    "boundaries — never against the operator's real ~/.secure database or real filesystem "
    "locations outside that sandbox. ATT&CK technique IDs and artifact shapes are drawn from "
    "MITRE ATT&CK / Atomic Red Team as CONTENT only, not as a live execution mechanism."
)


def _outcome_counts(results: "list[ValidationScenarioResultRecord]") -> "dict[str, int]":
    counts = {outcome: 0 for outcome in VALID_OUTCOMES}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    return counts


def _fmt_list(items) -> str:
    return ", ".join(str(i) for i in items) if items else "(none)"


def _fmt_checklist(checklist: "dict[str, bool]") -> str:
    if not checklist:
        return "(not applicable — see scenario notes)"
    return ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in checklist.items())


def _fmt_findings(findings: "list[dict]") -> str:
    if not findings:
        return "(none)"
    return "; ".join(json.dumps(f, sort_keys=True) for f in findings)


def generate_markdown_report(
    run: ValidationRunRecord, results: "list[ValidationScenarioResultRecord]"
) -> str:
    counts = _outcome_counts(results)
    total = len(results)
    failures = [r for r in results if r.outcome in ("MISS", "PARTIAL")]

    lines: "list[str]" = []
    lines.append("# Secure — Security Validation Report")
    lines.append("")
    lines.append(f"- **Secure version:** {run.secure_version}")
    lines.append(f"- **Run ID:** {run.run_id}")
    lines.append(f"- **Started:** {run.started_at}")
    lines.append(f"- **Completed:** {run.completed_at or '(incomplete)'}")
    lines.append(f"- **Total scenarios:** {total}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        "This report records the result of running Secure's own controlled validation "
        "framework (Phase 27) against Secure's real detection, correlation, and explanation "
        "code paths, using synthetic-but-realistic fixtures grounded in MITRE ATT&CK technique "
        "IDs. It is not a penetration test and does not simulate a real adversary end to end — "
        "see 'Scope and Honesty Notes' below for exactly what is and is not measured."
    )
    lines.append("")
    lines.append("Outcome counts (never filtered — every scenario this run recorded appears below):")
    lines.append("")
    for outcome in VALID_OUTCOMES:
        lines.append(f"- **{outcome}:** {counts[outcome]}")
    lines.append("")
    lines.append(
        "No single aggregate \"security score\" or percentage is calculated anywhere in this "
        "report, by design — a percentage would obscure exactly which capability gaps and "
        "misses exist, which is the opposite of this framework's purpose."
    )
    lines.append("")

    lines.append("## Failures and Gaps")
    lines.append("")
    if not failures:
        lines.append(
            "No MISS or PARTIAL outcomes this run. This does not mean Secure has no gaps — see "
            "the NOT_EVALUABLE and SENSOR_UNAVAILABLE rows in the full table below for "
            "documented, permanent capability boundaries that this framework deliberately "
            "cannot mark PASS."
        )
    else:
        for r in failures:
            lines.append(f"- **[{r.outcome}] {r.scenario_id}** — {r.notes or r.expected_result}")
    lines.append("")

    lines.append("## Scenario Summary")
    lines.append("")
    lines.append("| Scenario | Category | ATT&CK | Outcome | Latency (ms) |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        technique = f"{r.technique_id}" if r.technique_id else "—"
        latency = f"{r.latency_ms:.1f}" if r.latency_ms is not None else "—"
        lines.append(f"| {r.scenario_id} | {r.category} | {technique} | {r.outcome} | {latency} |")
    lines.append("")

    lines.append("## Full Scenario Detail")
    lines.append("")
    for r in results:
        technique = f"{r.technique_id} — {r.technique_name}" if r.technique_id else "(no ATT&CK mapping)"
        lines.append(f"### {r.scenario_id} — {r.outcome}")
        lines.append("")
        lines.append(f"- **Category:** {r.category}")
        lines.append(f"- **ATT&CK technique:** {technique}")
        lines.append(f"- **Description:** {r.description}")
        lines.append(f"- **Expected result:** {r.expected_result}")
        lines.append(f"- **Sensors that observed it:** {_fmt_list(r.sensors_observed)}")
        lines.append(f"- **Findings:** {_fmt_findings(r.findings)}")
        lines.append(f"- **Correlation result:** {r.correlation_result or '(not applicable)'}")
        lines.append(f"- **Explanation-quality checklist:** {_fmt_checklist(r.explanation_checklist)}")
        lines.append(f"- **Deduplication result:** {r.dedup_result or '(not applicable)'}")
        lines.append(
            f"- **Latency:** {f'{r.latency_ms:.1f}ms' if r.latency_ms is not None else '(not measured)'}"
        )
        lines.append(f"- **Outcome:** {r.outcome}")
        lines.append(f"- **Notes / limitations:** {r.notes or '(none)'}")
        lines.append("")

    lines.append("## Scope and Honesty Notes")
    lines.append("")
    lines.append(f"- {_SANDBOX_NOTE}")
    lines.append(f"- {_LATENCY_NOTE}")
    lines.append(
        "- NOT_EVALUABLE and SENSOR_UNAVAILABLE outcomes are recorded as first-class results, "
        "not omitted or treated as passing — see each scenario's own notes above for exactly "
        "why."
    )
    lines.append(
        "- This framework was not optimized to make Secure look good: scenarios were written to "
        "include deliberately missed, partially detected, unavailable, and not-evaluable cases "
        "alongside passing ones (see secure/validate/scenarios/ and docs/SECURITY_VALIDATION.md)."
    )
    lines.append("")

    return "\n".join(lines)


def generate_json_report(
    run: ValidationRunRecord, results: "list[ValidationScenarioResultRecord]"
) -> dict:
    return {
        "secure_version": run.secure_version,
        "run_id": run.run_id,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "total_scenarios": len(results),
        "outcome_counts": _outcome_counts(results),
        "scenarios": [asdict(r) for r in results],
        "notes": {
            "sandbox": _SANDBOX_NOTE,
            "latency": _LATENCY_NOTE,
            "no_aggregate_score": (
                "This report deliberately contains no single aggregate security score or "
                "percentage — see outcome_counts for the full, unfiltered breakdown."
            ),
        },
    }


def write_report(
    conn: sqlite3.Connection,
    run_id: "Optional[str]" = None,
    output_dir: "Optional[Path]" = None,
    *,
    write_json: bool = True,
) -> "tuple[Path, Optional[Path]]":
    """Resolves `run_id` (defaults to the latest COMPLETED run) to its
    persisted records, then writes docs/generated/VALIDATION_REPORT.md
    (always) and validation_report.json (unless write_json=False) into
    `output_dir` (defaults to docs/generated/ at the repo root).
    Returns (markdown_path, json_path_or_None). Raises ValueError if no
    matching run exists — never silently writes an empty report.
    """
    run = find_validation_run(conn, run_id) if run_id else find_latest_validation_run(conn)
    if run is None:
        raise ValueError(
            f"No validation run found (run_id={run_id!r}). Run `secure validate run` first."
            if run_id
            else "No completed validation run found. Run `secure validate run` first."
        )

    results = list_validation_scenario_results(conn, run.run_id)

    out_dir = output_dir or _DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / "VALIDATION_REPORT.md"
    md_path.write_text(generate_markdown_report(run, results))

    json_path = None
    if write_json:
        json_path = out_dir / "validation_report.json"
        json_path.write_text(json.dumps(generate_json_report(run, results), indent=2, sort_keys=True))

    return md_path, json_path
