"""
secure/validate/scenario.py — the pure ScenarioResult shape every
scenario function (secure/validate/scenarios/*.py) returns, plus a
small timing helper. No I/O, no scanner-specific knowledge — this
module doesn't know what a LaunchAgent or a listening port is, only
how to describe one scenario's outcome uniformly so runner.py and
report.py never special-case a category.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    technique_id: "Optional[str]"
    technique_name: "Optional[str]"
    category: str
    description: str
    expected_result: str
    sensors_observed: "list[str]"
    findings: "list[dict]"
    correlation_result: "Optional[str]"
    explanation_checklist: "dict[str, bool]"
    dedup_result: "Optional[str]"
    latency_ms: "Optional[float]"
    outcome: str
    notes: str
    started_at: str
    completed_at: str


def timed(scenario_id: str, build: "Callable[[], ScenarioResult]") -> ScenarioResult:
    """Runs `build()` (which does the actual fixture injection + real
    scan/correlate/explain calls) and returns its ScenarioResult, but
    with started_at/completed_at/latency_ms filled in from a wall-clock
    timer wrapped around the whole call — the scenario function itself
    never has to manage timestamps.

    Honesty note carried into every report: this measures in-process
    framework overhead (fixture setup + the real scan pass + explain
    call), not real-world attacker dwell time or detection latency
    against a live adversary — see docs/SECURITY_VALIDATION.md.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    result = build()
    latency_ms = (time.monotonic() - t0) * 1000.0
    completed_at = datetime.now(timezone.utc).isoformat()

    return ScenarioResult(
        scenario_id=result.scenario_id or scenario_id,
        technique_id=result.technique_id,
        technique_name=result.technique_name,
        category=result.category,
        description=result.description,
        expected_result=result.expected_result,
        sensors_observed=result.sensors_observed,
        findings=result.findings,
        correlation_result=result.correlation_result,
        explanation_checklist=result.explanation_checklist,
        dedup_result=result.dedup_result,
        latency_ms=latency_ms,
        outcome=result.outcome,
        notes=result.notes,
        started_at=started_at,
        completed_at=completed_at,
    )
