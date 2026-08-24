"""
secure/validate/runner.py — Stage 5 orchestration: collects every
category module's SCENARIOS list, runs each scenario against its own
fresh sandbox (secure/validate/sandbox.py), and persists both the run
and every individual result to the REAL database the CLI opens
(secure/storage/models/validate.py) — never the sandbox.

Two different databases are deliberately in play at once here, and
that split is the whole point:

  - Each scenario's FIXTURE INJECTION happens against its own
    throwaway sandbox() database/AppConfig, created fresh per scenario
    so no scenario can see another scenario's synthetic data.
  - The RESULT of running that scenario (a ScenarioResult) is recorded
    into the operator's real ~/.secure database via
    add_validation_scenario_result(), the same way any other Secure
    module's findings are recorded — so `secure validate list`/`show`
    and historical trend-watching work like every other Secure
    subsystem, and a validation run's own history survives across
    invocations.

Mirrors secure/detect/registry.py's own sync_registry() shape: iterate
items, persist each, accumulate into a summary dataclass the CLI
prints. Adds no new scenario or scoring logic of its own — every
scenario function it calls is unchanged from Stage 2-4.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from secure import __version__
from secure.storage.models import add_validation_run, add_validation_scenario_result, complete_validation_run
from secure.validate import VALID_OUTCOMES
from secure.validate.sandbox import sandbox
from secure.validate.scenario import ScenarioResult
from secure.validate.scenarios import connections as connections_scenarios
from secure.validate.scenarios import crosssensor as crosssensor_scenarios
from secure.validate.scenarios import detections as detections_scenarios
from secure.validate.scenarios import fileintegrity as fileintegrity_scenarios
from secure.validate.scenarios import listening as listening_scenarios
from secure.validate.scenarios import persistence as persistence_scenarios

# Ordered so a report reads in the same category order every run —
# deterministic output is part of the "two runs against the same build
# and fixtures produce equivalent results" requirement.
_SCENARIO_MODULES = (
    persistence_scenarios,
    fileintegrity_scenarios,
    connections_scenarios,
    listening_scenarios,
    detections_scenarios,
    crosssensor_scenarios,
)


@dataclass
class ValidationSummary:
    run_id: str
    started_at: str
    completed_at: str
    secure_version: str
    results: "list[ScenarioResult]" = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def count(self, outcome: str) -> int:
        return sum(1 for r in self.results if r.outcome == outcome)

    @property
    def counts_by_outcome(self) -> "dict[str, int]":
        # Always includes every outcome key, even at zero — a report
        # or CLI print that iterates this dict can never silently omit
        # an outcome bucket just because nothing landed in it this run.
        return {outcome: self.count(outcome) for outcome in VALID_OUTCOMES}


def all_scenario_functions() -> "list":
    """Every scenario function across every category module, in the
    fixed, deterministic order defined by _SCENARIO_MODULES above —
    the single source of truth both the CLI and any test that wants
    "all scenarios" should call, instead of re-listing modules.
    """
    functions = []
    for module in _SCENARIO_MODULES:
        functions.extend(module.SCENARIOS)
    return functions


def run_validation_suite(conn: sqlite3.Connection) -> ValidationSummary:
    """Runs every registered scenario and persists the run + each
    result into `conn` (the CALLER's database — for the CLI this is
    the real ~/.secure database, for a test it's whatever the test
    passes in). Each scenario still gets its own independent sandbox()
    for fixture injection; `conn` is never touched during a scenario's
    `build()` call, only afterward when the already-decided
    ScenarioResult is written down.
    """
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    add_validation_run(conn, run_id=run_id, started_at=started_at, secure_version=__version__)

    results: "list[ScenarioResult]" = []
    for scenario_fn in all_scenario_functions():
        with sandbox() as sb:
            result = scenario_fn(sb)
        results.append(result)
        add_validation_scenario_result(
            conn,
            run_id=run_id,
            scenario_id=result.scenario_id,
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
            latency_ms=result.latency_ms,
            outcome=result.outcome,
            notes=result.notes,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )

    completed_at = datetime.now(timezone.utc).isoformat()
    summary = ValidationSummary(
        run_id=run_id,
        started_at=started_at,
        completed_at=completed_at,
        secure_version=__version__,
        results=results,
    )
    detail = ", ".join(f"{outcome}={count}" for outcome, count in summary.counts_by_outcome.items())
    complete_validation_run(
        conn, run_id=run_id, completed_at=completed_at, scenario_count=summary.total_count, detail=detail
    )
    return summary
