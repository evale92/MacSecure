"""
integrations/sigma/scanner.py — orchestrates one Sigma scan pass: load
configured rules, run capability.check_capability() on every one of
them, evaluate whichever come back EVALUABLE against recent osquery
telemetry, and persist the results. The only file in this integration
that touches the database.

Persistence shape (deliberately different from yarax's Phase 16
"zero matches = zero observations" convention): EVERY loaded rule gets
exactly one `sigma_rule_result` integration_observations row, every
scan pass — evaluable or not, matched or not — because Phase 17
explicitly requires per-rule EVALUATION STATUS to be exposed, not just
matches. Only rules with a genuine match additionally get an
integration_alerts row; secure/correlate/signals.py's
_collect_integrations() only ever reads integration_alerts, so a
`sigma_rule_result` row (NOT_EVALUABLE or evaluated-with-no-match) can
never itself become a correlation signal — only a real match can,
preserving Phase 15's double-counting-prevention discipline.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from secure.config import AppConfig
from secure.integrations.base import STATUS_DEGRADED, STATUS_OK, IntegrationHealth
from secure.integrations.sigma.analysis import (
    classify_sigma_match_severity,
    level_is_recognized,
    match_interpretation_note,
)
from secure.integrations.sigma.availability import check_availability
from secure.integrations.sigma.capability import EvaluationStatus, check_capability
from secure.integrations.sigma.evaluator import RuleEvaluation, evaluate_rule
from secure.integrations.sigma.rules import RuleLoadError, SigmaRule, load_rules
from secure.storage.models import (
    add_integration_alert,
    add_integration_observations,
    add_integration_run,
    list_detection_rules,
    list_integration_observations,
)

INTEGRATION_NAME = "sigma"
SIGMA_RULE_RESULT = "sigma_rule_result"

DEFAULT_LOOKBACK_HOURS = 24.0
DEFAULT_OBSERVATION_LIMIT = 2000


@dataclass(frozen=True)
class SigmaRuleOutcome:
    """One rule's full result for this scan pass — what `secure
    integrations sigma rules`/`scan` report per rule.
    """

    rule: SigmaRule
    evaluation_status: str  # "evaluable" | "not_evaluable"
    capability_reason: str
    required_telemetry: str
    matched: bool
    matches_count: int
    observations_checked: int
    truncated: bool
    evaluation_error: "Optional[str]"
    observation_id: "Optional[int]"
    alert_id: "Optional[int]"


@dataclass
class SigmaScanResult:
    scanned_at: str
    run_id: str
    health: IntegrationHealth
    rules_loaded: List[SigmaRule] = field(default_factory=list)
    rule_load_errors: List[RuleLoadError] = field(default_factory=list)
    outcomes: List[SigmaRuleOutcome] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return self.health.available

    @property
    def evaluable_count(self) -> int:
        return sum(1 for o in self.outcomes if o.evaluation_status == EvaluationStatus.EVALUABLE.value)

    @property
    def not_evaluable_count(self) -> int:
        return sum(
            1 for o in self.outcomes if o.evaluation_status == EvaluationStatus.NOT_EVALUABLE.value
        )

    @property
    def matched_count(self) -> int:
        return sum(1 for o in self.outcomes if o.matched)


def _rule_result_fields(
    rule: SigmaRule,
    capability_status: str,
    capability_reason: str,
    required_telemetry: str,
    evaluation: "Optional[RuleEvaluation]",
) -> dict:
    fields = {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "level": rule.level,
        "sigma_status": rule.sigma_status,
        "tags": list(rule.tags),
        "category": (rule.logsource or {}).get("category"),
        "source_path": rule.source_path,
        "source_hash": rule.source_hash,
        "version_label": rule.version_label,
        "required_telemetry": required_telemetry,
        "evaluation_status": capability_status,
        "capability_reason": capability_reason,
        "matched": False,
        "observations_checked": 0,
        "truncated": False,
        "evaluation_error": None,
        "matches": [],
    }
    if evaluation is not None:
        fields["matched"] = evaluation.matched
        fields["observations_checked"] = evaluation.observations_checked
        fields["truncated"] = evaluation.truncated
        fields["evaluation_error"] = evaluation.error
        fields["matches"] = [
            {
                "observation_id": m.observation_id,
                "identity_key": m.identity_key,
                "collected_at": m.collected_at,
                "summary": m.summary,
            }
            for m in evaluation.matches
        ]
    return fields


def _build_alert_message(rule: SigmaRule, recognized: bool) -> str:
    return match_interpretation_note(rule.title, rule.level, recognized, rule.description)


def scan_sigma(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    lookback_hours: float = DEFAULT_LOOKBACK_HOURS,
    observation_limit: int = DEFAULT_OBSERVATION_LIMIT,
) -> SigmaScanResult:
    """Run every configured Sigma rule once: capability-check it, then
    (if EVALUABLE) evaluate it against osquery observations collected
    within the last `lookback_hours`. Persists one `sigma_rule_result`
    observation per rule and one integration_alerts row per genuine
    match.
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    health = check_availability()
    if not health.available:
        add_integration_run(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            started_at=now,
            completed_at=datetime.now(timezone.utc).isoformat(),
            status=health.status,
            detail=health.detail,
            tool_version=health.tool_version,
            observations_collected=0,
            alerts_generated=0,
        )
        return SigmaScanResult(scanned_at=now, run_id=run_id, health=health)

    rules_dir = cfg.sigma_rules_dir_path()
    rules, load_errors = load_rules(rules_dir)

    # Phase 25 Detection Engineering Workbench: a rule an operator has
    # explicitly disabled via `secure detect disable` is skipped here,
    # BEFORE it is ever capability-checked or evaluated — the real
    # enforcement half of that phase's own approved design. Every
    # detection_rules row defaults to enabled=True, and this query
    # returns [] entirely until an operator has both run
    # `secure detect sync` AND explicitly disabled something — so a
    # deployment that has never touched `secure detect` sees IDENTICAL
    # scan output to before this phase existed.
    disabled_rule_ids = {r.rule_key for r in list_detection_rules(conn, family="sigma", enabled=False)}
    if disabled_rule_ids:
        rules = [r for r in rules if r.rule_id not in disabled_rule_ids]

    cutoff_iso = (started_at - timedelta(hours=lookback_hours)).isoformat()

    # Cache one telemetry batch per observation_kind actually needed
    # this pass, rather than re-querying per rule — every EVALUABLE
    # process_creation rule shares the same "processes" batch, etc.
    telemetry_cache: dict = {}

    outcomes: List[SigmaRuleOutcome] = []
    observations_collected = 0
    alerts_generated = 0

    for rule in rules:
        capability = check_capability(rule)

        evaluation: "Optional[RuleEvaluation]" = None
        if capability.evaluable:
            support = capability.category_support
            if support.observation_kind not in telemetry_cache:
                telemetry_cache[support.observation_kind] = list_integration_observations(
                    conn,
                    integration=support.integration,
                    kind=support.observation_kind,
                    since=cutoff_iso,
                    limit=observation_limit,
                )
            batch = telemetry_cache[support.observation_kind]
            evaluation = evaluate_rule(rule, support, batch)

        fields = _rule_result_fields(
            rule,
            capability.status.value,
            capability.reason,
            capability.required_telemetry,
            evaluation,
        )
        source_query = (
            capability.required_telemetry
            if capability.evaluable
            else f"not evaluated: {capability.reason}"
        )

        observation_ids = add_integration_observations(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            rows=[(SIGMA_RULE_RESULT, rule.rule_id, fields, source_query, now)],
        )
        observation_id = observation_ids[0] if observation_ids else None
        observations_collected += 1

        alert_id: "Optional[int]" = None
        matched = bool(evaluation and evaluation.matched)
        if matched:
            recognized = level_is_recognized(rule.level)
            severity = classify_sigma_match_severity(rule.level)
            alert_id = add_integration_alert(
                conn,
                run_id=run_id,
                integration=INTEGRATION_NAME,
                kind=fields["category"] or "unknown",
                discrepancy="match",  # sigma has no "native comparison side" — always this constant, mirrors yarax
                severity=severity,
                identity_key=rule.rule_id,
                label=rule.title,
                message=_build_alert_message(rule, recognized),
                source_observation_id=observation_id,
            )
            alerts_generated += 1

        outcomes.append(
            SigmaRuleOutcome(
                rule=rule,
                evaluation_status=capability.status.value,
                capability_reason=capability.reason,
                required_telemetry=capability.required_telemetry,
                matched=matched,
                matches_count=len(evaluation.matches) if evaluation else 0,
                observations_checked=evaluation.observations_checked if evaluation else 0,
                truncated=evaluation.truncated if evaluation else False,
                evaluation_error=evaluation.error if evaluation else None,
                observation_id=observation_id,
                alert_id=alert_id,
            )
        )

    detail_parts = [
        f"rules_loaded={len(rules)}",
        f"evaluable={sum(1 for o in outcomes if o.evaluation_status == EvaluationStatus.EVALUABLE.value)}",
        f"not_evaluable={sum(1 for o in outcomes if o.evaluation_status == EvaluationStatus.NOT_EVALUABLE.value)}",
        f"matched={alerts_generated}",
        f"lookback_hours={lookback_hours}",
    ]
    if not rules and not load_errors:
        detail_parts.append(f"no rule files found in {rules_dir}")
    status = STATUS_DEGRADED if load_errors or any(o.evaluation_error for o in outcomes) else STATUS_OK
    if load_errors:
        detail_parts.append(f"rule_load_errors={len(load_errors)}")
    detail = "; ".join(detail_parts)
    effective_health = IntegrationHealth(
        status=status, detail=detail, collected_at=now, tool_version=health.tool_version
    )

    add_integration_run(
        conn,
        run_id=run_id,
        integration=INTEGRATION_NAME,
        started_at=now,
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=status,
        detail=detail,
        tool_version=health.tool_version,
        observations_collected=observations_collected,
        alerts_generated=alerts_generated,
    )

    return SigmaScanResult(
        scanned_at=now,
        run_id=run_id,
        health=effective_health,
        rules_loaded=rules,
        rule_load_errors=load_errors,
        outcomes=outcomes,
    )
