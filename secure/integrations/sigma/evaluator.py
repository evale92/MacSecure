"""
integrations/sigma/evaluator.py — runs one EVALUABLE SigmaRule against
a batch of already-collected osquery telemetry (integration_observations
rows secure/integrations/osquery/scanner.py already persisted) and
returns the bounded list of matches.

This module never touches the database and never decides whether a
rule is evaluable in the first place — that's capability.py's job,
always called first by scanner.py. Everything here assumes it has
already been told EVALUABLE and handed the right CategorySupport.

One osquery ExternalObservation's already-parsed `.fields` dict IS the
"event" a rule's selections are matched against, unmodified — every
Secure/osquery field name capability.py's field_map maps TO (`path`,
`cmdline`, `remote_address`, `remote_port`, `proto`, `process_name`)
is already exactly the key osquery's own
secure/integrations/osquery/parser.py writes into that dict, so no
event-shape translation is needed beyond the field_map lookup
condition.py's match_selection() already does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from secure.integrations.sigma.capability import CategorySupport
from secure.integrations.sigma.condition import (
    ConditionError,
    evaluate_condition,
    match_selection,
    parse_condition,
)
from secure.integrations.sigma.rules import SigmaRule
from secure.storage.models.integrations import IntegrationObservationRecord

# A single rule matching an unbounded number of observations would make
# both the persisted observation row and any resulting alert unreadable
# (and defeats "avoid indiscriminate scanning" in spirit even though
# this is post-hoc, not a scan target list). Bounded, not silently
# truncated — RuleEvaluation.truncated tells the caller when this cap
# was hit.
MAX_MATCHED_EVIDENCE = 25

_CONDITION_KEY = "condition"


@dataclass(frozen=True)
class MatchedEvidence:
    """One observation that satisfied a rule's condition — the "matched
    evidence" Phase 17 requires every rule to be able to expose.
    """

    observation_id: int
    identity_key: str
    collected_at: str
    summary: str


@dataclass(frozen=True)
class RuleEvaluation:
    """The outcome of running one EVALUABLE rule against one batch of
    observations. `error` is set (and `matched`/`matches` left empty)
    if the rule's condition itself couldn't be parsed or evaluated —
    this is reported as its own distinct outcome, never folded into
    either "matched" or a silent CLEAN.
    """

    matched: bool
    matches: "List[MatchedEvidence]"
    observations_checked: int
    truncated: bool
    error: "str | None"


def _selection_names(detection: dict) -> List[str]:
    return [key for key in detection.keys() if key != _CONDITION_KEY]


def _summarize_event(support: CategorySupport, fields: dict) -> str:
    parts = []
    for sigma_field, secure_field in support.field_map.items():
        value = fields.get(secure_field)
        if value:
            parts.append(f"{sigma_field}={value}")
    return ", ".join(parts) if parts else "(no mapped fields present)"


def evaluate_rule(
    rule: SigmaRule,
    support: CategorySupport,
    observations: "List[IntegrationObservationRecord]",
) -> RuleEvaluation:
    """Evaluate one rule's condition against every observation in
    `observations` (expected to already be filtered to
    support.observation_kind by the caller — this function doesn't
    re-check kind). Returns every match found, up to
    MAX_MATCHED_EVIDENCE.
    """
    try:
        condition_ast = parse_condition(rule.detection.get(_CONDITION_KEY, ""))
    except ConditionError as exc:
        return RuleEvaluation(
            matched=False,
            matches=[],
            observations_checked=0,
            truncated=False,
            error=f"condition parse error: {exc}",
        )

    selection_names = _selection_names(rule.detection)
    matches: List[MatchedEvidence] = []
    checked = 0
    truncated = False

    for obs in observations:
        checked += 1
        event = obs.fields
        try:
            selection_results: Dict[str, bool] = {
                name: match_selection(rule.detection[name], event, support.field_map)
                for name in selection_names
            }
            is_match = evaluate_condition(condition_ast, selection_results)
        except ConditionError as exc:
            return RuleEvaluation(
                matched=bool(matches),
                matches=matches,
                observations_checked=checked,
                truncated=truncated,
                error=f"condition evaluation error: {exc}",
            )

        if is_match:
            if len(matches) >= MAX_MATCHED_EVIDENCE:
                truncated = True
                continue
            matches.append(
                MatchedEvidence(
                    observation_id=obs.id,
                    identity_key=obs.identity_key,
                    collected_at=obs.collected_at,
                    summary=_summarize_event(support, event),
                )
            )

    return RuleEvaluation(
        matched=bool(matches),
        matches=matches,
        observations_checked=checked,
        truncated=truncated,
        error=None,
    )
