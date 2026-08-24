"""
secure/detect/firing_history.py — Phase 25 Stage 4: "what evidence
caused it to fire," per cataloged rule. Answers this by finding the
already-persisted alert rows a rule's own family already produces
(integration_alerts for sigma/yarax/suricata, correlation_alerts/
correlation_chain_alerts for Secure's own two correlation engines) and
handing each one to Phase 23's `explain_observation()` — the exact same
call the Alerts table and `secure investigate` already use. This module
adds ZERO new severity/confidence/evidence logic; it only locates which
already-stored rows belong to one specific catalog identity and asks
the existing explainer about each one.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List, Optional

from secure.evidence.model import ObservationRef
from secure.explain.explanation import Explanation
from secure.investigate.view import explain_observation
from secure.storage.models import (
    DetectionRuleRecord,
    IntegrationAlertRecord,
    list_correlation_alerts,
    list_correlation_chain_alerts,
    list_integration_alerts,
)
from secure.detect.registry import FAMILY_CORRELATE, FAMILY_SIGMA, FAMILY_SURICATA, FAMILY_YARAX

_CORRELATE_TEMPORAL = "temporal_clustering"
_CORRELATE_CHAIN = "chain_scoring"

# How many raw alert-table rows to scan when locating this rule's own
# firings, before this module's own identity filter narrows them down
# to `limit`. Generous on purpose — sigma/yarax/suricata all share one
# integration_alerts table across every rule in that family, so a
# small scan window could miss a real match for an infrequently-firing
# rule sitting behind more recent, unrelated alerts.
_SCAN_LIMIT = 1000


@dataclass(frozen=True)
class FiringEvent:
    """One occasion this rule fired, plus the SAME Explanation
    (severity/confidence/evidence/uncertainty) an analyst would see
    anywhere else in Secure looking at this exact row — never a
    second, parallel description of what happened.
    """

    source_table: str
    source_id: int
    occurred_at: "Optional[str]"
    severity: "Optional[str]"
    label: "Optional[str]"
    message: "Optional[str]"
    explanation: "Optional[Explanation]"


def _matches_sigma(record: DetectionRuleRecord, alert: IntegrationAlertRecord) -> bool:
    # sigma alerts are stored with identity_key == the rule's own id,
    # exactly — see secure/integrations/sigma/scanner.py's own
    # add_integration_alert(..., identity_key=rule.rule_id, ...).
    return alert.identity_key == record.rule_key


def _matches_yarax(record: DetectionRuleRecord, alert: IntegrationAlertRecord) -> bool:
    # yarax identity_key shape: "{file_hash_or_path}:{ruleset_name}:
    # {namespace}.{rule_name}" (secure/integrations/yarax/parser.py's
    # own parse_scan_results()) — ruleset_name is the segment between
    # the first and second colon. Tracked at ruleset-FILE granularity
    # (approved design), so any rule firing from within this ruleset
    # counts as a firing of this catalog entry.
    parts = alert.identity_key.split(":")
    return len(parts) >= 2 and parts[1] == record.rule_key


def _matches_suricata(record: DetectionRuleRecord, alert: IntegrationAlertRecord) -> bool:
    # suricata identity_key shape: "{flow_id}:{gid}:{signature_id}:
    # {rev}:{timestamp}" (secure/integrations/suricata/parser.py's own
    # _identity_key()) — rule_key is "gid:signature_id".
    parts = alert.identity_key.split(":")
    if len(parts) < 3:
        return False
    return f"{parts[1]}:{parts[2]}" == record.rule_key


_MATCHERS = {
    FAMILY_SIGMA: _matches_sigma,
    FAMILY_YARAX: _matches_yarax,
    FAMILY_SURICATA: _matches_suricata,
}


def _firing_event(conn: sqlite3.Connection, source_table: str, source_id: int, *, occurred_at, severity, label, message) -> FiringEvent:
    explanation = explain_observation(conn, ObservationRef(source_table=source_table, source_id=source_id))
    return FiringEvent(
        source_table=source_table, source_id=source_id, occurred_at=occurred_at,
        severity=severity, label=label, message=message, explanation=explanation,
    )


def firing_history(conn: sqlite3.Connection, record: DetectionRuleRecord, *, limit: int = 20) -> "List[FiringEvent]":
    """Every occasion this rule has fired, most recent first, up to
    `limit` — each paired with the same Explanation `secure explain`/
    `secure investigate` would show for that exact row. Returns `[]`
    for a rule that has never fired, which is a completely ordinary
    result, never an error.
    """
    if record.family in _MATCHERS:
        matcher = _MATCHERS[record.family]
        alerts = list_integration_alerts(conn, integration=record.family, limit=_SCAN_LIMIT)
        matched = [a for a in alerts if matcher(record, a)][:limit]
        return [
            _firing_event(
                conn, "integration_alerts", a.id,
                occurred_at=a.created_at, severity=a.severity, label=a.label, message=a.message,
            )
            for a in matched
        ]

    if record.family == FAMILY_CORRELATE:
        if record.rule_key == _CORRELATE_TEMPORAL:
            return [
                _firing_event(
                    conn, "correlation_alerts", a.id,
                    occurred_at=a.created_at, severity=a.severity, label=None, message=a.explanation,
                )
                for a in list_correlation_alerts(conn, limit=limit)
            ]
        if record.rule_key == _CORRELATE_CHAIN:
            return [
                _firing_event(
                    conn, "correlation_chain_alerts", a.id,
                    occurred_at=a.created_at, severity=a.severity, label=None, message=a.explanation,
                )
                for a in list_correlation_chain_alerts(conn, limit=limit)
            ]

    return []
