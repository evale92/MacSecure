"""
secure/ai/context.py — Phase 28's structured, read-only context
builder: the ONE place this whole package touches Secure's real data,
and the concrete enforcement of secure/ai/__init__.py's rule 1
("read-only by construction"). Every field here comes from an existing
read-only call — secure.investigate.view.investigate()/
explain_observation() (Phase 23), cached secure.storage.models
threat-intel reads (Phase 20, cache-only — never triggers a NEW
network lookup), and each integration's own check_availability()
(Phase 15-19/24). This module computes nothing new about a finding; it
only assembles and bounds what already exists.

Two modes:

    MODE_ENTITY   — "ask about this finding/entity" (the governing
        instruction's own examples: "why is this finding important?").
        Reuses secure.investigate.view.investigate() directly — the
        exact same call `secure investigate show` already uses, so an
        AI answer and the CLI's own investigation view can never
        disagree about what's known.
    MODE_FREEFORM — "what should I investigate next?" with no entity
        named. Pulls the most recent rows across every alert table
        that has a registered explainer (secure/explain/dispatch.py's
        own _EXPLAINERS set) plus recent anomaly_events, bounded by
        `per_table_limit`.

Every context is bounded (max_findings/max_timeline_events/
per_table_limit) — an oversized context is truncated, never silently
dropped without saying so (`truncated`/`notes` always reflect it
honestly). `AnalystContext.evidence_manifest()` derives the citation
whitelist directly from what's actually in the context (never
hand-maintained separately), so it can never drift out of sync with
what a model was actually shown.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from secure.config import AppConfig
from secure.explain.dispatch import explain
from secure.explain.explanation import Explanation
from secure.investigate.entity import INDICATOR, EntityRef
from secure.investigate.timeline import DEFAULT_MAX_HOPS
from secure.investigate.view import explain_observation, investigate
from secure.storage.models import (
    find_latest_lookups_for_indicator,
    list_anomaly_events,
    list_arp_alerts,
    list_ble_alerts,
    list_bluetooth_alerts,
    list_correlation_alerts,
    list_correlation_chain_alerts,
    list_file_integrity_alerts,
    list_integration_alerts,
    list_persistence_alerts,
    list_wifi_alerts,
)

MODE_ENTITY = "entity"
MODE_FREEFORM = "freeform"

DEFAULT_MAX_FINDINGS = 20
DEFAULT_MAX_TIMELINE_EVENTS = 30
DEFAULT_FREEFORM_PER_TABLE_LIMIT = 10
DEFAULT_FREEFORM_MAX_FINDINGS = 40

# Every alert table secure/explain/dispatch.py has a real explainer
# for, paired with its own most-recent-first list_* reader. Kept as a
# separate table here (not imported from dispatch._EXPLAINERS, which
# only tells us WHICH tables are explainable, not HOW to list recent
# rows) — same shape secure/investigate/view.py's own
# _ALERT_FINDER_BY_TABLE keeps for the identical reason.
_FREEFORM_ALERT_TABLES = (
    ("persistence_alerts", lambda conn, limit: list_persistence_alerts(conn, limit=limit)),
    ("file_integrity_alerts", lambda conn, limit: list_file_integrity_alerts(conn, limit=limit)),
    ("correlation_alerts", lambda conn, limit: list_correlation_alerts(conn, limit=limit)),
    ("correlation_chain_alerts", lambda conn, limit: list_correlation_chain_alerts(conn, limit=limit)),
    ("integration_alerts", lambda conn, limit: list_integration_alerts(conn, limit=limit)),
    ("arp_alerts", lambda conn, limit: list_arp_alerts(conn, limit=limit)),
    ("wifi_alerts", lambda conn, limit: list_wifi_alerts(conn, limit=limit)),
    ("bluetooth_alerts", lambda conn, limit: list_bluetooth_alerts(conn, limit=limit)),
    ("ble_alerts", lambda conn, limit: list_ble_alerts(conn, limit=limit)),
)


@dataclass
class AnalystContext:
    """Everything a model is allowed to see for one question — fully
    JSON-serializable (`to_dict()`), fully bounded, fully self-describing
    about what it left out (`truncated`/`notes`).
    """

    generated_at: str
    mode: str
    entity: "Optional[dict]"
    exists: "Optional[bool]"
    summary: dict
    findings: "list[dict]" = field(default_factory=list)
    timeline: "list[dict]" = field(default_factory=list)
    related_evidence: "list[dict]" = field(default_factory=list)
    pivots: "list[dict]" = field(default_factory=list)
    threat_intel: "list[dict]" = field(default_factory=list)
    tool_health: "list[dict]" = field(default_factory=list)
    truncated: bool = False
    notes: "list[str]" = field(default_factory=list)

    def evidence_manifest(self) -> "list[dict]":
        """Every (source_table, source_id) that appears anywhere in
        this context — the citation whitelist secure/ai/response.py
        checks every model-claimed citation against. Derived, not
        hand-maintained, so it can never omit or over-claim what the
        model actually saw.
        """
        ids = set()
        for bucket in (self.findings, self.timeline, self.related_evidence):
            for item in bucket:
                table = item.get("source_table")
                source_id = item.get("source_id")
                if table and source_id is not None:
                    ids.add((table, source_id))
        return [{"source_table": t, "source_id": i} for (t, i) in sorted(ids)]

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "mode": self.mode,
            "entity": self.entity,
            "exists": self.exists,
            "summary": self.summary,
            "findings": self.findings,
            "timeline": self.timeline,
            "related_evidence": self.related_evidence,
            "pivots": self.pivots,
            "threat_intel": self.threat_intel,
            "tool_health": self.tool_health,
            "evidence_manifest": self.evidence_manifest(),
            "truncated": self.truncated,
            "notes": self.notes,
        }


def _explanation_to_dict(source_table: str, source_id: int, explanation: "Optional[Explanation]") -> "Optional[dict]":
    if explanation is None:
        return None
    return {
        "kind": "alert",
        "source_table": source_table,
        "source_id": source_id,
        "citation": f"{source_table}#{source_id}",
        "summary": explanation.summary,
        "severity": explanation.severity,
        "confidence": explanation.confidence,
        "confidence_reason": explanation.confidence_reason,
        "significance": explanation.significance,
        "recommended_action_text": explanation.recommended_action_text,
        "evidence": [{"text": e.text, "provenance": e.provenance} for e in explanation.evidence],
        "correlated_events": list(explanation.correlated_events),
        "uncertainty_status": explanation.uncertainty_status,
        "uncertainty": list(explanation.uncertainty),
        "degraded": explanation.degraded,
        "degraded_reason": explanation.degraded_reason,
    }


def _collect_tool_health(cfg: AppConfig) -> "list[dict]":
    """Best-effort snapshot of every integration's own health — never
    raises, a single integration's health check failing just becomes
    its own honest 'error' row rather than aborting the whole context
    build.
    """
    from secure.dfir.velociraptor.availability import check_availability as velociraptor_health
    from secure.integrations.osquery.availability import check_availability as osquery_health
    from secure.integrations.sigma.availability import check_availability as sigma_health
    from secure.integrations.suricata.availability import check_availability as suricata_health
    from secure.integrations.yarax.availability import check_availability as yarax_health
    from secure.integrations.zeek.availability import check_availability as zeek_health

    checks = (
        ("osquery", lambda: osquery_health()),
        ("yarax", lambda: yarax_health()),
        ("sigma", lambda: sigma_health()),
        ("suricata", lambda: suricata_health(cfg)),
        ("zeek", lambda: zeek_health(cfg)),
        ("velociraptor", lambda: velociraptor_health(cfg)),
    )
    results = []
    for name, fn in checks:
        try:
            health = fn()
            results.append(
                {
                    "name": name, "status": health.status, "detail": health.detail,
                    "tool_version": health.tool_version, "collected_at": health.collected_at,
                }
            )
        except Exception as exc:  # never let a health check abort context assembly
            results.append(
                {
                    "name": name, "status": "error",
                    "detail": f"health check itself failed: {exc}",
                    "tool_version": None, "collected_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    return results


def _threat_intel_for_entity(conn: sqlite3.Connection, entity: EntityRef) -> "list[dict]":
    """Cache-only read — reuses find_latest_lookups_for_indicator()
    exactly as secure/threatintel/enrich.py's own attach_cached_threat_intel()
    does. NEVER triggers a new provider lookup (never calls .lookup()
    on anything) — preserves the existing 'nothing silently calls out
    to the network' invariant Phase 20 established.
    """
    if entity.entity_type != INDICATOR:
        return []
    indicator_type, _, indicator_value = entity.entity_key.partition(":")
    if not indicator_type or not indicator_value:
        return []
    lookups = find_latest_lookups_for_indicator(conn, indicator_type, indicator_value)
    return [
        {
            "provider": lookup.provider, "indicator_type": lookup.indicator_type,
            "indicator_value": lookup.indicator_value, "status": lookup.status,
            "verdict": lookup.verdict, "score": lookup.score, "score_meaning": lookup.score_meaning,
            "categories": list(lookup.categories), "queried_at": lookup.queried_at,
            "expires_at": lookup.expires_at, "detail": lookup.detail,
        }
        for lookup in lookups
    ]


def build_entity_context(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    entity: EntityRef,
    *,
    max_hops: "Optional[int]" = None,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_timeline_events: int = DEFAULT_MAX_TIMELINE_EVENTS,
) -> AnalystContext:
    hops = max_hops if max_hops is not None else DEFAULT_MAX_HOPS
    view = investigate(conn, entity, max_hops=hops)
    generated_at = datetime.now(timezone.utc).isoformat()
    entity_dict = {"entity_type": entity.entity_type, "entity_key": entity.entity_key}

    if not view.exists:
        return AnalystContext(
            generated_at=generated_at, mode=MODE_ENTITY, entity=entity_dict, exists=False,
            summary={}, tool_health=_collect_tool_health(cfg),
            notes=["This entity has no record in Secure's database at all — nothing to investigate yet."],
        )

    notes: "list[str]" = []
    truncated = False

    candidate_refs = list(view.anchors)
    if view.timeline:
        candidate_refs.extend(event.as_observation_ref() for event in view.timeline.events)

    findings: "list[dict]" = []
    seen = set()
    for ref in candidate_refs:
        key = (ref.source_table, ref.source_id)
        if key in seen:
            continue
        seen.add(key)
        if len(findings) >= max_findings:
            truncated = True
            notes.append(f"Findings truncated at {max_findings} — more evidence exists than shown.")
            break
        explained = _explanation_to_dict(ref.source_table, ref.source_id, explain_observation(conn, ref))
        if explained is not None:
            findings.append(explained)

    timeline_items: "list[dict]" = []
    if view.timeline:
        events = view.timeline.events[:max_timeline_events]
        if len(view.timeline.events) > max_timeline_events:
            truncated = True
            notes.append(f"Timeline truncated at {max_timeline_events} of {len(view.timeline.events)} events.")
        for event in events:
            timeline_items.append(
                {
                    "source_table": event.source_table, "source_id": event.source_id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "is_anchor": event.is_anchor, "hops_from_entity": event.hops_from_entity,
                }
            )

    related_items: "list[dict]" = []
    if view.related:
        for group in view.related.groups:
            for obs in group.observations:
                related_items.append(
                    {"source_table": obs.source_table, "source_id": obs.source_id, "hops": group.hops}
                )

    pivot_items = [
        {
            "entity_type": pivot.entity.entity_type, "entity_key": pivot.entity.entity_key,
            "reason": pivot.reason,
            "via": {"source_table": pivot.via.source_table, "source_id": pivot.via.source_id} if pivot.via else None,
        }
        for pivot in view.pivots
    ]

    return AnalystContext(
        generated_at=generated_at, mode=MODE_ENTITY, entity=entity_dict, exists=True,
        summary=view.summary, findings=findings, timeline=timeline_items,
        related_evidence=related_items, pivots=pivot_items,
        threat_intel=_threat_intel_for_entity(conn, entity), tool_health=_collect_tool_health(cfg),
        truncated=truncated, notes=notes,
    )


def build_freeform_context(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    per_table_limit: int = DEFAULT_FREEFORM_PER_TABLE_LIMIT,
    max_findings: int = DEFAULT_FREEFORM_MAX_FINDINGS,
) -> AnalystContext:
    findings: "list[dict]" = []
    notes: "list[str]" = []
    truncated = False

    for table, lister in _FREEFORM_ALERT_TABLES:
        if len(findings) >= max_findings:
            truncated = True
            break
        try:
            rows = lister(conn, per_table_limit)
        except Exception as exc:  # a single table read failing must never abort the whole context
            notes.append(f"Could not read recent {table}: {exc}")
            continue
        for row in rows:
            if len(findings) >= max_findings:
                truncated = True
                break
            explained = _explanation_to_dict(table, row.id, explain(row, table))
            if explained is not None:
                findings.append(explained)

    if truncated:
        notes.append(f"Findings truncated at {max_findings} across recent alert tables.")

    try:
        for anomaly in list_anomaly_events(conn, limit=per_table_limit):
            findings.append(
                {
                    "kind": "anomaly_event", "source_table": "anomaly_events", "source_id": anomaly.id,
                    "citation": f"anomaly_events#{anomaly.id}", "entity_type": anomaly.entity_type,
                    "entity_key": anomaly.entity_key, "feature_name": anomaly.feature_name,
                    "observed_value": anomaly.observed_value, "expected_summary": anomaly.expected_summary,
                    "anomaly_score": anomaly.anomaly_score, "anomaly_tier": anomaly.anomaly_tier,
                    "score_breakdown": anomaly.score_breakdown, "known": anomaly.known,
                }
            )
    except Exception as exc:
        notes.append(f"Could not read recent anomaly_events: {exc}")

    return AnalystContext(
        generated_at=datetime.now(timezone.utc).isoformat(), mode=MODE_FREEFORM,
        entity=None, exists=None, summary={}, findings=findings,
        tool_health=_collect_tool_health(cfg), truncated=truncated, notes=notes,
    )
