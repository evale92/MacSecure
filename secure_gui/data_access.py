"""The GUI's thin, read-only display-data layer — pure Python, no Tkinter.

Per the approved Product Phase 12 boundary (see docs/DESIGN_SYSTEM.md):

    DISPLAY:  GUI -> read-only query/model layer (this module) -> storage
    ACTIONS:  GUI -> CLI -> domain logic -> storage

This module reads alert records directly via secure.storage.models for
DISPLAY purposes only. It never writes to the database. Marking an
alert known/unknown, or any other state-changing action, still goes
through the existing CLI subprocess path — see ALERT_MARK_COMMANDS
below, which maps each alert source table to the CLI subcommand that
mutates it. This module builds the argv fragment; secure_gui.py's
existing job-queue/subprocess machinery is what actually runs it, so
an action taken from the Alerts pilot narrates into the same console
transcript as everything else in the app.

This module deliberately stays small and single-purpose (normalizing
9 existing alert tables, the 7 native ones plus correlation chains and
integration alerts, into one shape for one screen) rather than
becoming a general repository/service layer — see the "Do not create
a large repository/service abstraction yet" instruction in
docs/DESIGN_SYSTEM.md. If a future screen needs read-only access to
data this module doesn't already expose, prefer adding a narrow
function here over reaching for secure.storage.models directly from
inside a Tkinter view module.
"""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass
from typing import Dict, List, Tuple

from secure.baseline.constants import ANOMALY_TIERS, DEFAULT_ENTITY_CAP, ENTITY_CAPS
from secure.baseline.entities import ENTITY_TYPES
from secure.config import load_config
from secure.explain.dispatch import explain as _explain
from secure.explain.explanation import Explanation
from secure.storage import models
from secure.storage.database import Database

# Maps an AlertRow.source_table to the CLI subcommand argv (the parts
# after `secure`) that marks one alert in that table known/unknown.
# Verified directly against secure.cli.integrations's argparse wiring, and
# identical to what secure_gui.py's own per-domain "Mark Alert
# Known/Unknown…" buttons already run — this module doesn't invent a
# new action path, it reuses the existing one. arpwatch is the one
# exception in shape: its only markable alert entity is arp_alerts,
# exposed as `arpwatch mark` (no "-alert" suffix, unlike the others,
# which all use "mark-alert"). integration_alerts is deliberately absent:
# one table holds every engine's alerts, so its command is chosen per row
# (INTEGRATION_MARK_COMMANDS below).
ALERT_MARK_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "arp_alerts": ("arpwatch", "mark"),
    "wifi_alerts": ("wifi", "mark-alert"),
    "bluetooth_alerts": ("bluetooth", "mark-alert"),
    "ble_alerts": ("bluetooth", "ble", "mark-alert"),
    "persistence_alerts": ("persistence", "mark-alert"),
    "file_integrity_alerts": ("fileintegrity", "mark-alert"),
    "correlation_alerts": ("correlate", "mark-alert"),
    "correlation_chain_alerts": ("correlate", "chains", "mark-alert"),
}

# integration_alerts rows are marked by their own engine's command. An
# allowlist, never the stored integration string put into argv: an engine
# without mark-alert (zeek) or an unexpected value gives no command, so the
# row is shown but cannot be marked. The CLI also refuses another engine's
# alert (secure/cli/integrations.py _refuse_foreign_alert).
INTEGRATION_MARK_COMMANDS: Dict[str, Tuple[str, ...]] = {
    name: ("integrations", name, "mark-alert") for name in ("osquery", "yarax", "sigma", "suricata")
}

# So the operator always sees which engine an integration alert came from.
INTEGRATION_LABELS: Dict[str, str] = {
    "osquery": "Integration: osquery",
    "yarax": "Integration: YARA-X",
    "sigma": "Integration: Sigma",
    "suricata": "Integration: Suricata",
    "zeek": "Integration: Zeek",
}

# Display name for each source table's owning module — used for the
# Level 1 table's "source" column and the Level 2 evidence panel.
MODULE_LABELS: Dict[str, str] = {
    "arp_alerts": "ARP Watch",
    "wifi_alerts": "Wi-Fi",
    "bluetooth_alerts": "Bluetooth",
    "ble_alerts": "Bluetooth (BLE)",
    "persistence_alerts": "Process & Persistence",
    "file_integrity_alerts": "File Integrity",
    "correlation_alerts": "Correlation",
    "correlation_chain_alerts": "Correlation Chains",
}

# secure/correlate/signals.py uses its own short "module" keys when it
# builds each Signal (verified directly against that file) — these
# don't line up 1:1 with the *_alerts table names above (e.g. an
# arpwatch signal is tagged "arpwatch", not "arp"; a correlation can
# also pull in "inventory"/"connections"/"listening"/"process" signals
# that have no *_alerts table of their own at all). This is a
# deliberately separate lookup rather than derived from MODULE_LABELS,
# since conflating the two vocabularies would mislabel some members.
SIGNAL_MODULE_LABELS: Dict[str, str] = {
    "inventory": "Device Inventory",
    "connections": "Active Connections",
    "listening": "Listening Services",
    "arpwatch": "ARP Watch",
    "wifi": "Wi-Fi",
    "bluetooth": "Bluetooth",
    "ble": "Bluetooth (BLE)",
    "process": "Process & Persistence",
    "persistence": "Process & Persistence",
    "file_integrity": "File Integrity",
}


@dataclass(frozen=True)
class AlertRow:
    """One row of read-only display data for the Alerts pilot table.

    Built entirely from existing alert records — nothing here is
    fabricated. `summary`/`backend_text` are the backend's own message
    text, not GUI-generated prose, so this stays honest about what the
    backend actually said. `explanation` (Product Phase 13) is a
    separate, richer, structured `Explanation` — see
    secure/explain/explanation.py — derived from this same record by
    secure/explain/, never by this module or by the GUI itself (this
    module's only job is to call `secure.explain.dispatch.explain()`
    and carry the result, exactly like it already does for
    `secure.storage.models`'s list functions). See
    docs/DESIGN_SYSTEM.md's 3-level progressive disclosure:

        Level 1 (table row):     severity, summary, module, created_at
        Level 2 (EvidencePanel): explanation (significance, confidence,
                                  evidence, uncertainty, correlated
                                  events, recommended action)
        Level 3 (raw telemetry): raw (the full source record)
    """

    source_table: str
    source_id: int
    module: str
    created_at: str
    severity: str
    kind: str
    subject: str
    summary: str
    backend_text: str
    contributing_modules: Tuple[str, ...]
    evidence_count: int
    known: bool
    raw: dict
    explanation: Explanation
    # Which engine an integration_alerts row came from; None for every
    # other source table.
    integration: "str | None" = None

    @property
    def mark_command(self) -> "Tuple[str, ...] | None":
        """CLI subcommand argv (after `secure`) that marks this alert
        known/unknown, or None when there is none: an integration whose
        engine has no mark-alert (or an unexpected stored value), or a
        source table not in ALERT_MARK_COMMANDS. Callers must check."""
        if self.source_table == "integration_alerts":
            return INTEGRATION_MARK_COMMANDS.get(self.integration or "")
        return ALERT_MARK_COMMANDS.get(self.source_table)


def _dedupe_preserve_order(items: "list[str]") -> Tuple[str, ...]:
    seen: set = set()
    out: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


def _from_arp(rec) -> AlertRow:
    return AlertRow(
        source_table="arp_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["arp_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.ip,
        summary=rec.message,
        backend_text=rec.message,
        contributing_modules=(MODULE_LABELS["arp_alerts"],),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "arp_alerts"),
    )


def _from_wifi(rec) -> AlertRow:
    return AlertRow(
        source_table="wifi_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["wifi_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.ssid,
        summary=rec.message,
        backend_text=rec.message,
        contributing_modules=(MODULE_LABELS["wifi_alerts"],),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "wifi_alerts"),
    )


def _from_bluetooth(rec) -> AlertRow:
    return AlertRow(
        source_table="bluetooth_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["bluetooth_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.name or rec.identifier,
        summary=rec.message,
        backend_text=rec.message,
        contributing_modules=(MODULE_LABELS["bluetooth_alerts"],),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "bluetooth_alerts"),
    )


def _from_ble(rec) -> AlertRow:
    return AlertRow(
        source_table="ble_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["ble_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.name or rec.cb_uuid,
        summary=rec.message,
        backend_text=rec.message,
        contributing_modules=(MODULE_LABELS["ble_alerts"],),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "ble_alerts"),
    )


def _from_persistence(rec) -> AlertRow:
    return AlertRow(
        source_table="persistence_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["persistence_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.label or rec.identifier,
        summary=rec.message,
        backend_text=rec.message,
        contributing_modules=(MODULE_LABELS["persistence_alerts"],),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "persistence_alerts"),
    )


def _from_file_integrity(rec) -> AlertRow:
    return AlertRow(
        source_table="file_integrity_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["file_integrity_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.path,
        summary=rec.message,
        backend_text=rec.message + (f"\n\n{rec.context_notes}" if rec.context_notes else ""),
        contributing_modules=(MODULE_LABELS["file_integrity_alerts"],),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "file_integrity_alerts"),
    )


def _from_correlation(rec) -> AlertRow:
    member_modules = _dedupe_preserve_order(
        [SIGNAL_MODULE_LABELS.get(m.get("module"), m.get("module") or "?") for m in rec.members]
    )
    if not member_modules:
        member_modules = (MODULE_LABELS["correlation_alerts"],)

    first_line = rec.explanation.splitlines()[0] if rec.explanation else rec.fingerprint
    summary = first_line if len(first_line) <= 160 else first_line[:157] + "..."

    return AlertRow(
        source_table="correlation_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["correlation_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.triggered_by or "correlated_cluster",
        subject=f"{rec.module_count} module(s), {rec.signal_count} signal(s)",
        summary=summary,
        backend_text=rec.explanation,
        contributing_modules=member_modules,
        evidence_count=rec.signal_count,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "correlation_alerts"),
    )


def _from_integration(rec) -> AlertRow:
    label = INTEGRATION_LABELS.get(rec.integration, f"Integration: {rec.integration}")
    return AlertRow(
        source_table="integration_alerts",
        source_id=rec.id,
        module=label,
        created_at=rec.created_at,
        severity=rec.severity,
        kind=rec.kind,
        subject=rec.label or rec.identity_key,
        summary=rec.message,
        backend_text=rec.message,
        contributing_modules=(label,),
        evidence_count=1,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "integration_alerts"),
        integration=rec.integration,
    )


def _from_correlation_chain(rec) -> AlertRow:
    member_modules = _dedupe_preserve_order(
        [SIGNAL_MODULE_LABELS.get(m.get("module"), m.get("module") or "?") for m in rec.members]
    ) or (MODULE_LABELS["correlation_chain_alerts"],)
    first_line = rec.explanation.splitlines()[0] if rec.explanation else rec.fingerprint
    summary = first_line if len(first_line) <= 160 else first_line[:157] + "..."
    return AlertRow(
        source_table="correlation_chain_alerts",
        source_id=rec.id,
        module=MODULE_LABELS["correlation_chain_alerts"],
        created_at=rec.created_at,
        severity=rec.severity,
        kind="correlation_chain",
        subject=f"{rec.module_count} module(s), {rec.independent_fact_count} fact(s)",
        summary=summary,
        backend_text=rec.explanation,
        contributing_modules=member_modules,
        evidence_count=rec.independent_fact_count,
        known=rec.known,
        raw=asdict(rec),
        explanation=_explain(rec, "correlation_chain_alerts"),
    )


def list_all_alerts(conn: sqlite3.Connection, limit: int = 200) -> List[AlertRow]:
    """All alerts across the 9 source tables (the 7 native alert tables,
    correlation chains and integration alerts), normalized and merged.

    Fetches up to `limit` rows from each of the 9 underlying tables
    (so a single very active table can't crowd out the others before
    sorting), then returns the `limit` most recent overall, newest
    first. Read-only: this never writes to the database — see this
    module's docstring for the display/action boundary.
    """
    rows: List[AlertRow] = []
    rows.extend(_from_arp(r) for r in models.list_arp_alerts(conn, limit=limit))
    rows.extend(_from_wifi(r) for r in models.list_wifi_alerts(conn, limit=limit))
    rows.extend(_from_bluetooth(r) for r in models.list_bluetooth_alerts(conn, limit=limit))
    rows.extend(_from_ble(r) for r in models.list_ble_alerts(conn, limit=limit))
    rows.extend(_from_persistence(r) for r in models.list_persistence_alerts(conn, limit=limit))
    rows.extend(
        _from_file_integrity(r) for r in models.list_file_integrity_alerts(conn, limit=limit)
    )
    rows.extend(_from_correlation(r) for r in models.list_correlation_alerts(conn, limit=limit))
    rows.extend(
        _from_correlation_chain(r) for r in models.list_correlation_chain_alerts(conn, limit=limit)
    )
    # integration_alerts holds every engine in one table. Fetch with a larger
    # limit, then cap per-engine to prevent a noisy engine (e.g. suricata IDS)
    # from crowding out the others in the final sorted results.
    integration_rows = [
        _from_integration(r)
        for r in models.list_integration_alerts(conn, limit=limit * 2)
    ]
    # Deduplicate per-engine: keep at most (limit // 8) rows per engine to
    # ensure fair representation alongside the 7 native alert tables.
    max_per_engine = max(1, limit // 8)
    engine_counts: Dict[str, int] = {}
    for row in integration_rows:
        engine = row.integration or "unknown"
        if engine_counts.get(engine, 0) < max_per_engine:
            rows.append(row)
            engine_counts[engine] = engine_counts.get(engine, 0) + 1

    rows.sort(key=lambda r: r.created_at, reverse=True)
    return rows[:limit]


def fetch_all_alerts(limit: int = 200) -> List[AlertRow]:
    """Convenience wrapper: open the app's own database read-only and
    call list_all_alerts(). This is what secure_gui/alerts_view.py
    actually calls — kept separate from list_all_alerts() itself so
    that function stays trivially unit-testable against an in-memory
    or temp-file connection (see tests/test_gui_components.py),
    without every test needing a real, initialized app config.
    """
    cfg = load_config()
    with Database(cfg.database_path()) as db:
        return list_all_alerts(db.conn, limit=limit)


# ---------- Phase 14.5 Stage D: Baseline & Anomalies ----------
#
# Phase 14 (behavioral baselining/anomaly detection) has had zero GUI
# representation until now — `secure baseline status` / `secure
# anomalies list|show|mark` have only ever been CLI commands. This
# reuses the exact same DataTable + EvidencePanel pattern the Alerts
# pilot established above, rather than inventing a second UI pattern.
#
# Deliberately does NOT route through secure.explain.dispatch.explain()
# the way AlertRow does: that dispatcher has no registered explainer
# for anomaly_events (see secure/explain/dispatch.py's _EXPLAINERS —
# only the 7 *_alerts tables are registered), and a real
# baseline-specific explainer is Product Phase 14's own Stage 5
# ("secure/explain integration"), not yet built. Calling explain()
# here today would just silently degrade to a low-quality generic
# explanation built from attributes AnomalyEventRecord doesn't even
# have (it has no .severity or .message — see database.py's schema
# comment on why anomaly_events deliberately has no severity column).
# Rather than paper over that with a fabricated-looking panel, this
# renders AnomalyRow's own real fields directly (score breakdown,
# expected_summary, maturity context) — exactly what `secure anomalies
# show` already prints, just in table form. Wire this up to a real
# Explanation once Stage 5 lands.


@dataclass(frozen=True)
class BaselineOverview:
    """Read-only summary for the window's header — the same figures
    `secure baseline status` prints, computed the same way (see
    secure/cli/baseline.py's cmd_baseline_status)."""

    total_entities: int
    maturity_counts: Dict[str, int]
    excluded_count: int
    frozen_count: int
    cap_usage: Dict[str, Tuple[int, int]]  # entity_type -> (count, cap)
    total_anomalies: int
    tier_counts: Dict[str, int]
    unreviewed_anomalies: int
    latest_run: object  # models.BaselineRunRecord | None
    total_runs: int
    partial_runs: int
    failed_runs: int


def fetch_baseline_overview(conn: sqlite3.Connection) -> BaselineOverview:
    return BaselineOverview(
        total_entities=models.count_baseline_entities(conn),
        maturity_counts=models.count_baseline_entities_by_maturity(conn),
        excluded_count=models.count_baseline_entities_excluded(conn),
        frozen_count=models.count_baseline_entities_frozen(conn),
        cap_usage={
            et: (models.count_baseline_entities(conn, et), ENTITY_CAPS.get(et, DEFAULT_ENTITY_CAP))
            for et in ENTITY_TYPES
        },
        total_anomalies=models.count_anomaly_events(conn),
        tier_counts={tier: models.count_anomaly_events(conn, tier=tier) for tier in ANOMALY_TIERS},
        unreviewed_anomalies=models.count_anomaly_events(conn, known=False),
        latest_run=models.find_latest_baseline_run(conn),
        total_runs=models.count_baseline_runs(conn),
        partial_runs=models.count_baseline_runs(conn, status="partial"),
        failed_runs=models.count_baseline_runs(conn, status="failed"),
    )


@dataclass(frozen=True)
class AnomalyRow:
    """One row of read-only display data for the Baseline & Anomalies
    screen — built entirely from a real anomaly_events row (and, for
    the caveats, the entity's CURRENT baseline state) via
    secure.storage.models, same "nothing fabricated" discipline as
    AlertRow above.

        Level 1 (table row):     tier, entity, feature, observed value,
                                  observed_at, known
        Level 2 (EvidencePanel): expected_summary, score breakdown,
                                  maturity context, source reference,
                                  caveats (entity state now vs. at the
                                  time this anomaly was scored — see
                                  cmd_anomalies_show's docstring)
        Level 3 (raw telemetry): raw (the full anomaly_events record)
    """

    id: int
    entity_type: str
    entity_key: str
    feature_name: str
    observed_value: "str | None"
    observed_at: str
    created_at: str
    run_id: str
    expected_summary: str
    score_breakdown: Dict[str, int]
    anomaly_score: int
    anomaly_tier: str
    maturity_state_at_time: str
    eligible_weight_total_at_time: float
    eligible_distinct_days_at_time: int
    source_table: "str | None"
    source_id: "int | None"
    known: bool
    caveats: Tuple[str, ...]
    raw: dict

    @property
    def mark_command(self) -> Tuple[str, ...]:
        """CLI subcommand argv (after `secure`) that marks this anomaly
        event known/unknown — always `anomalies mark`, unlike AlertRow's
        per-source-table map, since every anomaly lives in the one
        anomaly_events table regardless of entity_type."""
        return ("anomalies", "mark")


def _anomaly_caveats(event, entity) -> Tuple[str, ...]:
    """Same caveat logic as cmd_anomalies_show() in secure/cli/anomalies.py
    — kept in sync with it deliberately (both describe the same "has
    this entity's real-world state since diverged from what it was when
    this anomaly was scored" question), not re-derived independently.
    """
    caveats: List[str] = []
    if entity is None:
        caveats.append(
            "No entity-level baseline record exists for this entity right now "
            "(feature-only entity types never get one from a scanner — only "
            "an operator action like exclude/freeze/reset creates one)."
        )
    else:
        if entity.excluded:
            caveats.append("This entity is currently EXCLUDED from baseline scoring.")
        if entity.frozen:
            caveats.append("This entity is currently FROZEN (baseline not adapting).")
        if entity.maturity_state != event.maturity_state_at_time:
            caveats.append(
                f"This entity's maturity has since changed to "
                f"'{entity.maturity_state}' (was '{event.maturity_state_at_time}' "
                "at the time)."
            )
    return tuple(caveats)


def _from_anomaly_event(conn: sqlite3.Connection, event) -> AnomalyRow:
    entity = models.find_baseline_entity(conn, event.entity_type, event.entity_key)
    return AnomalyRow(
        id=event.id,
        entity_type=event.entity_type,
        entity_key=event.entity_key,
        feature_name=event.feature_name,
        observed_value=event.observed_value,
        observed_at=event.observed_at,
        created_at=event.created_at,
        run_id=event.run_id,
        expected_summary=event.expected_summary,
        score_breakdown=event.score_breakdown,
        anomaly_score=event.anomaly_score,
        anomaly_tier=event.anomaly_tier,
        maturity_state_at_time=event.maturity_state_at_time,
        eligible_weight_total_at_time=event.eligible_weight_total_at_time,
        eligible_distinct_days_at_time=event.eligible_distinct_days_at_time,
        source_table=event.source_table,
        source_id=event.source_id,
        known=event.known,
        caveats=_anomaly_caveats(event, entity),
        raw=asdict(event),
    )


def list_all_anomalies(conn: sqlite3.Connection, limit: int = 200) -> List[AnomalyRow]:
    """Every anomaly event across every entity_type, most recent first —
    `models.list_anomaly_events(conn, limit=limit)` already returns
    across all entity types when entity_type isn't given (see its own
    docstring), so this just normalizes each row into an AnomalyRow.
    """
    events = models.list_anomaly_events(conn, limit=limit)
    return [_from_anomaly_event(conn, e) for e in events]


def fetch_all_anomalies(limit: int = 200) -> List[AnomalyRow]:
    """Convenience wrapper, same role as fetch_all_alerts() above: open
    the app's own database read-only and call list_all_anomalies()."""
    cfg = load_config()
    with Database(cfg.database_path()) as db:
        return list_all_anomalies(db.conn, limit=limit)


def fetch_baseline_overview_now() -> BaselineOverview:
    """Convenience wrapper, same role as fetch_all_anomalies() above."""
    cfg = load_config()
    with Database(cfg.database_path()) as db:
        return fetch_baseline_overview(db.conn)


def format_baseline_overview_text(overview: BaselineOverview) -> str:
    """One-line-per-section summary for the Baseline window's header —
    the same figures `secure baseline status` prints (see
    secure/cli/baseline.py), just condensed for a fixed-height header
    instead of a scrolling console.

    Lives here rather than in secure_gui/baseline_view.py because it is
    pure text over BaselineOverview's own fields and touches no widget:
    this module's docstring asks for exactly that split, and a view
    module cannot be imported at all in an interpreter without
    `_tkinter`, so anything left there is untestable by construction.
    """
    lines = []
    lines.append(f"Entities: {overview.total_entities}")
    if overview.maturity_counts:
        by_maturity = ", ".join(
            f"{state}={n}" for state, n in sorted(overview.maturity_counts.items())
        )
        lines.append(f"By maturity: {by_maturity}")
    lines.append(f"Excluded: {overview.excluded_count}   Frozen: {overview.frozen_count}")

    tier_text = ", ".join(
        f"{tier}={overview.tier_counts.get(tier, 0)}" for tier in ("critical", "high", "medium", "low")
    )
    lines.append(
        f"Anomalies: {overview.total_anomalies} total "
        f"({overview.unreviewed_anomalies} unreviewed) — {tier_text}"
    )

    run = overview.latest_run
    if run is None:
        lines.append("No baseline runs recorded yet.")
    else:
        lines.append(
            f"Latest run: {run.status} at {run.started_at} "
            f"({overview.total_runs} total, {overview.partial_runs} partial, "
            f"{overview.failed_runs} failed)"
        )
    return "\n".join(lines)


def format_anomaly_evidence_text(row: AnomalyRow) -> str:
    """Level 2 body text for the Baseline window's EvidencePanel:
    expected_summary, score breakdown, maturity context, source
    reference, then caveats — the same information `secure anomalies
    show <id>` prints (see secure/cli/anomalies.py's
    cmd_anomalies_show), reformatted for the panel. Pure formatting over
    AnomalyRow's own real fields — computes nothing new. See AnomalyRow's
    docstring for why this doesn't go through
    secure.explain.dispatch.explain() yet.

    Same reason as format_baseline_overview_text() for living here.
    """
    lines = []
    lines.append(f"Expected: {row.expected_summary}")

    lines.append("")
    lines.append("Score breakdown:")
    for component, points in row.score_breakdown.items():
        lines.append(f"  {component:18} {points}")
    lines.append(f"  {'total':18} {row.anomaly_score}")

    lines.append("")
    lines.append(f"Maturity at time of observation: {row.maturity_state_at_time}")
    lines.append(
        f"Eligible weight at time: {row.eligible_weight_total_at_time:g} "
        f"({row.eligible_distinct_days_at_time} distinct days)"
    )

    lines.append("")
    if row.source_table:
        lines.append(f"Source: {row.source_table}#{row.source_id}")
    else:
        lines.append("Source: (none recorded — see PROJECT_NOTES.md's provenance notes)")

    if row.caveats:
        lines.append("")
        lines.append("Caveats:")
        for c in row.caveats:
            lines.append(f"  - {c}")

    return "\n".join(lines)


@dataclass(frozen=True)
class PerformanceOverview:
    """Read-only summary for the Diagnostics -> Performance window
    (Phase 30) — the same figures `secure diagnostics performance`
    prints (see secure/cli/diagnostics.py), computed the same way via
    secure/diagnostics/'s own collectors. Diagnostics only — nothing
    here is a security finding.
    """

    hardware: object  # secure.diagnostics.hardware.HardwareSpecs
    system_health: object  # secure.diagnostics.system.SystemHealth
    self_usage: object  # secure.diagnostics.self_usage.SecureSelfUsage
    module_runs: list  # list[secure.storage.models.perf.PerfModuleRunRecord]
    integration_health: list  # list[tuple[str, IntegrationHealth]]
    dev_tool_usage: list  # list[secure.diagnostics.tools.DevToolUsage]
    warnings: list  # list[secure.diagnostics.budgets.PerfWarning]


def fetch_performance_overview_now() -> PerformanceOverview:
    """Convenience wrapper, same role as fetch_baseline_overview_now()
    above — opens the app's own database read-only and gathers one
    fresh snapshot from every secure/diagnostics/ collector.
    """
    from secure.diagnostics.budgets import evaluate_budgets
    from secure.diagnostics.hardware import collect_hardware_specs
    from secure.diagnostics.integrations_health import collect_integration_health
    from secure.diagnostics.milestones import previous_db_size_bytes
    from secure.diagnostics.self_usage import collect_self_usage
    from secure.diagnostics.system import collect_system_health
    from secure.diagnostics.tools import collect_dev_tool_usage

    cfg = load_config()
    hardware = collect_hardware_specs()
    system_health = collect_system_health(disk_path=cfg.app_dir_path())
    integration_health = collect_integration_health(cfg)
    dev_tool_usage = collect_dev_tool_usage(cfg.dev_tool_process_patterns)

    with Database(cfg.database_path()) as db:
        self_usage = collect_self_usage(db.conn, db_path=cfg.database_path(), log_path=cfg.log_path())
        module_runs = models.list_recent_perf_module_runs(db.conn, limit=50)
        warnings = evaluate_budgets(
            cfg, self_usage=self_usage, system_health=system_health, recent_module_runs=module_runs,
            previous_db_size_bytes=previous_db_size_bytes(db.conn),
        )

    return PerformanceOverview(
        hardware=hardware,
        system_health=system_health,
        self_usage=self_usage,
        module_runs=module_runs,
        integration_health=integration_health,
        dev_tool_usage=dev_tool_usage,
        warnings=warnings,
    )


@dataclass(frozen=True)
class AgentRepairsOverview:
    """Read-only summary for the Agent -> Repairs window (Phase 31) —
    the same rows `secure agent list`/`show` print, plus (for any run
    that reached a pending change request) the linked
    ai_change_requests row, joined here by id only, never duplicated
    (see secure/storage/models/agent.py's own module docstring for why
    approval state is always read by join, never copied onto a run).
    """

    runs: list  # list[secure.storage.models.agent.AgentRepairRunRecord]
    change_requests: dict  # {change_request_id: secure.storage.models.ai.AiChangeRequestRecord}
    git_ok: bool
    tool_available: bool
    ollama_configured: bool


def fetch_agent_repairs_overview_now(limit: int = 50) -> AgentRepairsOverview:
    """Convenience wrapper, same role as fetch_performance_overview_now()
    above — opens the app's own database read-only, lists recent repair
    runs, and resolves each one's linked change request (if any) so the
    GUI can show live approval status without a second round trip per
    row. Never approves/rejects/attempts/resumes anything itself — see
    secure_gui/agent_view.py, which routes every action through the
    real `secure agent ...` / `secure ai changes ...` CLI subprocess.
    """
    from secure.agent.runner import tool_available as _tool_available
    from secure.agent.worktree import is_git_repository as _is_git_repository

    cfg = load_config()
    git_ok = _is_git_repository()
    available = _tool_available(cfg)
    ollama_configured = bool(cfg.ollama_host)

    with Database(cfg.database_path()) as db:
        runs = models.list_agent_repair_runs(db.conn, limit=limit)
        change_requests = {}
        for run in runs:
            if run.change_request_id and run.change_request_id not in change_requests:
                cr = models.find_ai_change_request(db.conn, run.change_request_id)
                if cr is not None:
                    change_requests[run.change_request_id] = cr

    return AgentRepairsOverview(
        runs=runs, change_requests=change_requests, git_ok=git_ok,
        tool_available=available, ollama_configured=ollama_configured,
    )


def fetch_agent_actions_now(run_id: "Optional[str]" = None, limit: int = 200) -> list:
    """Phase 31.5: read-only fetch of agent_actions rows for the Agent
    -> Repairs window's Actions panel — the same rows `secure agent
    actions [--run-id ID]` prints. Every field returned here was
    already redacted at write time by secure/agent/audit.py; this
    function does no filtering of its own, it only opens the app's own
    database read-only and calls list_agent_actions()."""
    cfg = load_config()
    with Database(cfg.database_path()) as db:
        return models.list_agent_actions(db.conn, run_id=run_id, limit=limit)


def fetch_change_request_center_now(limit: int = 50) -> list:
    """Phase 40: read-only fetch for the Agent -> Change Requests
    window — every change request still awaiting a human, fully
    assembled by secure/agent/center.py (which is itself read-only).

    Same role as fetch_agent_repairs_overview_now() above: opens the
    app's own database, reads, closes. Approves nothing, rejects
    nothing, supersedes nothing — the window routes every action
    through the real `secure ...` CLI subprocess.
    """
    from secure.agent.center import list_pending_change_requests

    cfg = load_config()
    with Database(cfg.database_path()) as db:
        return list_pending_change_requests(db.conn, limit=limit)
