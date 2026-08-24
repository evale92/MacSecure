"""
secure/detect/registry.py — Phase 25 Stage 2: discovers what rules
currently exist in each of the four families and upserts them into the
`detection_rules` catalog. This is the ONLY place in secure/detect/
that calls into each family's own loader/availability code — every
other module in this package reads the catalog secure/detect/registry.py
already built, rather than re-discovering anything itself.

Never touches rule CONTENT — only identity, version, source,
telemetry, and capability, per secure/detect/__init__.py's own rule 1.
Never resets operator-owned catalog state (`enabled`, FP notes,
validation) — that discipline lives in
secure/storage/models/detect.py's upsert_detection_rule() itself, not
duplicated here.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from secure.config import AppConfig
from secure.integrations.base import STATUS_DEGRADED, STATUS_OK
from secure.integrations.sigma.capability import check_capability
from secure.integrations.sigma.rules import load_rules
from secure.integrations.suricata.availability import check_availability as suricata_check_availability
from secure.integrations.suricata.parser import ALERT_KIND as SURICATA_ALERT_KIND
from secure.integrations.yarax.availability import check_availability as yarax_check_availability
from secure.integrations.yarax.rulesets import load_rulesets
from secure.storage.models import DetectionRuleRecord, list_integration_observations, upsert_detection_rule

FAMILY_SIGMA = "sigma"
FAMILY_YARAX = "yarax"
FAMILY_SURICATA = "suricata"
FAMILY_CORRELATE = "correlate"
FAMILIES = (FAMILY_SIGMA, FAMILY_YARAX, FAMILY_SURICATA, FAMILY_CORRELATE)

CAPABILITY_EVALUABLE = "evaluable"
CAPABILITY_NOT_EVALUABLE = "not_evaluable"
CAPABILITY_ERROR = "error"
CAPABILITY_UNKNOWN = "unknown"

_YARAX_TELEMETRY = (
    "File content of targeted files — YARA-X never scans the whole disk; it only "
    "scans files a scan target already selected (unreviewed File Integrity Monitoring "
    "alerts, suspicious persistence entries, or an explicit user-requested path; see "
    "secure/integrations/yarax/targets.py)."
)
_SURICATA_TELEMETRY = (
    "Suricata's own EVE JSON alert stream (AppConfig.suricata_eve_log_path). Secure "
    "never loads or validates this signature's own rule content — this entry exists "
    "because it has fired at least once, observed passively via EVE output."
)
_CORRELATE_ENGINES: "Tuple[dict, ...]" = (
    dict(
        rule_key="temporal_clustering",
        title="Temporal Correlation Clustering",
        source="secure/correlate/analysis.py",
        version_label="v1",
        required_telemetry=(
            "Signals collected from at least one native module within the correlation "
            "lookback window (secure/correlate/signals.py) — devices, connections, "
            "listening services, arpwatch/wifi/bluetooth/ble alerts, process/persistence "
            "entries, file-integrity alerts, or integration_alerts from any integration."
        ),
    ),
    dict(
        rule_key="chain_scoring",
        title="Provenance-Aware Chain Scoring",
        source="secure/correlate/chains.py",
        version_label="v1",
        required_telemetry=(
            "evidence_links rows (Phase 21) connecting two or more stored observations — "
            "without at least one such link, walk_chain() has nothing to walk."
        ),
    ),
)


@dataclass
class SyncResult:
    """One `secure detect sync` pass's outcome — every (record, created)
    pair upserted, per family, plus any human-readable notes about rules
    that could NOT be cataloged at all (e.g. a Sigma file too malformed
    to even recover a rule_id from).
    """

    sigma: "List[Tuple[DetectionRuleRecord, bool]]" = field(default_factory=list)
    yarax: "List[Tuple[DetectionRuleRecord, bool]]" = field(default_factory=list)
    suricata: "List[Tuple[DetectionRuleRecord, bool]]" = field(default_factory=list)
    correlate: "List[Tuple[DetectionRuleRecord, bool]]" = field(default_factory=list)
    messages: "List[str]" = field(default_factory=list)

    @property
    def all_results(self) -> "List[Tuple[DetectionRuleRecord, bool]]":
        return [*self.sigma, *self.yarax, *self.suricata, *self.correlate]

    @property
    def total_count(self) -> int:
        return len(self.all_results)

    @property
    def new_count(self) -> int:
        return sum(1 for _, created in self.all_results if created)

    @property
    def updated_count(self) -> int:
        return sum(1 for _, created in self.all_results if not created)


def _sync_sigma(conn: sqlite3.Connection, cfg: AppConfig) -> "Tuple[List[Tuple[DetectionRuleRecord, bool]], List[str]]":
    rules, load_errors = load_rules(cfg.sigma_rules_dir_path())
    results: "List[Tuple[DetectionRuleRecord, bool]]" = []
    for rule in rules:
        capability = check_capability(rule)
        record, created = upsert_detection_rule(
            conn,
            family=FAMILY_SIGMA,
            rule_key=rule.rule_id,
            title=rule.title,
            source=rule.source_path,
            version_label=rule.version_label,
            required_telemetry=capability.required_telemetry,
            capability_status=capability.status.value,
            capability_reason=capability.reason,
        )
        results.append((record, created))

    # A rule file too malformed to recover even a rule_id from can't be
    # cataloged at all — we have no identity to key it by. Surfaced as
    # a message rather than silently dropped.
    messages = [
        f"sigma: could not catalog {err.source_path} — {err.detail}" for err in load_errors
    ]
    return results, messages


def _sync_yarax(conn: sqlite3.Connection, cfg: AppConfig) -> "Tuple[List[Tuple[DetectionRuleRecord, bool]], List[str]]":
    compiled, load_errors = load_rulesets(cfg.yara_rules_dir_path())
    engine_health = yarax_check_availability()

    results: "List[Tuple[DetectionRuleRecord, bool]]" = []
    for ruleset in compiled:
        if engine_health.available:
            status, reason = CAPABILITY_EVALUABLE, "ruleset compiled successfully and yara_x is available"
        else:
            status, reason = CAPABILITY_NOT_EVALUABLE, engine_health.detail
        record, created = upsert_detection_rule(
            conn,
            family=FAMILY_YARAX,
            rule_key=ruleset.info.name,
            title=ruleset.info.name,
            source=ruleset.info.source_path,
            version_label=ruleset.info.version_label,
            required_telemetry=_YARAX_TELEMETRY,
            capability_status=status,
            capability_reason=reason,
        )
        results.append((record, created))

    # A ruleset that failed to compile is still reportable — same
    # "broken content is still catalogable, since we DO know its
    # identity/hash from the file itself" reasoning
    # secure/integrations/yarax/rulesets.py's own RulesetLoadError
    # already established.
    for err in load_errors:
        record, created = upsert_detection_rule(
            conn,
            family=FAMILY_YARAX,
            rule_key=err.info.name,
            title=err.info.name,
            source=err.info.source_path,
            version_label=err.info.version_label,
            required_telemetry=_YARAX_TELEMETRY,
            capability_status=CAPABILITY_ERROR,
            capability_reason=err.detail,
        )
        results.append((record, created))

    return results, []


def _sync_suricata(
    conn: sqlite3.Connection, cfg: AppConfig, *, observation_limit: int = 1000
) -> "Tuple[List[Tuple[DetectionRuleRecord, bool]], List[str]]":
    """Passively aggregate distinct (gid, signature_id) pairs already
    observed in integration_observations — the only source of Suricata
    signature identity that exists anywhere in this codebase, since
    Secure never loads Suricata's own rule files. Observations come
    back newest-first (list_integration_observations()'s own
    contract), so the first occurrence of a given (gid, signature_id)
    is its freshest known signature text/rev.
    """
    health = suricata_check_availability(cfg)
    observations = list_integration_observations(
        conn, integration=FAMILY_SURICATA, kind=SURICATA_ALERT_KIND, limit=observation_limit
    )

    seen: "Dict[Tuple[str, str], dict]" = {}
    for obs in observations:
        fields = obs.fields
        gid = fields.get("gid")
        signature_id = fields.get("signature_id")
        if gid is None or signature_id is None:
            continue
        key = (str(gid), str(signature_id))
        if key not in seen:
            seen[key] = fields

    if health.status in (STATUS_OK, STATUS_DEGRADED):
        status = CAPABILITY_EVALUABLE
        reason = "this signature has fired at least once; Suricata's own EVE stream is currently readable"
    else:
        status = CAPABILITY_UNKNOWN
        reason = (
            f"Suricata is currently {health.status}: {health.detail} — cannot confirm this "
            "signature could fire again right now"
        )

    results: "List[Tuple[DetectionRuleRecord, bool]]" = []
    for (gid, signature_id), fields in sorted(seen.items()):
        record, created = upsert_detection_rule(
            conn,
            family=FAMILY_SURICATA,
            rule_key=f"{gid}:{signature_id}",
            title=fields.get("signature") or f"signature {signature_id}",
            source="external (Suricata-managed ruleset; Secure never loads Suricata's own rule files)",
            version_label=f"rev={fields.get('rev', 'unknown')}",
            required_telemetry=_SURICATA_TELEMETRY,
            capability_status=status,
            capability_reason=reason,
        )
        results.append((record, created))

    return results, []


def _sync_correlate(conn: sqlite3.Connection) -> "Tuple[List[Tuple[DetectionRuleRecord, bool]], List[str]]":
    results: "List[Tuple[DetectionRuleRecord, bool]]" = []
    for engine in _CORRELATE_ENGINES:
        record, created = upsert_detection_rule(
            conn,
            family=FAMILY_CORRELATE,
            rule_key=engine["rule_key"],
            title=engine["title"],
            source=engine["source"],
            version_label=engine["version_label"],
            required_telemetry=engine["required_telemetry"],
            capability_status=CAPABILITY_EVALUABLE,
            capability_reason="Secure's own native code; requires no external tool or binary",
        )
        results.append((record, created))
    return results, []


def sync_registry(conn: sqlite3.Connection, cfg: AppConfig) -> SyncResult:
    """Discover current rules across all four families and upsert them
    into `detection_rules`. Safe to run repeatedly — every family's own
    upsert path is idempotent by (family, rule_key), and operator-owned
    state (enabled/validation/FP notes) is never disturbed on a rule
    that already exists.
    """
    sigma_results, sigma_msgs = _sync_sigma(conn, cfg)
    yarax_results, yarax_msgs = _sync_yarax(conn, cfg)
    suricata_results, suricata_msgs = _sync_suricata(conn, cfg)
    correlate_results, correlate_msgs = _sync_correlate(conn)

    return SyncResult(
        sigma=sigma_results,
        yarax=yarax_results,
        suricata=suricata_results,
        correlate=correlate_results,
        messages=[*sigma_msgs, *yarax_msgs, *suricata_msgs, *correlate_msgs],
    )


def refresh_capability(conn: sqlite3.Connection, cfg: AppConfig, record: DetectionRuleRecord) -> "Tuple[str, str]":
    """Live re-check of one already-cataloged rule's capability status —
    never trusts the cached `capability_status` column, per
    secure/detect/__init__.py's own "show always re-checks live"
    discipline. Returns (status, reason); does NOT write to storage —
    callers (secure/cli/detect.py's `show`) decide whether to persist
    the refreshed value via upsert_detection_rule() on their next sync.
    """
    if record.family == FAMILY_SIGMA:
        rules, _ = load_rules(cfg.sigma_rules_dir_path())
        for rule in rules:
            if rule.rule_id == record.rule_key:
                capability = check_capability(rule)
                return capability.status.value, capability.reason
        return CAPABILITY_UNKNOWN, "rule no longer found in the configured Sigma rules directory"

    if record.family == FAMILY_YARAX:
        compiled, load_errors = load_rulesets(cfg.yara_rules_dir_path())
        for err in load_errors:
            if err.info.name == record.rule_key:
                return CAPABILITY_ERROR, err.detail
        for ruleset in compiled:
            if ruleset.info.name == record.rule_key:
                health = yarax_check_availability()
                if health.available:
                    return CAPABILITY_EVALUABLE, "ruleset compiled successfully and yara_x is available"
                return CAPABILITY_NOT_EVALUABLE, health.detail
        return CAPABILITY_UNKNOWN, "ruleset file no longer found in the configured YARA-X rules directory"

    if record.family == FAMILY_SURICATA:
        health = suricata_check_availability(cfg)
        if health.status in (STATUS_OK, STATUS_DEGRADED):
            return CAPABILITY_EVALUABLE, "this signature has fired at least once; Suricata's own EVE stream is currently readable"
        return (
            CAPABILITY_UNKNOWN,
            f"Suricata is currently {health.status}: {health.detail} — cannot confirm this "
            "signature could fire again right now",
        )

    # FAMILY_CORRELATE — Secure's own code, no external dependency to
    # ever be unavailable.
    return CAPABILITY_EVALUABLE, "Secure's own native code; requires no external tool or binary"
