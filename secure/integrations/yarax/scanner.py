"""
integrations/yarax/scanner.py — orchestrates one YARA-X scan pass over
an explicit, bounded list of files: load configured rulesets, hash and
scan each file against every ruleset, normalize matches, persist the
run/observations/alerts, and classify each match's severity from the
rule's own metadata (never assumed). This is the only file in the
yarax integration that touches the database or the filesystem's file
contents — mirrors every other scanner module's own "one file does the
I/O" split (secure/listening/scanner.py, secure/integrations/osquery/
scanner.py, ...).

Never expands a directory into "every file inside it" — a path that
isn't a regular file is skipped with an explicit reason, never silently
walked. Combined with targets.py only ever proposing already-flagged
suspicious/security-relevant files, this is what keeps scanning
targeted rather than an indiscriminate whole-disk sweep (Phase 16's
explicit instruction).
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from secure.config import AppConfig
from secure.evidence import (
    EvidenceLink,
    ObservationRef,
    RELATIONSHIP_DERIVED_EVIDENCE,
    record_link,
)
from secure.fileintegrity.hashing import DEFAULT_MAX_HASH_BYTES, compute_sha256
from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_OK,
    ExternalObservation,
    IntegrationHealth,
)
from secure.integrations.yarax import _engine
from secure.integrations.yarax.analysis import (
    classify_yara_match_severity,
    match_interpretation_note,
    rule_meta_has_recognized_severity,
)
from secure.integrations.yarax.availability import check_availability
from secure.integrations.yarax.parser import YARA_MATCH, parse_scan_results
from secure.integrations.yarax.rulesets import CompiledRuleset, RulesetLoadError, load_rulesets
from secure.integrations.yarax.targets import (
    ScanTarget,
    fim_alert_targets,
    persistence_suspicious_targets,
)
from secure.storage.models import (
    add_integration_alert,
    add_integration_observations,
    add_integration_run,
    list_detection_rules,
)

INTEGRATION_NAME = "yarax"

DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass
class YaraFileResult:
    path: str
    scanned: bool
    skip_reason: Optional[str] = None  # "not_found" | "is_a_directory" | "unreadable" | "too_large" | None
    file_hash: Optional[str] = None
    observations: List[ExternalObservation] = field(default_factory=list)
    ruleset_errors: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class YaraFinding:
    severity: str
    identity_key: str
    rule_name: str
    file_path: str
    message: str


@dataclass
class YaraScanResult:
    scanned_at: str
    run_id: str
    health: IntegrationHealth
    trigger: str
    rulesets_loaded: List[CompiledRuleset] = field(default_factory=list)
    ruleset_load_errors: List[RulesetLoadError] = field(default_factory=list)
    files: List[YaraFileResult] = field(default_factory=list)
    observations: List[ExternalObservation] = field(default_factory=list)
    findings: List[YaraFinding] = field(default_factory=list)
    evidence_links_recorded: int = 0

    @property
    def available(self) -> bool:
        return self.health.available


def _prepare_file(path_str: str, max_bytes: int) -> "tuple[Optional[bytes], Optional[str], Optional[str]]":
    """Returns (data, file_hash, skip_reason). Never follows a symlink
    into a directory silently — os.path checks below resolve exactly
    what's actually there.
    """
    path = Path(path_str)
    if not path.exists():
        return None, None, "not_found"
    if path.is_dir():
        return None, None, "is_a_directory"

    try:
        size = os.path.getsize(path_str)
    except OSError:
        return None, None, "unreadable"
    if size > max_bytes:
        return None, None, "too_large"

    file_hash, hash_skip_reason = compute_sha256(path_str, max_bytes=max_bytes)
    if hash_skip_reason is not None:
        return None, None, hash_skip_reason

    try:
        with open(path_str, "rb") as f:
            data = f.read()
    except OSError as exc:
        return None, None, f"unreadable: {exc}"

    return data, file_hash, None


def _scan_one_file(
    path_str: str,
    compiled_rulesets: List[CompiledRuleset],
    now: str,
    timeout_seconds: float,
    max_bytes: int,
) -> YaraFileResult:
    data, file_hash, skip_reason = _prepare_file(path_str, max_bytes)
    if skip_reason is not None:
        return YaraFileResult(path=path_str, scanned=False, skip_reason=skip_reason)

    observations: List[ExternalObservation] = []
    ruleset_errors: List[str] = []

    for compiled in compiled_rulesets:
        try:
            results = _engine.scan_bytes(compiled.rules, data, timeout_seconds=timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - one ruleset failing must not skip the others
            ruleset_errors.append(f"{compiled.info.name}: {type(exc).__name__}: {exc}")
            continue
        observations.extend(
            parse_scan_results(
                results,
                file_path=path_str,
                file_hash=file_hash,
                ruleset_info=compiled.info,
                collected_at=now,
            )
        )

    return YaraFileResult(
        path=path_str,
        scanned=True,
        file_hash=file_hash,
        observations=observations,
        ruleset_errors=ruleset_errors,
    )


def _build_message(observation: ExternalObservation, severity: str, recognized: bool) -> str:
    fields = observation.fields
    factual = (
        f"YARA rule '{fields['rule_namespace']}.{fields['rule_name']}' "
        f"(ruleset {fields['ruleset_name']}) matched {fields['file_path']}"
        + (f" (sha256 {fields['file_hash'][:16]}...)" if fields.get("file_hash") else "")
        + "."
    )
    return f"{factual} {match_interpretation_note(fields['rule_meta'], recognized)}"


def scan_paths(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    paths: List[str],
    *,
    trigger: str = "manual",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_HASH_BYTES,
    targets: "Optional[List[ScanTarget]]" = None,
) -> YaraScanResult:
    """Scan an explicit list of files (never a directory, never expanded)
    against every configured ruleset. `trigger` is a short label
    recorded in this run's detail text for audit purposes — "manual"
    (user-requested), "fim_alerts", or "persistence_suspicious" (see
    scan_fim_alerts()/scan_suspicious() below), never acted on
    differently by this function itself.

    `targets` (Phase 22 Stage 1, additive, optional) is the same
    ScanTarget list scan_fim_alerts()/scan_suspicious() already compute
    to build `paths` in the first place — passing it through here lets
    a finding that resulted from one of those targets also get a formal
    `derived_evidence` evidence_links row back to the file_integrity_
    alerts/persistence_alerts row that caused Secure to look at this
    file (see docs/EVIDENCE.md's "Stage 3 wiring" — this was previously
    computed by targets.py and then discarded; nothing about WHICH files
    get scanned or how they're scanned changes). A directly user-
    requested path (`trigger="manual"`, no `targets` passed) has no
    "caused by" ancestor and correctly gets no link at all.
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
        return YaraScanResult(scanned_at=now, run_id=run_id, health=health, trigger=trigger)

    rules_dir = cfg.yara_rules_dir_path()
    compiled_rulesets, load_errors = load_rulesets(rules_dir)

    # Phase 25 Detection Engineering Workbench: a ruleset FILE an
    # operator has explicitly disabled via `secure detect disable` is
    # skipped here, before any file is ever scanned against it — the
    # real enforcement half of that phase's own approved design,
    # tracked at the same ruleset-file granularity this integration
    # already compiles/versions at. Every detection_rules row defaults
    # to enabled=True, and this query returns [] entirely until an
    # operator has both run `secure detect sync` AND explicitly
    # disabled something — so a deployment that has never touched
    # `secure detect` sees IDENTICAL scan output to before this phase
    # existed.
    disabled_ruleset_names = {r.rule_key for r in list_detection_rules(conn, family="yarax", enabled=False)}
    if disabled_ruleset_names:
        compiled_rulesets = [c for c in compiled_rulesets if c.info.name not in disabled_ruleset_names]

    deduped_paths = list(dict.fromkeys(paths))
    file_results = [
        _scan_one_file(p, compiled_rulesets, now, timeout_seconds, max_bytes) for p in deduped_paths
    ]

    observations: List[ExternalObservation] = []
    for fr in file_results:
        observations.extend(fr.observations)

    detail_parts = [
        f"trigger={trigger}",
        f"rulesets_loaded={len(compiled_rulesets)}",
        f"files_scanned={sum(1 for fr in file_results if fr.scanned)}/{len(file_results)}",
    ]
    if not compiled_rulesets and not load_errors:
        detail_parts.append(f"no ruleset files found in {rules_dir}")
    status = STATUS_DEGRADED if load_errors or any(fr.ruleset_errors for fr in file_results) else STATUS_OK
    if load_errors:
        detail_parts.append(f"ruleset_load_errors={len(load_errors)}")
    detail = "; ".join(detail_parts)
    effective_health = IntegrationHealth(
        status=status, detail=detail, collected_at=now, tool_version=health.tool_version
    )

    observation_ids: List[int] = (
        add_integration_observations(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            rows=[
                (o.kind, o.identity_key, o.fields, o.source_query, o.collected_at)
                for o in observations
            ],
        )
        if observations
        else []
    )
    observation_id_by_key = {
        (o.kind, o.identity_key): obs_id for o, obs_id in zip(observations, observation_ids)
    }

    # Phase 22 Stage 1: path -> the ScanTarget that caused it to be
    # scanned, if any — a directly user-requested path simply has no
    # entry here, same as when `targets` isn't passed at all.
    path_to_target = {t.path: t for t in (targets or [])}

    findings: List[YaraFinding] = []
    evidence_links_recorded = 0
    for observation in observations:
        rule_meta = observation.fields["rule_meta"]
        severity = classify_yara_match_severity(rule_meta)
        recognized = rule_meta_has_recognized_severity(rule_meta)
        message = _build_message(observation, severity, recognized)
        source_observation_id = observation_id_by_key.get((observation.kind, observation.identity_key))

        alert_id = add_integration_alert(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            kind=YARA_MATCH,
            discrepancy="match",  # yarax has no "native comparison side" — always this constant, see docs/INTEGRATIONS.md
            severity=severity,
            identity_key=observation.identity_key,
            label=observation.fields["rule_name"],
            message=message,
            source_observation_id=source_observation_id,
        )
        findings.append(
            YaraFinding(
                severity=severity,
                identity_key=observation.identity_key,
                rule_name=observation.fields["rule_name"],
                file_path=observation.fields["file_path"],
                message=message,
            )
        )

        # Phase 22 Stage 1 (additive): this finding's own file was
        # scanned BECAUSE of an existing file_integrity_alerts/
        # persistence_alerts row — the YARA finding is DERIVED FROM
        # that original alert, the same relationship shape Suricata's
        # own process-context attribution already uses. A failure to
        # record the link is swallowed defensively, same discipline as
        # every other Stage 3 call site.
        target = path_to_target.get(observation.fields["file_path"])
        if target is not None:
            try:
                _, created = record_link(
                    conn,
                    EvidenceLink(
                        from_ref=ObservationRef(source_table="integration_alerts", source_id=alert_id),
                        to_ref=ObservationRef(source_table=target.source_table, source_id=target.source_id),
                        relationship=RELATIONSHIP_DERIVED_EVIDENCE,
                        match_basis="scan_target",
                        detail=f"YARA scan of {target.path!r} was triggered by {target.reason}",
                        created_by="yarax_scan_target",
                    ),
                )
                if created:
                    evidence_links_recorded += 1
            except Exception:  # noqa: BLE001 - defensive: enrichment must never fail the scan
                pass

    add_integration_run(
        conn,
        run_id=run_id,
        integration=INTEGRATION_NAME,
        started_at=now,
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=status,
        detail=detail,
        tool_version=health.tool_version,
        observations_collected=len(observations),
        alerts_generated=len(findings),
    )

    return YaraScanResult(
        scanned_at=now,
        run_id=run_id,
        health=effective_health,
        trigger=trigger,
        rulesets_loaded=compiled_rulesets,
        ruleset_load_errors=load_errors,
        files=file_results,
        observations=observations,
        findings=findings,
        evidence_links_recorded=evidence_links_recorded,
    )


def scan_fim_alerts(
    conn: sqlite3.Connection, cfg: AppConfig, *, limit: int = 100
) -> "tuple[List[ScanTarget], YaraScanResult]":
    """Scan files behind unreviewed MEDIUM/HIGH File Integrity
    Monitoring alerts — the "security-relevant FIM events" priority
    source (Phase 16). See targets.fim_alert_targets().
    """
    targets = fim_alert_targets(conn, limit=limit)
    result = scan_paths(conn, cfg, [t.path for t in targets], trigger="fim_alerts", targets=targets)
    return targets, result


def scan_suspicious(
    conn: sqlite3.Connection, cfg: AppConfig, *, limit: int = 100
) -> "tuple[List[ScanTarget], YaraScanResult]":
    """Scan executables behind unreviewed persistence "unusual/unsigned
    process" alerts — the "suspicious files" priority source (Phase 16).
    See targets.persistence_suspicious_targets().
    """
    targets = persistence_suspicious_targets(conn, limit=limit)
    result = scan_paths(conn, cfg, [t.path for t in targets], trigger="persistence_suspicious", targets=targets)
    return targets, result
