"""
cli/integrations.py — `secure integrations <engine> ...` diagnostics
(Phase 15). Structured as `integrations -> engine -> subcommand` (not
flattened to `secure osquery ...`) specifically so a second future
integration slots in as its own engine namespace without inventing a
new top-level command group — see secure/integrations/base.py's module
docstring for the same "smallest generic boundary" reasoning applied to
the CLI surface.

Five engines exist as of Phase 19 (osquery, Phase 15; yarax, Phase 16;
sigma, Phase 17; suricata, Phase 18; zeek, Phase 19). Every function
here is still named/scoped per-engine (`cmd_integrations_osquery_*` /
`cmd_integrations_yarax_*` / `cmd_integrations_sigma_*` /
`cmd_integrations_suricata_*` / `cmd_integrations_zeek_*`) rather than a
generic `cmd_integrations_status(engine)` dispatcher, since the
engines' commands genuinely differ (osquery has one `scan`; yarax has
`scan-file`/`scan-fim-alerts`/`scan-suspicious`/`rulesets`, since what
gets scanned is the whole point of Phase 16's targeting design; sigma
has `scan`/`rules`, since a rule's EVALUATION STATUS — not a file
target — is what Phase 17 requires to be inspectable on its own;
suricata has neither a `rulesets`/`rules` subcommand at all — Secure
owns none of Suricata's detection content, only its own log-reading
cursor, so there is nothing analogous to list; zeek has neither an
`alerts` nor a `mark-alert` subcommand at all — Zeek is a behavioral-
telemetry source, never a detection source, and structurally never
writes an integration_alerts row, so there is nothing for those
commands to show — see secure/integrations/zeek/scanner.py's module
docstring) — a forced-generic dispatcher would hide that difference,
not simplify it.
"""

from __future__ import annotations

import argparse
import uuid

from secure.diagnostics.instrument import instrument_module

from secure.integrations.osquery import INTEGRATION_NAME, scan_osquery
from secure.integrations.sigma import INTEGRATION_NAME as SIGMA_INTEGRATION_NAME
from secure.integrations.sigma import check_availability as sigma_check_availability
from secure.integrations.sigma.capability import EvaluationStatus, check_capability
from secure.integrations.sigma.rules import load_rules
from secure.integrations.sigma.scanner import scan_sigma
from secure.integrations.suricata import INTEGRATION_NAME as SURICATA_INTEGRATION_NAME
from secure.integrations.suricata import check_availability as suricata_check_availability
from secure.integrations.suricata.scanner import scan_suricata
from secure.integrations.yarax import INTEGRATION_NAME as YARAX_INTEGRATION_NAME
from secure.integrations.yarax import check_availability as yarax_check_availability
from secure.integrations.yarax.rulesets import load_rulesets
from secure.integrations.yarax.scanner import scan_fim_alerts, scan_paths, scan_suspicious
from secure.integrations.zeek import INTEGRATION_NAME as ZEEK_INTEGRATION_NAME
from secure.integrations.zeek import check_availability as zeek_check_availability
from secure.integrations.zeek.scanner import scan_zeek
from secure.storage.database import Database
from secure.storage.models import (
    find_integration_alert_by_id,
    find_latest_integration_run,
    list_integration_alerts,
    list_integration_observations,
    set_integration_alert_known,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger


def cmd_integrations_osquery_status(args: argparse.Namespace) -> int:
    """Show osquery's own availability/health, independent of running a
    full scan — a cheap diagnostic (secure integrations osquery scan
    also reports this, but a full scan additionally runs every query
    and the crosscheck; `status` alone is instant and side-effect-free
    beyond a small subprocess call for the version check).
    """
    cfg = _bootstrap()

    from secure.integrations.osquery import check_availability

    health = check_availability()
    print(f"osqueryi availability: {health.status.upper()}")
    print(f"  {health.detail}")
    if health.tool_version:
        print(f"  tool version: {health.tool_version}")

    with Database(cfg.database_path()) as db:
        last_run = find_latest_integration_run(db.conn, INTEGRATION_NAME)

    print()
    if last_run is None:
        print("No osquery scan has been run yet. Run: secure integrations osquery scan")
    else:
        print(f"Last scan: {last_run.started_at} (run id: {last_run.run_id})")
        print(f"  status: {last_run.status.upper()} — {last_run.detail or '(no detail)'}")
        print(
            f"  observations collected: {last_run.observations_collected}, "
            f"alerts generated: {last_run.alerts_generated}"
        )
    return 0 if health.available else 1


def cmd_integrations_osquery_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        with instrument_module(
            db.conn, run_group_id=uuid.uuid4().hex[:12], module="integrations", operation="scan",
            external_tool="osquery",
        ) as rec:
            result = scan_osquery(db.conn)
            rec.observations_processed = len(result.observations)
            rec.findings_produced = len(result.discrepancies)

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Health: {result.health.status.upper()} — {result.health.detail}")

    if not result.available:
        print()
        print(
            "osquery was unavailable/errored this pass — no observations or "
            "crosscheck alerts were produced. Secure's own native collectors "
            "are unaffected; this is only a cross-check source."
        )
        logger.warning(
            "osquery scan unavailable/error",
            extra={"event": "integrations_osquery_scan_unavailable", "component": "cli"},
        )
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"

    print(f"Observations collected: {len(result.observations)}")
    if result.failed_queries:
        print(f"Queries that failed this pass: {', '.join(result.failed_queries)}")
    print()

    if result.discrepancies:
        print(f"CROSS-CHECK DISCREPANCIES ({len(result.discrepancies)}):")
        for d in result.discrepancies:
            print(f"  [{d.severity.upper()}] {d.kind}/{d.discrepancy_type} — {d.identity_key}")
            print(f"           {d.message}")
        print()
        print("Review these, then: secure integrations osquery mark-alert <id> known|unknown")
    else:
        print(
            "No cross-check discrepancies — every listening port and launchd "
            "entry osquery reported this pass matches what Secure's own native "
            "scans already know about."
        )

    logger.info(
        "Ran an osquery integration scan",
        extra={"event": "integrations_osquery_scan", "component": "cli"},
    )
    return 1 if (result.discrepancies or result.failed_queries) else 0


def cmd_integrations_osquery_observations(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        observations = list_integration_observations(
            db.conn, integration=INTEGRATION_NAME, kind=args.kind, limit=args.limit
        )

    if not observations:
        print(
            "No osquery observations recorded yet. Run: secure integrations osquery scan"
        )
        return 0

    for record in observations:
        print(f"#{record.id:<5} [{record.kind}] {record.identity_key} — {record.collected_at}")
        print(f"          {record.fields}")

    return 0


def cmd_integrations_osquery_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_integration_alerts(db.conn, integration=INTEGRATION_NAME)

    if not alerts:
        print("No osquery cross-check alerts recorded yet. Run: secure integrations osquery scan")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():4}] "
            f"{record.kind}/{record.discrepancy} — {record.label or record.identity_key} "
            f"— {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def _refuse_foreign_alert(alert, integration: str, args: argparse.Namespace) -> "int | None":
    """Exit code 2 (after telling the operator which command to use) when
    `alert` belongs to another integration, else None. The id is looked up
    alone, so without this `osquery mark-alert <id>` could mark a Sigma
    alert; marking known removes an alert from review."""
    if alert.integration == integration:
        return None
    print(
        f"Refusing: alert #{args.alert_id} belongs to {alert.integration}, not {integration}. "
        f"Mark it with `secure integrations {alert.integration} mark-alert {args.alert_id} {args.status}`."
    )
    return 2


def cmd_integrations_osquery_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_integration_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No osquery alert found with id {args.alert_id}. "
                "Run `secure integrations osquery alerts` to see recorded alerts."
            )
            return 1
        refused = _refuse_foreign_alert(alert, "osquery", args)
        if refused is not None:
            return refused
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="integration_alerts", alert_id=alert.id,
                subject=alert.label or alert.identity_key,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_integration_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.label or alert.identity_key}) as {args.status}.")
    logger.info(
        "Marked an osquery integration alert known/unknown",
        extra={"event": "integrations_osquery_mark_alert", "component": "cli"},
    )
    return 0


# ---------- yarax (Phase 16) ----------


def cmd_integrations_yarax_status(args: argparse.Namespace) -> int:
    """Show yara_x's own availability/health and the configured ruleset
    directory's current contents, independent of running a scan."""
    cfg = _bootstrap()

    health = yarax_check_availability()
    print(f"yara_x availability: {health.status.upper()}")
    print(f"  {health.detail}")
    if health.tool_version:
        print(f"  library version: {health.tool_version}")

    rules_dir = cfg.yara_rules_dir_path()
    compiled, load_errors = load_rulesets(rules_dir)
    print()
    print(f"Ruleset directory: {rules_dir}")
    print(f"  rulesets loaded: {len(compiled)}")
    for c in compiled:
        print(f"    - {c.info.version_label} ({c.info.source_path})")
    if load_errors:
        print(f"  rulesets that failed to load: {len(load_errors)}")
        for e in load_errors:
            print(f"    - {e.info.name} ({e.info.source_path}): {e.detail}")

    with Database(cfg.database_path()) as db:
        last_run = find_latest_integration_run(db.conn, YARAX_INTEGRATION_NAME)

    print()
    if last_run is None:
        print("No YARA-X scan has been run yet.")
    else:
        print(f"Last scan: {last_run.started_at} (run id: {last_run.run_id})")
        print(f"  status: {last_run.status.upper()} — {last_run.detail or '(no detail)'}")
        print(
            f"  observations collected: {last_run.observations_collected}, "
            f"alerts generated: {last_run.alerts_generated}"
        )
    return 0 if health.available else 1


def _print_yara_scan_result(result, targets=None) -> None:
    print(f"Scan at {result.scanned_at} (run id: {result.run_id}, trigger: {result.trigger})")
    print(f"Health: {result.health.status.upper()} — {result.health.detail}")

    if not result.available:
        print()
        print(
            "yara_x was unavailable/errored this pass — no files were scanned. "
            "Secure's own native File Integrity Monitoring is unaffected; this "
            "is only an additional content-detection capability."
        )
        return

    if targets:
        reasons = {t.path: t.reason for t in targets}
    else:
        reasons = {}

    print(f"Rulesets loaded: {len(result.rulesets_loaded)}")
    if result.ruleset_load_errors:
        print(f"Rulesets that failed to load: {len(result.ruleset_load_errors)}")
        for e in result.ruleset_load_errors:
            print(f"  - {e.info.name}: {e.detail}")

    print()
    print(f"Files considered: {len(result.files)}")
    for fr in result.files:
        reason = f" ({reasons[fr.path]})" if fr.path in reasons else ""
        if not fr.scanned:
            print(f"  SKIPPED [{fr.skip_reason}] {fr.path}{reason}")
            continue
        match_note = f"{len(fr.observations)} match(es)" if fr.observations else "no matches"
        if fr.content_note:
            match_note += f" (bytes of a {fr.content_note.replace('_', ' ')}; contents not inspected)"
        print(f"  scanned  {fr.path}{reason} — {match_note}")
        for err in fr.ruleset_errors:
            print(f"      ruleset error: {err}")

    print()
    if result.findings:
        print(f"FINDINGS ({len(result.findings)}):")
        for finding in result.findings:
            print(f"  [{finding.severity.upper()}] rule '{finding.rule_name}' — {finding.file_path}")
            print(f"           {finding.message}")
        print()
        print("Review these, then: secure integrations yarax mark-alert <id> known|unknown")
    else:
        print("No rule matches this pass.")


def cmd_integrations_yarax_scan_file(args: argparse.Namespace) -> int:
    """Scan one or more explicitly-named files — the "user-requested
    files" priority source. Never expands a directory; a directory path
    is reported as skipped, not walked (see scanner.py's module
    docstring)."""
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_paths(db.conn, cfg, args.paths, trigger="manual", timeout_seconds=args.timeout)

    _print_yara_scan_result(result)
    logger.info(
        "Ran a YARA-X file scan",
        extra={"event": "integrations_yarax_scan_file", "component": "cli"},
    )
    if not result.available:
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"
    return 1 if result.findings else 0


def cmd_integrations_yarax_scan_fim_alerts(args: argparse.Namespace) -> int:
    """Scan files behind unreviewed MEDIUM/HIGH File Integrity Monitoring
    alerts — the "security-relevant FIM events" priority source."""
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        targets, result = scan_fim_alerts(db.conn, cfg)

    if not targets:
        print("No unreviewed MEDIUM/HIGH File Integrity Monitoring alerts to scan.")
        return 0

    _print_yara_scan_result(result, targets=targets)
    logger.info(
        "Ran a YARA-X scan over File Integrity Monitoring alerts",
        extra={"event": "integrations_yarax_scan_fim_alerts", "component": "cli"},
    )
    if not result.available:
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"
    return 1 if result.findings else 0


def cmd_integrations_yarax_scan_suspicious(args: argparse.Namespace) -> int:
    """Scan executables behind unreviewed persistence "unusual/unsigned
    process" alerts — the "suspicious files" priority source."""
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        targets, result = scan_suspicious(db.conn, cfg)

    if not targets:
        print("No unreviewed unusual/unsigned-process persistence alerts to scan.")
        return 0

    _print_yara_scan_result(result, targets=targets)
    logger.info(
        "Ran a YARA-X scan over suspicious persistence alerts",
        extra={"event": "integrations_yarax_scan_suspicious", "component": "cli"},
    )
    if not result.available:
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"
    return 1 if result.findings else 0


def cmd_integrations_yarax_rulesets(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    rules_dir = cfg.yara_rules_dir_path()
    compiled, load_errors = load_rulesets(rules_dir)

    print(f"Ruleset directory: {rules_dir}")
    if not compiled and not load_errors:
        print("No *.yar/*.yara files found. Add rule files there to configure rulesets.")
        return 0

    for c in compiled:
        print(f"  OK      {c.info.version_label} ({c.info.source_path})")
    for e in load_errors:
        print(f"  FAILED  {e.info.name} ({e.info.source_path}): {e.detail}")

    return 1 if load_errors else 0


def cmd_integrations_yarax_observations(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        observations = list_integration_observations(
            db.conn, integration=YARAX_INTEGRATION_NAME, kind=args.kind, limit=args.limit
        )

    if not observations:
        print("No YARA-X observations recorded yet.")
        return 0

    for record in observations:
        print(f"#{record.id:<5} [{record.kind}] {record.identity_key} — {record.collected_at}")
        print(f"          {record.fields}")

    return 0


def cmd_integrations_yarax_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_integration_alerts(db.conn, integration=YARAX_INTEGRATION_NAME)

    if not alerts:
        print("No YARA-X findings recorded yet.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.label or record.identity_key} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_integrations_yarax_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_integration_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No YARA-X finding found with id {args.alert_id}. "
                "Run `secure integrations yarax alerts` to see recorded findings."
            )
            return 1
        refused = _refuse_foreign_alert(alert, "yarax", args)
        if refused is not None:
            return refused
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="integration_alerts", alert_id=alert.id,
                subject=alert.label or alert.identity_key,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_integration_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.label or alert.identity_key}) as {args.status}.")
    logger.info(
        "Marked a YARA-X integration alert known/unknown",
        extra={"event": "integrations_yarax_mark_alert", "component": "cli"},
    )
    return 0


# ---------- sigma (Phase 17) ----------


def cmd_integrations_sigma_status(args: argparse.Namespace) -> int:
    """Show PyYAML's own availability/health, the configured rule
    directory's contents (with each rule's own EVALUABLE/NOT_EVALUABLE
    capability verdict — cheap, requires no telemetry query), and the
    last scan's summary. No scan is run.
    """
    cfg = _bootstrap()

    health = sigma_check_availability()
    print(f"PyYAML availability: {health.status.upper()}")
    print(f"  {health.detail}")
    if health.tool_version:
        print(f"  library version: {health.tool_version}")

    rules_dir = cfg.sigma_rules_dir_path()
    rules, load_errors = load_rules(rules_dir)
    print()
    print(f"Rule directory: {rules_dir}")
    print(f"  rules loaded: {len(rules)}")
    for rule in rules:
        capability = check_capability(rule)
        tag = "EVALUABLE    " if capability.evaluable else "NOT_EVALUABLE"
        print(f"    [{tag}] {rule.version_label} — {rule.title}")
        print(f"        {capability.reason}")
    if load_errors:
        print(f"  rules that failed to load: {len(load_errors)}")
        for e in load_errors:
            print(f"    - {e.source_path}: {e.detail}")

    with Database(cfg.database_path()) as db:
        last_run = find_latest_integration_run(db.conn, SIGMA_INTEGRATION_NAME)

    print()
    if last_run is None:
        print("No Sigma scan has been run yet.")
    else:
        print(f"Last scan: {last_run.started_at} (run id: {last_run.run_id})")
        print(f"  status: {last_run.status.upper()} — {last_run.detail or '(no detail)'}")
        print(
            f"  observations collected: {last_run.observations_collected}, "
            f"alerts generated: {last_run.alerts_generated}"
        )
    return 0 if health.available else 1


def cmd_integrations_sigma_rules(args: argparse.Namespace) -> int:
    """List every configured rule with its capability verdict, without
    running a scan or touching telemetry — the fastest way to check
    "would this rule even be evaluable" while authoring/importing rules.
    """
    cfg = _bootstrap()
    rules_dir = cfg.sigma_rules_dir_path()
    rules, load_errors = load_rules(rules_dir)

    print(f"Rule directory: {rules_dir}")
    if not rules and not load_errors:
        print("No *.yml/*.yaml files found. Add rule files there to configure Sigma rules.")
        return 0

    for rule in rules:
        capability = check_capability(rule)
        tag = "EVALUABLE    " if capability.evaluable else "NOT_EVALUABLE"
        print(f"  [{tag}] {rule.version_label} — {rule.title} ({rule.source_path})")
        print(f"      required telemetry: {capability.required_telemetry}")
        print(f"      {capability.reason}")
    for e in load_errors:
        print(f"  FAILED  {e.source_path}: {e.detail}")

    return 1 if load_errors else 0


def cmd_integrations_sigma_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        with instrument_module(
            db.conn, run_group_id=uuid.uuid4().hex[:12], module="integrations", operation="scan",
            external_tool="sigma",
        ) as rec:
            result = scan_sigma(db.conn, cfg, lookback_hours=args.lookback_hours)
            rec.observations_processed = result.evaluable_count
            rec.findings_produced = result.matched_count

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Health: {result.health.status.upper()} — {result.health.detail}")

    if not result.available:
        print()
        print(
            "PyYAML was unavailable/errored this pass — no rules were evaluated. "
            "Secure's own native collectors are unaffected; this is only an "
            "additional detection-rule layer."
        )
        logger.warning(
            "sigma scan unavailable/error",
            extra={"event": "integrations_sigma_scan_unavailable", "component": "cli"},
        )
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"

    print(f"Rules loaded: {len(result.rules_loaded)}")
    if result.rule_load_errors:
        print(f"Rules that failed to load: {len(result.rule_load_errors)}")
        for e in result.rule_load_errors:
            print(f"  - {e.source_path}: {e.detail}")
    print(
        f"Evaluable: {result.evaluable_count}, "
        f"not evaluable: {result.not_evaluable_count}, "
        f"matched: {result.matched_count}"
    )
    print()

    for outcome in result.outcomes:
        status_tag = outcome.evaluation_status.upper()
        print(f"  [{status_tag}] {outcome.rule.title}")
        if outcome.evaluation_status == EvaluationStatus.NOT_EVALUABLE.value:
            print(f"      {outcome.capability_reason}")
            continue
        note = f"{outcome.matches_count} match(es)" if outcome.matched else "no match"
        checked = f"({outcome.observations_checked} observation(s) checked)"
        truncated_note = " [evidence truncated]" if outcome.truncated else ""
        print(f"      {note} {checked}{truncated_note}")
        if outcome.evaluation_error:
            print(f"      evaluation error: {outcome.evaluation_error}")

    print()
    matched_outcomes = [o for o in result.outcomes if o.matched]
    if matched_outcomes:
        print(f"MATCHES ({len(matched_outcomes)}):")
        for o in matched_outcomes:
            print(f"  [{o.rule.level or 'unspecified'}] {o.rule.title} (alert #{o.alert_id})")
        print()
        print("Review these, then: secure integrations sigma mark-alert <id> known|unknown")
    else:
        print("No rule matches this pass.")

    logger.info(
        "Ran a Sigma scan",
        extra={"event": "integrations_sigma_scan", "component": "cli"},
    )
    return 1 if matched_outcomes else 0


def cmd_integrations_sigma_observations(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        observations = list_integration_observations(
            db.conn, integration=SIGMA_INTEGRATION_NAME, kind=args.kind, limit=args.limit
        )

    if not observations:
        print("No Sigma observations recorded yet. Run: secure integrations sigma scan")
        return 0

    for record in observations:
        fields = record.fields
        print(
            f"#{record.id:<5} [{fields.get('evaluation_status')}] "
            f"{fields.get('title')} — {record.collected_at}"
        )
        print(f"          {record.fields}")

    return 0


def cmd_integrations_sigma_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_integration_alerts(db.conn, integration=SIGMA_INTEGRATION_NAME)

    if not alerts:
        print("No Sigma rule matches recorded yet. Run: secure integrations sigma scan")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.label or record.identity_key} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_integrations_sigma_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_integration_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No Sigma match found with id {args.alert_id}. "
                "Run `secure integrations sigma alerts` to see recorded matches."
            )
            return 1
        refused = _refuse_foreign_alert(alert, "sigma", args)
        if refused is not None:
            return refused
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="integration_alerts", alert_id=alert.id,
                subject=alert.label or alert.identity_key,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_integration_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.label or alert.identity_key}) as {args.status}.")
    logger.info(
        "Marked a Sigma integration alert known/unknown",
        extra={"event": "integrations_sigma_mark_alert", "component": "cli"},
    )
    return 0


# ---------- suricata (Phase 18) ----------


def cmd_integrations_suricata_status(args: argparse.Namespace) -> int:
    """Show Suricata's own EVE log availability/packet-visibility health
    and the last scan's summary. No scan is run — see
    secure/integrations/suricata/availability.py for exactly what
    "health" means here (log presence, freshness, AND confirmed packet
    capture, not just "the file exists").
    """
    cfg = _bootstrap()

    health = suricata_check_availability(cfg)
    print(f"Suricata EVE log availability: {health.status.upper()}")
    print(f"  {health.detail}")
    if health.tool_version:
        print(f"  suricata binary version: {health.tool_version}")

    configured_path = cfg.suricata_eve_log_path_resolved()
    print()
    print(f"Configured EVE log path: {configured_path or '(not configured)'}")

    with Database(cfg.database_path()) as db:
        last_run = find_latest_integration_run(db.conn, SURICATA_INTEGRATION_NAME)

    print()
    if last_run is None:
        print("No Suricata scan has been run yet.")
    else:
        print(f"Last scan: {last_run.started_at} (run id: {last_run.run_id})")
        print(f"  status: {last_run.status.upper()} — {last_run.detail or '(no detail)'}")
        print(
            f"  observations collected: {last_run.observations_collected}, "
            f"alerts generated: {last_run.alerts_generated}"
        )
    return 0 if health.available else 1


def cmd_integrations_suricata_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        with instrument_module(
            db.conn, run_group_id=uuid.uuid4().hex[:12], module="integrations", operation="scan",
            external_tool="suricata",
        ) as rec:
            result = scan_suricata(db.conn, cfg)
            rec.observations_processed = len(result.new_alert_observations)
            rec.findings_produced = len(result.findings)

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Health: {result.health.status.upper()} — {result.health.detail}")

    if not result.available:
        print()
        print(
            "Suricata's EVE log was unavailable/unreadable this pass — no alerts were "
            "ingested. Secure's own native network monitoring is unaffected; this is only "
            "an additional IDS evidence source."
        )
        logger.warning(
            "suricata scan unavailable/error",
            extra={"event": "integrations_suricata_scan_unavailable", "component": "cli"},
        )
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"

    if result.health.status == "degraded":
        print(
            "  NOTE: packet visibility is degraded this pass — see the health detail above. "
            "Any absence of new alerts should NOT be read as 'nothing happened.'"
        )

    print(f"New alerts ingested: {len(result.findings)}")
    if result.skipped_records:
        print(f"Alert records skipped (missing required fields): {result.skipped_records}")
    if result.malformed_lines:
        print(f"Unparseable EVE log lines: {result.malformed_lines}")
    print()

    if result.findings:
        print(f"FINDINGS ({len(result.findings)}):")
        for finding in result.findings:
            print(f"  [{finding.severity.upper()}] {finding.signature}")
            print(f"           {finding.message}")
        print()
        print("Review these, then: secure integrations suricata mark-alert <id> known|unknown")
    else:
        print("No new alerts this pass.")

    logger.info(
        "Ran a Suricata EVE ingestion scan",
        extra={"event": "integrations_suricata_scan", "component": "cli"},
    )
    return 1 if result.findings else 0


def cmd_integrations_suricata_observations(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        observations = list_integration_observations(
            db.conn, integration=SURICATA_INTEGRATION_NAME, kind=args.kind, limit=args.limit
        )

    if not observations:
        print("No Suricata observations recorded yet. Run: secure integrations suricata scan")
        return 0

    for record in observations:
        print(f"#{record.id:<5} [{record.kind}] {record.identity_key} — {record.collected_at}")
        print(f"          {record.fields}")

    return 0


def cmd_integrations_suricata_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_integration_alerts(db.conn, integration=SURICATA_INTEGRATION_NAME)

    if not alerts:
        print("No Suricata alerts recorded yet. Run: secure integrations suricata scan")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.label or record.identity_key} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_integrations_suricata_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_integration_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No Suricata alert found with id {args.alert_id}. "
                "Run `secure integrations suricata alerts` to see recorded alerts."
            )
            return 1
        refused = _refuse_foreign_alert(alert, "suricata", args)
        if refused is not None:
            return refused
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="integration_alerts", alert_id=alert.id,
                subject=alert.label or alert.identity_key,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_integration_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.label or alert.identity_key}) as {args.status}.")
    logger.info(
        "Marked a Suricata integration alert known/unknown",
        extra={"event": "integrations_suricata_mark_alert", "component": "cli"},
    )
    return 0


# ---------- zeek (Phase 19) ----------


def cmd_integrations_zeek_status(args: argparse.Namespace) -> int:
    """Show Zeek's own log availability/freshness health and the last
    scan's summary. No scan is run. See
    secure/integrations/zeek/availability.py for exactly what "health"
    means here — and how it deliberately differs from Suricata's own
    packet-visibility health check.
    """
    cfg = _bootstrap()

    health = zeek_check_availability(cfg)
    print(f"Zeek log availability: {health.status.upper()}")
    print(f"  {health.detail}")
    if health.tool_version:
        print(f"  zeek binary version: {health.tool_version}")

    configured_dir = cfg.zeek_log_dir_resolved()
    print()
    print(f"Configured log directory: {configured_dir or '(not configured)'}")

    with Database(cfg.database_path()) as db:
        last_run = find_latest_integration_run(db.conn, ZEEK_INTEGRATION_NAME)

    print()
    if last_run is None:
        print("No Zeek scan has been run yet.")
    else:
        print(f"Last scan: {last_run.started_at} (run id: {last_run.run_id})")
        print(f"  status: {last_run.status.upper()} — {last_run.detail or '(no detail)'}")
        print(
            f"  observations collected: {last_run.observations_collected}, "
            f"alerts generated: {last_run.alerts_generated} (always 0 — Zeek is a "
            "behavioral-telemetry source, never a detection source)"
        )
    return 0 if health.available else 1


def cmd_integrations_zeek_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        with instrument_module(
            db.conn, run_group_id=uuid.uuid4().hex[:12], module="integrations", operation="scan",
            external_tool="zeek",
        ) as rec:
            result = scan_zeek(db.conn, cfg)
            rec.observations_processed = sum(result.counts_by_kind.values())
            rec.findings_produced = 0  # Zeek is behavioral telemetry only — never writes alerts

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Health: {result.health.status.upper()} — {result.health.detail}")

    if not result.available:
        print()
        print(
            "Zeek's log directory was unavailable/unreadable this pass — nothing was "
            "ingested. Secure's own native network monitoring and Suricata's own "
            "detection evidence are unaffected; this is only an additional behavioral-"
            "telemetry source."
        )
        logger.warning(
            "zeek scan unavailable/error",
            extra={"event": "integrations_zeek_scan_unavailable", "component": "cli"},
        )
        return 2  # unavailable/error: see docs/INTEGRATIONS.md "Exit codes"

    counts = result.counts_by_kind
    print(
        f"Observations ingested: {sum(counts.values())} "
        f"(conn={counts.get('conn', 0)}, dns={counts.get('dns', 0)}, "
        f"ssl={counts.get('ssl', 0)}, http={counts.get('http', 0)})"
    )
    if result.dedup_counts:
        print(
            "Connection dedup awareness: "
            + ", ".join(f"{k}={v}" for k, v in sorted(result.dedup_counts.items()))
        )
    if result.malformed_lines_by_log:
        print(
            "Unparseable log lines: "
            + ", ".join(f"{k}={v}" for k, v in sorted(result.malformed_lines_by_log.items()))
        )
    print(
        f"Baseline: {result.baseline_entities_updated} dns_query/tls_sni entities updated, "
        f"{result.baseline_anomalies_generated} anomaly finding(s) generated."
    )
    print()
    print(
        "No alerts — Zeek is a behavioral-telemetry source, never a detection source. "
        "Review ingested evidence with: secure integrations zeek observations"
    )

    logger.info(
        "Ran a Zeek log ingestion scan",
        extra={"event": "integrations_zeek_scan", "component": "cli"},
    )
    return 0


def cmd_integrations_zeek_observations(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        observations = list_integration_observations(
            db.conn, integration=ZEEK_INTEGRATION_NAME, kind=args.kind, limit=args.limit
        )

    if not observations:
        print("No Zeek observations recorded yet. Run: secure integrations zeek scan")
        return 0

    for record in observations:
        print(f"#{record.id:<5} [{record.kind}] {record.identity_key} — {record.collected_at}")
        print(f"          {record.fields}")

    return 0
