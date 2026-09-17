"""

cli.py — the command-line interface. This is the "front door" of the
app for now: everything you can do, you do through one of these
subcommands.

Design choice (beginner-friendly on purpose):
    argparse from the standard library, with one subcommand per
    action. No external CLI framework needed for something this
    small.

Commands:
    secure init                  Set up config, database, and log file.
                                  Use --role to label this machine (see
                                  the multi-device note below).
    secure status                Show where everything lives and a
                                  quick summary of the database.
    secure add-note "text"       Insert a test row into the database,
                                  to prove config -> logging -> storage
                                  are wired together correctly.
    secure explain <source> <id> Developer/debug: print the full
                                  Product Phase 13 explanation
                                  (confidence, evidence, uncertainty,
                                  recommended action) for one alert.
                                  Read-only. <source> is one of
                                  arpwatch/wifi/bluetooth/ble/
                                  persistence/fileintegrity/correlate/
                                  integrations.
                                  See secure/explain/.
    secure check                 Run the macOS security posture check
                                  (FileVault, firewall, Gatekeeper, SIP,
                                  automatic updates, pending updates,
                                  Remote Login/Screen Sharing/other
                                  sharing services) and store the
                                  results. See secure/checks/. Use
                                  --quick to skip the one check that
                                  talks to the network.
    secure snapshot               "Continuity" snapshot: files changed
                                  in this project/~/.secure, changed
                                  LaunchAgents/LaunchDaemons, and
                                  posture changes since the last check
                                  — all in the last --minutes (default
                                  15). See secure/continuity.py.
    secure inventory scan         Discover devices on the local network
                                  (ARP cache + a ping sweep of this
                                  Mac's own subnet), record IP/MAC/
                                  hostname/vendor/first-last-seen, and
                                  flag any newly-appearing device. See
                                  secure/inventory/.
    secure inventory list         List every device ever recorded.
    secure inventory name <id> "Name"
                                  Give a device (by IP or MAC) a
                                  friendly name.
    secure inventory mark <id> known|unknown
                                  Mark a device (by IP or MAC) as known
                                  or unknown.
    secure inventory prune        Remove stored device rows that
                                  shouldn't have been recorded as
                                  devices (empty addresses, broadcast,
                                  multicast) — see the Phase 4 bugfix
                                  note in PROJECT_NOTES.md.
    secure connections scan       Show this Mac's active TCP/UDP
                                  connections (local/remote address,
                                  port, state, PID, process name),
                                  record them, and flag any newly-seen
                                  remote destination. See
                                  secure/connections/.
    secure connections endpoints  List every remote destination ever
                                  recorded (the historical inventory).
    secure connections mark <id> known|unknown
                                  Mark a remote destination (by the id
                                  shown in `endpoints`) as known or
                                  unknown.
    secure listening scan         Audit every port this Mac is
                                  currently listening on (owning
                                  process, whether it's localhost-only
                                  or exposed to your network, and a
                                  plain-English risk note), and flag
                                  any newly-appeared service. See
                                  secure/listening/.
    secure listening list         List every listening service ever
                                  recorded (the historical inventory).
    secure listening mark <id> known|unknown
                                  Mark a listening service (by the id
                                  shown in `list`) as known or unknown.
    secure arpwatch scan          Read the ARP table, compare against
                                  last scan, and flag unexpected IP-
                                  to-MAC changes (especially the
                                  default gateway) or same-scan
                                  conflicts. Never sends any ARP
                                  traffic itself. See secure/arpwatch/.
    secure arpwatch list          List every arpwatch alert ever
                                  recorded.
    secure arpwatch mark <id> known|unknown
                                  Mark an arpwatch alert (by the id
                                  shown in `list`) as known or unknown.
    secure wifi scan              Show this Mac's current Wi-Fi
                                  connection (SSID, BSSID, channel,
                                  security, signal), warn on weak/open
                                  security, and flag a first-time
                                  network or lookalike SSID. Never
                                  joins, disconnects, or attacks
                                  anything. See secure/wifi/.
    secure wifi list               List every Wi-Fi network ever
                                  recorded (the historical inventory).
    secure wifi mark <id> known|unknown
                                  Mark a Wi-Fi network (by the id shown
                                  in `list`) as known or unknown.
    secure wifi alerts             List every lookalike-SSID alert
                                  ever recorded.
    secure wifi mark-alert <id> known|unknown
                                  Mark a wifi alert (by the id shown in
                                  `alerts`) as known or unknown.
    secure bluetooth scan         Show Bluetooth devices macOS already
                                  knows about (paired/configured/
                                  connected — NOT a live nearby-BLE
                                  scan, see secure/bluetooth/), flag a
                                  first-time device, and flag a device
                                  persistently seen while still
                                  untrusted. Never pairs, intercepts,
                                  or accesses anything.
    secure bluetooth list          List every Bluetooth device ever
                                  recorded.
    secure bluetooth mark <id> trusted|untrusted
                                  Mark a Bluetooth device (by the id
                                  shown in `list`) as trusted or
                                  untrusted.
    secure bluetooth alerts        List every persistent-unknown-device
                                  alert ever recorded.
    secure bluetooth mark-alert <id> known|unknown
                                  Mark a bluetooth alert (by the id
                                  shown in `alerts`) as known or
                                  unknown.
    secure bluetooth state         Check Bluetooth's current power/
                                  authorization state for this process
                                  (see secure/bluetooth/ble/state.py) —
                                  run this before `ble scan` if you're
                                  unsure why a scan isn't finding
                                  anything.
    secure bluetooth ble scan [--duration SECONDS]
                                  Run a live BLE discovery scan (see
                                  secure/bluetooth/ble/) — real nearby
                                  advertising peripherals, not just
                                  devices macOS already knows about.
                                  Flags first-time peripherals,
                                  persistently-seen untrusted
                                  peripherals, and significant RSSI
                                  changes. Never pairs, connects, or
                                  accesses anything — listens only.
    secure bluetooth ble list      List every BLE peripheral ever
                                  recorded.
    secure bluetooth ble mark <id> trusted|untrusted
                                  Mark a BLE peripheral (by the id
                                  shown in `ble list`) as trusted or
                                  untrusted.
    secure bluetooth ble alerts    List every BLE alert ever recorded.
    secure bluetooth ble mark-alert <id> known|unknown
                                  Mark a BLE alert (by the id shown in
                                  `ble alerts`) as known or unknown.
    secure persistence scan        Inventory running processes and
                                  common macOS persistence mechanisms
                                  (LaunchAgents, LaunchDaemons, login
                                  items — see secure/persistence/),
                                  record executable paths and
                                  best-effort code-signing info, and
                                  flag newly-created persistence
                                  entries and unusual/unsigned new
                                  processes. Never deletes, quarantines,
                                  disables, or modifies anything.
    secure persistence processes   List every process executable ever
                                  recorded.
    secure persistence items       List every persistence entry
                                  (LaunchAgent/LaunchDaemon/login item)
                                  ever recorded.
    secure persistence mark-process <id> known|unknown
                                  Mark a process entry (by the id shown
                                  in `processes`) as known or unknown.
    secure persistence mark-item <id> known|unknown
                                  Mark a persistence entry (by the id
                                  shown in `items`) as known or unknown.
    secure persistence alerts      List every persistence alert ever
                                  recorded.
    secure persistence mark-alert <id> known|unknown
                                  Mark a persistence alert (by the id
                                  shown in `alerts`) as known or
                                  unknown.
    secure integrations osquery status
                                  Show osqueryi availability/health and
                                  the last scan's summary, without
                                  running a full scan. See secure/
                                  integrations/.
    secure integrations osquery scan
                                  Collect processes/sockets/listening
                                  ports/launchd via osqueryi, normalize
                                  and store the results, and cross-check
                                  listening ports and launchd persistence
                                  against Secure's own native scans.
                                  Never disables or replaces any native
                                  collector — osquery is an additional,
                                  cross-checking source only. Unavailable/
                                  failed osquery always shows as
                                  unavailable/degraded, never clean.
    secure integrations osquery observations [--kind K] [--limit N]
                                  List recently collected osquery
                                  observations (raw normalized facts,
                                  not alerts).
    secure integrations osquery alerts
                                  List cross-check discrepancies only —
                                  a native/osquery MATCH never produces
                                  a row here (see crosscheck.py).
    secure integrations osquery mark-alert <id> known|unknown
                                  Mark a cross-check alert (by the id
                                  shown in `alerts`) as known or unknown.
    secure integrations yarax status
                                  Show yara_x availability/health,
                                  configured rulesets, and the last
                                  scan's summary. See secure/
                                  integrations/yarax/.
    secure integrations yarax scan-file <path> [<path> ...]
                                  Scan explicitly-named file(s) against
                                  every configured ruleset
                                  (user-requested files). Never scans a
                                  directory's contents.
    secure integrations yarax scan-fim-alerts
                                  Scan files behind unreviewed MEDIUM/
                                  HIGH File Integrity Monitoring alerts
                                  (security-relevant FIM events).
    secure integrations yarax scan-suspicious
                                  Scan executables behind unreviewed
                                  unusual/unsigned-process persistence
                                  alerts (suspicious files).
    secure integrations yarax rulesets
                                  List configured rulesets (from
                                  ~/.secure/yara_rules/ by default) and
                                  any that failed to load.
    secure integrations yarax observations [--kind K] [--limit N]
                                  List recently collected YARA-X
                                  observations (rule matches).
    secure integrations yarax alerts
                                  List YARA-X rule-match findings. A
                                  match is not automatically treated as
                                  malware — see docs/INTEGRATIONS.md.
    secure integrations yarax mark-alert <id> known|unknown
                                  Mark a finding (by the id shown in
                                  `alerts`) as known or unknown.
    secure integrations sigma status
                                  Show PyYAML availability/health,
                                  configured rules with their EVALUABLE/
                                  NOT_EVALUABLE capability verdicts, and
                                  the last scan's summary. See secure/
                                  integrations/sigma/.
    secure integrations sigma rules
                                  List configured Sigma rules (from
                                  ~/.secure/sigma_rules/ by default) and
                                  their capability verdict, without
                                  running a scan.
    secure integrations sigma scan [--lookback-hours N]
                                  Evaluate every configured rule against
                                  recent osquery telemetry. A rule Secure
                                  lacks telemetry for is always reported
                                  NOT_EVALUABLE, never treated as clean.
    secure integrations sigma observations [--kind K] [--limit N]
                                  List recent per-rule scan results — one
                                  row per loaded rule, every scan pass,
                                  evaluable or not, matched or not.
    secure integrations sigma alerts
                                  List Sigma rule-match findings. A match
                                  is not automatically treated as
                                  malicious — see docs/INTEGRATIONS.md.
    secure integrations sigma mark-alert <id> known|unknown
                                  Mark a finding (by the id shown in
                                  `alerts`) as known or unknown.
    secure integrations suricata status
                                  Show EVE JSON log availability AND
                                  packet-visibility health (not just
                                  whether the file exists — see secure/
                                  integrations/suricata/availability.py)
                                  and the last scan's summary.
    secure integrations suricata scan
                                  Ingest new alert records from the
                                  configured EVE log, correlate each
                                  against Secure's own native connection
                                  observations when identity and timing
                                  support it, and store the results.
                                  Secure never runs, configures, or
                                  manages Suricata itself, and never
                                  reproduces its detection logic — only
                                  its own already-written log output is
                                  read.
    secure integrations suricata observations [--kind K] [--limit N]
                                  List recently ingested EVE records
                                  (alert findings and packet-capture
                                  stats snapshots).
    secure integrations suricata alerts
                                  List Suricata IDS alerts.
    secure integrations suricata mark-alert <id> known|unknown
                                  Mark an alert (by the id shown in
                                  `alerts`) as known or unknown.
    secure integrations zeek status
                                  Show Zeek's own log availability/
                                  freshness health and the last scan's
                                  summary.
    secure integrations zeek scan
                                  Ingest new conn/dns/ssl/http log
                                  records, classify each conn.log record
                                  for dedup-awareness against Secure's
                                  own native connections and Suricata's
                                  own ingested alerts, feed DNS/TLS
                                  identities into the behavioral-
                                  baseline layer, and store the results.
                                  Zeek is behavioral telemetry, never a
                                  detection source — this command never
                                  produces alerts. Secure never runs,
                                  configures, or manages Zeek itself.
    secure integrations zeek observations [--kind K] [--limit N]
                                  List recently ingested Zeek records
                                  (kind=conn/dns/ssl/http).
    secure threatintel lookup auto|ip|domain|hash <value>
                                  Look up one indicator against every
                                  registered threat-intelligence
                                  provider (cache-first). This is the
                                  ONLY command in the whole app that can
                                  make a real external network request
                                  for an arbitrary indicator. Private/
                                  local indicators are never sent to a
                                  network-capable provider. Enrichment,
                                  not ground truth — never blocks
                                  anything and never upgrades Secure's
                                  own severity/confidence on its own.
    secure threatintel history [--type T] [--value V] [--provider P] [--limit N]
                                  List previously recorded lookups.
                                  Read-only; makes no new queries.
    secure threatintel providers  List every registered provider and
                                  whether it makes outbound network
                                  calls.

Multi-device note:
    This same project is meant to be copied onto more than one
    machine. Run `secure init --role server` on the machine that
    stays on all the time (e.g. the Mac mini), and `secure init
    --role workstation` (or just `secure init`, since that's the
    default) on machines that don't (e.g. a laptop). Each machine
    keeps entirely its own config/database/log under its own
    ~/.secure — nothing here talks over the network yet.

Try it:
    python -m secure init --role workstation
    python -m secure status
    python -m secure add-note "hello from the CLI"
    python -m secure status
    python -m secure check
    python -m secure snapshot
    python -m secure inventory scan
    python -m secure inventory list
    python -m secure inventory prune
    python -m secure connections scan
    python -m secure connections endpoints
    python -m secure listening scan
    python -m secure listening list
    python -m secure arpwatch scan
    python -m secure arpwatch list
    python -m secure wifi scan
    python -m secure wifi list
    python -m secure wifi alerts
    python -m secure bluetooth scan
    python -m secure bluetooth list
    python -m secure bluetooth alerts
    python -m secure bluetooth state
    python -m secure bluetooth ble scan
    python -m secure bluetooth ble list
    python -m secure bluetooth ble alerts
    python -m secure persistence scan
    python -m secure persistence processes
    python -m secure persistence items
    python -m secure persistence alerts
    python -m secure integrations osquery status
    python -m secure integrations osquery scan
    python -m secure integrations osquery observations
    python -m secure integrations osquery alerts
    python -m secure integrations yarax status
    python -m secure integrations yarax rulesets
    python -m secure integrations yarax scan-file /path/to/file
    python -m secure integrations yarax scan-fim-alerts
    python -m secure integrations yarax scan-suspicious
    python -m secure integrations yarax alerts
    python -m secure integrations sigma status
    python -m secure integrations sigma rules
    python -m secure integrations sigma scan
    python -m secure integrations sigma alerts
    python -m secure integrations suricata status
    python -m secure integrations suricata scan
    python -m secure integrations suricata alerts
    python -m secure integrations zeek status
    python -m secure integrations zeek scan
    python -m secure integrations zeek observations
    python -m secure threatintel providers
    python -m secure threatintel lookup auto 8.8.8.8
    python -m secure threatintel history

"""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
from secure.baseline.constants import ANOMALY_TIERS
from secure.baseline.entities import ENTITY_TYPES
from secure.config import (
    DEVICE_ROLES,
    ConfigError,
    load_config,
)
from secure.correlate.analysis import DEFAULT_WINDOW_SECONDS
from secure.correlate.scanner import DEFAULT_LOOKBACK_HOURS
from secure.correlate.chain_scanner import DEFAULT_LOOKBACK_HOURS as CHAIN_DEFAULT_LOOKBACK_HOURS
from secure.logging_setup import setup_logging
from secure.storage.models import add_event
from secure.threatintel.indicators import INDICATOR_TYPES


logger = logging.getLogger(__name__)

def _bootstrap():
    """Load config and turn on logging. Every command needs this."""
    cfg = load_config()
    setup_logging(cfg.log_path(), level=cfg.log_level)
    return cfg


def _record_alert_review_change(
    conn,
    *,
    source_table: str,
    alert_id: int,
    subject: str,
    severity: str,
    was_known: bool,
    now_known: bool,
) -> None:
    """Append-only history of an alert's review-state change, via the
    existing generic `events` table — no schema change (see
    PROJECT_NOTES.md, Product Phase 13). Records an explicit
    UNKNOWN -> KNOWN or KNOWN -> UNKNOWN transition rather than just
    the new value, and deliberately stores only a concise `subject`
    (e.g. an IP, SSID, or path), not the alert's full message, so
    marking the same alert repeatedly doesn't pile up duplicated long
    text in the events table. Does not print anything and does not
    affect the calling command's exit code — this is pure history,
    invisible to stdout.

    Callers are expected to only invoke this when `was_known !=
    now_known` (an actual change) — see each `cmd_*_mark_alert`
    handler.
    """
    transition = f"{'KNOWN' if was_known else 'UNKNOWN'} -> {'KNOWN' if now_known else 'UNKNOWN'}"
    message = f"{source_table} alert #{alert_id} ({subject}) severity={severity}: {transition}"
    add_event(conn, category="alert_review_change", message=message)


def _record_anomaly_review_change(
    conn,
    *,
    event: "object",
    was_known: bool,
    now_known: bool,
) -> None:
    """Append-only history of an anomaly event's review-state change
    (Phase 14 Stage 4F) — same generic-`events`-table pattern as
    _record_alert_review_change() above (Product Phase 13), but its own
    category ("anomaly_review_change") so anomaly review history stays
    distinguishable from every pre-Phase-14 alert source's review
    history rather than conflated with it. Records the anomaly's id,
    entity, feature, tier, and source reference (not the full
    expected_summary) as the concise subject, for the same "don't pile
    up duplicated long text on repeated marking" reason
    _record_alert_review_change() documents.

    Callers are expected to only invoke this when `was_known !=
    now_known` (an actual change) — see cmd_anomalies_mark.
    """
    transition = f"{'KNOWN' if was_known else 'UNKNOWN'} -> {'KNOWN' if now_known else 'UNKNOWN'}"
    source_ref = f" source={event.source_table}#{event.source_id}" if event.source_table else ""
    message = (
        f"anomaly_events #{event.id} ({event.entity_type}/{event.entity_key}, "
        f"{event.feature_name}) tier={event.anomaly_tier}{source_ref}: {transition}"
    )
    add_event(conn, category="anomaly_review_change", message=message)



from .root import (
    _EXPLAIN_SOURCES,
    cmd_init,
    cmd_status,
    cmd_add_note,
    cmd_explain,
    cmd_check,
    cmd_snapshot,
    cmd_self_mark_update_context,
    cmd_run_all,
)
from .downloads import cmd_downloads
from .loghunt import cmd_loghunt
from secure.loghunt.hunts import HUNTS as _LOGHUNTS

HUNT_NAMES = tuple(_LOGHUNTS)
from .inventory import (
    _format_device_line,
    cmd_inventory_scan,
    cmd_inventory_list,
    cmd_inventory_name,
    cmd_inventory_mark,
    cmd_inventory_prune,
)
from .connections import (
    _format_connection_line,
    cmd_connections_scan,
    cmd_connections_endpoints,
    cmd_connections_mark,
)
from .listening import (
    _format_listening_line,
    cmd_listening_scan,
    cmd_listening_list,
    cmd_listening_mark,
)
from .arpwatch import (
    _SEVERITY_RANK,
    cmd_arpwatch_scan,
    cmd_arpwatch_list,
    cmd_arpwatch_mark,
)
from .wifi import (
    _format_bssid,
    cmd_wifi_scan,
    cmd_wifi_list,
    cmd_wifi_mark,
    cmd_wifi_alerts,
    cmd_wifi_mark_alert,
)
from .bluetooth import (
    _format_bluetooth_device_line,
    cmd_bluetooth_scan,
    cmd_bluetooth_list,
    cmd_bluetooth_mark,
    cmd_bluetooth_alerts,
    cmd_bluetooth_mark_alert,
    cmd_bluetooth_state,
)
from .ble import (
    _format_ble_peripheral_line,
    cmd_bluetooth_ble_scan,
    cmd_bluetooth_ble_list,
    cmd_bluetooth_ble_mark,
    cmd_bluetooth_ble_alerts,
    cmd_bluetooth_ble_mark_alert,
)
from .persistence import (
    cmd_persistence_scan,
    _format_process_entry_line,
    cmd_persistence_processes,
    cmd_persistence_mark_process,
    _format_persistence_entry_line,
    cmd_persistence_items,
    cmd_persistence_mark_item,
    cmd_persistence_alerts,
    cmd_persistence_mark_alert,
)
from .integrations import (
    cmd_integrations_osquery_status,
    cmd_integrations_osquery_scan,
    cmd_integrations_osquery_observations,
    cmd_integrations_osquery_alerts,
    cmd_integrations_osquery_mark_alert,
    cmd_integrations_yarax_status,
    cmd_integrations_yarax_scan_file,
    cmd_integrations_yarax_scan_fim_alerts,
    cmd_integrations_yarax_scan_suspicious,
    cmd_integrations_yarax_rulesets,
    cmd_integrations_yarax_observations,
    cmd_integrations_yarax_alerts,
    cmd_integrations_yarax_mark_alert,
    cmd_integrations_sigma_status,
    cmd_integrations_sigma_rules,
    cmd_integrations_sigma_scan,
    cmd_integrations_sigma_observations,
    cmd_integrations_sigma_alerts,
    cmd_integrations_sigma_mark_alert,
    cmd_integrations_suricata_status,
    cmd_integrations_suricata_scan,
    cmd_integrations_suricata_observations,
    cmd_integrations_suricata_alerts,
    cmd_integrations_suricata_mark_alert,
    cmd_integrations_zeek_status,
    cmd_integrations_zeek_scan,
    cmd_integrations_zeek_observations,
)
from secure.cli.threatintel import (
    cmd_threatintel_lookup,
    cmd_threatintel_history,
    cmd_threatintel_providers,
)
from .fileintegrity import (
    cmd_fileintegrity_scan,
    cmd_fileintegrity_watch_add,
    cmd_fileintegrity_watch_list,
    cmd_fileintegrity_watch_remove,
    cmd_fileintegrity_files,
    cmd_fileintegrity_mark_file,
    cmd_fileintegrity_events,
    cmd_fileintegrity_alerts,
    cmd_fileintegrity_mark_alert,
)
from .correlate import (
    cmd_correlate_run,
    cmd_correlate_list,
    cmd_correlate_mark_alert,
    cmd_correlate_chains_run,
    cmd_correlate_chains_list,
    cmd_correlate_chains_mark_alert,
)
from .investigate import (
    cmd_investigate_show,
    cmd_investigate_types,
)
from .dfir import (
    cmd_dfir_status,
    cmd_dfir_suggest,
    cmd_dfir_collect,
    cmd_dfir_list,
    cmd_dfir_show,
    cmd_dfir_evidence,
)
from .validate import (
    cmd_validate_run,
    cmd_validate_list,
    cmd_validate_show,
    cmd_validate_report,
)
from .ai import (
    cmd_ai_status,
    cmd_ai_roles,
    cmd_ai_ask,
    cmd_ai_history,
    cmd_ai_show,
    cmd_ai_verify_list_ops,
    cmd_ai_verify_run,
    cmd_ai_verify_suite,
    cmd_ai_verify_history,
    cmd_ai_verify_show,
    cmd_ai_changes_propose,
    cmd_ai_changes_list,
    cmd_ai_changes_show,
    cmd_ai_changes_approve,
    cmd_ai_changes_reject,
)
from .detect import (
    cmd_detect_sync,
    cmd_detect_list,
    cmd_detect_show,
    cmd_detect_enable,
    cmd_detect_disable,
    cmd_detect_test,
    cmd_detect_annotate,
)
from secure.investigate.entity import ENTITY_TYPES as INVESTIGATE_ENTITY_TYPES
from secure.investigate.timeline import DEFAULT_MAX_HOPS
from .baseline import (
    cmd_baseline_status,
    cmd_baseline_list,
    cmd_baseline_show,
    _set_baseline_flag,
    cmd_baseline_exclude,
    cmd_baseline_include,
    cmd_baseline_freeze,
    cmd_baseline_unfreeze,
    cmd_baseline_reset,
)
from .anomalies import (
    cmd_anomalies_list,
    cmd_anomalies_show,
    cmd_anomalies_mark,
)
from .agent import (
    cmd_agent_status,
    cmd_agent_discover,
    cmd_agent_run,
    cmd_agent_list,
    cmd_agent_show,
    cmd_agent_resume,
    cmd_agent_remove_worktree,
    cmd_agent_approve,
    cmd_agent_actions,
    cmd_agent_center_check,
    cmd_agent_center_list,
    cmd_agent_center_show,
    cmd_agent_diagnose,
    cmd_agent_memory,
    cmd_agent_maintain,
    cmd_agent_promote,
    cmd_agent_toolchain,
    cmd_agent_verified,
    cmd_agent_supervise,
    cmd_agent_supervisor_plist,
    cmd_agent_supervisor_propose,
)
from secure.agent.orchestrator import RepairNotEligible
from secure.agent.worktree import WorktreeError
from .diagnostics import (
    cmd_diagnostics_performance,
    cmd_diagnostics_system,
    cmd_diagnostics_modules,
    cmd_diagnostics_tools,
    cmd_diagnostics_history,
    cmd_diagnostics_milestone_record,
    cmd_diagnostics_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure",
        description="Foundation CLI for the Secure project (no security "
        "features yet — just config, storage, and logging plumbing).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init", help="Create the config file, database, and log file."
    )
    init_parser.add_argument(
        "--role",
        choices=DEVICE_ROLES,
        default=None,
        help="Label this machine as 'server' (always-on) or 'workstation' "
        "(comes and goes). Defaults to 'workstation' on first init; "
        "omit on later runs to leave the existing role unchanged.",
    )
    init_parser.set_defaults(func=cmd_init)

    status_parser = subparsers.add_parser(
        "status", help="Show app paths and a summary of stored events."
    )
    status_parser.set_defaults(func=cmd_status)

    note_parser = subparsers.add_parser(
        "add-note", help="Insert a test event row into the database."
    )
    note_parser.add_argument("text", help="Text to store as the event message.")
    note_parser.set_defaults(func=cmd_add_note)

    explain_parser = subparsers.add_parser(
        "explain",
        help="Developer/debug: print the full Phase-13 explanation "
        "(confidence, evidence, uncertainty, recommended action) for one "
        "alert. Read-only.",
    )
    explain_parser.add_argument(
        "source", choices=sorted(_EXPLAIN_SOURCES.keys()), help="Which alert table to look in."
    )
    explain_parser.add_argument("alert_id", help="Alert id (see e.g. `secure arpwatch list`).")
    explain_parser.set_defaults(func=cmd_explain)

    check_parser = subparsers.add_parser(
        "check",
        help="Run the macOS security posture check (FileVault, firewall, "
        "Gatekeeper, SIP, updates, XProtect, sharing services).",
    )
    check_parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip the pending-updates check, the only one that talks to "
        "the network and can take several seconds.",
    )
    check_parser.set_defaults(func=cmd_check)

    downloads_parser = subparsers.add_parser(
        "downloads",
        help="Where recent downloads came from (macOS quarantine history), with "
        "installers, IP-address hosts and plain-http downloads flagged.",
    )
    downloads_parser.add_argument("--days", type=int, default=30, help="How far back to look (default: 30).")
    downloads_parser.add_argument("--limit", type=int, default=500, help="Most events to show (default: 500).")
    downloads_parser.add_argument("--flagged", action="store_true", help="Show only flagged downloads.")
    downloads_parser.set_defaults(func=cmd_downloads)

    loghunt_parser = subparsers.add_parser(
        "loghunt",
        help="Search the macOS unified log with fixed hunts (Gatekeeper, XProtect, TCC denials, "
        "quarantine checks) and summarise matches by message template.",
    )
    loghunt_parser.add_argument("--hours", type=int, default=24, help="Window, 1-72 hours (default: 24).")
    loghunt_parser.add_argument("--hunt", action="append", choices=sorted(HUNT_NAMES),
                                help="Run only this hunt; repeat for several (default: all).")
    loghunt_parser.set_defaults(func=cmd_loghunt)

    snapshot_parser = subparsers.add_parser(
        "snapshot",
        help="Continuity snapshot: file/app-state/launch-item/posture changes "
        "in the last N minutes.",
    )
    snapshot_parser.add_argument(
        "--minutes",
        type=int,
        default=15,
        help="How far back to look for file changes (default: 15).",
    )
    snapshot_parser.set_defaults(func=cmd_snapshot)

    inventory_parser = subparsers.add_parser(
        "inventory", help="Local network device inventory (scan/list/name/mark)."
    )
    inventory_subparsers = inventory_parser.add_subparsers(
        dest="inventory_command", required=True
    )

    inventory_scan_parser = inventory_subparsers.add_parser(
        "scan", help="Discover devices on the local network right now."
    )
    inventory_scan_parser.add_argument(
        "--no-ping-sweep",
        action="store_true",
        help="Skip the ICMP ping sweep; only read whatever's already in the ARP cache.",
    )
    inventory_scan_parser.set_defaults(func=cmd_inventory_scan)

    inventory_list_parser = inventory_subparsers.add_parser(
        "list", help="List every device ever recorded (the historical inventory)."
    )
    inventory_list_parser.set_defaults(func=cmd_inventory_list)

    inventory_name_parser = inventory_subparsers.add_parser(
        "name", help="Give a device a friendly name."
    )
    inventory_name_parser.add_argument("identifier", help="The device's IP or MAC address.")
    inventory_name_parser.add_argument("name", help="Friendly name to store.")
    inventory_name_parser.set_defaults(func=cmd_inventory_name)

    inventory_mark_parser = inventory_subparsers.add_parser(
        "mark", help="Mark a device as known or unknown."
    )
    inventory_mark_parser.add_argument("identifier", help="The device's IP or MAC address.")
    inventory_mark_parser.add_argument("status", choices=["known", "unknown"])
    inventory_mark_parser.set_defaults(func=cmd_inventory_mark)

    inventory_prune_parser = inventory_subparsers.add_parser(
        "prune",
        help="Remove stored device rows that shouldn't have been recorded "
        "as devices (empty addresses, broadcast, multicast).",
    )
    inventory_prune_parser.set_defaults(func=cmd_inventory_prune)

    connections_parser = subparsers.add_parser(
        "connections", help="Active TCP/UDP connection monitor (scan/endpoints/mark)."
    )
    connections_subparsers = connections_parser.add_subparsers(
        dest="connections_command", required=True
    )

    connections_scan_parser = connections_subparsers.add_parser(
        "scan", help="Show this Mac's active connections right now."
    )
    connections_scan_parser.set_defaults(func=cmd_connections_scan)

    connections_endpoints_parser = connections_subparsers.add_parser(
        "endpoints", help="List every remote destination ever recorded."
    )
    connections_endpoints_parser.set_defaults(func=cmd_connections_endpoints)

    connections_mark_parser = connections_subparsers.add_parser(
        "mark", help="Mark a remote destination as known or unknown."
    )
    connections_mark_parser.add_argument(
        "endpoint_id", type=int, help="The destination's id, from `secure connections endpoints`."
    )
    connections_mark_parser.add_argument("status", choices=["known", "unknown"])
    connections_mark_parser.set_defaults(func=cmd_connections_mark)

    listening_parser = subparsers.add_parser(
        "listening", help="Listening port and service audit (scan/list/mark)."
    )
    listening_subparsers = listening_parser.add_subparsers(
        dest="listening_command", required=True
    )

    listening_scan_parser = listening_subparsers.add_parser(
        "scan", help="Show every port this Mac is currently listening on."
    )
    listening_scan_parser.set_defaults(func=cmd_listening_scan)

    listening_list_parser = listening_subparsers.add_parser(
        "list", help="List every listening service ever recorded."
    )
    listening_list_parser.set_defaults(func=cmd_listening_list)

    listening_mark_parser = listening_subparsers.add_parser(
        "mark", help="Mark a listening service as known or unknown."
    )
    listening_mark_parser.add_argument(
        "service_id", type=int, help="The service's id, from `secure listening list`."
    )
    listening_mark_parser.add_argument("status", choices=["known", "unknown"])
    listening_mark_parser.set_defaults(func=cmd_listening_mark)

    arpwatch_parser = subparsers.add_parser(
        "arpwatch", help="ARP/neighbor-table monitoring (scan/list/mark)."
    )
    arpwatch_subparsers = arpwatch_parser.add_subparsers(
        dest="arpwatch_command", required=True
    )

    arpwatch_scan_parser = arpwatch_subparsers.add_parser(
        "scan", help="Read the ARP table now and flag any unexpected changes."
    )
    arpwatch_scan_parser.set_defaults(func=cmd_arpwatch_scan)

    arpwatch_list_parser = arpwatch_subparsers.add_parser(
        "list", help="List every arpwatch alert ever recorded."
    )
    arpwatch_list_parser.set_defaults(func=cmd_arpwatch_list)

    arpwatch_mark_parser = arpwatch_subparsers.add_parser(
        "mark", help="Mark an arpwatch alert as known or unknown."
    )
    arpwatch_mark_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure arpwatch list`."
    )
    arpwatch_mark_parser.add_argument("status", choices=["known", "unknown"])
    arpwatch_mark_parser.set_defaults(func=cmd_arpwatch_mark)

    wifi_parser = subparsers.add_parser(
        "wifi", help="Wi-Fi security monitor (scan/list/mark/alerts/mark-alert)."
    )
    wifi_subparsers = wifi_parser.add_subparsers(dest="wifi_command", required=True)

    wifi_scan_parser = wifi_subparsers.add_parser(
        "scan", help="Show this Mac's current Wi-Fi connection and flag anything worth review."
    )
    wifi_scan_parser.set_defaults(func=cmd_wifi_scan)

    wifi_list_parser = wifi_subparsers.add_parser(
        "list", help="List every Wi-Fi network ever recorded."
    )
    wifi_list_parser.set_defaults(func=cmd_wifi_list)

    wifi_mark_parser = wifi_subparsers.add_parser(
        "mark", help="Mark a Wi-Fi network as known or unknown."
    )
    wifi_mark_parser.add_argument(
        "network_id", type=int, help="The network's id, from `secure wifi list`."
    )
    wifi_mark_parser.add_argument("status", choices=["known", "unknown"])
    wifi_mark_parser.set_defaults(func=cmd_wifi_mark)

    wifi_alerts_parser = wifi_subparsers.add_parser(
        "alerts", help="List every lookalike-SSID alert ever recorded."
    )
    wifi_alerts_parser.set_defaults(func=cmd_wifi_alerts)

    wifi_mark_alert_parser = wifi_subparsers.add_parser(
        "mark-alert", help="Mark a wifi alert as known or unknown."
    )
    wifi_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure wifi alerts`."
    )
    wifi_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    wifi_mark_alert_parser.set_defaults(func=cmd_wifi_mark_alert)

    bluetooth_parser = subparsers.add_parser(
        "bluetooth",
        help="Bluetooth/BLE visibility (scan/list/mark/alerts/mark-alert/state/ble).",
    )
    bluetooth_subparsers = bluetooth_parser.add_subparsers(dest="bluetooth_command", required=True)

    bluetooth_scan_parser = bluetooth_subparsers.add_parser(
        "scan", help="Show Bluetooth devices macOS already knows about and flag anything worth review."
    )
    bluetooth_scan_parser.set_defaults(func=cmd_bluetooth_scan)

    bluetooth_list_parser = bluetooth_subparsers.add_parser(
        "list", help="List every Bluetooth device ever recorded."
    )
    bluetooth_list_parser.set_defaults(func=cmd_bluetooth_list)

    bluetooth_mark_parser = bluetooth_subparsers.add_parser(
        "mark", help="Mark a Bluetooth device as trusted or untrusted."
    )
    bluetooth_mark_parser.add_argument(
        "device_id", type=int, help="The device's id, from `secure bluetooth list`."
    )
    bluetooth_mark_parser.add_argument("status", choices=["trusted", "untrusted"])
    bluetooth_mark_parser.set_defaults(func=cmd_bluetooth_mark)

    bluetooth_alerts_parser = bluetooth_subparsers.add_parser(
        "alerts", help="List every persistent-unknown-device alert ever recorded."
    )
    bluetooth_alerts_parser.set_defaults(func=cmd_bluetooth_alerts)

    bluetooth_mark_alert_parser = bluetooth_subparsers.add_parser(
        "mark-alert", help="Mark a bluetooth alert as known or unknown."
    )
    bluetooth_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure bluetooth alerts`."
    )
    bluetooth_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    bluetooth_mark_alert_parser.set_defaults(func=cmd_bluetooth_mark_alert)

    bluetooth_state_parser = bluetooth_subparsers.add_parser(
        "state",
        help="Check Bluetooth's current power/authorization state for this process.",
    )
    bluetooth_state_parser.set_defaults(func=cmd_bluetooth_state)

    # `secure bluetooth ble ...` — a second level of nesting, deliberately
    # kept separate from the plain `secure bluetooth ...` commands above:
    # those read what macOS already knows about (system_profiler); these
    # run a real live BLE scan (Bleak/CoreBluetooth) with its own
    # identifier space (cb_uuid, not a Bluetooth MAC address) and its own
    # storage tables. See secure/bluetooth/ble/'s docs for why they're not
    # merged.
    bluetooth_ble_parser = bluetooth_subparsers.add_parser(
        "ble", help="Live BLE peripheral discovery (scan/list/mark/alerts/mark-alert)."
    )
    bluetooth_ble_subparsers = bluetooth_ble_parser.add_subparsers(
        dest="bluetooth_ble_command", required=True
    )

    bluetooth_ble_scan_parser = bluetooth_ble_subparsers.add_parser(
        "scan", help="Run a live BLE discovery scan and flag anything worth review."
    )
    bluetooth_ble_scan_parser.add_argument(
        "--duration",
        type=float,
        default=8.0,
        help="How many seconds to scan for (default: 8.0). BLE peripherals "
        "broadcast periodically, so a very short duration may miss some.",
    )
    bluetooth_ble_scan_parser.set_defaults(func=cmd_bluetooth_ble_scan)

    bluetooth_ble_list_parser = bluetooth_ble_subparsers.add_parser(
        "list", help="List every BLE peripheral ever recorded."
    )
    bluetooth_ble_list_parser.set_defaults(func=cmd_bluetooth_ble_list)

    bluetooth_ble_mark_parser = bluetooth_ble_subparsers.add_parser(
        "mark", help="Mark a BLE peripheral as trusted or untrusted."
    )
    bluetooth_ble_mark_parser.add_argument(
        "peripheral_id", type=int, help="The peripheral's id, from `secure bluetooth ble list`."
    )
    bluetooth_ble_mark_parser.add_argument("status", choices=["trusted", "untrusted"])
    bluetooth_ble_mark_parser.set_defaults(func=cmd_bluetooth_ble_mark)

    bluetooth_ble_alerts_parser = bluetooth_ble_subparsers.add_parser(
        "alerts", help="List every BLE alert ever recorded."
    )
    bluetooth_ble_alerts_parser.set_defaults(func=cmd_bluetooth_ble_alerts)

    bluetooth_ble_mark_alert_parser = bluetooth_ble_subparsers.add_parser(
        "mark-alert", help="Mark a BLE alert as known or unknown."
    )
    bluetooth_ble_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure bluetooth ble alerts`."
    )
    bluetooth_ble_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    bluetooth_ble_mark_alert_parser.set_defaults(func=cmd_bluetooth_ble_mark_alert)

    persistence_parser = subparsers.add_parser(
        "persistence",
        help="Process and Persistence Monitor "
        "(scan/processes/items/mark-process/mark-item/alerts/mark-alert).",
    )
    persistence_subparsers = persistence_parser.add_subparsers(
        dest="persistence_command", required=True
    )

    persistence_scan_parser = persistence_subparsers.add_parser(
        "scan",
        help="Inventory running processes and startup/persistence mechanisms, "
        "flag anything worth review.",
    )
    persistence_scan_parser.set_defaults(func=cmd_persistence_scan)

    persistence_processes_parser = persistence_subparsers.add_parser(
        "processes", help="List every process executable ever recorded."
    )
    persistence_processes_parser.set_defaults(func=cmd_persistence_processes)

    persistence_mark_process_parser = persistence_subparsers.add_parser(
        "mark-process", help="Mark a process entry as known or unknown."
    )
    persistence_mark_process_parser.add_argument(
        "entry_id", type=int, help="The entry's id, from `secure persistence processes`."
    )
    persistence_mark_process_parser.add_argument("status", choices=["known", "unknown"])
    persistence_mark_process_parser.set_defaults(func=cmd_persistence_mark_process)

    persistence_items_parser = persistence_subparsers.add_parser(
        "items",
        help="List every persistence entry (LaunchAgent/LaunchDaemon/login item) "
        "ever recorded.",
    )
    persistence_items_parser.set_defaults(func=cmd_persistence_items)

    persistence_mark_item_parser = persistence_subparsers.add_parser(
        "mark-item", help="Mark a persistence entry as known or unknown."
    )
    persistence_mark_item_parser.add_argument(
        "entry_id", type=int, help="The entry's id, from `secure persistence items`."
    )
    persistence_mark_item_parser.add_argument("status", choices=["known", "unknown"])
    persistence_mark_item_parser.set_defaults(func=cmd_persistence_mark_item)

    persistence_alerts_parser = persistence_subparsers.add_parser(
        "alerts", help="List every persistence alert ever recorded."
    )
    persistence_alerts_parser.set_defaults(func=cmd_persistence_alerts)

    persistence_mark_alert_parser = persistence_subparsers.add_parser(
        "mark-alert", help="Mark a persistence alert as known or unknown."
    )
    persistence_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure persistence alerts`."
    )
    persistence_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    persistence_mark_alert_parser.set_defaults(func=cmd_persistence_mark_alert)

    integrations_parser = subparsers.add_parser(
        "integrations",
        help="External security-engine integrations (osquery, yarax, sigma, "
        "suricata, zeek — see secure/integrations/). Secure's own native "
        "collectors are never disabled or replaced by these; treat as an "
        "additional, cross-checking/telemetry source.",
    )
    integrations_subparsers = integrations_parser.add_subparsers(
        dest="integrations_engine", required=True
    )

    osquery_parser = integrations_subparsers.add_parser(
        "osquery", help="The osquery integration (processes/sockets/listening ports/launchd)."
    )
    osquery_subparsers = osquery_parser.add_subparsers(
        dest="integrations_osquery_command", required=True
    )

    osquery_status_parser = osquery_subparsers.add_parser(
        "status",
        help="Show osqueryi availability/health and the last scan's summary "
        "(no scan is run).",
    )
    osquery_status_parser.set_defaults(func=cmd_integrations_osquery_status)

    osquery_scan_parser = osquery_subparsers.add_parser(
        "scan",
        help="Collect processes/sockets/listening ports/launchd via osqueryi, "
        "store the results, and cross-check listening ports and launchd "
        "persistence against Secure's own native scans.",
    )
    osquery_scan_parser.set_defaults(func=cmd_integrations_osquery_scan)

    osquery_observations_parser = osquery_subparsers.add_parser(
        "observations", help="List recently collected osquery observations."
    )
    osquery_observations_parser.add_argument(
        "--kind",
        default=None,
        help="Only show observations of this kind (processes/process_open_sockets/"
        "listening_ports/launchd).",
    )
    osquery_observations_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to show (default 50)."
    )
    osquery_observations_parser.set_defaults(func=cmd_integrations_osquery_observations)

    osquery_alerts_parser = osquery_subparsers.add_parser(
        "alerts",
        help="List osquery cross-check discrepancies. A native/osquery match "
        "never produces a row here.",
    )
    osquery_alerts_parser.set_defaults(func=cmd_integrations_osquery_alerts)

    osquery_mark_alert_parser = osquery_subparsers.add_parser(
        "mark-alert", help="Mark an osquery cross-check alert as known or unknown."
    )
    osquery_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure integrations osquery alerts`."
    )
    osquery_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    osquery_mark_alert_parser.set_defaults(func=cmd_integrations_osquery_mark_alert)

    yarax_parser = integrations_subparsers.add_parser(
        "yarax",
        help="The YARA-X integration — content-pattern file scanning. "
        "See secure/integrations/yarax/.",
    )
    yarax_subparsers = yarax_parser.add_subparsers(
        dest="integrations_yarax_command", required=True
    )

    yarax_status_parser = yarax_subparsers.add_parser(
        "status",
        help="Show yara_x availability/health, configured rulesets, and the "
        "last scan's summary (no scan is run).",
    )
    yarax_status_parser.set_defaults(func=cmd_integrations_yarax_status)

    yarax_scan_file_parser = yarax_subparsers.add_parser(
        "scan-file",
        help="Scan one or more explicitly-named files (user-requested files) "
        "against every configured ruleset. Never scans a directory's contents.",
    )
    yarax_scan_file_parser.add_argument("paths", nargs="+", help="File path(s) to scan.")
    yarax_scan_file_parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Per-file scan timeout in seconds (default 10).",
    )
    yarax_scan_file_parser.set_defaults(func=cmd_integrations_yarax_scan_file)

    yarax_scan_fim_alerts_parser = yarax_subparsers.add_parser(
        "scan-fim-alerts",
        help="Scan files behind unreviewed MEDIUM/HIGH File Integrity Monitoring "
        "alerts (security-relevant FIM events).",
    )
    yarax_scan_fim_alerts_parser.set_defaults(func=cmd_integrations_yarax_scan_fim_alerts)

    yarax_scan_suspicious_parser = yarax_subparsers.add_parser(
        "scan-suspicious",
        help="Scan executables behind unreviewed unusual/unsigned-process "
        "persistence alerts (suspicious files).",
    )
    yarax_scan_suspicious_parser.set_defaults(func=cmd_integrations_yarax_scan_suspicious)

    yarax_rulesets_parser = yarax_subparsers.add_parser(
        "rulesets", help="List configured rulesets and any that failed to load."
    )
    yarax_rulesets_parser.set_defaults(func=cmd_integrations_yarax_rulesets)

    yarax_observations_parser = yarax_subparsers.add_parser(
        "observations", help="List recently collected YARA-X observations (matches)."
    )
    yarax_observations_parser.add_argument(
        "--kind", default=None, help="Only show observations of this kind (yara_match)."
    )
    yarax_observations_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to show (default 50)."
    )
    yarax_observations_parser.set_defaults(func=cmd_integrations_yarax_observations)

    yarax_alerts_parser = yarax_subparsers.add_parser(
        "alerts", help="List YARA-X rule-match findings."
    )
    yarax_alerts_parser.set_defaults(func=cmd_integrations_yarax_alerts)

    yarax_mark_alert_parser = yarax_subparsers.add_parser(
        "mark-alert", help="Mark a YARA-X finding as known or unknown."
    )
    yarax_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The finding's id, from `secure integrations yarax alerts`."
    )
    yarax_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    yarax_mark_alert_parser.set_defaults(func=cmd_integrations_yarax_mark_alert)

    sigma_parser = integrations_subparsers.add_parser(
        "sigma",
        help="The Sigma detection integration — a bounded subset of Sigma "
        "rules evaluated against osquery telemetry. See "
        "secure/integrations/sigma/.",
    )
    sigma_subparsers = sigma_parser.add_subparsers(
        dest="integrations_sigma_command", required=True
    )

    sigma_status_parser = sigma_subparsers.add_parser(
        "status",
        help="Show PyYAML availability/health, configured rules and their "
        "EVALUABLE/NOT_EVALUABLE capability verdicts, and the last scan's "
        "summary (no scan is run).",
    )
    sigma_status_parser.set_defaults(func=cmd_integrations_sigma_status)

    sigma_rules_parser = sigma_subparsers.add_parser(
        "rules",
        help="List configured Sigma rules and their EVALUABLE/NOT_EVALUABLE "
        "capability verdict, without running a scan.",
    )
    sigma_rules_parser.set_defaults(func=cmd_integrations_sigma_rules)

    sigma_scan_parser = sigma_subparsers.add_parser(
        "scan",
        help="Evaluate every configured Sigma rule against recent osquery "
        "telemetry and store the results. A rule Secure lacks telemetry for "
        "is always reported NOT_EVALUABLE, never treated as clean.",
    )
    sigma_scan_parser.add_argument(
        "--lookback-hours", type=float, default=24.0,
        help="How far back to look for osquery telemetry (default 24).",
    )
    sigma_scan_parser.set_defaults(func=cmd_integrations_sigma_scan)

    sigma_observations_parser = sigma_subparsers.add_parser(
        "observations",
        help="List recent per-rule scan results (evaluation status, matched "
        "evidence) — one row per loaded rule, every scan pass.",
    )
    sigma_observations_parser.add_argument(
        "--kind", default=None, help="Only show observations of this kind (sigma_rule_result)."
    )
    sigma_observations_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to show (default 50)."
    )
    sigma_observations_parser.set_defaults(func=cmd_integrations_sigma_observations)

    sigma_alerts_parser = sigma_subparsers.add_parser(
        "alerts", help="List Sigma rule-match findings."
    )
    sigma_alerts_parser.set_defaults(func=cmd_integrations_sigma_alerts)

    sigma_mark_alert_parser = sigma_subparsers.add_parser(
        "mark-alert", help="Mark a Sigma finding as known or unknown."
    )
    sigma_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The finding's id, from `secure integrations sigma alerts`."
    )
    sigma_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    sigma_mark_alert_parser.set_defaults(func=cmd_integrations_sigma_mark_alert)

    suricata_parser = integrations_subparsers.add_parser(
        "suricata",
        help="The Suricata network IDS integration — reads Suricata's own "
        "EVE JSON log output. Secure never runs or configures Suricata "
        "itself. See secure/integrations/suricata/.",
    )
    suricata_subparsers = suricata_parser.add_subparsers(
        dest="integrations_suricata_command", required=True
    )

    suricata_status_parser = suricata_subparsers.add_parser(
        "status",
        help="Show EVE log availability and packet-visibility health "
        "(not just whether the log file exists) and the last scan's "
        "summary (no scan is run).",
    )
    suricata_status_parser.set_defaults(func=cmd_integrations_suricata_status)

    suricata_scan_parser = suricata_subparsers.add_parser(
        "scan",
        help="Ingest new alert records from the configured EVE JSON log, "
        "correlate each against Secure's own native connection "
        "observations when identity and timing support it, and store "
        "the results.",
    )
    suricata_scan_parser.set_defaults(func=cmd_integrations_suricata_scan)

    suricata_observations_parser = suricata_subparsers.add_parser(
        "observations",
        help="List recently ingested EVE records — alert findings "
        "(kind=eve_alert) and packet-capture stats snapshots "
        "(kind=capture_stats).",
    )
    suricata_observations_parser.add_argument(
        "--kind", default=None, help="Only show observations of this kind (eve_alert/capture_stats)."
    )
    suricata_observations_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to show (default 50)."
    )
    suricata_observations_parser.set_defaults(func=cmd_integrations_suricata_observations)

    suricata_alerts_parser = suricata_subparsers.add_parser(
        "alerts", help="List Suricata IDS alerts."
    )
    suricata_alerts_parser.set_defaults(func=cmd_integrations_suricata_alerts)

    suricata_mark_alert_parser = suricata_subparsers.add_parser(
        "mark-alert", help="Mark a Suricata alert as known or unknown."
    )
    suricata_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure integrations suricata alerts`."
    )
    suricata_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    suricata_mark_alert_parser.set_defaults(func=cmd_integrations_suricata_mark_alert)

    zeek_parser = integrations_subparsers.add_parser(
        "zeek",
        help="The Zeek behavioral network telemetry integration — reads Zeek's "
        "own conn/dns/ssl/http JSON log output. Never a detection source "
        "(no alerts/mark-alert command — see secure/integrations/zeek/).",
    )
    zeek_subparsers = zeek_parser.add_subparsers(
        dest="integrations_zeek_command", required=True
    )

    zeek_status_parser = zeek_subparsers.add_parser(
        "status",
        help="Show Zeek log directory availability/freshness health and the "
        "last scan's summary (no scan is run).",
    )
    zeek_status_parser.set_defaults(func=cmd_integrations_zeek_status)

    zeek_scan_parser = zeek_subparsers.add_parser(
        "scan",
        help="Ingest new conn/dns/ssl/http log records, classify conn.log "
        "records for dedup-awareness against Secure's own native "
        "connections and Suricata's own ingested alerts, feed DNS query "
        "domains and TLS SNI hostnames into the behavioral-baseline "
        "layer, and store the results. Never produces alerts.",
    )
    zeek_scan_parser.set_defaults(func=cmd_integrations_zeek_scan)

    zeek_observations_parser = zeek_subparsers.add_parser(
        "observations",
        help="List recently ingested Zeek records (kind=conn/dns/ssl/http).",
    )
    zeek_observations_parser.add_argument(
        "--kind", default=None, help="Only show observations of this kind (conn/dns/ssl/http)."
    )
    zeek_observations_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to show (default 50)."
    )
    zeek_observations_parser.set_defaults(func=cmd_integrations_zeek_observations)

    threatintel_parser = subparsers.add_parser(
        "threatintel",
        help="Provider-neutral threat-intelligence enrichment (Phase 20) — see "
        "secure/threatintel/. Enrichment, not ground truth: never blocks anything "
        "and never upgrades Secure's own severity/confidence on its own.",
    )
    threatintel_subparsers = threatintel_parser.add_subparsers(
        dest="threatintel_command", required=True
    )

    threatintel_lookup_parser = threatintel_subparsers.add_parser(
        "lookup",
        help="Look up one indicator against every registered provider (cache-first; "
        "this is the ONLY command that can make a real external network request). "
        "Private/local indicators are never sent to a network-capable provider.",
    )
    threatintel_lookup_parser.add_argument(
        "type", choices=["auto", *INDICATOR_TYPES],
        help="ip / domain / hash, or 'auto' to detect from the value.",
    )
    threatintel_lookup_parser.add_argument("value", help="The indicator value to look up.")
    threatintel_lookup_parser.set_defaults(func=cmd_threatintel_lookup)

    threatintel_history_parser = threatintel_subparsers.add_parser(
        "history", help="List previously recorded lookups (read-only; no new queries made)."
    )
    threatintel_history_parser.add_argument("--type", default=None, help="Filter by indicator type.")
    threatintel_history_parser.add_argument("--value", default=None, help="Filter by exact indicator value.")
    threatintel_history_parser.add_argument("--provider", default=None, help="Filter by provider name.")
    threatintel_history_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum rows to show (default 50)."
    )
    threatintel_history_parser.set_defaults(func=cmd_threatintel_history)

    threatintel_providers_parser = threatintel_subparsers.add_parser(
        "providers", help="List every registered provider and whether it makes outbound network calls."
    )
    threatintel_providers_parser.set_defaults(func=cmd_threatintel_providers)

    fileintegrity_parser = subparsers.add_parser(
        "fileintegrity",
        help="File Integrity Monitoring (scan/watch-add/watch-list/watch-remove/"
        "files/mark-file/events/alerts/mark-alert).",
    )
    fileintegrity_subparsers = fileintegrity_parser.add_subparsers(
        dest="fileintegrity_command", required=True
    )

    fi_scan_parser = fileintegrity_subparsers.add_parser(
        "scan",
        help="Walk every enabled watch path and record what changed since the last scan.",
    )
    fi_scan_parser.set_defaults(func=cmd_fileintegrity_scan)

    fi_watch_add_parser = fileintegrity_subparsers.add_parser(
        "watch-add", help="Add a file or folder to the watch list."
    )
    fi_watch_add_parser.add_argument("path", help="File or folder to monitor.")
    fi_watch_add_parser.add_argument(
        "--no-recursive", action="store_true",
        help="Only watch this exact path's own files, don't descend into subfolders.",
    )
    fi_watch_add_parser.add_argument(
        "--sensitivity", choices=["normal", "startup", "self"], default="normal",
        help="'startup' for LaunchAgent/LaunchDaemon locations (severity is based on "
        "the referenced executable), 'self' for Secure's own files, 'normal' otherwise.",
    )
    fi_watch_add_parser.set_defaults(func=cmd_fileintegrity_watch_add)

    fi_watch_list_parser = fileintegrity_subparsers.add_parser(
        "watch-list", help="List every registered watch path."
    )
    fi_watch_list_parser.set_defaults(func=cmd_fileintegrity_watch_list)

    fi_watch_remove_parser = fileintegrity_subparsers.add_parser(
        "watch-remove", help="Disable a watch path (its recorded history is kept)."
    )
    fi_watch_remove_parser.add_argument(
        "watch_path_id", type=int, help="The watch path's id, from `secure fileintegrity watch-list`."
    )
    fi_watch_remove_parser.set_defaults(func=cmd_fileintegrity_watch_remove)

    fi_files_parser = fileintegrity_subparsers.add_parser(
        "files", help="List monitored files and their current recorded state."
    )
    fi_files_parser.add_argument("--limit", type=int, default=200, help="Max rows to show (default: 200).")
    fi_files_parser.set_defaults(func=cmd_fileintegrity_files)

    fi_mark_file_parser = fileintegrity_subparsers.add_parser(
        "mark-file", help="Mark a file entry as known or unknown."
    )
    fi_mark_file_parser.add_argument(
        "entry_id", type=int, help="The file entry's id, from `secure fileintegrity files`."
    )
    fi_mark_file_parser.add_argument("status", choices=["known", "unknown"])
    fi_mark_file_parser.set_defaults(func=cmd_fileintegrity_mark_file)

    fi_events_parser = fileintegrity_subparsers.add_parser(
        "events", help="Show the full history of file changes ever observed."
    )
    fi_events_parser.add_argument("--path", default=None, help="Only show events for this exact path.")
    fi_events_parser.add_argument("--limit", type=int, default=200, help="Max rows to show (default: 200).")
    fi_events_parser.set_defaults(func=cmd_fileintegrity_events)

    fi_alerts_parser = fileintegrity_subparsers.add_parser(
        "alerts", help="List every file integrity alert ever recorded."
    )
    fi_alerts_parser.set_defaults(func=cmd_fileintegrity_alerts)

    fi_mark_alert_parser = fileintegrity_subparsers.add_parser(
        "mark-alert", help="Mark a file integrity alert as known or unknown."
    )
    fi_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure fileintegrity alerts`."
    )
    fi_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    fi_mark_alert_parser.set_defaults(func=cmd_fileintegrity_mark_alert)

    self_parser = subparsers.add_parser(
        "self",
        help="Secure's own app-level housekeeping (currently: mark-update-context).",
    )
    self_subparsers = self_parser.add_subparsers(dest="self_command", required=True)

    self_mark_update_context_parser = self_subparsers.add_parser(
        "mark-update-context",
        help="Record that an intentional Secure Update/reload is happening now, so "
        "file integrity monitoring doesn't flag the resulting self-file changes as "
        "unexplained.",
    )
    self_mark_update_context_parser.add_argument(
        "--note", default="", help="Optional short note stored with the marker."
    )
    self_mark_update_context_parser.set_defaults(func=cmd_self_mark_update_context)

    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Cross-Module Correlation (run/list/mark-alert) — flag clusters of "
        "signals from DIFFERENT modules that happened close together in time.",
    )
    correlate_subparsers = correlate_parser.add_subparsers(dest="correlate_command", required=True)

    correlate_run_parser = correlate_subparsers.add_parser(
        "run",
        help="Look for cross-module signal clusters in everything already recorded.",
    )
    correlate_run_parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_WINDOW_SECONDS,
        help=f"Signals within this many seconds of each other cluster together "
        f"(default: {DEFAULT_WINDOW_SECONDS:.0f}).",
    )
    correlate_run_parser.add_argument(
        "--lookback-hours",
        type=float,
        default=DEFAULT_LOOKBACK_HOURS,
        help=f"Only consider signals from the last this-many hours "
        f"(default: {DEFAULT_LOOKBACK_HOURS:.0f}).",
    )
    correlate_run_parser.set_defaults(func=cmd_correlate_run)

    correlate_list_parser = correlate_subparsers.add_parser(
        "list", help="List every correlation alert ever recorded."
    )
    correlate_list_parser.set_defaults(func=cmd_correlate_list)

    correlate_mark_alert_parser = correlate_subparsers.add_parser(
        "mark-alert", help="Mark a correlation alert as known or unknown."
    )
    correlate_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure correlate list`."
    )
    correlate_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    correlate_mark_alert_parser.set_defaults(func=cmd_correlate_mark_alert)

    # Phase 22: provenance-aware CHAIN correlation — a separate, parallel
    # command family under `correlate`, not a replacement for run/list/
    # mark-alert above (see chains.py's module docstring for why).
    correlate_chains_parser = correlate_subparsers.add_parser(
        "chains",
        help="Provenance-aware evidence CHAINS (run/list/mark-alert) — walk asserted "
        "evidence_links relationships (Phase 21) into multi-step chains, deduplicated "
        "by Phase 21 lineage so repeated/confirming observations don't inflate scoring.",
    )
    correlate_chains_subparsers = correlate_chains_parser.add_subparsers(
        dest="correlate_chains_command", required=True
    )

    correlate_chains_run_parser = correlate_chains_subparsers.add_parser(
        "run",
        help="Walk and score every evidence chain touched by recent evidence_links activity.",
    )
    correlate_chains_run_parser.add_argument(
        "--lookback-hours",
        type=float,
        default=CHAIN_DEFAULT_LOOKBACK_HOURS,
        help=f"Only consider evidence_links rows from the last this-many hours "
        f"(default: {CHAIN_DEFAULT_LOOKBACK_HOURS:.0f}).",
    )
    correlate_chains_run_parser.set_defaults(func=cmd_correlate_chains_run)

    correlate_chains_list_parser = correlate_chains_subparsers.add_parser(
        "list", help="List every chain alert ever recorded."
    )
    correlate_chains_list_parser.set_defaults(func=cmd_correlate_chains_list)

    correlate_chains_mark_alert_parser = correlate_chains_subparsers.add_parser(
        "mark-alert", help="Mark a chain alert as known or unknown."
    )
    correlate_chains_mark_alert_parser.add_argument(
        "alert_id", type=int, help="The alert's id, from `secure correlate chains list`."
    )
    correlate_chains_mark_alert_parser.add_argument("status", choices=["known", "unknown"])
    correlate_chains_mark_alert_parser.set_defaults(func=cmd_correlate_chains_mark_alert)

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Phase 14 baseline/anomaly operator controls "
        "(status/list/show/exclude/include/freeze/unfreeze/reset).",
    )
    baseline_subparsers = baseline_parser.add_subparsers(
        dest="baseline_command", required=True
    )

    baseline_status_parser = baseline_subparsers.add_parser(
        "status",
        help="Overview of baseline entities, maturity, exclusions/freezes, "
        "anomaly counts, and the most recent baseline run.",
    )
    baseline_status_parser.set_defaults(func=cmd_baseline_status)

    baseline_list_parser = baseline_subparsers.add_parser(
        "list", help="List baseline entities, optionally filtered."
    )
    baseline_list_parser.add_argument(
        "--entity-type", dest="entity_type", choices=list(ENTITY_TYPES), default=None,
        help="Only show this entity_type.",
    )
    baseline_list_parser.add_argument(
        "--maturity", dest="maturity", default=None,
        help="Only show this maturity_state (no_baseline/learning/established/stale).",
    )
    baseline_list_parser.add_argument(
        "--excluded", action="store_true", default=None, help="Only show excluded entities."
    )
    baseline_list_parser.add_argument(
        "--frozen", action="store_true", default=None, help="Only show frozen entities."
    )
    baseline_list_parser.set_defaults(func=cmd_baseline_list)

    baseline_show_parser = baseline_subparsers.add_parser(
        "show",
        help="Show one entity's full baseline detail (maturity, per-feature "
        "state, recent anomaly events).",
    )
    baseline_show_parser.add_argument("entity_type", choices=list(ENTITY_TYPES))
    baseline_show_parser.add_argument("entity_key")
    baseline_show_parser.set_defaults(func=cmd_baseline_show)

    baseline_exclude_parser = baseline_subparsers.add_parser(
        "exclude",
        help="Exclude an entity from baseline scoring going forward "
        "(still logged; never deletes history).",
    )
    baseline_exclude_parser.add_argument("entity_type", choices=list(ENTITY_TYPES))
    baseline_exclude_parser.add_argument("entity_key")
    baseline_exclude_parser.set_defaults(func=cmd_baseline_exclude)

    baseline_include_parser = baseline_subparsers.add_parser(
        "include",
        help="Undo `exclude` — resume normal scoring going forward "
        "(does not retroactively rescore anything).",
    )
    baseline_include_parser.add_argument("entity_type", choices=list(ENTITY_TYPES))
    baseline_include_parser.add_argument("entity_key")
    baseline_include_parser.set_defaults(func=cmd_baseline_include)

    baseline_freeze_parser = baseline_subparsers.add_parser(
        "freeze",
        help="Stop this entity's 'current normal' from adapting further; "
        "anomaly comparisons continue against the frozen baseline.",
    )
    baseline_freeze_parser.add_argument("entity_type", choices=list(ENTITY_TYPES))
    baseline_freeze_parser.add_argument("entity_key")
    baseline_freeze_parser.set_defaults(func=cmd_baseline_freeze)

    baseline_unfreeze_parser = baseline_subparsers.add_parser(
        "unfreeze", help="Undo `freeze` — resume adapting going forward."
    )
    baseline_unfreeze_parser.add_argument("entity_type", choices=list(ENTITY_TYPES))
    baseline_unfreeze_parser.add_argument("entity_key")
    baseline_unfreeze_parser.set_defaults(func=cmd_baseline_unfreeze)

    baseline_reset_parser = baseline_subparsers.add_parser(
        "reset",
        help="Clear one entity's learned baseline back to no_baseline. Raw "
        "observation history and past anomaly findings are always preserved.",
    )
    baseline_reset_parser.add_argument(
        "entity_type", nargs="?", choices=list(ENTITY_TYPES), default=None
    )
    baseline_reset_parser.add_argument("entity_key", nargs="?", default=None)
    baseline_reset_parser.add_argument(
        "--all", action="store_true",
        help="Reset every entity instead of one (optionally scoped with "
        "--entity-type). Requires --yes.",
    )
    baseline_reset_parser.add_argument(
        "--entity-type", dest="all_entity_type", choices=list(ENTITY_TYPES), default=None,
        help="With --all, restrict the reset to this entity_type only.",
    )
    baseline_reset_parser.add_argument(
        "--yes", action="store_true",
        help="Actually perform a --all reset. Without this, --all only previews "
        "what would happen.",
    )
    baseline_reset_parser.set_defaults(func=cmd_baseline_reset)

    anomalies_parser = subparsers.add_parser(
        "anomalies",
        help="Phase 14 anomaly findings (list/show/mark).",
    )
    anomalies_subparsers = anomalies_parser.add_subparsers(
        dest="anomalies_command", required=True
    )

    anomalies_list_parser = anomalies_subparsers.add_parser(
        "list", help="List anomaly events, optionally filtered."
    )
    anomalies_list_parser.add_argument(
        "--tier", choices=list(ANOMALY_TIERS), default=None, help="Only show this tier."
    )
    anomalies_list_parser.add_argument(
        "--entity-type", dest="entity_type", choices=list(ENTITY_TYPES), default=None,
        help="Only show this entity_type.",
    )
    anomalies_known_group = anomalies_list_parser.add_mutually_exclusive_group()
    anomalies_known_group.add_argument(
        "--known", action="store_true", help="Only show anomalies already marked known."
    )
    anomalies_known_group.add_argument(
        "--unknown", action="store_true", help="Only show anomalies still awaiting review."
    )
    anomalies_list_parser.add_argument(
        "--since-hours", dest="since_hours", type=float, default=None,
        help="Only show anomalies observed in the last N hours.",
    )
    anomalies_list_parser.add_argument(
        "--limit", type=int, default=50, help="Maximum number of results (default 50)."
    )
    anomalies_list_parser.set_defaults(func=cmd_anomalies_list)

    anomalies_show_parser = anomalies_subparsers.add_parser(
        "show",
        help="Show one anomaly's full score breakdown, source reference, and "
        "current baseline caveats.",
    )
    anomalies_show_parser.add_argument("event_id", type=int, help="The anomaly's id, from `secure anomalies list`.")
    anomalies_show_parser.set_defaults(func=cmd_anomalies_show)

    anomalies_mark_parser = anomalies_subparsers.add_parser(
        "mark", help="Mark an anomaly event as known or unknown."
    )
    anomalies_mark_parser.add_argument("event_id", type=int, help="The anomaly's id, from `secure anomalies list`.")
    anomalies_mark_parser.add_argument("status", choices=["known", "unknown"])
    anomalies_mark_parser.set_defaults(func=cmd_anomalies_mark)

    run_all_parser = subparsers.add_parser(
        "run-all",
        help="Run every scan that feeds correlation (inventory/connections/"
        "listening/arpwatch/wifi/bluetooth/ble/persistence/fileintegrity), "
        "then correlate the result in one pass.",
    )
    run_all_parser.set_defaults(func=cmd_run_all)

    # Phase 23: entity-centric investigation (read-only) — see
    # secure/investigate/'s own package docstring.
    investigate_parser = subparsers.add_parser(
        "investigate",
        help="Entity-centric investigation (types/show) — pivot among processes, "
        "destinations, persistence, files, and every alert/finding linked to them.",
    )
    investigate_subparsers = investigate_parser.add_subparsers(
        dest="investigate_command", required=True
    )

    investigate_types_parser = investigate_subparsers.add_parser(
        "types", help="List every entity type `show` accepts and how to build its key."
    )
    investigate_types_parser.set_defaults(func=cmd_investigate_types)

    investigate_show_parser = investigate_subparsers.add_parser(
        "show",
        help="Show one entity's summary, timeline, related evidence, and pivot targets. "
        "Run `secure investigate types` first if you're unsure how to build entity_key.",
    )
    investigate_show_parser.add_argument("entity_type", choices=INVESTIGATE_ENTITY_TYPES)
    investigate_show_parser.add_argument("entity_key")
    investigate_show_parser.add_argument(
        "--max-hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help=f"How many evidence_links hops to walk out from this entity (default: {DEFAULT_MAX_HOPS}).",
    )
    investigate_show_parser.set_defaults(func=cmd_investigate_show)

    # Phase 24: Targeted DFIR Integration (secure/dfir/) — Velociraptor
    # as a specialist forensic collection engine, invoked only via the
    # explicit `collect` subcommand below. Every other subcommand here
    # is read-only.
    dfir_parser = subparsers.add_parser(
        "dfir",
        help="Targeted DFIR collection via Velociraptor (status/suggest/collect/list/show/evidence) — "
        "narrowly scoped, user-approved forensic collection tied to an investigation.",
    )
    dfir_subparsers = dfir_parser.add_subparsers(dest="dfir_command", required=True)

    dfir_status_parser = dfir_subparsers.add_parser(
        "status", help="Check whether the velociraptor binary is usable, and show the configured artifact allowlist."
    )
    dfir_status_parser.set_defaults(func=cmd_dfir_status)

    dfir_suggest_parser = dfir_subparsers.add_parser(
        "suggest",
        help="Read-only: list HIGH+/LIKELY+ findings on this entity worth considering a collection for. "
        "Never executes anything.",
    )
    dfir_suggest_parser.add_argument("entity_type", choices=INVESTIGATE_ENTITY_TYPES)
    dfir_suggest_parser.add_argument("entity_key")
    dfir_suggest_parser.set_defaults(func=cmd_dfir_suggest)

    dfir_collect_parser = dfir_subparsers.add_parser(
        "collect",
        help="Run ONE Velociraptor artifact collection. The artifact must already be in "
        "AppConfig.dfir_artifact_allowlist. This explicit invocation IS the approval — "
        "nothing in Secure ever runs a collection on its own.",
    )
    dfir_collect_parser.add_argument("--artifact", required=True, help="Exact Velociraptor artifact name.")
    dfir_collect_parser.add_argument(
        "--param", action="append", metavar="KEY=VALUE",
        help="Artifact parameter, repeatable (e.g. --param pid=123 --param path=/tmp).",
    )
    dfir_collect_parser.add_argument("--reason", required=True, help="Why this collection is being run.")
    dfir_collect_parser.add_argument("--entity-type", dest="entity_type", required=True, choices=INVESTIGATE_ENTITY_TYPES)
    dfir_collect_parser.add_argument("--entity-key", dest="entity_key", required=True)
    dfir_collect_parser.add_argument(
        "--source-table", dest="source_table", default=None,
        help="Optional: the exact finding (source_table) that motivated this collection.",
    )
    dfir_collect_parser.add_argument(
        "--source-id", dest="source_id", type=int, default=None,
        help="Optional: the exact finding's row id, paired with --source-table.",
    )
    dfir_collect_parser.set_defaults(func=cmd_dfir_collect)

    dfir_list_parser = dfir_subparsers.add_parser("list", help="List every forensic collection ever recorded.")
    dfir_list_parser.add_argument("--entity-type", dest="entity_type", default=None, choices=[None, *INVESTIGATE_ENTITY_TYPES])
    dfir_list_parser.add_argument("--entity-key", dest="entity_key", default=None)
    dfir_list_parser.add_argument("--limit", type=int, default=100)
    dfir_list_parser.set_defaults(func=cmd_dfir_list)

    dfir_show_parser = dfir_subparsers.add_parser("show", help="Show one collection's full detail.")
    dfir_show_parser.add_argument("collection_id", type=int)
    dfir_show_parser.set_defaults(func=cmd_dfir_show)

    dfir_evidence_parser = dfir_subparsers.add_parser(
        "evidence", help="List the normalized evidence rows one collection produced."
    )
    dfir_evidence_parser.add_argument("collection_id", type=int)
    dfir_evidence_parser.set_defaults(func=cmd_dfir_evidence)

    # Phase 25: Detection Engineering Workbench (secure/detect/) — a
    # catalog layered on top of Sigma/YARA-X/Suricata/Secure's own
    # correlation engines, never a fifth rule language. `enable`/
    # `disable` are real enforcement for sigma/yarax only; every other
    # subcommand is read-only.
    detect_parser = subparsers.add_parser(
        "detect",
        help="Detection rule catalog (sync/list/show/enable/disable/test/annotate) across Sigma, "
        "YARA-X, Suricata, and Secure's own correlation engines.",
    )
    detect_subparsers = detect_parser.add_subparsers(dest="detect_command", required=True)

    detect_sync_parser = detect_subparsers.add_parser(
        "sync", help="Discover current rules across all four families and refresh the catalog."
    )
    detect_sync_parser.set_defaults(func=cmd_detect_sync)

    detect_list_parser = detect_subparsers.add_parser("list", help="List cataloged detection rules.")
    detect_list_parser.add_argument(
        "--family", default=None, choices=[None, "sigma", "yarax", "suricata", "correlate"]
    )
    detect_list_parser.add_argument("--enabled-only", action="store_true")
    detect_list_parser.add_argument("--disabled-only", action="store_true")
    detect_list_parser.add_argument(
        "--validation-status", dest="validation_status", default=None,
        choices=[None, "unvalidated", "passed", "failed"],
    )
    detect_list_parser.add_argument("--limit", type=int, default=200)
    detect_list_parser.set_defaults(func=cmd_detect_list)

    detect_show_parser = detect_subparsers.add_parser(
        "show", help="Show one rule's full detail: telemetry, live capability, validation, recent firings."
    )
    detect_show_parser.add_argument("rule_id", type=int)
    detect_show_parser.add_argument("--limit", type=int, default=20, help="Max recent firings to show.")
    detect_show_parser.set_defaults(func=cmd_detect_show)

    detect_enable_parser = detect_subparsers.add_parser(
        "enable",
        help="Enable a rule. Real enforcement for sigma/yarax (skipped before evaluation if disabled); "
        "tracking-only for suricata/correlate.",
    )
    detect_enable_parser.add_argument("rule_id", type=int)
    detect_enable_parser.set_defaults(func=cmd_detect_enable)

    detect_disable_parser = detect_subparsers.add_parser(
        "disable",
        help="Disable a rule. Real enforcement for sigma/yarax; tracking-only for suricata/correlate.",
    )
    detect_disable_parser.add_argument("rule_id", type=int)
    detect_disable_parser.set_defaults(func=cmd_detect_disable)

    detect_test_parser = detect_subparsers.add_parser(
        "test",
        help="Run deterministic benign/suspicious fixtures for one rule (or every cataloged rule) "
        "through its own family's existing evaluator.",
    )
    detect_test_parser.add_argument("rule_id", type=int, nargs="?", default=None)
    detect_test_parser.add_argument(
        "--family", default=None, choices=[None, "sigma", "yarax", "suricata", "correlate"],
        help="When rule_id is omitted, limit to one family (default: every cataloged rule).",
    )
    detect_test_parser.set_defaults(func=cmd_detect_test)

    detect_annotate_parser = detect_subparsers.add_parser(
        "annotate", help="Set this rule's free-text false-positive notes."
    )
    detect_annotate_parser.add_argument("rule_id", type=int)
    detect_annotate_parser.add_argument("notes")
    detect_annotate_parser.set_defaults(func=cmd_detect_annotate)

    # Phase 27: Security Validation (secure/validate/) — a controlled,
    # repeatable framework that runs synthetic-but-realistic fixtures
    # against Secure's own real scanner/correlate/explain code paths,
    # entirely inside a throwaway sandbox database, and records every
    # scenario's PASS/PARTIAL/MISS/NOT_EVALUABLE/SENSOR_UNAVAILABLE
    # outcome — never filtered — into the real database for later
    # reporting.
    validate_parser = subparsers.add_parser(
        "validate",
        help="Controlled security validation framework: run synthetic ATT&CK-grounded scenarios "
        "against Secure's own detection/correlation/explanation layers and record the results.",
    )
    validate_subparsers = validate_parser.add_subparsers(dest="validate_command", required=True)

    validate_run_parser = validate_subparsers.add_parser(
        "run", help="Run every registered validation scenario and record the results."
    )
    validate_run_parser.set_defaults(func=cmd_validate_run)

    validate_list_parser = validate_subparsers.add_parser("list", help="List past validation runs.")
    validate_list_parser.add_argument("--limit", type=int, default=50)
    validate_list_parser.set_defaults(func=cmd_validate_list)

    validate_show_parser = validate_subparsers.add_parser(
        "show", help="Show one validation run's full per-scenario table."
    )
    validate_show_parser.add_argument("run_id")
    validate_show_parser.set_defaults(func=cmd_validate_show)

    validate_report_parser = validate_subparsers.add_parser(
        "report",
        help="Write docs/generated/VALIDATION_REPORT.md (+ validation_report.json) for one run "
        "(default: the latest completed run).",
    )
    validate_report_parser.add_argument(
        "run_id", nargs="?", default=None, help="Defaults to the latest completed run."
    )
    validate_report_parser.add_argument(
        "--output-dir", default=None, help="Defaults to docs/generated/ at the repo root."
    )
    validate_report_parser.add_argument(
        "--no-json", action="store_true", help="Skip writing validation_report.json."
    )
    validate_report_parser.set_defaults(func=cmd_validate_report)

    # Phase 28: Local AI Security Analyst (secure/ai/) — an OPTIONAL,
    # read-only investigation assistant. The AI is never a detection
    # authority and can never autonomously change anything; see
    # secure/ai/__init__.py's own five hard rules. More `secure ai ...`
    # subcommands (ask/history/show/verify/changes) are added by later
    # Phase 28 stages, following this exact same registration shape.
    ai_parser = subparsers.add_parser(
        "ai",
        help="Optional local AI investigation assistant (Ollama / OpenAI-compatible). "
        "Read-only, explanatory only — never a detection authority, never autonomous.",
    )
    ai_subparsers = ai_parser.add_subparsers(dest="ai_command", required=True)

    ai_status_parser = ai_subparsers.add_parser(
        "status", help="Show configured local AI providers and whether each is reachable."
    )
    ai_status_parser.set_defaults(func=cmd_ai_status)

    ai_roles_parser = ai_subparsers.add_parser(
        "roles",
        help="Phase 32 (Part 2): show which provider is assigned to each engineering-maintenance "
        "role (PRIMARY_CODER, INDEPENDENT_REVIEWER) and whether it's currently usable.",
    )
    ai_roles_parser.set_defaults(func=cmd_ai_roles)

    ai_ask_parser = ai_subparsers.add_parser(
        "ask", help="Ask the AI analyst a question, optionally scoped to one entity."
    )
    ai_ask_parser.add_argument("question")
    ai_ask_parser.add_argument("--entity-type", default=None)
    ai_ask_parser.add_argument("--entity-key", default=None)
    ai_ask_parser.set_defaults(func=cmd_ai_ask)

    ai_history_parser = ai_subparsers.add_parser("history", help="List past AI analyst queries.")
    ai_history_parser.add_argument("--limit", type=int, default=50)
    ai_history_parser.set_defaults(func=cmd_ai_history)

    ai_show_parser = ai_subparsers.add_parser("show", help="Show one AI analyst query's full detail.")
    ai_show_parser.add_argument("query_id", type=int)
    ai_show_parser.set_defaults(func=cmd_ai_show)

    # secure ai verify ... — the constrained verification mode. A fixed,
    # allowlisted set of read-only-plus-deterministic-test operations;
    # see secure/ai/verify/__init__.py for the hard rules. Never gives
    # any caller — human or model — unrestricted shell access.
    ai_verify_parser = ai_subparsers.add_parser(
        "verify", help="Constrained, allowlisted verification operations (inspect files/tests, run pytest, "
        "run the validation suite, check tool health). No unrestricted shell access."
    )
    ai_verify_subparsers = ai_verify_parser.add_subparsers(dest="ai_verify_command", required=True)

    ai_verify_list_ops_parser = ai_verify_subparsers.add_parser(
        "list-ops", help="List the fixed set of allowed verification operations."
    )
    ai_verify_list_ops_parser.set_defaults(func=cmd_ai_verify_list_ops)

    ai_verify_run_parser = ai_verify_subparsers.add_parser(
        "run", help="Run a single allowlisted verification operation."
    )
    ai_verify_run_parser.add_argument("op", help="One of the operations listed by `secure ai verify list-ops`.")
    ai_verify_run_parser.add_argument("--path", default=None, help="For read_file: a path relative to the project root.")
    ai_verify_run_parser.add_argument("--scenario-id", default=None, help="For run_scenario.")
    ai_verify_run_parser.add_argument("--test-path", default=None, help="For run_pytest: one file from list_tests.")
    ai_verify_run_parser.add_argument("--timeout", type=float, default=None, help="For run_pytest, in seconds.")
    ai_verify_run_parser.set_defaults(func=cmd_ai_verify_run)

    ai_verify_suite_parser = ai_verify_subparsers.add_parser(
        "suite", help="Run the fixed default verification bundle (tests, validation suite, tool health)."
    )
    ai_verify_suite_parser.set_defaults(func=cmd_ai_verify_suite)

    ai_verify_history_parser = ai_verify_subparsers.add_parser("history", help="List past verification runs.")
    ai_verify_history_parser.add_argument("--limit", type=int, default=50)
    ai_verify_history_parser.set_defaults(func=cmd_ai_verify_history)

    ai_verify_show_parser = ai_verify_subparsers.add_parser("show", help="Show one verification run's full detail.")
    ai_verify_show_parser.add_argument("run_id", type=int)
    ai_verify_show_parser.set_defaults(func=cmd_ai_verify_show)

    # secure ai changes ... — the change-request workflow. Every
    # AI-proposed change is born PENDING; only an explicit human action
    # here (approve/reject) can ever move it out of that state. See
    # secure/ai/changes/__init__.py's own hard rules.
    ai_changes_parser = ai_subparsers.add_parser(
        "changes", help="AI-proposed change requests: propose, list, show, approve, reject. "
        "Nothing here executes a change — approval is a record only."
    )
    ai_changes_subparsers = ai_changes_parser.add_subparsers(dest="ai_changes_command", required=True)

    ai_changes_propose_parser = ai_changes_subparsers.add_parser(
        "propose", help="Run Model A -> Model B -> deterministic tests -> PENDING change request."
    )
    ai_changes_propose_parser.add_argument("--title", required=True)
    ai_changes_propose_parser.add_argument("--topic", required=True, help="What to propose simplifying/changing.")
    ai_changes_propose_parser.add_argument("--affected-component", required=True)
    ai_changes_propose_parser.add_argument("--entity-type", default=None)
    ai_changes_propose_parser.add_argument("--entity-key", default=None)
    ai_changes_propose_parser.set_defaults(func=cmd_ai_changes_propose)

    ai_changes_list_parser = ai_changes_subparsers.add_parser("list", help="List change requests.")
    ai_changes_list_parser.add_argument("--status", default=None, choices=["pending", "approved", "rejected"])
    ai_changes_list_parser.add_argument("--limit", type=int, default=50)
    ai_changes_list_parser.set_defaults(func=cmd_ai_changes_list)

    ai_changes_show_parser = ai_changes_subparsers.add_parser("show", help="Show one change request's full detail.")
    ai_changes_show_parser.add_argument("cr_id")
    ai_changes_show_parser.set_defaults(func=cmd_ai_changes_show)

    ai_changes_approve_parser = ai_changes_subparsers.add_parser(
        "approve", help="Approve a pending change request. Requires its exact revision hash."
    )
    ai_changes_approve_parser.add_argument("cr_id")
    ai_changes_approve_parser.add_argument("revision_hash")
    ai_changes_approve_parser.add_argument("--approved-by", default=None)
    ai_changes_approve_parser.set_defaults(func=cmd_ai_changes_approve)

    ai_changes_reject_parser = ai_changes_subparsers.add_parser("reject", help="Reject a pending change request.")
    ai_changes_reject_parser.add_argument("cr_id")
    ai_changes_reject_parser.add_argument("--approved-by", default=None)
    ai_changes_reject_parser.set_defaults(func=cmd_ai_changes_reject)

    # Phase 30: Performance & Diagnostics. Ordinary, always-on
    # behavior — no enable/disable flag, no "Developer Mode" gate (see
    # secure/cli/diagnostics.py's own module docstring). Diagnostics
    # only — nothing here can change any scan's own detection/scoring
    # behavior.
    diagnostics_parser = subparsers.add_parser(
        "diagnostics",
        help="Performance & diagnostics: hardware/system health, Secure's own resource "
        "footprint, per-module timing, and integration/tool status. Never a security finding.",
    )
    diagnostics_subparsers = diagnostics_parser.add_subparsers(dest="diagnostics_command", required=True)

    diagnostics_performance_parser = diagnostics_subparsers.add_parser(
        "performance", help="Concise one-screen summary: system + Secure + any budget warnings."
    )
    diagnostics_performance_parser.set_defaults(func=cmd_diagnostics_performance)

    diagnostics_system_parser = diagnostics_subparsers.add_parser(
        "system", help="Full hardware specs + live system health detail."
    )
    diagnostics_system_parser.set_defaults(func=cmd_diagnostics_system)

    diagnostics_modules_parser = diagnostics_subparsers.add_parser(
        "modules", help="Recent per-module/integration scan timings."
    )
    diagnostics_modules_parser.add_argument("--limit", type=int, default=50)
    diagnostics_modules_parser.add_argument("--module", default=None, help="Filter to one module name.")
    diagnostics_modules_parser.add_argument(
        "--sort-by-duration", action="store_true", help="Show the most expensive runs first."
    )
    diagnostics_modules_parser.set_defaults(func=cmd_diagnostics_modules)

    diagnostics_tools_parser = diagnostics_subparsers.add_parser(
        "tools", help="External integration health + development-tool process aggregate."
    )
    diagnostics_tools_parser.set_defaults(func=cmd_diagnostics_tools)

    diagnostics_history_parser = diagnostics_subparsers.add_parser(
        "history", help="List recorded performance milestones."
    )
    diagnostics_history_parser.add_argument("--limit", type=int, default=50)
    diagnostics_history_parser.set_defaults(func=cmd_diagnostics_history)

    diagnostics_milestone_parser = diagnostics_subparsers.add_parser(
        "milestone", help="Record a performance milestone for later comparison."
    )
    diagnostics_milestone_subparsers = diagnostics_milestone_parser.add_subparsers(
        dest="diagnostics_milestone_command", required=True
    )
    diagnostics_milestone_record_parser = diagnostics_milestone_subparsers.add_parser(
        "record", help='Record a milestone, e.g. secure diagnostics milestone record "Phase 30"'
    )
    diagnostics_milestone_record_parser.add_argument("label")
    diagnostics_milestone_record_parser.add_argument("--notes", default=None)
    diagnostics_milestone_record_parser.set_defaults(func=cmd_diagnostics_milestone_record)

    diagnostics_report_parser = diagnostics_subparsers.add_parser(
        "report",
        help="Write docs/generated/PERFORMANCE_REPORT.md (+ performance_report.json), sanitized "
        "of secrets.",
    )
    diagnostics_report_parser.add_argument(
        "--output-dir", default=None, help="Defaults to docs/generated/ at the repo root."
    )
    diagnostics_report_parser.add_argument(
        "--no-json", action="store_true", help="Skip writing performance_report.json."
    )
    diagnostics_report_parser.set_defaults(func=cmd_diagnostics_report)

    # secure agent ... (Phase 31: Agent Foundation). Supervised,
    # human-approved autonomous repair — see secure/agent/'s own module
    # docstring for the five hard rules this whole command group is
    # built around. `run`/`resume` are the only commands that can ever
    # produce a PENDING ai_change_requests row; nothing here can ever
    # approve one — that stays exclusively `secure ai changes approve`.
    agent_parser = subparsers.add_parser(
        "agent",
        help="Supervised, human-approved autonomous repair (Phase 31). Runs mini-SWE-agent "
        "against an isolated git worktree, verifies with pytest + secure validate, and — only "
        "on a full pass — proposes a normal, human-approved change request. Never applies "
        "anything to the live repository on its own.",
    )
    agent_subparsers = agent_parser.add_subparsers(dest="agent_command", required=True)

    agent_status_parser = agent_subparsers.add_parser(
        "status", help="Whether the tool/Ollama/git-worktree preconditions are ready."
    )
    agent_status_parser.set_defaults(func=cmd_agent_status)

    agent_discover_parser = agent_subparsers.add_parser(
        "discover", help="List current deterministic test/validation/detection-rule failures."
    )
    agent_discover_parser.set_defaults(func=cmd_agent_discover)

    agent_run_parser = agent_subparsers.add_parser(
        "run", help="Attempt a repair. Discovers candidates unless --trigger-kind/--trigger-ref are given."
    )
    agent_run_parser.add_argument(
        "--trigger-kind", choices=["pytest_failure", "validate_scenario_failure", "detect_rule_test_failure"],
        default=None, help="Attempt exactly this one trigger instead of auto-discovering.",
    )
    agent_run_parser.add_argument("--trigger-ref", default=None, help="Required with --trigger-kind.")
    agent_run_parser.add_argument("--trigger-detail", default=None, help="Optional detail text for a manual trigger.")
    agent_run_parser.add_argument(
        "--limit", type=int, default=1, help="Maximum number of candidates to attempt in this invocation (default: 1)."
    )
    agent_run_parser.set_defaults(func=cmd_agent_run)

    agent_list_parser = agent_subparsers.add_parser("list", help="List repair runs.")
    agent_list_parser.add_argument("--status", default=None)
    agent_list_parser.add_argument("--limit", type=int, default=50)
    agent_list_parser.set_defaults(func=cmd_agent_list)

    agent_show_parser = agent_subparsers.add_parser("show", help="Show one repair run's full detail.")
    agent_show_parser.add_argument("run_id")
    agent_show_parser.set_defaults(func=cmd_agent_show)

    agent_resume_parser = agent_subparsers.add_parser(
        "resume", help="Resume a run left in status='running' by a crashed/killed Secure process."
    )
    agent_resume_parser.add_argument("run_id")
    agent_resume_parser.set_defaults(func=cmd_agent_resume)

    agent_remove_worktree_parser = agent_subparsers.add_parser(
        "remove-worktree", help="Delete a finished run's isolated worktree from disk. The database record is kept."
    )
    agent_remove_worktree_parser.add_argument("run_id")
    agent_remove_worktree_parser.set_defaults(func=cmd_agent_remove_worktree)

    agent_approve_parser = agent_subparsers.add_parser(
        "approve",
        help="Revalidate a repair's worktree diff against its change request, then approve it if unchanged. "
        "Refuses (and supersedes + regenerates the change request) if the worktree has drifted since it "
        "was proposed. The only way secure/agent/ ever approves anything — see secure/cli/agent.py.",
    )
    agent_approve_parser.add_argument("run_id")
    agent_approve_parser.add_argument("--approved-by", default=None)
    agent_approve_parser.set_defaults(func=cmd_agent_approve)

    agent_actions_parser = agent_subparsers.add_parser(
        "actions",
        help="Phase 31.5: list every audited subprocess/git/filesystem/proposed-system-change action "
        "secure/agent/ has recorded, optionally filtered to one run. See docs/AGENT_FOUNDATION.md.",
    )
    agent_actions_parser.add_argument("--run-id", default=None, help="Show only actions recorded under this run_id.")
    agent_actions_parser.add_argument("--limit", type=int, default=200)
    agent_actions_parser.set_defaults(func=cmd_agent_actions)

    # Phase 40 — Change Request Center. Read-only assembly of every
    # field a human needs before deciding, plus a content-integrity
    # re-check that supersedes a request whose content changed. None of
    # these three commands can approve anything; approval remains the
    # single explicit `secure ai changes approve <cr_id> <hash>` action.
    agent_center_parser = agent_subparsers.add_parser(
        "center",
        help="Phase 40: list change requests awaiting approval, with the diff/tests/reviewer/"
        "classification/rollback detail needed to decide. Read-only.",
    )
    agent_center_sub = agent_center_parser.add_subparsers(dest="center_command")
    agent_center_parser.add_argument("--limit", type=int, default=50)
    agent_center_parser.set_defaults(func=cmd_agent_center_list)

    agent_center_show_parser = agent_center_sub.add_parser(
        "show", help="Show one change request in full (VIEW DETAILS); --diff and --tests add those panes."
    )
    agent_center_show_parser.add_argument("cr_id")
    agent_center_show_parser.add_argument("--diff", action="store_true", help="Also print the actual diff.")
    agent_center_show_parser.add_argument("--tests", action="store_true", help="Also print test results and the review.")
    agent_center_show_parser.set_defaults(func=cmd_agent_center_show)

    agent_center_check_parser = agent_center_sub.add_parser(
        "check",
        help="Re-verify a change request's content still hashes to its recorded revision, and supersede "
        "it if not. Approval must never transfer to changed content.",
    )
    agent_center_check_parser.add_argument("cr_id")
    agent_center_check_parser.set_defaults(func=cmd_agent_center_check)

    # Phase 42 — Background Supervisor. `supervise` runs one bounded,
    # observe-only pass (this is what a launchd job would invoke).
    # `supervisor-plist` prints the plist that WOULD schedule it, and
    # `supervisor-propose` raises the approval-gated change request.
    # None of the three installs anything: this project ships no code
    # that writes to LaunchAgents or invokes the service-management
    # tool.
    agent_supervise_parser = agent_subparsers.add_parser(
        "supervise",
        help="Phase 42: run one bounded, observe-only supervision pass (health, integration health, "
        "fast verification, failure review, pending-approval review). Cannot start a repair.",
    )
    agent_supervise_parser.add_argument("--verbose", action="store_true", help="Print each job's output.")
    agent_supervise_parser.set_defaults(func=cmd_agent_supervise)

    agent_plist_parser = agent_subparsers.add_parser(
        "supervisor-plist",
        help="Phase 42: print the launchd plist that would schedule the supervisor. Installs nothing.",
    )
    agent_plist_parser.add_argument("--label", default="com.securemb.supervisor")
    agent_plist_parser.add_argument("--interval", type=int, default=3600)
    agent_plist_parser.set_defaults(func=cmd_agent_supervisor_plist)

    agent_propose_parser = agent_subparsers.add_parser(
        "supervisor-propose",
        help="Phase 42: raise the approval-gated SYSTEM_CHANGE request for installing the supervisor. "
        "Creates a pending change request and stops.",
    )
    agent_propose_parser.add_argument("--label", default="com.securemb.supervisor")
    agent_propose_parser.add_argument("--interval", type=int, default=3600)
    agent_propose_parser.set_defaults(func=cmd_agent_supervisor_propose)

    # Phase 43 — Automated Failure Diagnosis. Runs the full required
    # sequence, with reproduction as a gate in front of it: a failure
    # that does not recur, or whose reproduction is inconclusive, stops
    # here and no repair is attempted or fabricated.
    agent_diagnose_parser = agent_subparsers.add_parser(
        "diagnose",
        help="Phase 43: detect -> reproduce -> bounded-context diagnosis -> isolated repair -> "
        "targeted/broader tests -> independent review. Stops honestly if the failure does not recur.",
    )
    agent_diagnose_parser.add_argument("--trigger-ref", default=None, help="Diagnose only this trigger ref.")
    agent_diagnose_parser.add_argument("--all", action="store_true", help="Diagnose every eligible failure, not just the first.")
    agent_diagnose_parser.add_argument(
        "--reproduce-only", action="store_true",
        help="Only run the reproduction step and report it. Never starts a repair.",
    )
    agent_diagnose_parser.set_defaults(func=cmd_agent_diagnose)

    # Phase 44 — Verified Self-Healing. Read-only evaluation of the
    # eleven authoritative criteria. Promotes nothing: VERIFIED is a
    # measurement, and eligibility is not permission.
    agent_verified_parser = agent_subparsers.add_parser(
        "verified",
        help="Phase 44: evaluate all eleven VERIFIED criteria for one repair run and print the "
        "checklist. Read-only; promotes and approves nothing.",
    )
    agent_verified_parser.add_argument("run_id")
    agent_verified_parser.set_defaults(func=cmd_agent_verified)

    # Phase 45 — Maintenance Memory. Structured repair history, and
    # recall of prior evidence for a failure happening now. Read-only,
    # and deliberately offers no way to re-apply an old patch.
    agent_memory_parser = agent_subparsers.add_parser(
        "memory",
        help="Phase 45: structured repair history; with --trigger-ref, the prior repair evidence "
        "relevant to a failure happening now. Evidence, not authority — never re-applies a patch.",
    )
    agent_memory_parser.add_argument("--trigger-ref", default=None, help="Recall evidence for this failing test/scenario.")
    agent_memory_parser.add_argument("--trigger-kind", default=None, help="Trigger kind for --trigger-ref (default pytest_failure).")
    agent_memory_parser.add_argument("--detail", default=None, help="Failure detail text, to sharpen the signature match.")
    agent_memory_parser.add_argument("--limit", type=int, default=20)
    agent_memory_parser.set_defaults(func=cmd_agent_memory)

    # Phase 46 — Dependency & Security Tool Maintenance. Surveys and
    # proposes; installs and updates nothing. Exits 1 when situations
    # were found, matching the CLI's own findings-worth-reviewing
    # convention.
    agent_toolchain_parser = agent_subparsers.add_parser(
        "toolchain",
        help="Phase 46: survey external tools and dependencies for maintenance situations. "
        "Installs and updates nothing; --propose raises approval-gated change requests.",
    )
    agent_toolchain_parser.add_argument(
        "--propose", action="store_true",
        help="Raise an approval-gated change request for each situation found.",
    )
    agent_toolchain_parser.set_defaults(func=cmd_agent_toolchain)

    # Phase 47 — Supervised Autonomous Maintenance. One bounded pass of
    # the complete loop. Applies nothing and changes no host state; a
    # verified SAFE_PROJECT_CODE repair is reported as ELIGIBLE for
    # promotion, which a human still performs.
    agent_maintain_parser = agent_subparsers.add_parser(
        "maintain",
        help="Phase 47: run one bounded pass of the complete maintenance loop. Applies nothing to the "
        "live checkout and changes no host state.",
    )
    agent_maintain_parser.add_argument("--all", action="store_true", help="Process every eligible failure.")
    agent_maintain_parser.set_defaults(func=cmd_agent_maintain)

    # Phase 47.5 — automatic promotion of a fully VERIFIED
    # SAFE_PROJECT_CODE repair. Read-only without --apply. This is the
    # only command besides `secure agent approve` that can write to the
    # live working tree, and it refuses unless every gate condition is
    # affirmatively satisfied.
    agent_promote_parser = agent_subparsers.add_parser(
        "promote",
        help="Phase 47.5: evaluate the promotion gate for a repair run; with --apply, promote a fully "
        "VERIFIED SAFE_PROJECT_CODE repair into the live working tree. Never commits.",
    )
    agent_promote_parser.add_argument("run_id")
    agent_promote_parser.add_argument(
        "--apply", action="store_true",
        help="Actually promote. Without this the command is read-only and writes nothing.",
    )
    agent_promote_parser.add_argument(
        "--run-tiers", action="store_true",
        help="Run the Phase 36 verification tiers against the repair's worktree first. Without this, "
        "the tier criteria read UNKNOWN and promotion is refused.",
    )
    agent_promote_parser.set_defaults(func=cmd_agent_promote)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        exit_code = args.func(args)
    except ConfigError as exc:
        # Corrupted/malformed ~/.secure/config.json (Phase 29 Stage 7) —
        # see ConfigError's own docstring for why this is never
        # auto-repaired. A clear message + exit code 2, not a raw
        # traceback.
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)
    except sqlite3.DatabaseError as exc:
        # A corrupted/truncated secure.db, or one genuinely not a
        # SQLite file (Phase 29 Stage 7 — deliberately induced by
        # writing garbage bytes to a database path during this phase's
        # own audit). Never auto-repaired or deleted, same "no
        # autonomous remediation" discipline as ConfigError above.
        print(
            f"Database error: {exc}. The database file may be corrupted or is not a "
            "valid SQLite file. Secure will not repair or delete it automatically — "
            "restore it from a backup, or move it aside so a fresh one can be "
            "created on the next run.",
            file=sys.stderr,
        )
        sys.exit(2)
    except PermissionError as exc:
        # Cannot read/write ~/.secure (or a path inside it) at all —
        # Phase 29 Stage 7. A clear message pointing at the exact path
        # involved, not a raw traceback.
        print(f"Permission error: {exc}", file=sys.stderr)
        sys.exit(2)
    except RepairNotEligible as exc:
        # secure/agent/policy.py already refused this trigger (bounded
        # retries reached, wrong trigger kind, not a git repo, etc.) —
        # Phase 31. A clear message, never a raw traceback.
        print(f"Repair not eligible: {exc}", file=sys.stderr)
        sys.exit(2)
    except WorktreeError as exc:
        # git itself failed to create/remove/inspect a repair worktree
        # (Phase 31) — most commonly "the live checkout is not a git
        # repository", a real precondition this app cannot silently
        # work around.
        print(f"Agent worktree error: {exc}", file=sys.stderr)
        sys.exit(2)
    else:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
