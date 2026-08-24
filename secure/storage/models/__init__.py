"""
secure/storage/models/ — friendly, typed functions for reading and
writing rows, split into one file per domain (Phase 14.5 Stage C).

This __init__.py re-exports every name from every domain submodule
so `from secure.storage.models import X` and `from secure.storage
import models; models.X(...)` both keep working exactly as before —
this split changed which FILE each function lives in, not its
behavior, signature, or SQL. See each submodule (events.py,
checks.py, continuity.py, inventory.py, connections.py,
listening.py, arpwatch.py, wifi.py, bluetooth.py, ble.py,
persistence.py, correlate.py, fileintegrity.py, baseline.py,
integrations.py, threatintel.py, evidence.py, perf.py, ai.py,
agent.py) for its own domain-scoped docstring.

This is still the ONLY place that should contain SQL. Every other
part of the app calls these functions instead of touching sqlite3
directly.

Original per-table documentation, preserved verbatim:

models.py — friendly, typed functions for reading and writing rows.

This is the ONLY place that should contain SQL. Every other part of
the app calls these functions instead of touching sqlite3 directly.
That gives you one place to look when the schema changes later.

Two concepts live here:

    - "events" — a generic record of something that happened (e.g.
      "app started", "config loaded"). Deliberately generic.
    - "posture_checks" — one row per individual macOS security posture
      check result (see secure/checks/), e.g. "FileVault: PASS". Rows
      from the same `secure check` run share a `run_id` so you can
      pull "the last full run" back out as a group. This module has
      no idea what a check actually *is* — it only knows how to store
      and retrieve the plain strings (name/status/message/
      remediation) it's handed; the checks package owns the logic.
    - "snapshots" — one row per `secure snapshot` run (see
      secure/continuity.py). `summary` is a short one-line description
      for quick scanning; `details` is the full result as a JSON
      string (this module doesn't parse it — it's opaque storage,
      same JSON that's also written to ~/.secure/snapshots/*.json).
    - "devices" — one row per device ever seen on the local network
      (see secure/inventory/), the app's historical device inventory.
      Rows are matched/updated by MAC address when one was captured
      (the more stable identity), or by IP when it wasn't. `known`
      defaults to 0 (unknown) for every newly-discovered device — you
      mark it known yourself.
    - "connection_events" — one row per individual TCP/UDP connection
      (or listening socket) observed during a `secure connections
      scan` (see secure/connections/). Append-only, full history, same
      run_id-groups-a-scan pattern as posture_checks. This module
      doesn't interpret proto/state/etc — it only stores what the
      connections package already parsed.
    - "remote_endpoints" — one row per distinct remote destination
      (remote address + port + protocol) this Mac has ever connected
      out to, deduplicated the same way "devices" dedupes local
      devices. `known` defaults to 0 (unknown) for a newly-seen
      destination — you mark it known yourself. This is what "flag an
      unexpected outbound connection for review" keys off.
    - "listening_events" — one row per listening TCP/UDP socket
      observed during a `secure listening scan` (see
      secure/listening/). Append-only, full history, same
      run_id-groups-a-scan pattern as connection_events.
    - "listening_services" — one row per distinct listening service
      this Mac has ever been observed running, deduplicated by
      (proto, bind_scope, process_name, identity_port) — see
      secure/listening/scanner.py for why identity_port often isn't
      the raw port number. `known` defaults to 0 (unknown) for a
      newly-seen service — you mark it known yourself. This is what
      "alert when a new service begins listening" keys off.
    - "arp_observations" — one row per real ARP entry observed during
      a `secure arpwatch scan` (see secure/arpwatch/). Append-only,
      full history, same run_id-groups-a-scan pattern as
      connection_events/listening_events.
    - "arp_mappings" — this Mac's current best-known IP -> MAC
      mapping, one row per IP, updated in place. What "did this IP's
      MAC change since last time" is compared against.
    - "arp_alerts" — one row per alert an arpwatch scan raised (a MAC
      change, a gateway MAC change, or a same-scan conflict). `known`
      defaults to 0 (unknown/unreviewed) — you mark it known yourself,
      same pattern as devices/remote_endpoints/listening_services.
    - "wifi_observations" — one row per Wi-Fi status snapshot taken by
      a `secure wifi scan` (see secure/wifi/). Append-only, full
      history, same run_id-groups-a-scan pattern as
      connection_events/listening_events/arp_observations.
    - "wifi_networks" — one row per distinct Wi-Fi network (SSID, or
      SSID+BSSID when the BSSID is available) this Mac has ever
      connected to, deduplicated and updated in place, same
      known/unknown pattern as devices/remote_endpoints/
      listening_services. What "warn when joining an unknown network"
      and "detect a new BSSID for a known SSID" key off.
    - "wifi_alerts" — one row per lookalike-SSID alert a wifi scan
      raised. `known` defaults to 0 (unreviewed) — you mark it known
      yourself, same pattern as arp_alerts. Weak/open security is
      re-evaluated fresh every scan instead of being stored here — see
      secure/wifi/scanner.py.
    - "bluetooth_observations" — one row per Bluetooth device observed
      by a `secure bluetooth scan` (see secure/bluetooth/). Append-only,
      full history, same run_id-groups-a-scan pattern as
      connection_events/listening_events/arp_observations/
      wifi_observations.
    - "bluetooth_devices" — one row per distinct Bluetooth device this
      Mac has ever seen, deduplicated by identifier (its Bluetooth
      address) and updated in place. `trusted` defaults to 0
      (untrusted) for a newly-seen device — you mark it trusted
      yourself, same known/unknown-style pattern as
      devices/remote_endpoints/listening_services/wifi_networks, just
      named for this domain's own vocabulary. `times_seen` is what
      persistent-unknown-device detection keys off. `paired`/`connected`
      hold this device's CURRENT state (added after the fact via a
      column migration — see database.py) so that
      upsert_bluetooth_device() can report the PRIOR state before
      overwriting it, which is what new-pairing/first-connection
      transition detection keys off — see secure/bluetooth/scanner.py.
    - "bluetooth_alerts" — one row per alert a bluetooth scan raised:
      "seen nearby in several scans while still untrusted", "an
      untrusted device just became paired", or "an untrusted device
      connected for the first time". `known` defaults to 0
      (unreviewed) — you mark it known yourself, same pattern as
      arp_alerts/wifi_alerts. A brand-new device is surfaced as a NEW
      tag in scan output instead of a row here — see
      secure/bluetooth/scanner.py.
    - "ble_observations" — one row per BLE peripheral advertisement
      observed by a `secure bluetooth ble scan` (see
      secure/bluetooth/ble/). Append-only, full history, same
      run_id-groups-a-scan pattern as bluetooth_observations. Uses a
      DIFFERENT identifier space than bluetooth_devices — see the
      schema comment in database.py for why cb_uuid (a per-app
      CoreBluetooth UUID) and a Bluetooth MAC address can't be reliably
      merged.
    - "ble_peripherals" — one row per distinct CoreBluetooth UUID ever
      seen advertising nearby, deduplicated and updated in place — same
      shape/role as bluetooth_devices, for the live-BLE identifier
      space. `times_seen` is a floor, not an exact count, since many
      modern devices rotate their real BLE address for privacy — see
      database.py's schema comment.
    - "ble_alerts" — one row per alert a live BLE scan raised:
      persistent-unknown-peripheral, or a significant RSSI change.
      `known` defaults to 0 (unreviewed), same pattern as every other
      *_alerts table. A brand-new peripheral is surfaced as a NEW tag
      in scan output instead of a row here.
    - "process_entries" — one row per distinct running-process
      executable path ever seen (see secure/persistence/), deduplicated
      by `executable_path` and updated in place — deliberately NOT an
      append-only history (see database.py's schema comment for why).
      `signing_status` is computed once, when the entry is first
      created, and not re-checked on later scans. `known` defaults to
      0 (unreviewed) — you mark it known yourself.
    - "persistence_observations" — one row per persistence-mechanism
      entry (LaunchAgent/LaunchDaemon/login item) observed by a
      `secure persistence scan`. Append-only, full history, same
      run_id-groups-a-scan pattern as every other `*_observations`
      table — persistence items are few enough and change rarely
      enough that the usual pattern fits fine here, unlike processes.
    - "persistence_entries" — one row per distinct persistence entry
      ever seen, deduplicated by (kind, path) — or by (kind, label)
      when no path is available, e.g. some login items — and updated
      in place. Unlike process_entries, `signing_status` here IS
      re-checked and overwritten every scan, which is what lets
      upsert_persistence_entry() report the PRIOR value for
      signing-changed-since-last-scan detection (see
      secure/persistence/scanner.py). `known` defaults to 0.
    - "persistence_alerts" — one row per alert a persistence scan
      raised: a brand-new persistence entry, an unusual/unsigned new
      process, or an existing persistence entry whose backing
      executable went from signed to unsigned. `known` defaults to 0.
    - "correlation_alerts" — one row per cluster `secure correlate`
      (see secure/correlate/) found: 2+ signals from DISTINCT modules
      that happened within its time window of each other. Unlike every
      table above, nothing here comes from a live scan — it's entirely
      derived from rows already in this database. `members` is the
      full list of contributing signals as a JSON array (module, kind,
      strength, identifier, source_table, source_id, timestamp) so
      every correlation alert stays traceable back to its sources;
      `explanation` is a plain-English breakdown of the score.
      `fingerprint` (a hash of the member rows' identities) is UNIQUE,
      so re-running correlate never re-alerts on the same cluster.
      `known` defaults to 0.
    - "file_watch_paths" — the small, user-configurable list of
      files/folders monitored by `secure fileintegrity scan` (see
      secure/fileintegrity/). `sensitivity` ("startup"/"self"/"normal")
      drives severity; `last_scan_status` ("ok"/"incomplete") reflects
      whether the most recent scan could fully enumerate this path.
    - "file_entries" — current known state of every monitored file, one
      row per path, updated in place — the baseline itself. `known`
      defaults to 1 for a path's first-ever observation (establishing a
      baseline IS trusting current state) and 0 for a genuinely new
      file found on a later scan. `program_path`/`program_signing_status`/
      `program_exists` are populated only for LaunchAgent/LaunchDaemon
      plists.
    - "file_change_events" — full, append-only history of every change
      a file-integrity scan observed (baseline/created/modified/
      metadata_only/deleted/renamed/program_target_changed). `details`
      is a JSON object with the full before/after metadata and a
      plain-English list of what changed.
    - "file_integrity_alerts" — one row per alert a file-integrity scan
      raised. `known` defaults to 0. `context_notes` carries
      non-erasing annotations like "known update context".
    - "file_integrity_scans" — one row per `secure fileintegrity scan`
      run: timing, per-watch-path attempted/completed/incomplete status,
      and full file/alert counters — the forensic record that lets
      later analysis tell a complete scan from a partial one.
    - "baseline_entities" — Product Phase 14. One row per
      (entity_type, entity_key) Secure is tracking "normal" behavior
      for. Lifetime counters only; never reset by drift/rolling-window
      handling. `maturity_state` is computed by
      secure/baseline/maturity.py and written back here — this module
      only stores it, it doesn't compute it (SQL only lives here; the
      maturity rules are pure logic that live in secure/baseline/).
    - "baseline_activity" — Phase 14. Append-only gap-filling
      observation log for the two entity_types with no existing
      history table of their own ("inventory" devices, "process"
      executables). Every other entity_type is read directly from its
      existing *_events/*_observations table instead.
    - "baseline_feature_stats" — Phase 14. Summarized "what's normal"
      per (entity, feature_name, feature_value): lifetime counters plus
      a rolling-window view, recomputed by secure/baseline/engine.py.
    - "baseline_time_stats" — Phase 14. Per-entity time-of-day
      (night/morning/afternoon/evening) and weekday/weekend activity
      distribution, with its own maturity gate independent of the
      entity's overall maturity_state.
    - "anomaly_events" — Phase 14. One row per anomaly finding the
      baseline engine produced. Deliberately has no `severity` column —
      an anomaly never overrides the severity of whatever it describes;
      see secure/explain/baseline_explainer.py. `score_breakdown` is a
      JSON object of {component_name: points}, so every point in
      `anomaly_score` traces back to a named, reproducible rule.
    - "baseline_runs" — Phase 14. One row per baseline-engine
      maintenance/update pass — mirrors file_integrity_scans' role, a
      forensic/performance record independent of the anomaly findings
      themselves, including how many entities were skipped for
      insufficient history or an entity-type cap.

"""

from __future__ import annotations

from .events import (
    Event,
    add_event,
    list_events,
    count_events,
    has_recent_event,
)

from .checks import (
    PostureCheckRecord,
    add_posture_result,
    list_recent_posture_results,
    last_posture_run_id,
)

from .continuity import (
    SnapshotRecord,
    add_snapshot,
    list_recent_snapshots,
)

from .inventory import (
    DeviceRecord,
    _row_to_device,
    upsert_device,
    list_devices,
    find_device_by_identifier,
    set_device_friendly_name,
    set_device_known,
    delete_junk_devices,
    _BROADCAST_MAC,
)

from .connections import (
    ConnectionEventRecord,
    add_connection_events,
    list_recent_connection_events,
    last_connection_run_id,
    RemoteEndpointRecord,
    _row_to_endpoint,
    upsert_remote_endpoint,
    list_remote_endpoints,
    ProcessDestinationRecord,
    _row_to_process_destination,
    upsert_process_destination,
    find_process_destination_by_id,
    list_process_destinations,
    list_process_destinations_for_process,
    list_process_destinations_for_remote,
    find_remote_endpoint_by_id,
    find_remote_endpoint_by_identity,
    set_remote_endpoint_known,
)

from .listening import (
    ListeningEventRecord,
    add_listening_events,
    list_recent_listening_events,
    last_listening_run_id,
    ListeningServiceRecord,
    _row_to_listening_service,
    upsert_listening_service,
    list_listening_services,
    find_listening_service_by_id,
    set_listening_service_known,
)

from .arpwatch import (
    add_arp_observations,
    ArpMappingRecord,
    _row_to_arp_mapping,
    upsert_arp_mapping,
    list_arp_mappings,
    ArpAlertRecord,
    _row_to_arp_alert,
    add_arp_alert,
    list_arp_alerts,
    find_arp_alert_by_id,
    set_arp_alert_known,
)

from .wifi import (
    add_wifi_observation,
    WifiNetworkRecord,
    _row_to_wifi_network,
    upsert_wifi_network,
    list_wifi_networks,
    find_wifi_network_by_id,
    set_wifi_network_known,
    list_known_ssids,
    WifiAlertRecord,
    _row_to_wifi_alert,
    add_wifi_alert,
    list_wifi_alerts,
    find_wifi_alert_by_id,
    set_wifi_alert_known,
)

from .bluetooth import (
    add_bluetooth_observations,
    BluetoothDeviceRecord,
    _row_to_bluetooth_device,
    upsert_bluetooth_device,
    list_bluetooth_devices,
    find_bluetooth_device_by_id,
    set_bluetooth_device_trusted,
    BluetoothAlertRecord,
    _row_to_bluetooth_alert,
    add_bluetooth_alert,
    list_bluetooth_alerts,
    find_bluetooth_alert_by_id,
    set_bluetooth_alert_known,
    has_bluetooth_alert_of_kind,
)

from .ble import (
    add_ble_observations,
    BlePeripheralRecord,
    _row_to_ble_peripheral,
    upsert_ble_peripheral,
    list_ble_peripherals,
    find_ble_peripheral_by_id,
    set_ble_peripheral_trusted,
    BleAlertRecord,
    _row_to_ble_alert,
    add_ble_alert,
    list_ble_alerts,
    find_ble_alert_by_id,
    set_ble_alert_known,
    has_ble_alert_of_kind,
)

from .persistence import (
    ProcessEntryRecord,
    _row_to_process_entry,
    upsert_process_entry,
    find_process_entry_by_path,
    list_process_entries,
    find_process_entry_by_id,
    set_process_entry_known,
    add_persistence_observations,
    PersistenceEntryRecord,
    _row_to_persistence_entry,
    upsert_persistence_entry,
    list_persistence_entries,
    find_persistence_entry_by_id,
    set_persistence_entry_known,
    PersistenceAlertRecord,
    _row_to_persistence_alert,
    add_persistence_alert,
    list_persistence_alerts,
    find_persistence_alert_by_id,
    set_persistence_alert_known,
)

from .correlate import (
    CorrelationAlertRecord,
    _row_to_correlation_alert,
    add_correlation_alert,
    list_correlation_alerts,
    find_correlation_alert_by_id,
    set_correlation_alert_known,
)

from .fileintegrity import (
    FileWatchPathRecord,
    _row_to_watch_path,
    add_watch_path,
    list_watch_paths,
    find_watch_path_by_id,
    find_watch_path_by_path,
    set_watch_path_enabled,
    set_watch_path_scan_status,
    FileEntryRecord,
    _row_to_file_entry,
    insert_file_entry,
    update_file_entry,
    touch_file_entry_last_seen,
    rename_file_entry,
    delete_file_entry,
    find_file_entry_by_path,
    find_file_entry_by_id,
    find_file_entries_by_hash,
    list_file_entries_for_watch_path,
    list_file_entries,
    set_file_entry_known,
    FileChangeEventRecord,
    _row_to_file_change_event,
    add_file_change_event,
    list_file_change_events,
    FileIntegrityAlertRecord,
    _row_to_file_integrity_alert,
    add_file_integrity_alert,
    list_file_integrity_alerts,
    find_file_integrity_alert_by_id,
    set_file_integrity_alert_known,
    FileIntegrityScanRecord,
    _row_to_file_integrity_scan,
    add_file_integrity_scan,
    list_file_integrity_scans,
    find_latest_file_integrity_scan,
    _FILE_ENTRY_METADATA_COLUMNS,
)

from .baseline import (
    BaselineEntityRecord,
    _row_to_baseline_entity,
    get_or_create_baseline_entity,
    count_baseline_entities,
    count_baseline_entities_by_maturity,
    count_baseline_entities_excluded,
    count_baseline_entities_frozen,
    record_baseline_observation,
    set_baseline_entity_maturity,
    set_baseline_entity_excluded,
    set_baseline_entity_frozen,
    list_baseline_entities,
    find_baseline_entity,
    find_baseline_entity_by_id,
    delete_baseline_entity,
    reset_baseline_entity,
    BaselineActivityRecord,
    _row_to_baseline_activity,
    add_baseline_activity,
    list_baseline_activity,
    BaselineFeatureStatRecord,
    _row_to_baseline_feature_stat,
    upsert_baseline_feature_stat,
    list_baseline_feature_stats,
    get_baseline_feature_stat,
    BaselineTimeStatRecord,
    _row_to_baseline_time_stat,
    upsert_baseline_time_stat,
    get_baseline_time_stat,
    AnomalyEventRecord,
    _row_to_anomaly_event,
    find_anomaly_event,
    add_anomaly_event,
    list_anomaly_events,
    count_anomaly_events,
    find_anomaly_event_by_id,
    set_anomaly_event_known,
    BaselineRunRecord,
    _row_to_baseline_run,
    add_baseline_run,
    list_baseline_runs,
    count_baseline_runs,
    find_latest_baseline_run,
    BaselineFeatureActivityRecord,
    _row_to_baseline_feature_activity,
    add_baseline_feature_activity,
    list_baseline_feature_activity,
    BaselineFeatureMaturityRecord,
    _row_to_baseline_feature_maturity,
    get_or_create_baseline_feature_maturity,
    record_feature_maturity_observation,
    set_baseline_feature_maturity_state,
    find_baseline_feature_maturity,
    list_baseline_feature_maturity,
)

from .integrations import (
    IntegrationRunRecord,
    _row_to_integration_run,
    add_integration_run,
    list_integration_runs,
    find_latest_integration_run,
    IntegrationObservationRecord,
    _row_to_integration_observation,
    add_integration_observations,
    list_integration_observations,
    IntegrationAlertRecord,
    _row_to_integration_alert,
    add_integration_alert,
    list_integration_alerts,
    find_integration_alert_by_id,
    set_integration_alert_known,
)

from .threatintel import (
    ThreatIntelLookupRecord,
    _row_to_lookup,
    add_threat_intel_lookup,
    find_fresh_lookup,
    list_threat_intel_lookups,
    find_latest_lookups_for_indicator,
    find_latest_lookup,
)
from .evidence import (
    EvidenceLinkRecord,
    EvidenceLinkObservationRecord,
    add_evidence_link,
    touch_evidence_link,
    add_evidence_link_observation,
    find_evidence_link_by_fingerprint,
    find_evidence_link_by_id,
    list_evidence_links_for,
    list_evidence_link_observations,
)
from .correlate_chains import (
    CorrelationChainAlertRecord,
    add_correlation_chain_alert,
    list_correlation_chain_alerts,
    find_correlation_chain_alert_by_id,
    set_correlation_chain_alert_known,
)
from .dfir import (
    ForensicCollectionRecord,
    ForensicEvidenceItemRecord,
    add_forensic_collection,
    find_forensic_collection_by_id,
    list_forensic_collections,
    add_forensic_evidence_item,
    find_forensic_evidence_item_by_id,
    list_forensic_evidence_items_for_collection,
)
from .detect import (
    DetectionRuleRecord,
    DetectionRuleTestRunRecord,
    find_detection_rule_by_id,
    find_detection_rule,
    list_detection_rules,
    upsert_detection_rule,
    set_detection_rule_enabled,
    set_detection_rule_validation,
    set_detection_rule_fp_notes,
    add_detection_rule_test_run,
    list_detection_rule_test_runs,
)

from .validate import (
    ValidationRunRecord,
    ValidationScenarioResultRecord,
    add_validation_run,
    complete_validation_run,
    find_validation_run,
    find_latest_validation_run,
    list_validation_runs,
    add_validation_scenario_result,
    list_validation_scenario_results,
)

from .perf import (
    PerfModuleRunRecord,
    PerfMilestoneRecord,
    add_perf_module_run,
    list_recent_perf_module_runs,
    list_perf_module_runs_for_group,
    add_perf_milestone,
    list_perf_milestones,
    count_total_findings,
)

from .agent import (
    AgentRepairRunRecord,
    add_agent_repair_run,
    complete_agent_repair_run,
    set_agent_repair_run_change_request,
    find_agent_repair_run,
    list_agent_repair_runs,
    list_agent_repair_runs_for_trigger,
    AgentActionRecord,
    add_agent_action,
    list_agent_actions,
)

from .agent_memory import (
    MaintenanceMemoryRecord,
    ToolVersionRecord,
    latest_tool_version,
    list_tool_versions,
    record_tool_version,
    add_maintenance_memory,
    find_maintenance_memory_by_component,
    find_maintenance_memory_by_signature,
    find_maintenance_memory_for_run,
    link_regression,
    list_maintenance_memory,
)

from .ai import (
    AiAnalystQueryRecord,
    AiVerificationRunRecord,
    AiChangeRequestRecord,
    add_ai_analyst_query,
    complete_ai_analyst_query,
    find_ai_analyst_query,
    list_ai_analyst_queries,
    add_ai_verification_run,
    complete_ai_verification_run,
    find_ai_verification_run,
    list_ai_verification_runs,
    add_ai_change_request,
    find_ai_change_request,
    list_ai_change_requests,
    set_ai_change_request_status,
    set_ai_change_request_classification,
    mark_ai_change_request_notified,
)

