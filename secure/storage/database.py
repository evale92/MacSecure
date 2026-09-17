"""
database.py — owns the SQLite connection and the database schema.

Design choice (beginner-friendly on purpose):
    SQLite instead of a full database server. It's a single file on
    disk, ships with Python's standard library (the `sqlite3` module),
    and needs no separate process running — a good fit for a local,
    single-user security tool.

What's in this file:
    - connect(): opens (and creates, if needed) the database file.
    - init_schema(): creates tables if they don't already exist.
    - Database: a small context-manager wrapper so callers can write

          with Database(path) as db:
              db.execute(...)

      and not have to think about opening/closing connections.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from secure.permissions import harden_dir, harden_file

# The schema starts minimal: one general-purpose "events" table, plus
# (as of Phase 2) one table for macOS security posture check results.
# Later, real monitoring features can either write into `events` or
# add their own tables here — that's future work.
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    category    TEXT NOT NULL,
    message     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posture_checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    status      TEXT NOT NULL,
    message     TEXT NOT NULL,
    remediation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    window_minutes INTEGER NOT NULL,
    summary        TEXT NOT NULL,
    details        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mac           TEXT,
    ip            TEXT NOT NULL,
    hostname      TEXT,
    vendor        TEXT,
    friendly_name TEXT,
    known         INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

-- A device with a known MAC is unique by that MAC (its most stable
-- identity); devices without a captured MAC aren't constrained here
-- and are instead deduplicated by IP in application code (see
-- upsert_device() in models.py) since SQLite can't express "unique
-- unless NULL, in which case dedupe some other way" in one index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac
    ON devices(mac) WHERE mac IS NOT NULL;

-- One row per connection observed in a single `secure connections scan`
-- (see secure/connections/) — the full, append-only history. Rows
-- from the same scan share a run_id, same pattern as posture_checks.
-- `id` has been a stable AUTOINCREMENT primary key since this table
-- was first created — it is the durable per-observation identity
-- Phase 14's process_destination anomaly provenance references
-- (source_table='connection_events', source_id=id; see
-- process_destinations' schema comment below for why that table's own
-- id is NOT used for this). The only historical gap was at the
-- application layer: add_connection_events() used to insert this
-- table's rows via one bulk executemany() call, which never surfaced
-- each row's real id back to its caller — fixed by inserting one row
-- at a time (still one commit for the whole batch) and collecting
-- each cursor.lastrowid as it's assigned. Every row this table has
-- ever stored, past or future, has always had a genuine, unique id.
CREATE TABLE IF NOT EXISTS connection_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    proto         TEXT NOT NULL,
    local_addr    TEXT,
    local_port    INTEGER,
    remote_addr   TEXT,
    remote_port   INTEGER,
    state         TEXT,
    pid           INTEGER,
    process_name  TEXT
);

-- One row per distinct remote destination (address+port+protocol)
-- this Mac has ever been observed connecting out to. Unlike
-- connection_events (a full history log), this is deduplicated and
-- updated in place — it's what "flag newly-seen destinations" and
-- "mark known/unknown" key off, the same role `devices` plays for
-- local-network inventory.
CREATE TABLE IF NOT EXISTS remote_endpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_addr   TEXT NOT NULL,
    remote_port   INTEGER NOT NULL,
    proto         TEXT NOT NULL,
    process_name  TEXT,
    known         INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_endpoints_identity
    ON remote_endpoints(remote_addr, remote_port, proto);

-- Phase 14 Stage 4C: a stable identity for one (process, destination)
-- pair, matching secure.baseline.entities.process_destination_key()'s
-- scope exactly — deliberately separate from remote_endpoints above,
-- which is scoped by destination ALONE (an unexpected-outbound-
-- connection tracker unrelated to Phase 14, whose existing "one row
-- per destination regardless of which process" semantics must not
-- change). `process_name` stores the literal string '(unknown)' for
-- unattributed connections rather than NULL, matching
-- process_destination_key()'s own fallback — SQLite's UNIQUE index
-- treats NULL as distinct from NULL, which would silently defeat
-- dedup for every unattributed connection if NULL were used instead.
--
-- This table is an AGGREGATE view only (observation_count/first_seen/
-- last_seen per pair, one row per distinct pair) — same role
-- remote_endpoints plays for destinations alone. Its `id` is NOT used
-- as anomaly provenance (a Stage 4C/4D design that was corrected):
-- one process_destination row can dedupe MANY individual connections
-- across many scans, so its id can't identify which specific
-- connection observation produced a given anomaly. Real provenance
-- (secure/connections/scanner.py) instead references the exact
-- connection_events row via source_table='connection_events',
-- source_id=connection_events.id — connection_events has always had a
-- stable per-row `id` (see below); the only historical gap was that
-- add_connection_events() bulk-inserted with executemany() and never
-- surfaced those ids to its caller. See add_connection_events()'s
-- docstring in secure/storage/models.py for the fix.
CREATE TABLE IF NOT EXISTS process_destinations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name  TEXT NOT NULL,
    remote_addr   TEXT NOT NULL,
    remote_port   INTEGER NOT NULL,
    proto         TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_process_destinations_identity
    ON process_destinations(process_name, remote_addr, remote_port, proto);

-- One row per listening socket observed in a single `secure listening
-- scan` (see secure/listening/) — full, append-only history, same
-- run_id-groups-a-scan pattern as connection_events. Has always had a
-- stable per-row `id`; this is the row anomaly provenance references
-- (source_table='listening_events', source_id=listening_events.id —
-- see secure/listening/scanner.py) for exactly the same reason
-- connection_events.id is process_destination provenance and not
-- process_destinations.id: listening_services (below) dedupes many
-- scans' worth of the same service into one updated-in-place row, so
-- its id can't identify which specific scan observation produced a
-- given anomaly. Phase 14.5 Stage B fixed the same executemany()
-- id-surfacing gap here that connection_events had — see
-- add_listening_events()'s docstring in secure/storage/models.py.
CREATE TABLE IF NOT EXISTS listening_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    proto         TEXT NOT NULL,
    local_addr    TEXT,
    local_port    INTEGER,
    bind_scope    TEXT NOT NULL,
    pid           INTEGER,
    process_name  TEXT
);

-- One row per distinct listening *service*, deduplicated and updated
-- in place — what "alert when a new service begins listening" keys
-- off. Identity is (proto, bind_scope, process_name, identity_port)
-- rather than the raw port number, because most dev-tool listeners
-- (JetBrains, VS Code, Postman, ...) rebind to a different
-- OS-assigned ephemeral port every time they restart; treating every
-- different ephemeral port as a brand-new service would flag nearly
-- every scan as full of "new" services and bury any signal that
-- actually matters. See secure/listening/scanner.py's
-- _identity_port() docstring for exactly how identity_port is chosen.
-- This id is an aggregate/identity reference only (like
-- process_destinations.id and remote_endpoints.id) — never anomaly
-- provenance; see listening_events's schema comment above.
CREATE TABLE IF NOT EXISTS listening_services (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    proto          TEXT NOT NULL,
    bind_scope     TEXT NOT NULL,
    process_name   TEXT NOT NULL,
    identity_port  TEXT NOT NULL,
    local_addr     TEXT,
    local_port     INTEGER,
    known          INTEGER NOT NULL DEFAULT 0,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_listening_services_identity
    ON listening_services(proto, bind_scope, process_name, identity_port);

-- One row per real ARP entry observed in a single `secure arpwatch
-- scan` (see secure/arpwatch/) — full, append-only history, same
-- run_id-groups-a-scan pattern as connection_events/listening_events.
CREATE TABLE IF NOT EXISTS arp_observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    ip          TEXT NOT NULL,
    mac         TEXT NOT NULL,
    hostname    TEXT
);

-- This Mac's current best-known IP -> MAC mapping, one row per IP,
-- updated in place each scan. This is the state "did this IP's MAC
-- change since last time" is compared against — the core signal this
-- phase watches for (see secure/arpwatch/analysis.py).
CREATE TABLE IF NOT EXISTS arp_mappings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL UNIQUE,
    mac         TEXT NOT NULL,
    is_gateway  INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

-- One row per alert raised by an arpwatch scan (a MAC change, a
-- gateway MAC change, or a same-scan IP/MAC conflict) — the
-- reviewable queue `secure arpwatch list`/`mark` work against, same
-- known/unknown pattern as devices/remote_endpoints/listening_services.
CREATE TABLE IF NOT EXISTS arp_alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    ip            TEXT NOT NULL,
    mac           TEXT,
    previous_mac  TEXT,
    message       TEXT NOT NULL,
    known         INTEGER NOT NULL DEFAULT 0
);

-- One row per Wi-Fi status snapshot taken by a `secure wifi scan` (see
-- secure/wifi/) — full, append-only history, same run_id-groups-a-scan
-- pattern as connection_events/listening_events/arp_observations. Only
-- written while actually associated with a network; a scan that finds
-- no Wi-Fi connection writes nothing here.
CREATE TABLE IF NOT EXISTS wifi_observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    ssid        TEXT NOT NULL,
    bssid       TEXT,
    channel     TEXT,
    phy_mode    TEXT,
    security    TEXT,
    rssi        INTEGER,
    noise       INTEGER
);

-- One row per distinct Wi-Fi network this Mac has ever connected to,
-- deduplicated and updated in place — the reviewable entity
-- `secure wifi list`/`mark` work against, same known/unknown pattern
-- as devices/remote_endpoints/listening_services. A first-time network
-- (or a first-time BSSID under an SSID that already has others) is
-- what "warn when joining an unknown network" / "detect unexpected
-- BSSID changes" key off — see secure/wifi/scanner.py.
CREATE TABLE IF NOT EXISTS wifi_networks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid        TEXT NOT NULL,
    bssid       TEXT,
    known       INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

-- A network with a captured BSSID is unique by (ssid, bssid) — the
-- same access point seen again. Networks whose BSSID isn't available
-- (very common on modern macOS without Location Services granted to
-- the calling process — see secure/wifi/status.py) aren't constrained
-- here and are instead deduplicated by ssid alone in application code
-- (see upsert_wifi_network() in models.py) — the same
-- nullable-unique-column pattern devices.mac already uses for devices
-- with no captured MAC.
CREATE UNIQUE INDEX IF NOT EXISTS idx_wifi_networks_identity
    ON wifi_networks(ssid, bssid) WHERE bssid IS NOT NULL;

-- One row per Wi-Fi alert raised by a scan — currently just
-- lookalike/suspicious SSID names (see secure/wifi/scanner.py); weak
-- or open security is a standing condition re-evaluated fresh every
-- scan (like a Phase 2 posture check) rather than a discrete event, so
-- it's printed in scan output but not stored here. `known` defaults to
-- 0 (unreviewed), same pattern as arp_alerts.
CREATE TABLE IF NOT EXISTS wifi_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    ssid        TEXT NOT NULL,
    bssid       TEXT,
    message     TEXT NOT NULL,
    known       INTEGER NOT NULL DEFAULT 0
);

-- One row per Bluetooth device observed in a single `secure bluetooth
-- scan` (see secure/bluetooth/) — full, append-only history, same
-- run_id-groups-a-scan pattern as every other *_observations table.
-- `identifier` is this device's Bluetooth address, normalized to
-- lowercase colon-separated form.
CREATE TABLE IF NOT EXISTS bluetooth_observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    name        TEXT,
    paired      INTEGER NOT NULL DEFAULT 0,
    connected   INTEGER NOT NULL DEFAULT 0,
    rssi        INTEGER
);

-- One row per distinct Bluetooth device this Mac has ever seen,
-- deduplicated and updated in place — the reviewable entity
-- `secure bluetooth list`/`mark` work against, same shape as
-- devices/remote_endpoints/listening_services/wifi_networks, but
-- named `trusted` rather than `known` to match this phase's spec
-- vocabulary ("mark trusted devices"). `times_seen` is how many
-- separate scans have observed this device — what persistent-unknown-
-- device detection keys off (see secure/bluetooth/scanner.py).
CREATE TABLE IF NOT EXISTS bluetooth_devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier  TEXT NOT NULL UNIQUE,
    name        TEXT,
    trusted     INTEGER NOT NULL DEFAULT 0,
    times_seen  INTEGER NOT NULL DEFAULT 0,
    last_rssi   INTEGER,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

-- One row per alert a bluetooth scan raised — currently just
-- "persistently seen nearby while still untrusted" (see
-- secure/bluetooth/scanner.py). A brand-new device is surfaced via a
-- NEW tag in scan output instead (same as devices/remote_endpoints/
-- listening_services/wifi_networks), not a row here. `known` defaults
-- to 0 (unreviewed), same pattern as arp_alerts/wifi_alerts.
CREATE TABLE IF NOT EXISTS bluetooth_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    name        TEXT,
    message     TEXT NOT NULL,
    known       INTEGER NOT NULL DEFAULT 0
);

-- Live BLE discovery (see secure/bluetooth/ble/) — deliberately a
-- SEPARATE identifier space from bluetooth_devices/bluetooth_*, not a
-- merge into it. bluetooth_devices.identifier is a real Bluetooth MAC
-- address, taken from system_profiler's list of devices macOS already
-- has a relationship with (paired/configured/connected). A live BLE
-- scan (via Bleak/CoreBluetooth) instead sees `cb_uuid` — a per-app
-- CoreBluetooth-assigned UUID that is NOT a MAC address and generally
-- cannot be reliably correlated with one; Apple does this deliberately,
-- for privacy. Forcing these two identifier spaces into one table
-- would create false correlations. Keeping them separate lets Secure
-- honestly report "devices seen over BLE" and "devices actually paired
-- with this Mac" as what they are: overlapping but distinct views. See
-- PROJECT_NOTES.md for the full explanation of this limitation.

-- One row per BLE peripheral advertisement observed in a single
-- `secure bluetooth ble scan` — append-only, full history, same
-- run_id-groups-a-scan pattern as bluetooth_observations.
CREATE TABLE IF NOT EXISTS ble_observations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL,
    run_id              TEXT NOT NULL,
    cb_uuid             TEXT NOT NULL,
    name                TEXT,
    rssi                INTEGER,
    service_uuids       TEXT,  -- JSON array of strings
    manufacturer_data   TEXT   -- JSON object: {company_id_hex: payload_hex}
);

-- One row per distinct CoreBluetooth UUID this Mac has ever seen
-- advertising nearby, deduplicated and updated in place — same
-- trusted/times_seen shape as bluetooth_devices, but for the live-BLE
-- identifier space. Read the caveat above (and in PROJECT_NOTES.md)
-- before treating `times_seen`/first_seen/last_seen as a precise count
-- of distinct physical devices: many modern phones rotate their real
-- BLE link-layer address every ~15 minutes for privacy, independent of
-- anything this app can control, so persistence tracking here is a
-- floor, not an exact count.
CREATE TABLE IF NOT EXISTS ble_peripherals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cb_uuid     TEXT NOT NULL UNIQUE,
    name        TEXT,
    trusted     INTEGER NOT NULL DEFAULT 0,
    times_seen  INTEGER NOT NULL DEFAULT 0,
    first_rssi  INTEGER,
    last_rssi   INTEGER,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

-- One row per alert a live BLE scan raised — persistent-unknown
-- peripheral, or a significant RSSI swing. A brand-new peripheral is
-- surfaced via a NEW tag in scan output instead (same pattern as
-- bluetooth_alerts), not a row here. `known` defaults to 0
-- (unreviewed), same pattern as every other *_alerts table.
CREATE TABLE IF NOT EXISTS ble_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cb_uuid     TEXT NOT NULL,
    name        TEXT,
    message     TEXT NOT NULL,
    known       INTEGER NOT NULL DEFAULT 0
);

-- Phase 10: Process and Persistence Monitor (see secure/persistence/).
-- Deliberately does NOT follow the usual "*_observations = full
-- append-only history every scan" pattern for processes specifically —
-- a Mac routinely runs 300-600+ processes and most of them are boring,
-- constantly-churning noise (short-lived helpers, PIDs recycled
-- immediately); logging every single one on every scan would balloon
-- this table for very little signal. Instead, `process_entries` is
-- deduplicated by executable path (the stable identity — PIDs are
-- not), same shape as devices/bluetooth_devices/ble_peripherals, and
-- that dedup IS the history that matters: "have we ever seen this
-- executable run before." Persistence items (LaunchAgents/
-- LaunchDaemons/login items) are far fewer in number and change far
-- less often, so they DO get the usual full-history treatment via
-- `persistence_observations`, same as every other monitoring feature.
CREATE TABLE IF NOT EXISTS process_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    executable_path TEXT NOT NULL UNIQUE,
    process_name    TEXT,
    run_as_user     TEXT,
    signing_status  TEXT,
    known           INTEGER NOT NULL DEFAULT 0,
    times_seen      INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

-- One row per persistence-mechanism entry (LaunchAgent/LaunchDaemon/
-- login item) observed in a single `secure persistence scan` —
-- append-only history, same run_id-groups-a-scan pattern as every
-- other *_observations table. `kind` is one of "launch_agent_user",
-- "launch_agent_global", "launch_daemon", "login_item", or a kind from
-- secure/persistence/extra_locations.py (authorization_plugin, kext, ...). Has always
-- had a stable per-row `id`; this is the row anomaly provenance
-- references (source_table='persistence_observations',
-- source_id=persistence_observations.id — see
-- secure/persistence/scanner.py) rather than persistence_entries.id
-- (below), for exactly the same reason connection_events.id is
-- process_destination provenance and not process_destinations.id:
-- persistence_entries dedupes many scans' worth of the same entry into
-- one updated-in-place row, so its id can't identify which specific
-- scan observation produced a given anomaly. Phase 14.5 Stage B fixed
-- the same executemany() id-surfacing gap here that connection_events
-- and listening_events had — see add_persistence_observations()'s
-- docstring in secure/storage/models.py.
CREATE TABLE IF NOT EXISTS persistence_observations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    label         TEXT,
    path          TEXT,
    program_path  TEXT,
    run_at_load   INTEGER,
    keep_alive    INTEGER
);

-- One row per distinct persistence entry ever seen, deduplicated and
-- updated in place — same known/unknown pattern as
-- devices/remote_endpoints/listening_services/wifi_networks. A
-- LaunchAgent/LaunchDaemon is identified by its plist's own file path
-- (`path`, unique per kind); a login item generally has a resolvable
-- `path` too (via System Events), but when it doesn't, it's
-- deduplicated by (kind, label) instead — same nullable-unique-column
-- fallback pattern wifi_networks already uses for BSSID-less networks.
-- This id is an aggregate/identity reference only (like
-- process_destinations.id and listening_services.id) — never anomaly
-- provenance; see persistence_observations's schema comment above.
CREATE TABLE IF NOT EXISTS persistence_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,
    path            TEXT,
    label           TEXT,
    program_path    TEXT,
    signing_status  TEXT,
    known           INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_persistence_entries_path
    ON persistence_entries(kind, path) WHERE path IS NOT NULL;

-- One row per alert a persistence scan raised: a brand-new persistence
-- entry (any kind), an unusual/unsigned NEW process, or an existing
-- persistence entry's backing executable going from signed to
-- unsigned between scans. `target_type` says what the alert is about
-- ("process", "launch_agent_user", "launch_agent_global",
-- "launch_daemon", "login_item", or an extra_locations.py kind); `identifier` is that target's
-- executable path, plist path, or login item name. `known` defaults
-- to 0 (unreviewed), same pattern as every other *_alerts table.
CREATE TABLE IF NOT EXISTS persistence_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    identifier   TEXT NOT NULL,
    label        TEXT,
    message      TEXT NOT NULL,
    known        INTEGER NOT NULL DEFAULT 0
);

-- Cross-Module Correlation (see secure/correlate/). Unlike every table
-- above, this one is never populated from a subprocess or a live scan
-- of the outside world — it's a derived view OVER the tables above,
-- computed entirely by reading rows already sitting in this database.
-- `secure correlate` gathers "new/flagged" rows across every other
-- monitoring module into a common Signal shape (timestamp, module,
-- severity, identifier), groups ones that happened within --window
-- seconds of each other, and keeps only clusters spanning 2+ DISTINCT
-- modules — the whole point is independent corroboration across
-- unrelated subsystems, not re-flagging what one module's own alerts
-- already cover. `members` holds the full list of contributing
-- signals (module, kind, strength, identifier, source_table, source_id,
-- timestamp) as a JSON array, so every correlation alert stays
-- traceable back to the exact rows that produced it; `explanation` is
-- a plain-English breakdown of how `score` was computed and why it
-- landed at `severity` — see secure/correlate/analysis.py. `fingerprint`
-- is a stable hash of the member rows' (source_table, source_id) pairs,
-- UNIQUE-constrained so re-running `secure correlate` (including as
-- part of `secure run-all`) over overlapping history is idempotent —
-- the same cluster is never alerted on twice.
CREATE TABLE IF NOT EXISTS correlation_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    fingerprint     TEXT NOT NULL UNIQUE,
    window_seconds  REAL NOT NULL,
    cluster_start   TEXT NOT NULL,
    cluster_end     TEXT NOT NULL,
    module_count    INTEGER NOT NULL,
    signal_count    INTEGER NOT NULL,
    score           INTEGER NOT NULL,
    severity        TEXT NOT NULL,
    triggered_by    TEXT,
    context_notes   TEXT,
    explanation     TEXT NOT NULL,
    members         TEXT NOT NULL,
    known           INTEGER NOT NULL DEFAULT 0
);

-- Phase 11: File Integrity Monitoring (see secure/fileintegrity/).
-- Five tables. `file_watch_paths` is the small, user-configurable list
-- of files/folders actually monitored (never full-disk); `sensitivity`
-- is "startup" (LaunchAgents/LaunchDaemons — severity of a change here
-- depends on the REFERENCED EXECUTABLE, not the plist's own signing
-- state, which is meaningless), "self" (Secure's own source/config —
-- see secure/fileintegrity/paths.py's default list), or "normal" (any
-- other user-added folder). `last_scan_status` is "ok" or "incomplete"
-- (set when any part of this watch path could not be enumerated this
-- run — see file_integrity_scans below and scanner.py's walk logic) so
-- a partial-visibility watch path is visible at a glance without
-- digging through scan history.
CREATE TABLE IF NOT EXISTS file_watch_paths (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    path              TEXT NOT NULL UNIQUE,
    recursive         INTEGER NOT NULL DEFAULT 1,
    max_depth         INTEGER,
    sensitivity       TEXT NOT NULL DEFAULT 'normal',
    enabled           INTEGER NOT NULL DEFAULT 1,
    added_at          TEXT NOT NULL,
    last_scan_at      TEXT,
    last_scan_status  TEXT
);

-- Current known state of every monitored file, one row per path,
-- updated in place — the baseline itself, and what each new scan
-- compares against. `hash` is NULL for symlinks (never hashed — see
-- hashing.py) and for files skipped as too-large or unreadable
-- (`skipped_reason` explains why). `dev`/`ino` back the honest
-- rename-detection rule in analysis.py: a shared (dev, ino) between a
-- missing path and a new path is the filesystem's own identity and is
-- trusted; a shared content hash alone is NOT — see
-- file_change_events.rename_confidence. `program_path`/
-- `program_signing_status`/`program_exists` are populated only for
-- LaunchAgent/LaunchDaemon plists (reusing secure/persistence's plist
-- parser and codesign check — see scanner.py) and stay NULL for every
-- other file. A file's very first observation (its watch path's
-- baseline scan) is inserted here directly with `known = 1` — the act
-- of establishing a baseline IS choosing to trust current state as the
-- reference point, matching how snapshot/baseline tools like this are
-- conventionally expected to behave (see PROJECT_NOTES.md). Genuinely
-- new files found on a LATER scan default to `known = 0`, same
-- reviewable-state pattern as every other *_entries/*_devices table.
CREATE TABLE IF NOT EXISTS file_entries (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_path_id            INTEGER NOT NULL,
    path                     TEXT NOT NULL UNIQUE,
    hash                     TEXT,
    size                     INTEGER,
    mtime                    TEXT,
    uid                      INTEGER,
    owner                    TEXT,
    gid                      INTEGER,
    group_name               TEXT,
    mode                     TEXT,
    is_executable            INTEGER NOT NULL DEFAULT 0,
    is_symlink               INTEGER NOT NULL DEFAULT 0,
    symlink_target           TEXT,
    dev                      INTEGER,
    ino                      INTEGER,
    program_path             TEXT,
    program_signing_status   TEXT,
    program_exists           INTEGER,
    known                    INTEGER NOT NULL DEFAULT 0,
    unreadable               INTEGER NOT NULL DEFAULT 0,
    unreadable_reason        TEXT,
    skipped_reason           TEXT,
    first_seen               TEXT NOT NULL,
    last_seen                TEXT NOT NULL,
    last_hashed_at           TEXT
);

-- Full, append-only history of every change a file-integrity scan
-- observed — same run_id-groups-a-scan pattern as every other
-- *_observations/*_events table. `change_type` is one of "baseline"
-- (first-ever observation of this path, no alert), "created",
-- "modified" (hash differs), "metadata_only" (hash unchanged, but
-- owner/group/mode/executable-bit/symlink state differs — see
-- refinement in PROJECT_NOTES.md: this is NOT automatically low
-- severity), "deleted", "renamed" (confirmed via dev+ino identity
-- only — see rename_confidence), or "program_target_changed" (a
-- LaunchAgent/LaunchDaemon's Program/ProgramArguments target changed,
-- recorded as its own event even though the plist's own "modified"
-- event also fires — independent evidence, not a replacement for it).
-- `details` is a JSON object holding the full before/after metadata
-- and a plain-English list of what changed, since a single change can
-- touch several fields at once; see analysis.py's diff_metadata().
CREATE TABLE IF NOT EXISTS file_change_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at         TEXT NOT NULL,
    run_id             TEXT NOT NULL,
    watch_path_id      INTEGER NOT NULL,
    path               TEXT NOT NULL,
    old_path           TEXT,
    change_type        TEXT NOT NULL,
    previous_hash      TEXT,
    new_hash           TEXT,
    rename_confidence  TEXT,
    details            TEXT NOT NULL
);

-- One row per alert a file-integrity scan raised — same known/unknown
-- reviewable-queue pattern as every other *_alerts table.
-- `context_notes` carries a non-erasing annotation such as "occurred
-- during a known Secure Update/reload context" (see
-- apply_self_update_context() in analysis.py) — the alert is still
-- recorded at its (possibly capped) severity, never silently dropped.
CREATE TABLE IF NOT EXISTS file_integrity_alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    run_id         TEXT NOT NULL,
    kind           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    path           TEXT NOT NULL,
    message        TEXT NOT NULL,
    context_notes  TEXT,
    known          INTEGER NOT NULL DEFAULT 0
);

-- One row per `secure fileintegrity scan` run — a forensic/coverage
-- record independent of the change events themselves, so later
-- analysis (including correlation) can distinguish "this scan saw
-- everything" from "this scan had gaps." `watch_paths_attempted`/
-- `_completed`/`_incomplete` are JSON arrays of paths (the incomplete
-- one holds {"path": ..., "reasons": {...}} objects); a watch path
-- landing in `_incomplete` means at least one directory under it could
-- not be enumerated this run (permission error, I/O error, missing
-- mount, etc.) — its previous baseline for anything under the
-- unreadable directory is preserved untouched, never inferred deleted
-- (see scanner.py's walk logic and PROJECT_NOTES.md).
CREATE TABLE IF NOT EXISTS file_integrity_scans (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                      TEXT NOT NULL UNIQUE,
    started_at                  TEXT NOT NULL,
    completed_at                TEXT,
    duration_seconds            REAL,
    watch_paths_attempted       TEXT NOT NULL,
    watch_paths_completed       TEXT NOT NULL,
    watch_paths_incomplete      TEXT NOT NULL,
    files_visited               INTEGER NOT NULL DEFAULT 0,
    files_hashed                INTEGER NOT NULL DEFAULT 0,
    files_skipped_unchanged     INTEGER NOT NULL DEFAULT 0,
    files_skipped_too_large     INTEGER NOT NULL DEFAULT 0,
    files_skipped_excluded      INTEGER NOT NULL DEFAULT 0,
    files_unreadable            INTEGER NOT NULL DEFAULT 0,
    alerts_generated            INTEGER NOT NULL DEFAULT 0
);

-- Product Phase 14: Behavioral Baselining and Anomaly Detection (see
-- secure/baseline/ and docs/BASELINING.md). Nine tables (this one plus
-- baseline_activity, baseline_feature_stats, baseline_time_stats,
-- anomaly_events, baseline_feature_activity, baseline_feature_maturity,
-- baseline_runs, and process_destinations). One row per entity Secure
-- tracks "normal" behavior for — an (entity_type, entity_key) pair,
-- e.g. ("process", "/usr/bin/curl") or ("process_destination",
-- "Syncthing::203.0.113.5:22067/tcp"). entity_key reuses the same
-- identifier vocabulary as secure/correlate/signals.py wherever an
-- entity_type overlaps with an existing correlation module (see
-- secure/baseline/entities.py). All counters here are LIFETIME
-- figures, never reset by drift/rolling-window handling — see
-- baseline_feature_stats for the "current normal" rolling view.
-- `eligible_*` columns count only observations that passed the
-- poisoning-protection rules in secure/baseline/eligibility.py; the
-- plain `observation_count`/`distinct_days_observed` columns count ALL
-- observations regardless of eligibility, kept for visibility/audit.
-- `maturity_state` is one of "no_baseline"/"learning"/"established"/
-- "stale" — see secure/baseline/maturity.py for the exact promotion
-- rules and named, configurable thresholds. `excluded`/`frozen` are
-- user controls (`secure baseline exclude`/`freeze`):
--   - excluded: the entity is skipped entirely by anomaly SCORING, but
--     raw activity is still logged (at weight 0) — history is never
--     deleted just because an entity is excluded.
--   - frozen (Stage 4G, corrected here — this comment previously said
--     a frozen entity's LIFETIME counters keep updating; they do not):
--     record_baseline_observation()/record_feature_maturity_observation()/
--     the feature-stats-update step are all skipped entirely while
--     frozen, so NEITHER this table's lifetime counters NOR
--     baseline_feature_stats/baseline_feature_maturity change at all —
--     "what's normal" stays pinned exactly at freeze time. Raw activity
--     logging and anomaly SCORING (comparisons against the pinned
--     baseline) both continue normally; only the counters that define
--     "current normal" stop advancing. See history.py's
--     record_gap_observation()/record_entity_observation() and
--     engine.py's evaluate_and_record_feature_observation() for the
--     exact `if frozen: ... skip stat-writing` guards.
CREATE TABLE IF NOT EXISTS baseline_entities (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type                   TEXT NOT NULL,
    entity_key                    TEXT NOT NULL,
    maturity_state                TEXT NOT NULL DEFAULT 'no_baseline',
    first_observed_at             TEXT,
    last_observed_at              TEXT,
    first_eligible_observed_at    TEXT,
    last_eligible_observed_at     TEXT,
    observation_count             INTEGER NOT NULL DEFAULT 0,
    distinct_days_observed        INTEGER NOT NULL DEFAULT 0,
    eligible_weight_total         REAL NOT NULL DEFAULT 0,
    eligible_distinct_days        INTEGER NOT NULL DEFAULT 0,
    excluded                      INTEGER NOT NULL DEFAULT 0,
    frozen                        INTEGER NOT NULL DEFAULT 0,
    created_at                    TEXT NOT NULL,
    updated_at                    TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_entities_identity
    ON baseline_entities(entity_type, entity_key);

-- The gap-filling observation log for the two entity types that have
-- no existing append-only history to read from: "inventory" devices
-- (the `devices` table above only stores first_seen/last_seen/known)
-- and "process" executables (`process_entries` above is deliberately
-- deduplicated-only). Every OTHER baseline entity_type (connections,
-- listening, wifi, bluetooth, ble, persistence, file_integrity)
-- already has its own full *_events/*_observations table, and baseline
-- computation reads those directly instead of writing a parallel copy
-- here (see secure/baseline/history.py) — this table exists ONLY to
-- close the two real gaps identified during Phase 14 design review.
-- `eligibility_reason` is one of the six named reasons in
-- secure/baseline/eligibility.py, recorded at write time using only
-- what was known at that moment and never rewritten later (see that
-- module's docstring on why eligibility is forward-only); `weight` is
-- the numeric weight (1.0/0.5/0.0) that reason implies.
CREATE TABLE IF NOT EXISTS baseline_activity (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL,
    run_id              TEXT NOT NULL,
    entity_type         TEXT NOT NULL,
    entity_key          TEXT NOT NULL,
    eligibility_reason  TEXT NOT NULL,
    weight              REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_baseline_activity_entity
    ON baseline_activity(entity_type, entity_key);

-- Summarized "what's normal" lookup for one entity's one feature
-- dimension — e.g. entity_type="process_destination",
-- entity_key="Syncthing::203.0.113.5:22067/tcp",
-- feature_name="destination", feature_value the destination itself.
-- Deliberately summarized, not a raw-event mirror (Phase 14 spec: "do
-- not create tables merely to mirror existing historical tables").
-- `lifetime_*` never decays and backs the OLD-NORMAL narrative;
-- `rolling_*` covers only the trailing ROLLING_WINDOW_DAYS (see
-- secure/baseline/constants.py) and is what CURRENT-NORMAL
-- rarity/recency scoring reads — recomputed from the entity's
-- underlying history (its existing *_events/*_observations table, or
-- baseline_activity for the two gap types) rather than maintained via
-- fragile incremental decrement — see secure/baseline/engine.py.
CREATE TABLE IF NOT EXISTS baseline_feature_stats (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type              TEXT NOT NULL,
    entity_key               TEXT NOT NULL,
    feature_name             TEXT NOT NULL,
    feature_value            TEXT NOT NULL,
    lifetime_weight_total    REAL NOT NULL DEFAULT 0,
    lifetime_distinct_days   INTEGER NOT NULL DEFAULT 0,
    rolling_weight_total     REAL NOT NULL DEFAULT 0,
    rolling_distinct_days    INTEGER NOT NULL DEFAULT 0,
    first_seen               TEXT NOT NULL,
    last_seen                TEXT NOT NULL,
    updated_at                TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_feature_stats_identity
    ON baseline_feature_stats(entity_type, entity_key, feature_name, feature_value);

-- Time-of-day / day-of-week distribution for one entity's eligible
-- activity as a whole (not broken down per feature) — the Phase 14
-- spec's four broad buckets (night/morning/afternoon/evening) plus
-- weekday/weekend, deliberately coarse (see
-- secure/baseline/time_buckets.py). Carries its OWN maturity gate,
-- independent of baseline_entities.maturity_state — see
-- TIME_MIN_OBSERVATIONS/TIME_MIN_DISTINCT_DAYS in constants.py —
-- since an entity's activity can be evenly spread through the day
-- (fast temporal maturity) or lopsided (slow), independent of how
-- much overall history exists.
CREATE TABLE IF NOT EXISTS baseline_time_stats (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type             TEXT NOT NULL,
    entity_key              TEXT NOT NULL,
    night_weight            REAL NOT NULL DEFAULT 0,
    morning_weight          REAL NOT NULL DEFAULT 0,
    afternoon_weight        REAL NOT NULL DEFAULT 0,
    evening_weight          REAL NOT NULL DEFAULT 0,
    weekday_weight          REAL NOT NULL DEFAULT 0,
    weekend_weight          REAL NOT NULL DEFAULT 0,
    distinct_days_observed  INTEGER NOT NULL DEFAULT 0,
    total_weight            REAL NOT NULL DEFAULT 0,
    updated_at               TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_time_stats_identity
    ON baseline_time_stats(entity_type, entity_key);

-- One row per anomaly finding secure/baseline's scoring engine
-- produced (see secure/baseline/scoring.py + engine.py) — never a
-- second detection engine: every field here is derived from history
-- already stored elsewhere. `severity` is deliberately NOT a column
-- here — an anomaly never overrides or replaces the severity of
-- whatever it's describing (see secure/explain/baseline_explainer.py,
-- which looks up the linked alert's real severity via
-- source_table/source_id when one exists, per Phase 14 approval:
-- "do not replace existing severity with anomaly score").
-- `score_breakdown` is a JSON object of {component_name: points}, so
-- every point in `anomaly_score` traces back to a named, reproducible
-- rule rather than a bare number. `maturity_state_at_time`/
-- `eligible_weight_total_at_time`/`eligible_distinct_days_at_time` are
-- a COPY of the entity's baseline_entities state at the moment of this
-- evaluation (not a live join), so a later change to the entity's
-- maturity never rewrites the story an old anomaly_events row tells.
CREATE TABLE IF NOT EXISTS anomaly_events (
    id                              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                      TEXT NOT NULL,
    run_id                          TEXT NOT NULL,
    entity_type                     TEXT NOT NULL,
    entity_key                      TEXT NOT NULL,
    feature_name                    TEXT NOT NULL,
    observed_value                  TEXT,
    observed_at                     TEXT NOT NULL,
    expected_summary                TEXT NOT NULL,
    score_breakdown                 TEXT NOT NULL,
    anomaly_score                   INTEGER NOT NULL,
    anomaly_tier                    TEXT NOT NULL,
    maturity_state_at_time          TEXT NOT NULL,
    eligible_weight_total_at_time   REAL NOT NULL,
    eligible_distinct_days_at_time  INTEGER NOT NULL,
    source_table                    TEXT,
    source_id                       INTEGER,
    known                           INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_entity
    ON anomaly_events(entity_type, entity_key);

-- Stage 4 idempotence guarantee: (run_id, entity_type, entity_key,
-- feature_name) is UNIQUE. One run_id is one scan pass for one
-- module; re-evaluating the exact same pass's same entity/feature (a
-- defensive retry, a re-run triggered without any new underlying
-- observation) must never create a second row for it — see
-- secure/baseline/engine.py's maybe_record_anomaly_event(), which
-- checks-then-inserts rather than relying on a raw INSERT failing. A
-- genuinely new scan always mints a new run_id, so real day-over-day
-- anomalies for the same entity/feature are never deduplicated away.
CREATE UNIQUE INDEX IF NOT EXISTS idx_anomaly_events_dedup
    ON anomaly_events(run_id, entity_type, entity_key, feature_name);

-- One row per baseline-engine maintenance/update pass — mirrors
-- file_integrity_scans' role exactly: a forensic/performance record
-- independent of the anomaly findings themselves.
-- `comparisons_skipped_insufficient_history` counts entities evaluated
-- but not scored because their maturity_state was NO_BASELINE at the
-- time; `entities_skipped_cap` counts entities that could not be
-- created because their entity_type's cap (see ENTITY_CAPS in
-- secure/baseline/constants.py) was already reached — this must stay
-- visible, never a silent stop (Phase 14 approval item 5).
-- Append-only raw history for feature dimensions that have NO
-- existing per-scan log anywhere else in this database — unlike
-- baseline_activity (which fills the gap for two whole ENTITY types),
-- this fills the gap for three specific FEATURE dimensions whose
-- parent entity/table already has other history, but this one
-- attribute's past values were never recorded: process/persistence
-- signing_status (process_entries only computes it once, at
-- first-seen; persistence_entries overwrites it in place every scan
-- with no log; see their schema comments above), listening bind_scope
-- (listening_events never stored the classified scope, only the raw
-- local_addr), and Wi-Fi security type (wifi_observations stores it,
-- actually — but see PROJECT_NOTES.md/docs/BASELINING.md: wifi
-- security is included here for a uniform three-feature rollout
-- rather than a special-cased fourth read path). ZERO BACKFILL: the
-- first row here is the first real observation logged after Phase 14
-- shipped — nothing is ever fabricated from an entity's pre-existing
-- first_seen/last_seen. `eligible`/`eligibility_reason`/`weight` are
-- the same six-reason vocabulary as baseline_activity (see
-- secure/baseline/eligibility.py) — reused as-is, not a second
-- eligibility system. A feature_value of NULL means the sensor
-- genuinely could not determine a value this scan (e.g. Wi-Fi security
-- enrichment failed, or codesign itself never ran) — always logged
-- with eligibility_reason="partial_sensor_data"/weight=0, NEVER folded
-- in as if it were an ordinary observed category (Phase 14 extension
-- approval item 6).
CREATE TABLE IF NOT EXISTS baseline_feature_activity (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL,
    run_id              TEXT NOT NULL,
    entity_type         TEXT NOT NULL,
    entity_key          TEXT NOT NULL,
    feature_name        TEXT NOT NULL,
    feature_value       TEXT,
    observed_at         TEXT NOT NULL,
    eligible            INTEGER NOT NULL,
    eligibility_reason  TEXT NOT NULL,
    weight              REAL NOT NULL,
    source_table        TEXT,
    source_id           INTEGER
);

CREATE INDEX IF NOT EXISTS idx_baseline_feature_activity_entity
    ON baseline_feature_activity(entity_type, entity_key, feature_name);

-- Maturity state for one FEATURE dimension of one entity — kept
-- deliberately separate from baseline_entities.maturity_state (Phase
-- 14 extension approval item 2: "a process may have an ESTABLISHED
-- entity baseline while its signing_status feature baseline is still
-- LEARNING" — mature entity history must never make a newly
-- introduced feature dimension look mature by association). Computed
-- by the exact same secure/baseline/maturity.compute_maturity() pure
-- function used for baseline_entities, just fed this row's own
-- eligible_weight_total/eligible_distinct_days/span instead of the
-- entity's — one state machine, two independent scopes.
CREATE TABLE IF NOT EXISTS baseline_feature_maturity (
    id                           INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type                  TEXT NOT NULL,
    entity_key                   TEXT NOT NULL,
    feature_name                 TEXT NOT NULL,
    maturity_state                TEXT NOT NULL DEFAULT 'no_baseline',
    first_observed_at            TEXT,
    last_observed_at             TEXT,
    first_eligible_observed_at   TEXT,
    last_eligible_observed_at    TEXT,
    observation_count            INTEGER NOT NULL DEFAULT 0,
    eligible_weight_total        REAL NOT NULL DEFAULT 0,
    eligible_distinct_days       INTEGER NOT NULL DEFAULT 0,
    updated_at                   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_feature_maturity_identity
    ON baseline_feature_maturity(entity_type, entity_key, feature_name);

-- One row per baseline/anomaly evaluation pass for one module's scan
-- (run_id matches the SAME run_id that scanner already generated for
-- its own scan — e.g. wifi/scanner.py's baseline pass and its Wi-Fi
-- scan share one run_id, no second id is minted). Stage 4 (approval
-- item 2/12) extends Stage 1's original five counters with enough
-- detail that a PARTIAL pass can never look identical to a CLEAN one:
--   features_evaluated/features_updated  — feature-dimension calls
--       attempted vs. ones that actually produced an updated stat
--       (entities_evaluated/entities_updated keep their original
--       Stage 1 meaning: gap-filled ENTITY-level observations, for
--       "inventory"/"process").
--   comparisons_skipped_insufficient_history — kept from Stage 1:
--       observations that were eligible but produced no breakdown at
--       all (ineligible-weight-zero OR unavailable sensor combined).
--   incomplete_inputs — the narrower subset of the above caused
--       specifically by a sensor/parser that could not determine a
--       value this pass (feature_value/partial_sensor_data), as
--       opposed to poisoning-protection eligibility rules doing their
--       job correctly — this is what actually degrades a pass from
--       "clean" to "partial" (approval item 3/12).
--   errors_count/error_summary — unexpected exceptions caught around
--       one item's evaluation, logged and skipped rather than aborting
--       the whole pass; error_summary is a small bounded JSON array of
--       short messages, not a full traceback dump.
--   status — 'success' | 'partial' | 'failed', computed once at the
--       end of the pass (see secure/baseline/engine.py's
--       finalize_baseline_run()) so a caller never has to re-derive it
--       from the raw counters by hand.
CREATE TABLE IF NOT EXISTS baseline_runs (
    id                                        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                                    TEXT NOT NULL UNIQUE,
    started_at                                TEXT NOT NULL,
    completed_at                              TEXT,
    duration_seconds                          REAL,
    entities_evaluated                        INTEGER NOT NULL DEFAULT 0,
    entities_updated                          INTEGER NOT NULL DEFAULT 0,
    features_evaluated                        INTEGER NOT NULL DEFAULT 0,
    features_updated                          INTEGER NOT NULL DEFAULT 0,
    anomalies_generated                       INTEGER NOT NULL DEFAULT 0,
    comparisons_skipped_insufficient_history  INTEGER NOT NULL DEFAULT 0,
    entities_skipped_cap                      INTEGER NOT NULL DEFAULT 0,
    incomplete_inputs                         INTEGER NOT NULL DEFAULT 0,
    errors_count                              INTEGER NOT NULL DEFAULT 0,
    error_summary                             TEXT,
    status                                    TEXT NOT NULL DEFAULT 'success'
);

CREATE INDEX IF NOT EXISTS idx_baseline_runs_started_at
    ON baseline_runs(started_at);

-- Phase 15 — External Telemetry Foundation. One row per collection
-- attempt for one external integration (osquery today, others later —
-- see secure/integrations/base.py). `status` is always exactly one of
-- IntegrationHealth's four values ('ok' | 'degraded' | 'unavailable' |
-- 'error') — never a silent success on failure, per the phase's
-- explicit instruction. `observations_collected`/`alerts_generated` let
-- `secure integrations osquery status` show a real count without a
-- second query over integration_observations/integration_alerts.
CREATE TABLE IF NOT EXISTS integration_runs (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                   TEXT NOT NULL UNIQUE,
    integration              TEXT NOT NULL,
    started_at               TEXT NOT NULL,
    completed_at             TEXT,
    status                   TEXT NOT NULL,
    detail                   TEXT,
    tool_version             TEXT,
    observations_collected   INTEGER NOT NULL DEFAULT 0,
    alerts_generated         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_integration_runs_integration
    ON integration_runs(integration, started_at);

-- One row per ExternalObservation an integration collected — the exact
-- raw normalized fact, with its own exact source_query provenance (see
-- secure/integrations/base.py's ExternalObservation docstring). This is
-- the append-only history table the same "exact observation, not a
-- deduped identity row" discipline Phase 14.5 Stage B established for
-- connections/wifi/listening/persistence applies to here: a later
-- anomaly or cross-check finding referencing one of these rows should
-- point at the one specific scan's `id`, never something resolved after
-- the fact from a deduplicated table.
CREATE TABLE IF NOT EXISTS integration_observations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    run_id         TEXT NOT NULL,
    integration    TEXT NOT NULL,
    kind           TEXT NOT NULL,
    identity_key   TEXT NOT NULL,
    fields_json    TEXT NOT NULL,
    source_query   TEXT NOT NULL,
    collected_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_integration_observations_run
    ON integration_observations(run_id);
CREATE INDEX IF NOT EXISTS idx_integration_observations_kind
    ON integration_observations(integration, kind);

-- Cross-check discrepancies only — see secure/integrations/osquery/
-- crosscheck.py's module docstring for why a native/osquery MATCH never
-- reaches this table at all (that's the structural fix for "don't let
-- the same observation count as independent corroboration twice", not
-- a filter applied after the fact). `discrepancy` is 'osquery_only' or
-- 'native_only'; `severity` is 'high' or 'low' per crosscheck.py's
-- asymmetric convention. `known` follows the same unreviewed/reviewed
-- convention as every other *_alerts table in this app.
-- `source_observation_id` references the exact integration_observations
-- row that produced an 'osquery_only' discrepancy (the same "exact raw
-- observation, not something reconstructed later" discipline as every
-- other provenance link in this schema) — NULL for a 'native_only'
-- discrepancy, which by definition has no corresponding osquery
-- observation to point at.
CREATE TABLE IF NOT EXISTS integration_alerts (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at              TEXT NOT NULL,
    run_id                  TEXT NOT NULL,
    integration             TEXT NOT NULL,
    kind                    TEXT NOT NULL,
    discrepancy             TEXT NOT NULL,
    severity                TEXT NOT NULL,
    identity_key            TEXT NOT NULL,
    label                   TEXT,
    message                 TEXT NOT NULL,
    source_observation_id   INTEGER,
    known                   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_integration_alerts_run
    ON integration_alerts(run_id);

-- Phase 20: threat-intelligence enrichment lookups — see
-- secure/threatintel/. One row per provider lookup PERFORMED (never
-- fabricated): a cache/history entry, not a verdict Secure itself
-- computed. `indicator_type` is 'ip'/'domain'/'hash';
-- `indicator_value` is the exact string looked up (normalized —
-- lowercased for domain/hash, canonical form for ip). `provider` is
-- the short stable provider name (e.g. "local_feed", "virustotal").
-- `status` is one of secure/threatintel/base.py's LookupStatus
-- constants (ok/not_found/unavailable/error/rate_limited/
-- skipped_private) — 'not_found' is NEVER collapsed into a "clean"
-- verdict; they are stored as clearly distinct facts (Phase 20's own
-- explicit "never silently turn 'not found' into safe" instruction).
-- `verdict` (nullable) is Secure's own translated bucket
-- (unknown/clean/suspicious/malicious) from the provider's raw
-- response — only meaningful when status='ok'. `score`/`score_meaning`
-- carry the provider's own raw reputation number and a plain-language
-- note of what it means for THAT provider (scores are never compared
-- across providers). `categories_json` is a JSON list of provider tags
-- (e.g. ["malware", "c2"]). `raw_response_json` is the provenance: the
-- (possibly truncated) normalized provider response actually received,
-- never fabricated. `source_query` records exactly what was requested
-- (a URL/method or file path — never an API key or other secret).
-- `expires_at` is this lookup's own TTL-based cache expiration (ISO
-- 8601); a fresh re-query is only made once now() > expires_at.
CREATE TABLE IF NOT EXISTS threat_intel_lookups (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL,
    indicator_type      TEXT NOT NULL,
    indicator_value     TEXT NOT NULL,
    provider            TEXT NOT NULL,
    queried_at          TEXT NOT NULL,
    status              TEXT NOT NULL,
    verdict             TEXT,
    score               REAL,
    score_meaning       TEXT,
    categories_json     TEXT,
    raw_response_json   TEXT,
    source_query        TEXT NOT NULL,
    expires_at          TEXT,
    detail              TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_lookups_indicator
    ON threat_intel_lookups(indicator_type, indicator_value, provider);
CREATE INDEX IF NOT EXISTS idx_threat_intel_lookups_expires
    ON threat_intel_lookups(expires_at);

-- Phase 21: the unified evidence, lineage, and deduplication model —
-- see secure/evidence/. Purely additive: this table does not replace,
-- rename, or restructure ANY existing table, and no existing row is
-- ever rewritten because of this table's existence. It exists to give
-- a real, queryable home to a relationship that today is either
-- invisible (osquery's crosscheck.py: a native/osquery MATCH produces
-- literally nothing) or recorded only as free-text fields on the
-- dependent row itself (Zeek's dedup_status/dedup_detail columns,
-- Suricata's alert message string) — never as a link a caller could
-- query from the OTHER side, and never with one shared vocabulary
-- across all three.
--
-- One row per lineage/dedup FACT connecting two rows already sitting
-- elsewhere in this database. `from_source_table`/`from_source_id` is
-- the "later"/"dependent" side (e.g. the Zeek conn.log observation, or
-- the Suricata alert); `to_source_table`/`to_source_id` is the
-- "matched"/"explaining" side (e.g. the connection_events row this
-- matched, or the connection_events row an alert's process context was
-- derived from) — both are exact row ids into their own real table,
-- the same "exact observation, never a deduplicated identity row"
-- discipline every other provenance link in this schema already
-- follows (see anomaly_events.source_table/source_id above).
-- `relationship` is one of secure/evidence/model.py's three
-- RELATIONSHIP_* constants (duplicate_observation /
-- same_event_confirmation / derived_evidence) — deliberately NOT four:
-- "genuinely independent corroboration" (the fourth concept Phase 21
-- asks to distinguish) is represented structurally by the ABSENCE of
-- any row here connecting two pieces of evidence, not a fourth stored
-- value, the same "make the invariant structural" discipline Phase
-- 20's ProviderLookupResult used for "not found is not safe."
-- `match_basis` is a short free-text label for HOW the match was
-- established (e.g. "identity+timing") — intentionally not a closed
-- vocabulary, so a future matching technique never needs a schema
-- change to be described. `time_delta_seconds` is populated only for
-- timing-based matches. `detail` is the same always-populated,
-- human-readable discipline every other table's own detail/message
-- column already uses. `created_by` names the exact mechanism that
-- wrote this row (e.g. "zeek_dedup", "suricata_correlate",
-- "osquery_crosscheck") — a link is never anonymous about its own
-- origin. This table deliberately carries NO severity/confidence/
-- anomaly/trust column of its own, per Phase 21's own explicit
-- instruction not to collapse those concepts into the evidence model —
-- each referenced row's own severity/confidence/known state stays
-- entirely on that row's own table, untouched.
--
-- CORRECTION (still within Phase 21, before this table was ever
-- reported as finished): the original design below keyed idempotence
-- off the exact (from_source_table, from_source_id, ...) row ids. That
-- works for Zeek/Suricata, whose log-cursor/timestamp-cursor mechanism
-- means a rescan produces literally zero new observations for an
-- already-classified match — but osquery has no such cursor (see
-- secure/integrations/osquery/scanner.py's own docstring): every scan
-- re-runs live queries and inserts a genuinely NEW integration_
-- observations row even when the underlying real-world fact (a port
-- still listening, a persistence entry still present) hasn't changed at
-- all. Keying idempotence off that ever-changing row id meant a fresh
-- evidence_links row was written on EVERY osquery scan for one ongoing,
-- unchanged relationship — confirmed empirically by a test written to
-- assert idempotence, which failed on first run.
--
-- The fix distinguishes two different questions this table was
-- conflating: "the sensor observed this again at time T"
-- (integration_observations — untouched, still append-only, still logs
-- every single scan; repeated observations remain useful historical
-- evidence and are NEVER suppressed) versus "these two pieces/entities
-- are related" (evidence_links — now keyed off a LOGICAL identity that
-- stays stable across repeat observations of the same fact, not the
-- ephemeral row id of whichever observation happened to trigger it
-- this time).
--
-- `from_fingerprint`/`to_fingerprint` are that logical identity: see
-- secure/evidence/fingerprint.py's logical_ref_identity(). When a
-- caller supplies an ObservationRef.logical_key (osquery does, built
-- from its own stable identity_key — see crosscheck.py's Match; Zeek/
-- Suricata do NOT, so their fingerprint falls back to source_id exactly
-- as before, meaning their already-idempotent behavior is completely
-- unchanged by this correction), the fingerprint is (source_table,
-- logical_key) rather than (source_table, source_id) — durable across
-- however many times the same real fact gets re-observed.
--
-- Idempotence: (from_fingerprint, to_fingerprint, relationship) is now
-- UNIQUE (replacing the old raw-id unique index below). A repeat
-- confirmation of an already-known logical relationship does NOT insert
-- a second evidence_links row — instead secure/evidence/record.py's
-- record_link() UPDATEs `last_seen`/`times_seen`/`from_source_id`
-- (which now means "the most recent confirming observation's row id")
-- in place, while `first_source_id` (new) and `first_seen`/`created_at`
-- are preserved exactly as first written, never overwritten. Every
-- individual confirmation — including every osquery scan pass, however
-- many there are — still gets its own exact-provenance row in the new
-- evidence_link_observations table below, so no per-scan history is
-- lost even though evidence_links itself now represents the
-- RELATIONSHIP, not the scan.
CREATE TABLE IF NOT EXISTS evidence_links (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL,
    from_source_table   TEXT NOT NULL,
    from_source_id      INTEGER NOT NULL,
    first_source_id     INTEGER NOT NULL,
    from_fingerprint    TEXT NOT NULL,
    to_source_table     TEXT NOT NULL,
    to_source_id        INTEGER NOT NULL,
    to_fingerprint      TEXT NOT NULL,
    relationship        TEXT NOT NULL,
    match_basis         TEXT NOT NULL,
    time_delta_seconds  REAL,
    detail              TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    times_seen          INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_evidence_links_from
    ON evidence_links(from_source_table, from_source_id);
CREATE INDEX IF NOT EXISTS idx_evidence_links_to
    ON evidence_links(to_source_table, to_source_id);
-- NOTE: the fingerprint-based unique index (superseding the old
-- raw-id-only idx_evidence_links_dedup) is deliberately NOT created
-- here. On a database that already has an evidence_links table from
-- before this correction, `from_fingerprint` doesn't exist as a column
-- yet at the point this script runs — CREATE TABLE IF NOT EXISTS above
-- is a no-op against an existing table, so the column only appears once
-- _ensure_column() (below, in init_schema()) has run. Creating the
-- index against a column that may not exist yet would break every
-- existing database on upgrade. See init_schema()'s own
-- _ensure_evidence_links_dedup_index() call, run AFTER the column
-- migrations, for where this index actually gets (re)created.

-- Append-only exact provenance for every individual confirmation of one
-- evidence_links relationship — one row per record_link() call, whether
-- that call created a brand-new logical link or touched an existing
-- one. This is what preserves per-scan history (test 6: "repeated scans
-- do not inflate future correlation as independent evidence" — the
-- CORRELATION-visible fact stays one evidence_links row; the raw
-- per-scan detail lives only here, one level down, for anyone who
-- wants it) without pretending each repeat observation is itself a new
-- relationship.
CREATE TABLE IF NOT EXISTS evidence_link_observations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_link_id   INTEGER NOT NULL,
    from_source_table  TEXT NOT NULL,
    from_source_id     INTEGER NOT NULL,
    observed_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_link_observations_link
    ON evidence_link_observations(evidence_link_id);

-- Phase 22: provenance-aware behavioral correlation (secure/correlate/
-- chains.py). A SEPARATE, parallel kind of correlation finding from
-- `correlation_alerts` above — that table and secure/correlate/
-- analysis.py's own temporal-clustering model are completely untouched
-- by this phase; this table exists alongside it, never replacing it
-- (see docs/EVIDENCE.md's Phase 22 section for why "add alongside,
-- don't replace" was the approved design).
--
-- One row per scored chain: a walk over evidence_links starting from
-- one row (`start_source_table`/`start_source_id`), collapsed into
-- independent "confirmation groups" (duplicate_observation/
-- same_event_confirmation links merge nodes that are the SAME
-- real-world fact observed more than once — see chains.py's own
-- module docstring) before anything is counted, so repeated
-- observations of one fact can never inflate corroboration.
-- `raw_observation_count` is every node walked, duplicates included;
-- `independent_fact_count` is the count AFTER collapsing — the number
-- that actually drives scoring. `meaningful_relationship_count` counts
-- derived_evidence links that cross two independent facts from
-- DIFFERENT modules — the "file created -> YARA finding -> process
-- execution -> ..." chain shape, backed by real evidence_links rows,
-- not a hardcoded module-pair heuristic. `concentration` (0..1) is the
-- largest single module's share of independent facts; `confidence`/
-- `uncertainty_notes` reuse secure/explain/vocab.py's existing
-- CONFIRMED/LIKELY/UNCERTAIN/INSUFFICIENT_EVIDENCE axis (a separate
-- axis from severity, same discipline as every other explainer in this
-- app). `benign_context_notes` reuses secure/correlate/context.py's
-- real boot-time detection. `severity` uses the exact same 5-tier
-- vocabulary and score thresholds as correlation_alerts.severity
-- (secure/correlate/analysis.py's severity_for_score(), imported
-- directly, not reimplemented) — "critical" means the same thing in
-- both tables. `members` is every node visited (JSON array of
-- {source_table, source_id, module, source, group_id}); `edges` is
-- every evidence_links row traversed (JSON array of {relationship,
-- from_source_table, from_source_id, to_source_table, to_source_id,
-- match_basis, evidence_link_id}) — so a chain alert stays traceable
-- back to the exact rows and links that produced it, the same
-- discipline correlation_alerts.members already established.
-- `fingerprint` (a stable hash over every node's exact identity, via
-- secure/evidence/fingerprint.py's existing stable_fingerprint()) is
-- UNIQUE, so re-scoring overlapping history is idempotent — the same
-- chain is never alerted on twice.
CREATE TABLE IF NOT EXISTS correlation_chain_alerts (
    id                              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at                      TEXT NOT NULL,
    run_id                          TEXT NOT NULL,
    fingerprint                     TEXT NOT NULL UNIQUE,
    start_source_table              TEXT NOT NULL,
    start_source_id                 INTEGER NOT NULL,
    raw_observation_count           INTEGER NOT NULL,
    independent_fact_count          INTEGER NOT NULL,
    module_count                    INTEGER NOT NULL,
    source_count                    INTEGER NOT NULL,
    meaningful_relationship_count   INTEGER NOT NULL,
    concentration                   REAL NOT NULL,
    raw_score                       INTEGER NOT NULL,
    score                           INTEGER NOT NULL,
    severity                        TEXT NOT NULL,
    confidence                      TEXT NOT NULL,
    uncertainty_notes               TEXT NOT NULL,
    benign_context_notes            TEXT,
    explanation                     TEXT NOT NULL,
    members                         TEXT NOT NULL,
    edges                           TEXT NOT NULL,
    known                           INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_correlation_chain_alerts_run
    ON correlation_chain_alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_correlation_chain_alerts_start
    ON correlation_chain_alerts(start_source_table, start_source_id);

-- Phase 24: Targeted DFIR Integration (secure/dfir/). Velociraptor is
-- Secure's specialist forensic collection engine, invoked narrowly and
-- only on explicit human approval — never a general framework Secure
-- reimplements, and never triggered automatically by a scan or by
-- run-all. Two tables, purely additive, touching nothing that exists:
--
-- `forensic_collections` — one row per collection ATTEMPT, whether it
-- succeeded or not. The "user-approved collection" step from the
-- instruction's own pipeline (finding/investigation -> user-approved
-- collection -> Velociraptor artifact/result -> normalized forensic
-- evidence -> Secure investigation) is represented structurally, not as
-- a separate request/approval row: per explicit approval, the single
-- act of an operator running `secure dfir collect` with an exact
-- artifact name, parameters, and `reason` IS the approval — the same
-- "one deliberate CLI command is the whole trigger, nothing fires on
-- its own" discipline `secure threatintel lookup` (Phase 20) and
-- `secure correlate chains run` (Phase 22) already established, not a
-- new ceremony invented for this phase alone. `artifact_name` and
-- `parameters_json` are the exact request as given (an allowlist check
-- against config.py's `dfir_artifact_allowlist` happens in
-- secure/dfir/, BEFORE a row here is ever written for a rejected
-- artifact — a refused request leaves no row, it simply never
-- happened); `reason` is the operator's own stated justification, never
-- inferred. `entity_type`/`entity_key` is the EntityRef (Phase 23) this
-- collection is ABOUT; `source_table`/`source_id` is the specific
-- finding that motivated it, nullable for an operator-initiated
-- collection with no single triggering alert. `status` is exactly one
-- of secure/integrations/base.py's own STATUS_OK/DEGRADED/UNAVAILABLE/
-- ERROR constants, reused directly rather than a second vocabulary —
-- per the instruction's own "treat forensic collection failure as
-- unavailable, not exculpatory evidence," UNAVAILABLE/ERROR here must
-- never be read anywhere as "collected, found nothing." `tool_version`
-- is Velociraptor's own version string when discoverable, independent
-- of anything about Secure's own code. `evidence_item_count` is a
-- denormalized count purely for cheap listing — the real rows are
-- `forensic_evidence_items` below, keyed by `collection_id`.
CREATE TABLE IF NOT EXISTS forensic_collections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT NOT NULL,
    requested_at        TEXT NOT NULL,
    started_at          TEXT,
    completed_at        TEXT,
    artifact_name       TEXT NOT NULL,
    parameters_json     TEXT NOT NULL,
    reason              TEXT NOT NULL,
    entity_type         TEXT NOT NULL,
    entity_key          TEXT NOT NULL,
    source_table        TEXT,
    source_id           INTEGER,
    status              TEXT NOT NULL,
    detail              TEXT NOT NULL,
    tool_version        TEXT,
    evidence_item_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_forensic_collections_entity
    ON forensic_collections(entity_type, entity_key);
CREATE INDEX IF NOT EXISTS idx_forensic_collections_source
    ON forensic_collections(source_table, source_id);

-- One row per NORMALIZED fact extracted from one collection's raw
-- result rows — the same "reshape into a common shape, never
-- interpret" discipline secure/integrations/base.py's
-- ExternalObservation already established for osquery/YARA-X/Sigma,
-- applied here to Velociraptor's own arbitrary-per-artifact VQL result
-- columns. `collection_id` is the exact forensic_collections row this
-- came from (never a deduplicated identity row — same "exact
-- observation" discipline as integration_observations.run_id linkage).
-- `kind` is the artifact_name this row came from (namespacing, same as
-- ExternalObservation.kind); `fields_json` is the raw result row,
-- reshaped only insofar as it's already valid JSON, never trimmed or
-- reinterpreted. `raw_row_index` is this row's own position within its
-- collection's result set — exact provenance back to one specific
-- output row, not just "somewhere in this collection."
CREATE TABLE IF NOT EXISTS forensic_evidence_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT NOT NULL,
    collection_id   INTEGER NOT NULL,
    kind            TEXT NOT NULL,
    raw_row_index   INTEGER NOT NULL,
    fields_json     TEXT NOT NULL,
    collected_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forensic_evidence_items_collection
    ON forensic_evidence_items(collection_id);

-- Phase 25: Detection Engineering Workbench (secure/detect/). A
-- coherent lifecycle for the detection rules Secure already evaluates
-- or observes across four families -- Sigma, YARA-X, Suricata, and
-- Secure's own correlation engines -- WITHOUT inventing a fifth,
-- universal rule language. Each family keeps its own native format,
-- loader, and evaluator (secure/integrations/sigma/, .../yarax/,
-- .../suricata/, secure/correlate/); these two tables are purely a
-- CATALOG layered on top, tracking identity/version/enabled-state/
-- telemetry-requirements/validation for whatever each family's own
-- existing loader already knows how to discover -- never re-storing
-- rule CONTENT (a Sigma condition, a YARA pattern, a Suricata
-- signature body) here.
--
-- `family` is one of "sigma"/"yarax"/"suricata"/"correlate".
-- `rule_key` is that family's own natural identity string, chosen to
-- match the actual granularity each family can toggle/version at
-- today (see docs/DETECTION_ENGINEERING.md for the full reasoning):
-- a Sigma rule's own `id` field; a YARA-X RULESET FILE's stem (not an
-- individual named rule within it -- that's the only granularity
-- anything in this codebase can already compile/enable/version at,
-- per explicit approval); a Suricata signature's "gid:signature_id"
-- (only ever discovered AFTER it has fired at least once via EVE JSON
-- -- Secure never loads Suricata's own rule files, so this table can
-- never claim to catalog signatures that haven't fired yet); or one
-- of exactly two hand-registered static identifiers for Secure's own
-- correlation engines ("temporal_clustering", "chain_scoring") --
-- always present regardless of scan history, since they're Secure's
-- own code, not external/user-supplied content. UNIQUE(family,
-- rule_key) is this table's own identity -- sync/discovery always
-- upserts by this pair, never inserts a duplicate.
--
-- `enabled` is REAL enforcement for sigma/yarax (per explicit
-- approval): secure/integrations/sigma/scanner.py and .../yarax/
-- scanner.py consult this table and skip a disabled rule/ruleset
-- before it is ever evaluated -- default TRUE, so with nothing
-- disabled, scan output is unchanged from before this phase existed.
-- For suricata/correlate, `enabled` is TRACKING-ONLY (Secure doesn't
-- control Suricata's own engine at all, and disabling a whole
-- correlation algorithm is a separate, bigger decision than this
-- phase's own scope) -- never consulted by any scanner for those two
-- families; this asymmetry is documented, not hidden.
--
-- `required_telemetry` and `capability_status`/`capability_reason`
-- are a CACHE of the family's own existing capability/availability
-- check (Sigma's check_capability(), YARA-X/Suricata's
-- check_availability()) as of the last `secure detect sync` --
-- `secure detect show` always re-checks live rather than trusting a
-- stale cache for anything the operator is actually looking at.
--
-- `validation_status`/`last_tested_at` are set ONLY by
-- `secure detect test` (secure/detect/validate.py) running this
-- rule's own deterministic benign+suspicious fixtures through that
-- family's OWN existing evaluator -- never inferred from a real scan
-- match, and never defaulted to anything but "unvalidated" for a
-- rule nobody has explicitly tested yet (never fabricated as
-- "passed").
--
-- `false_positive_notes` is free text, entirely operator-authored via
-- `secure detect annotate` -- Secure itself never writes to this
-- column.
CREATE TABLE IF NOT EXISTS detection_rules (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    family                TEXT NOT NULL,
    rule_key              TEXT NOT NULL,
    title                 TEXT NOT NULL,
    source                TEXT NOT NULL,
    version_label         TEXT NOT NULL,
    enabled               INTEGER NOT NULL DEFAULT 1,
    required_telemetry    TEXT NOT NULL,
    capability_status     TEXT NOT NULL DEFAULT 'unknown',
    capability_reason     TEXT NOT NULL DEFAULT '',
    validation_status     TEXT NOT NULL DEFAULT 'unvalidated',
    last_tested_at        TEXT,
    false_positive_notes  TEXT NOT NULL DEFAULT '',
    first_seen_at         TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    UNIQUE(family, rule_key)
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_family
    ON detection_rules(family);

-- Append-only history of every `secure detect test` run against one
-- rule -- never overwritten or pruned, the same "keep every
-- observation" discipline threat_intel_lookups (Phase 20) already
-- established for its own per-lookup cache rows. `expected` is what
-- the fixture ITSELF declares it should do ("fire"/"no_fire");
-- `actual` is what really happened, including "error" (the family's
-- own evaluator raised) and "not_evaluable" (Sigma's own capability
-- gate rejected the fixture rule/telemetry pairing) as HONEST outcomes
-- distinct from a genuine no-match -- never collapsed into "no_fire".
-- `passed` is `actual == expected` computed once at write time, kept
-- as its own column purely so `secure detect list
-- --validation-status` never has to re-derive it from free-text.
CREATE TABLE IF NOT EXISTS detection_rule_test_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id       INTEGER NOT NULL,
    tested_at     TEXT NOT NULL,
    fixture_name  TEXT NOT NULL,
    expected      TEXT NOT NULL,
    actual        TEXT NOT NULL,
    passed        INTEGER NOT NULL,
    detail        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detection_rule_test_runs_rule
    ON detection_rule_test_runs(rule_id);

-- Phase 27 Security Validation (see secure/validate/). One row per
-- `secure validate run` invocation -- groups every scenario result
-- from that run, same run_id-groups-a-run convention every other
-- *_runs table in this app already uses (integration_runs,
-- forensic_collections, baseline_runs). This table and
-- validation_scenario_results below are the ONLY things this phase
-- ever writes to the OPERATOR's real database -- the scenarios
-- THEMSELVES always execute against a throwaway, temp-file sandbox
-- database (see secure/validate/sandbox.py), never against the rows
-- these two tables' own connection is attached to. Recording that a
-- validation run happened, and what it found, is legitimate audit
-- history for the real database; re-running the scenarios' actual
-- detection logic against real operator data is not, and never
-- happens here.
CREATE TABLE IF NOT EXISTS validation_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL UNIQUE,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    secure_version  TEXT NOT NULL,
    scenario_count  INTEGER NOT NULL DEFAULT 0,
    detail          TEXT NOT NULL DEFAULT ''
);

-- One row per scenario outcome within one validation run -- append-
-- only, never overwritten, same discipline as detection_rule_test_runs
-- above: a scenario's outcome (including a deliberate MISS/
-- NOT_EVALUABLE/SENSOR_UNAVAILABLE) is a permanent fact about that run,
-- never silently replaced. `outcome` is always one of PASS / PARTIAL /
-- MISS / NOT_EVALUABLE / SENSOR_UNAVAILABLE (secure/validate/__init__.py's
-- own vocabulary) -- the report generator (secure/validate/report.py)
-- is structurally unable to filter any of these out, since it only
-- ever reads "every row for this run_id."  `*_json` columns hold
-- small, already-serialized structures (sensor name lists, finding
-- summaries, the explanation-quality checklist) -- this table doesn't
-- interpret them, only stores and returns them verbatim, same as every
-- other `*_json` column in this schema.
CREATE TABLE IF NOT EXISTS validation_scenario_results (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                      TEXT NOT NULL,
    scenario_id                 TEXT NOT NULL,
    technique_id                TEXT,
    technique_name              TEXT,
    category                    TEXT NOT NULL,
    description                 TEXT NOT NULL,
    expected_result             TEXT NOT NULL,
    sensors_observed_json       TEXT NOT NULL,
    findings_json                TEXT NOT NULL,
    correlation_result          TEXT,
    explanation_checklist_json  TEXT NOT NULL,
    dedup_result                TEXT,
    latency_ms                  REAL,
    outcome                     TEXT NOT NULL,
    notes                       TEXT NOT NULL DEFAULT '',
    started_at                  TEXT NOT NULL,
    completed_at                TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_validation_scenario_results_run
    ON validation_scenario_results(run_id);

-- Phase 28 Local AI Security Analyst (see secure/ai/). One row per
-- `secure ai ask` invocation -- append-only audit trail, same
-- "a permanent fact about what was asked and what the model actually
-- saw" discipline validation_scenario_results above already
-- established. `context_manifest_json` is the exact list of evidence
-- ids (source_table/source_id pairs) actually handed to the model for
-- this question -- the citation-validity check compares every id the
-- model claims against exactly this list, never against the live
-- database, so "what the model was allowed to know" stays a fixed,
-- auditable fact even if the underlying data changes later.
-- `analyst_answer_json`/`verifier_answer_json` hold the fully parsed,
-- structured answer (facts/interpretations/assessments/hypotheses,
-- each with its own citation), not just raw text -- the raw text is
-- ALSO kept (`*_raw_response`) so a parsing bug is always independently
-- auditable against what the model actually said. Both providers/
-- models are always recorded even when the verifier pass didn't run
-- (verifier_* columns stay NULL) -- this table never silently omits
-- that a second opinion wasn't sought.
CREATE TABLE IF NOT EXISTS ai_analyst_queries (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    asked_at                 TEXT NOT NULL,
    completed_at             TEXT,
    mode                     TEXT NOT NULL DEFAULT 'analyze',
    entity_type              TEXT,
    entity_key               TEXT,
    question                 TEXT NOT NULL,
    provider_a               TEXT,
    model_a                  TEXT,
    provider_b               TEXT,
    model_b                  TEXT,
    context_manifest_json    TEXT NOT NULL DEFAULT '[]',
    analyst_raw_response     TEXT,
    analyst_answer_json      TEXT,
    verifier_raw_response    TEXT,
    verifier_answer_json     TEXT,
    citation_valid_count     INTEGER NOT NULL DEFAULT 0,
    citation_invalid_count   INTEGER NOT NULL DEFAULT 0,
    latency_ms               REAL,
    status                   TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_ai_analyst_queries_asked_at
    ON ai_analyst_queries(asked_at);

-- One row per constrained-verification-mode run (secure/ai/verify/) --
-- read-only inspection plus deterministic test/validation-suite
-- execution, NEVER a modification of real host state. `operations_json`
-- records exactly which allowlisted operations ran (each one drawn
-- from a fixed, hardcoded enum -- see secure/ai/verify/runner.py's own
-- module docstring for why the model never supplies a raw command
-- string); `results_json` is each operation's own outcome (exit code,
-- truncated stdout/stderr, deterministic PASS/FAIL) -- the deterministic
-- test framework decides pass/fail here, never the LLM (see this
-- table's own `overall_status`, computed the same way, before any
-- model ever sees the result). May stand alone (query_id NULL, e.g. a
-- scheduled health check) or be linked to the query/change-request that
-- triggered it.
CREATE TABLE IF NOT EXISTS ai_verification_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id         INTEGER,
    started_at       TEXT NOT NULL,
    completed_at     TEXT,
    operations_json  TEXT NOT NULL DEFAULT '[]',
    results_json     TEXT NOT NULL DEFAULT '[]',
    overall_status   TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_ai_verification_runs_query
    ON ai_verification_runs(query_id);

-- One row per AI-proposed system change (secure/ai/changes/) -- the
-- hard safety boundary of this whole phase. Every row is born with
-- status='pending' and a `revision_hash` (a hash of the EXACT proposed
-- content) -- approval (secure/cli/ai.py's `secure ai changes approve`)
-- can only ever move a row from pending to approved, is only ever
-- triggered by an explicit human CLI/GUI action (never by either
-- model, never by tests passing, never by both models agreeing --
-- see secure/ai/changes/workflow.py's own docstring), and is checked
-- against `revision_hash` at execution time -- if the proposal content
-- changed since approval, the hash no longer matches and the approval
-- no longer applies. Nothing in this codebase ever transitions a row
-- to 'approved' except that one explicit CLI path. `notified_at`/
-- `notify_status` record whether the email notification was
-- successfully sent -- but email delivery (or its failure) never gates
-- CR creation and is NEVER treated as approval, per this phase's own
-- governing instruction.
CREATE TABLE IF NOT EXISTS ai_change_requests (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    cr_id                 TEXT NOT NULL UNIQUE,
    created_at            TEXT NOT NULL,
    revision_hash         TEXT NOT NULL,
    title                 TEXT NOT NULL,
    proposed_change       TEXT NOT NULL,
    reason                TEXT NOT NULL,
    affected_component    TEXT NOT NULL,
    risks                 TEXT NOT NULL DEFAULT '',
    verification_run_id   INTEGER,
    model_a_opinion       TEXT NOT NULL DEFAULT '',
    model_b_opinion       TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'pending',
    approved_at           TEXT,
    approved_by           TEXT,
    notified_at           TEXT,
    notify_status         TEXT NOT NULL DEFAULT 'not_sent',
    -- Phase 39: the change class, denormalized onto the change request
    -- so the Change Request Center (Phase 40) and the notification
    -- rules (Phase 41) can filter on it without joining back to a
    -- repair run — and so a change request from a non-agent source
    -- (Phase 46) can carry one too. The authoritative copy is the
    -- classification text embedded in `risks`, which IS covered by
    -- revision_hash; this column is for querying, not for deciding.
    classification        TEXT
);

CREATE INDEX IF NOT EXISTS idx_ai_change_requests_status
    ON ai_change_requests(status);

-- Phase 30: Performance & Diagnostics. Deliberately minimal — only two
-- tables, per the approved design's own "keep storage minimal, no
-- high-frequency telemetry" instruction. Live hardware/system-health
-- reads (secure/diagnostics/hardware.py, system.py) are never persisted
-- at all; they're computed fresh on every `secure diagnostics system`
-- call. These two tables exist only for what genuinely benefits from
-- history: recent per-operation performance, and occasional
-- explicitly-recorded milestones.

CREATE TABLE IF NOT EXISTS perf_module_runs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_group_id          TEXT NOT NULL,
    module                TEXT NOT NULL,
    operation             TEXT NOT NULL,
    external_tool         TEXT,
    started_at            TEXT NOT NULL,
    completed_at          TEXT NOT NULL,
    duration_seconds      REAL NOT NULL,
    cpu_time_seconds       REAL,
    rss_bytes_at_end      INTEGER,
    observations_processed INTEGER,
    findings_produced     INTEGER,
    error                 TEXT,
    timed_out             INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_perf_module_runs_module
    ON perf_module_runs(module, completed_at);
CREATE INDEX IF NOT EXISTS idx_perf_module_runs_group
    ON perf_module_runs(run_group_id);

CREATE TABLE IF NOT EXISTS perf_milestones (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    label                 TEXT NOT NULL,
    recorded_at           TEXT NOT NULL,
    secure_version        TEXT NOT NULL,
    run_all_duration_seconds REAL,
    secure_peak_rss_bytes INTEGER,
    db_size_bytes         INTEGER,
    notes                 TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_perf_milestones_recorded_at
    ON perf_milestones(recorded_at);

-- Phase 31 — Agent Foundation. One row per attempted autonomous repair
-- run. Deliberately a single flat table, not a family of tables the
-- way Phase 28's ai_* tables are split by concern — everything here
-- describes one run's own lifecycle (trigger -> sandbox -> tool ->
-- verification -> optional change request), so splitting it further
-- would just mean joining it back together on every read. This table
-- is NEVER read by secure/ai/changes/workflow.py's five hard rules —
-- it only ever supplies text for propose_change()'s existing
-- arguments; approval state itself lives solely in ai_change_requests,
-- referenced here by change_request_id, to avoid two tables ever
-- disagreeing about whether something was approved.
CREATE TABLE IF NOT EXISTS agent_repair_runs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                TEXT NOT NULL UNIQUE,
    created_at            TEXT NOT NULL,
    completed_at          TEXT,
    status                TEXT NOT NULL DEFAULT 'running',
    attempt_number        INTEGER NOT NULL DEFAULT 1,
    max_attempts          INTEGER NOT NULL,
    trigger_kind          TEXT NOT NULL,
    trigger_ref           TEXT NOT NULL,
    trigger_detail        TEXT NOT NULL DEFAULT '',
    base_commit           TEXT NOT NULL,
    worktree_path         TEXT NOT NULL,
    agent_home_path       TEXT NOT NULL,
    tool_name             TEXT NOT NULL DEFAULT 'mini-swe-agent',
    tool_version           TEXT NOT NULL DEFAULT '',
    model_name            TEXT NOT NULL DEFAULT '',
    -- Reproducibility (added per explicit user instruction): the exact
    -- argv and generated mini-SWE-agent config YAML this run was
    -- invoked with, plus a hash of the raw transcript file bytes read
    -- back — so a completed run's own inputs can be inspected or
    -- replayed later without guessing, and so a transcript file that
    -- was altered after the fact (on disk, outside Secure) is
    -- detectable by re-hashing it and comparing.
    tool_argv_json        TEXT NOT NULL DEFAULT '[]',
    mini_config_yaml      TEXT NOT NULL DEFAULT '',
    transcript_hash       TEXT,
    transcript_path       TEXT,
    agent_exit_status     TEXT,
    diff_path             TEXT,
    diff_hash             TEXT,
    changed_files_json    TEXT NOT NULL DEFAULT '[]',
    denylist_violation    TEXT,
    pytest_status         TEXT,
    pytest_summary        TEXT NOT NULL DEFAULT '',
    validate_status       TEXT,
    validate_summary      TEXT NOT NULL DEFAULT '',
    verification_passed   INTEGER,
    change_request_id     TEXT,
    stop_reason           TEXT NOT NULL DEFAULT '',
    notes                 TEXT NOT NULL DEFAULT '',
    -- Phase 38 — Independent Reviewer. "Record both assessments" (the
    -- phase's own words): `coder_assessment` is the PRIMARY_CODER
    -- tool's own account of what it did, stored verbatim but never
    -- trusted (Secure's independently computed diff above is what is
    -- actually believed); the review_* columns are the
    -- INDEPENDENT_REVIEWER model's structured assessment of that same
    -- patch. `review_blocking_json` is computed by
    -- secure/agent/review.py from the answers, never taken from the
    -- model's own prose, so a model cannot declare itself
    -- blocking-free. `review_disagreement` is 1 only when the coder
    -- claimed success and the reviewer raised a blocking finding —
    -- the material-disagreement condition that stops automatic
    -- progression. All nullable/defaulted: a run from before this
    -- phase, or one where no reviewer was configured, carries honest
    -- emptiness rather than a fabricated clean review.
    coder_assessment      TEXT NOT NULL DEFAULT '',
    review_status         TEXT,
    review_provider       TEXT NOT NULL DEFAULT '',
    review_model          TEXT NOT NULL DEFAULT '',
    review_answers_json   TEXT NOT NULL DEFAULT '[]',
    review_blocking_json  TEXT NOT NULL DEFAULT '[]',
    review_summary        TEXT NOT NULL DEFAULT '',
    review_error          TEXT,
    review_disagreement   INTEGER,
    -- Phase 39 — Change Classification. The deterministic class this
    -- change was assigned before promotion, plus the human-readable
    -- reasons that produced it. Never derived from a model's opinion:
    -- secure/agent/classify.py computes it from changed paths and the
    -- diff's added lines, and a model may only raise it, never lower
    -- it. Stored on the run for auditability; the same value is bound
    -- into the change request's approval hash via its `risks` text.
    classification        TEXT,
    classification_reasons TEXT NOT NULL DEFAULT '',
    -- Phase 43 — Automated Failure Diagnosis. Whether the original
    -- failure was independently confirmed to still occur BEFORE any
    -- repair was attempted. `reproduced` is three-state on purpose:
    -- 1 (still fails), 0 (passes now), NULL (could not tell) — an
    -- inconclusive reproduction is never collapsed into either
    -- certainty. Phase 44 reads this column as its first VERIFIED
    -- criterion ("original failure was reproduced before repair"), so
    -- a run that predates this phase honestly reads back as NULL
    -- rather than as a confirmed reproduction.
    reproduction_status   TEXT,
    reproduced            INTEGER,
    reproduction_detail   TEXT NOT NULL DEFAULT '',
    reproduction_command  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_repair_runs_status
    ON agent_repair_runs(status);
CREATE INDEX IF NOT EXISTS idx_agent_repair_runs_trigger
    ON agent_repair_runs(trigger_kind, trigger_ref);

-- Phase 31.5 — Agent Action Audit. One row per externally visible
-- action secure/agent/ (or its CLI) performs: every subprocess it
-- invokes, every git operation, every filesystem-changing operation,
-- and every proposed/actual system change (a change request being
-- proposed, superseded, or approved). Deliberately NOT scoped to
-- run_id-having actions only — run_id is nullable because some audited
-- actions (e.g. removing a finished run's worktree) happen after the
-- run itself finished, and a few (a rejected/refused revalidation
-- attempt) can happen with no successful run at all. Never stores
-- secrets, environment variables, model prompt text verbatim, or file
-- contents — see secure/agent/audit.py's own module docstring for the
-- redaction rules; only metadata about what ran lives here.
CREATE TABLE IF NOT EXISTS agent_actions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id             TEXT,
    timestamp          TEXT NOT NULL,
    component          TEXT NOT NULL,
    action             TEXT NOT NULL,
    argv_json          TEXT NOT NULL DEFAULT '[]',
    cwd                TEXT,
    target             TEXT NOT NULL DEFAULT '',
    mutating           INTEGER NOT NULL DEFAULT 0,
    approval_required  INTEGER NOT NULL DEFAULT 0,
    exit_code          INTEGER,
    result_summary     TEXT NOT NULL DEFAULT '',
    duration_seconds   REAL
);

CREATE INDEX IF NOT EXISTS idx_agent_actions_run_id
    ON agent_actions(run_id);
CREATE INDEX IF NOT EXISTS idx_agent_actions_timestamp
    ON agent_actions(timestamp);

-- Phase 45 — Maintenance Memory. One row per completed repair attempt,
-- written AFTER the run reaches a terminal status. Deliberately a
-- separate table from agent_repair_runs rather than more columns on
-- it: that table records one run's own lifecycle, whereas this one is
-- the durable, searchable engineering record that outlives the
-- worktree, the diff file, and eventually the run row's usefulness.
--
-- "Do not use unrestricted chat history as the primary memory system"
-- (the phase's own words): nothing here stores conversation text,
-- model prose, or a transcript. Every column is a structured fact
-- already established deterministically elsewhere.
--
-- `failure_signature` is a stable, normalized fingerprint of WHAT
-- failed (not of one particular occurrence), so a later failure can
-- find prior work on the same thing. It deliberately excludes
-- timestamps, run ids, and absolute paths, which would make every
-- occurrence unique and the table unsearchable.
--
-- `outcome` and `approval_decision` are recorded as they actually
-- happened, including rejections and failures — a memory that only
-- remembers successes would systematically mislead the thing reading
-- it.
CREATE TABLE IF NOT EXISTS agent_maintenance_memory (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at           TEXT NOT NULL,
    run_id                TEXT NOT NULL,
    failure_signature     TEXT NOT NULL,
    trigger_kind          TEXT NOT NULL,
    trigger_ref           TEXT NOT NULL,
    affected_component    TEXT NOT NULL DEFAULT '',
    root_cause            TEXT NOT NULL DEFAULT '',
    repair_strategy       TEXT NOT NULL DEFAULT '',
    framework             TEXT NOT NULL DEFAULT '',
    model_name            TEXT NOT NULL DEFAULT '',
    files_changed_json    TEXT NOT NULL DEFAULT '[]',
    base_commit           TEXT NOT NULL DEFAULT '',
    diff_hash             TEXT,
    verification_summary  TEXT NOT NULL DEFAULT '',
    verified              INTEGER,
    reviewer_assessment   TEXT NOT NULL DEFAULT '',
    classification        TEXT,
    approval_decision     TEXT NOT NULL DEFAULT 'none',
    change_request_id     TEXT,
    outcome               TEXT NOT NULL,
    rollback              TEXT NOT NULL DEFAULT '',
    -- Set later, by link_regression(), when a subsequent failure is
    -- attributed to this repair. Nullable because most repairs never
    -- acquire one, and a fabricated empty value would read as "checked
    -- and found none."
    regression_run_id     TEXT,
    regression_note       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agent_memory_signature
    ON agent_maintenance_memory(failure_signature);
CREATE INDEX IF NOT EXISTS idx_agent_memory_run
    ON agent_maintenance_memory(run_id);
CREATE INDEX IF NOT EXISTS idx_agent_memory_recorded_at
    ON agent_maintenance_memory(recorded_at);

-- Phase 46 — Dependency & Security Tool Maintenance. The last version
-- string Secure OBSERVED for each external component, so a later
-- survey can notice that it changed. Deliberately an observation
-- record, not a policy: nothing here pins, requires, or enforces a
-- version, and writing a row never causes an install. A component
-- whose version cannot be determined is simply absent rather than
-- recorded as an empty string, so "we have never seen a version" and
-- "the version is blank" stay distinguishable.
CREATE TABLE IF NOT EXISTS agent_tool_versions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    component     TEXT NOT NULL,
    tool_version  TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    UNIQUE(component, tool_version)
);

CREATE INDEX IF NOT EXISTS idx_agent_tool_versions_component
    ON agent_tool_versions(component);
"""

# Columns added to an already-shipped table after the fact.
# `CREATE TABLE IF NOT EXISTS` (above) can't add a column to a table
# that already exists under an older shape, so each entry here is
# healed in separately by _ensure_column() — additive and
# non-destructive, same "schema heals itself, safe to call every run"
# spirit as the rest of init_schema(), just for the one situation
# CREATE TABLE IF NOT EXISTS can't cover on its own. This is the first
# time this project has needed to alter an existing table's shape
# rather than just adding new tables — see PROJECT_NOTES.md's change
# log for why (bluetooth_devices needed paired/connected columns added
# so pairing/reconnection *transitions* can be detected, which requires
# knowing the PREVIOUS state before this scan's upsert overwrites it).
_COLUMN_MIGRATIONS = [
    ("bluetooth_devices", "paired", "INTEGER NOT NULL DEFAULT 0"),
    ("bluetooth_devices", "connected", "INTEGER NOT NULL DEFAULT 0"),
    # Phase 21 logical-identity correction (see evidence_links' own
    # schema comment above) — heals a database whose evidence_links
    # table was already created under the old raw-id-only shape during
    # this same phase's earlier dev/test runs. No DEFAULT is meaningful
    # for these (there is no correct value to backfill for a pre-
    # existing row that predates the concept of a logical fingerprint),
    # so they're added nullable — additive and non-destructive, existing
    # rows simply carry NULL here until next touched.
    ("evidence_links", "first_source_id", "INTEGER"),
    ("evidence_links", "from_fingerprint", "TEXT"),
    ("evidence_links", "to_fingerprint", "TEXT"),
    ("evidence_links", "first_seen", "TEXT"),
    ("evidence_links", "last_seen", "TEXT"),
    ("evidence_links", "times_seen", "INTEGER NOT NULL DEFAULT 1"),
    # Phase 38 — Independent Reviewer. Heals an agent_repair_runs table
    # created by Phases 31-37, which predate the review columns. Every
    # one is additive with a safe default (or nullable where no value
    # would be honest for a run that predates the concept of an
    # independent review) — a pre-Phase-38 run reads back as "no review
    # was performed," which is exactly what happened.
    ("agent_repair_runs", "coder_assessment", "TEXT NOT NULL DEFAULT ''"),
    ("agent_repair_runs", "review_status", "TEXT"),
    ("agent_repair_runs", "review_provider", "TEXT NOT NULL DEFAULT ''"),
    ("agent_repair_runs", "review_model", "TEXT NOT NULL DEFAULT ''"),
    ("agent_repair_runs", "review_answers_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("agent_repair_runs", "review_blocking_json", "TEXT NOT NULL DEFAULT '[]'"),
    ("agent_repair_runs", "review_summary", "TEXT NOT NULL DEFAULT ''"),
    ("agent_repair_runs", "review_error", "TEXT"),
    ("agent_repair_runs", "review_disagreement", "INTEGER"),
    # Phase 39 — Change Classification.
    ("agent_repair_runs", "classification", "TEXT"),
    ("agent_repair_runs", "classification_reasons", "TEXT NOT NULL DEFAULT ''"),
    ("ai_change_requests", "classification", "TEXT"),
    # Phase 43 — Automated Failure Diagnosis.
    ("agent_repair_runs", "reproduction_status", "TEXT"),
    ("agent_repair_runs", "reproduced", "INTEGER"),
    ("agent_repair_runs", "reproduction_detail", "TEXT NOT NULL DEFAULT ''"),
    ("agent_repair_runs", "reproduction_command", "TEXT NOT NULL DEFAULT ''"),
]


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a SQLite connection, creating the file/folder if needed.

    secure.db holds this Mac's entire recorded activity history (see
    docs/THREAT_MODEL.md). Phase 29 Stage 4 hardens both the file and
    its parent directory to owner-only permissions every time a
    connection is opened, best-effort (see secure/permissions.py).
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    harden_dir(db_path.parent)

    conn = sqlite3.connect(db_path)
    # Return rows that behave like dicts (row["column"]) instead of
    # plain tuples — much easier to read while learning the codebase.
    conn.row_factory = sqlite3.Row
    harden_file(db_path)
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """Add `column` to `table` if it isn't already there. Safe to call every run.

    SQLite's `ALTER TABLE ... ADD COLUMN` errors if the column already
    exists (there's no `IF NOT EXISTS` for it), so this checks
    PRAGMA table_info() first. Always additive with a DEFAULT, never
    destructive — existing rows just get the default value for the new
    column.
    """
    existing_columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing_columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _ensure_evidence_links_dedup_index(conn: sqlite3.Connection) -> None:
    """(Re)create evidence_links' unique dedup index on the fingerprint
    columns, and backfill those columns on any pre-existing row that
    predates this correction (see evidence_links' own schema comment
    above). Must run AFTER `_COLUMN_MIGRATIONS` has healed
    from_fingerprint/to_fingerprint/first_source_id/first_seen/last_seen
    onto the table — on a fresh database CREATE TABLE already created
    these columns and this is a harmless no-op/IF NOT EXISTS; on an
    upgraded database this is what makes the index buildable at all
    (SQLite has no way to defer "create this index, but only once this
    column exists" inside a single executescript, hence the separate
    step).

    Backfill values reconstruct exactly what today's logic would have
    produced with no logical_key (i.e. the pre-correction behavior:
    fingerprint = "table:id"), first_source_id = the row's own existing
    from_source_id, first_seen/last_seen = its existing created_at — the
    most honest available reconstruction, never fabricated beyond what
    the row already recorded. `times_seen` already defaults to 1 via its
    own column DDL, so no separate backfill is needed for it.
    """
    conn.execute(
        "UPDATE evidence_links SET "
        "from_fingerprint = from_source_table || ':' || from_source_id "
        "WHERE from_fingerprint IS NULL"
    )
    conn.execute(
        "UPDATE evidence_links SET "
        "to_fingerprint = to_source_table || ':' || to_source_id "
        "WHERE to_fingerprint IS NULL"
    )
    conn.execute(
        "UPDATE evidence_links SET first_source_id = from_source_id WHERE first_source_id IS NULL"
    )
    conn.execute(
        "UPDATE evidence_links SET first_seen = created_at WHERE first_seen IS NULL"
    )
    conn.execute(
        "UPDATE evidence_links SET last_seen = created_at WHERE last_seen IS NULL"
    )
    conn.execute("DROP INDEX IF EXISTS idx_evidence_links_dedup")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_links_dedup_fingerprint "
        "ON evidence_links(from_fingerprint, to_fingerprint, relationship)"
    )


def init_schema(conn: sqlite3.Connection) -> None:
    """Create tables if they don't already exist. Safe to call every run."""
    conn.executescript(SCHEMA)
    for table, column, ddl in _COLUMN_MIGRATIONS:
        _ensure_column(conn, table, column, ddl)
    _ensure_evidence_links_dedup_index(conn)
    conn.commit()


class Database:
    """Small context-manager wrapper around a SQLite connection.

    Usage:
        with Database(db_path) as db:
            db.conn.execute("SELECT ...")
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> "Database":
        self.conn = connect(self.db_path)
        init_schema(self.conn)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None
