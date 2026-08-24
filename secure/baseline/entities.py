"""
secure/baseline/entities.py — Phase 14 entity_type/entity_key
derivation. Pure functions, no I/O.

Reuses the exact same identifier vocabulary secure/correlate/signals.py
already established wherever a baseline entity_type overlaps with an
existing correlation module (inventory/process/listening/wifi/
bluetooth/ble), so the two features describe the same real-world thing
the same way. `process_destination` and `file_watch_path` are new —
they exist only for baselining, not for correlation's signal shape.

entity_type values baselined (Phase 14 approval item 2):
    inventory            — LAN devices, by mac-or-ip.
    process              — running executables, by path.
    process_destination  — one (process, remote destination) pair, so
                            "normal" is never shared across processes
                            (approval item 5's Chrome-vs-Syncthing
                            requirement).
    listening            — listening services, by service identity.
    wifi                 — Wi-Fi networks, by SSID (+BSSID when known).
    bluetooth            — paired/configured Bluetooth devices.
    ble                  — BLE peripherals (rotation caveat applies —
                            see PROJECT_NOTES.md / database.py).
    persistence          — LaunchAgents/LaunchDaemons/login items.
    file_watch_path      — aggregated at the watch-path level, not per
                            file, to avoid combinatorial entity growth.
    dns_query            — (Phase 19) domains this Mac has queried,
                            observed via Zeek's dns.log — see
                            secure/integrations/zeek/scanner.py. A
                            gap-filling entity_type (like inventory/
                            process): Zeek is the only source of this
                            history, so it's recorded via
                            secure.baseline.history.record_gap_observation(),
                            same as inventory/process.
    tls_sni              — (Phase 19) TLS SNI hostnames this Mac has
                            connected to, observed via Zeek's ssl.log.
                            Also gap-filling, same reasoning as
                            dns_query.
"""

from __future__ import annotations

INVENTORY = "inventory"
PROCESS = "process"
PROCESS_DESTINATION = "process_destination"
LISTENING = "listening"
WIFI = "wifi"
BLUETOOTH = "bluetooth"
BLE = "ble"
PERSISTENCE = "persistence"
FILE_WATCH_PATH = "file_watch_path"
DNS_QUERY = "dns_query"
TLS_SNI = "tls_sni"

ENTITY_TYPES = (
    INVENTORY,
    PROCESS,
    PROCESS_DESTINATION,
    LISTENING,
    WIFI,
    BLUETOOTH,
    BLE,
    PERSISTENCE,
    FILE_WATCH_PATH,
    DNS_QUERY,
    TLS_SNI,
)


def inventory_key(mac: "str | None", ip: str) -> str:
    """Matches secure.correlate.signals._collect_inventory()'s identifier: mac if present, else ip."""
    return mac or ip


def process_key(executable_path: str) -> str:
    """Matches secure.correlate.signals._collect_process()'s identifier."""
    return executable_path


def process_destination_key(process_name: "str | None", remote_addr: str, remote_port: int, proto: str) -> str:
    """A composite entity so one process's normal destinations never
    make the same destination look normal for a different process
    (approval item 5). `process_name` falls back to "(unknown)" rather
    than None so the key stays a plain string and destinations from
    unattributed connections still get SOME baseline, grouped together
    rather than silently dropped.
    """
    name = process_name or "(unknown)"
    return f"{name}::{remote_addr}:{remote_port}/{proto}"


def listening_key(process_name: "str | None", identity_port: str, proto: str) -> str:
    """Matches secure.correlate.signals._collect_listening()'s identifier shape."""
    name = process_name or "(unknown)"
    return f"{name}:{identity_port}/{proto}"


def wifi_key(ssid: str) -> str:
    """SSID alone — matches secure.correlate.signals._collect_wifi()'s identifier.
    (wifi_networks may also have a bssid, but signals.py already treats
    ssid as the correlation identity; baselining follows suit for
    consistency between the two features.)
    """
    return ssid


def bluetooth_key(identifier: str) -> str:
    """Matches secure.correlate.signals._collect_bluetooth()'s identifier (a Bluetooth address)."""
    return identifier


def ble_key(cb_uuid: str) -> str:
    """Matches secure.correlate.signals._collect_ble()'s identifier. Rotation
    caveat: many devices change their real BLE address every ~15
    minutes, so cb_uuid identity here is a floor on distinct physical
    devices, not exact — see database.py's ble_peripherals schema
    comment. Baseline scoring treats ble entities conservatively for
    this reason (never over-weighted — approval item 1's explicit
    "do not over-weight ambient BLE presence" instruction).
    """
    return cb_uuid


def persistence_key(kind: str, path_or_label: str) -> str:
    """kind::path (or kind::label when no path is available), mirroring
    persistence_entries' own (kind, path)-else-(kind, label) dedup
    rule in secure/storage/models.py.
    """
    return f"{kind}::{path_or_label}"


def file_watch_path_key(watch_path_id: int) -> str:
    """Aggregated at the watch-path level (not per file) — a watch path
    can cover thousands of files; baselining "how much change activity
    is normal for THIS path" instead avoids an entity-count explosion
    while still being meaningfully specific per approval item 1.
    """
    return str(watch_path_id)


def dns_query_key(domain: str) -> str:
    """The already-normalized domain string (see
    secure.integrations.zeek.identity.dns_query_domain()) — no further
    transformation here; kept as its own function purely so callers
    reference one named identifier, matching every other *_key()
    function in this module, rather than passing a bare string.
    """
    return domain


def tls_sni_key(hostname: str) -> str:
    """The already-normalized SNI hostname string (see
    secure.integrations.zeek.identity.tls_sni_hostname()) — see
    dns_query_key()'s docstring for why this exists as a thin wrapper.
    """
    return hostname
