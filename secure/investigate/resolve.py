"""
secure/investigate/resolve.py — Phase 23 Stage 2: entity resolution.

Two directions, both read-only, both composed entirely from existing
list_*/find_* storage functions (plus the small number added alongside
this stage where a filtered read genuinely didn't exist yet — see
secure/storage/models/connections.py's list_process_destinations_for_*()
and find_remote_endpoint_by_identity(), and fileintegrity.py's
find_file_entries_by_hash()):

    resolve_entity(conn, EntityRef)      -> EntityResolution
        "Here's everything that IS this entity" — its own identity row
        (if it has one), and every ObservationRef that anchors it (the
        starting points secure/evidence/chain.py's walk_chain() and
        timeline.py's build_timeline() both need).

    resolve_observation(conn, ObservationRef) -> list[EntityRef]
        The reverse: "given this one exact row (an alert someone
        clicked), which entity/entities does it belong to" — how an
        analyst gets FROM a specific finding INTO an investigation.

Identity matching is always exact-string equality against a key built
by the SAME canonical key function secure/baseline/entities.py (or
secure/investigate/entity.py, for the three investigate-only types)
already defines — never a second, hand-rolled parse of an entity_key
string. This is deliberate: entity_key strings are opaque identifiers
here, not a mini-format to decode (a destination's remote_addr can
itself contain colons for IPv6, which would make splitting on ":"
ambiguous) — recomputing a candidate row's own key and comparing is
always unambiguous, regardless of what the key happens to look like.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from secure.evidence.model import ObservationRef
from secure.investigate.entity import (
    BLE,
    BLUETOOTH,
    DESTINATION,
    DNS_QUERY,
    FILE,
    FILE_WATCH_PATH,
    INDICATOR,
    INVENTORY,
    LISTENING,
    PERSISTENCE,
    PROCESS,
    PROCESS_DESTINATION,
    TLS_SNI,
    WIFI,
    EntityRef,
    ble_key,
    bluetooth_key,
    destination_key,
    dns_query_key,
    file_key,
    file_watch_path_key,
    indicator_key,
    inventory_key,
    listening_key,
    persistence_key,
    process_destination_key,
    process_key,
    tls_sni_key,
    wifi_key,
)
from secure.storage.models import (
    find_baseline_entity,
    find_file_entries_by_hash,
    find_file_entry_by_path,
    find_latest_lookups_for_indicator,
    find_persistence_entry_by_id,
    find_process_entry_by_path,
    find_watch_path_by_id,
    list_ble_peripherals,
    list_bluetooth_devices,
    list_devices,
    list_listening_services,
    list_persistence_entries,
    list_process_destinations,
    list_remote_endpoints,
    list_wifi_networks,
)


@dataclass
class EntityResolution:
    """The result of resolving one EntityRef: whether it's on record at
    all, a small presentation-ready identity summary (never a raw row
    dump — see `summary`'s own field docs), and every ObservationRef
    that anchors it for evidence-chain walking / timeline building.
    """

    entity: EntityRef
    exists: bool
    summary: Dict[str, object] = field(default_factory=dict)
    anchors: List[ObservationRef] = field(default_factory=list)


def _empty(entity: EntityRef) -> EntityResolution:
    return EntityResolution(entity=entity, exists=False)


def _resolve_process(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    record = find_process_entry_by_path(conn, entity.entity_key)
    if record is None:
        return _empty(entity)
    return EntityResolution(
        entity=entity,
        exists=True,
        summary={
            "executable_path": record.executable_path,
            "process_name": record.process_name,
            "run_as_user": record.run_as_user,
            "signing_status": record.signing_status,
            "times_seen": record.times_seen,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "known": record.known,
        },
        anchors=[ObservationRef(source_table="process_entries", source_id=record.id)],
    )


def _resolve_process_destination(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_process_destinations(conn):
        if process_destination_key(record.process_name, record.remote_addr, record.remote_port, record.proto) == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "process_name": record.process_name,
                    "remote_addr": record.remote_addr,
                    "remote_port": record.remote_port,
                    "proto": record.proto,
                    "observation_count": record.observation_count,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="process_destinations", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_destination(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_remote_endpoints(conn):
        if destination_key(record.remote_addr, record.remote_port, record.proto) == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "remote_addr": record.remote_addr,
                    "remote_port": record.remote_port,
                    "proto": record.proto,
                    "process_name": record.process_name,
                    "known": record.known,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="remote_endpoints", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_listening(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_listening_services(conn):
        if listening_key(record.process_name, record.identity_port, record.proto) == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "proto": record.proto,
                    "bind_scope": record.bind_scope,
                    "process_name": record.process_name,
                    "identity_port": record.identity_port,
                    "known": record.known,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="listening_services", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_wifi(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    # wifi_key() is ssid-only — a single SSID can legitimately have
    # multiple wifi_networks rows (distinct BSSIDs), so every matching
    # row is an anchor, not just the first.
    anchors: List[ObservationRef] = []
    summary: Dict[str, object] = {}
    for record in list_wifi_networks(conn):
        if wifi_key(record.ssid) == entity.entity_key:
            anchors.append(ObservationRef(source_table="wifi_networks", source_id=record.id))
            summary.setdefault("ssid", record.ssid)
            summary.setdefault("bssids", []).append(record.bssid)  # type: ignore[union-attr]
    if not anchors:
        return _empty(entity)
    return EntityResolution(entity=entity, exists=True, summary=summary, anchors=anchors)


def _resolve_bluetooth(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_bluetooth_devices(conn):
        if bluetooth_key(record.identifier) == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "identifier": record.identifier,
                    "name": record.name,
                    "trusted": record.trusted,
                    "times_seen": record.times_seen,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="bluetooth_devices", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_ble(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_ble_peripherals(conn):
        if ble_key(record.cb_uuid) == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "cb_uuid": record.cb_uuid,
                    "name": record.name,
                    "trusted": record.trusted,
                    "times_seen": record.times_seen,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="ble_peripherals", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_inventory(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_devices(conn):
        if inventory_key(record.mac, record.ip) == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "mac": record.mac,
                    "ip": record.ip,
                    "hostname": record.hostname,
                    "vendor": record.vendor,
                    "friendly_name": record.friendly_name,
                    "known": record.known,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="devices", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_persistence(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    for record in list_persistence_entries(conn):
        if persistence_key(record.kind, record.path or record.label or "") == entity.entity_key:
            return EntityResolution(
                entity=entity,
                exists=True,
                summary={
                    "kind": record.kind,
                    "path": record.path,
                    "label": record.label,
                    "program_path": record.program_path,
                    "signing_status": record.signing_status,
                    "known": record.known,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                },
                anchors=[ObservationRef(source_table="persistence_entries", source_id=record.id)],
            )
    return _empty(entity)


def _resolve_file_watch_path(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    try:
        watch_path_id = int(entity.entity_key)
    except ValueError:
        return _empty(entity)
    record = find_watch_path_by_id(conn, watch_path_id)
    if record is None or file_watch_path_key(record.id) != entity.entity_key:
        return _empty(entity)
    return EntityResolution(
        entity=entity,
        exists=True,
        summary={
            "path": record.path,
            "recursive": record.recursive,
            "sensitivity": record.sensitivity,
            "enabled": record.enabled,
            "last_scan_at": record.last_scan_at,
            "last_scan_status": record.last_scan_status,
        },
        anchors=[ObservationRef(source_table="file_watch_paths", source_id=record.id)],
    )


def _resolve_file(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    record = find_file_entry_by_path(conn, entity.entity_key)
    if record is None:
        return _empty(entity)
    return EntityResolution(
        entity=entity,
        exists=True,
        summary={
            "path": record.path,
            "hash": record.hash,
            "size": record.size,
            "is_executable": record.is_executable,
            "known": record.known,
        },
        anchors=[ObservationRef(source_table="file_entries", source_id=record.id)],
    )


def _resolve_dns_or_tls(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    # dns_query/tls_sni have no identity table of their own — see
    # secure/baseline/entities.py's own module docstring: they're
    # gap-filling entity types, tracked ONLY via baseline_activity.
    # Resolution here is therefore "does baseline know about this at
    # all," with no anchor ObservationRef (there is no one row that IS
    # this entity — see timeline.py for how its history is still shown
    # via baseline_activity/integration_observations instead).
    baseline_entity = find_baseline_entity(conn, entity.entity_type, entity.entity_key)
    if baseline_entity is None:
        return _empty(entity)
    return EntityResolution(
        entity=entity,
        exists=True,
        summary={
            "maturity_state": baseline_entity.maturity_state,
            "first_observed_at": baseline_entity.first_observed_at,
            "last_observed_at": baseline_entity.last_observed_at,
        },
    )


def _resolve_indicator(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    # No identity table of its own either — see entity.py's own
    # docstring. "Existence" here means SOME already-cached threat-intel
    # lookup or SOME exact-hash cross-reference against a monitored
    # file is on record; a lookup with status "not_found" still counts
    # as existing (a real lookup WAS performed — see
    # secure/threatintel/enrich.py's own "not found is not safe/absence
    # of evidence" discipline), it's the ABSENCE of any lookup record at
    # all that means exists=False here.
    indicator_type, _, value = entity.entity_key.partition(":")
    summary: Dict[str, object] = {"indicator_type": indicator_type, "value": value}
    anchors: List[ObservationRef] = []
    if indicator_type == "hash":
        matches = find_file_entries_by_hash(conn, value)
        anchors = [ObservationRef(source_table="file_entries", source_id=m.id) for m in matches]
        summary["matching_file_count"] = len(matches)
    exists = bool(anchors) or bool(_cached_lookup_count(conn, indicator_type, value))
    return EntityResolution(entity=entity, exists=exists, summary=summary, anchors=anchors)


def _cached_lookup_count(conn: sqlite3.Connection, indicator_type: str, value: str) -> int:
    return len(find_latest_lookups_for_indicator(conn, indicator_type, value))


_RESOLVERS = {
    PROCESS: _resolve_process,
    PROCESS_DESTINATION: _resolve_process_destination,
    DESTINATION: _resolve_destination,
    LISTENING: _resolve_listening,
    WIFI: _resolve_wifi,
    BLUETOOTH: _resolve_bluetooth,
    BLE: _resolve_ble,
    INVENTORY: _resolve_inventory,
    PERSISTENCE: _resolve_persistence,
    FILE_WATCH_PATH: _resolve_file_watch_path,
    FILE: _resolve_file,
    DNS_QUERY: _resolve_dns_or_tls,
    TLS_SNI: _resolve_dns_or_tls,
    INDICATOR: _resolve_indicator,
}


def resolve_entity(conn: sqlite3.Connection, entity: EntityRef) -> EntityResolution:
    """Resolve one EntityRef against everything already on record.
    Never raises for an entity_type with no resolver registered (there
    is none today — every ENTITY_TYPES value has one — but this stays
    defensive the same way secure/evidence/chain.py's timestamp
    resolution does, so a future entity_type added without its resolver
    wired up degrades to "not found" rather than crashing an
    investigation).
    """
    resolver = _RESOLVERS.get(entity.entity_type)
    if resolver is None:
        return _empty(entity)
    return resolver(conn, entity)


# ---------- reverse resolution: one row -> its entity/entities ----------
#
# Scoped to tables with an EXACT, unambiguous entity mapping only (see
# this module's own docstring). A table not listed here returns []
# rather than guessing — pivoting FROM a table without a clean mapping
# (most *_alerts tables, whose own identifier fields don't reliably
# match another table's key format) isn't attempted; an analyst still
# reaches the right entity by investigating it directly once identified
# from the alert's own message/evidence.

def resolve_observation(conn: sqlite3.Connection, ref: ObservationRef) -> List[EntityRef]:
    handler = _OBSERVATION_HANDLERS.get(ref.source_table)
    if handler is None:
        return []
    try:
        return handler(conn, ref.source_id)
    except Exception:  # noqa: BLE001 — reverse-resolution must never break a pivot
        return []


def _from_process_entries(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT executable_path FROM process_entries WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=PROCESS, entity_key=process_key(row["executable_path"]))]


def _from_persistence_entries(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    record = find_persistence_entry_by_id(conn, source_id)
    if record is None:
        return []
    return [EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key(record.kind, record.path or record.label or ""))]


def _from_listening_services(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute(
        "SELECT process_name, identity_port, proto FROM listening_services WHERE id = ?", (source_id,)
    ).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=LISTENING, entity_key=listening_key(row["process_name"], row["identity_port"], row["proto"]))]


def _from_wifi_networks(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT ssid FROM wifi_networks WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=WIFI, entity_key=wifi_key(row["ssid"]))]


def _from_bluetooth_devices(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT identifier FROM bluetooth_devices WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=BLUETOOTH, entity_key=bluetooth_key(row["identifier"]))]


def _from_ble_peripherals(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT cb_uuid FROM ble_peripherals WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=BLE, entity_key=ble_key(row["cb_uuid"]))]


def _from_devices(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT mac, ip FROM devices WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=INVENTORY, entity_key=inventory_key(row["mac"], row["ip"]))]


def _from_process_destinations(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute(
        "SELECT process_name, remote_addr, remote_port, proto FROM process_destinations WHERE id = ?",
        (source_id,),
    ).fetchone()
    if row is None:
        return []
    return [
        EntityRef(
            entity_type=PROCESS_DESTINATION,
            entity_key=process_destination_key(row["process_name"], row["remote_addr"], row["remote_port"], row["proto"]),
        ),
        EntityRef(
            entity_type=DESTINATION,
            entity_key=destination_key(row["remote_addr"], row["remote_port"], row["proto"]),
        ),
    ]


def _from_remote_endpoints(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute(
        "SELECT remote_addr, remote_port, proto FROM remote_endpoints WHERE id = ?", (source_id,)
    ).fetchone()
    if row is None:
        return []
    return [EntityRef(entity_type=DESTINATION, entity_key=destination_key(row["remote_addr"], row["remote_port"], row["proto"]))]


def _from_connection_events(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute(
        "SELECT remote_addr, remote_port, proto FROM connection_events WHERE id = ?", (source_id,)
    ).fetchone()
    if row is None or row["remote_addr"] is None or row["remote_port"] is None:
        return []
    return [EntityRef(entity_type=DESTINATION, entity_key=destination_key(row["remote_addr"], row["remote_port"], row["proto"]))]


def _from_file_entries(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT path, watch_path_id FROM file_entries WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    refs = [EntityRef(entity_type=FILE, entity_key=file_key(row["path"]))]
    if row["watch_path_id"] is not None:
        refs.append(EntityRef(entity_type=FILE_WATCH_PATH, entity_key=file_watch_path_key(row["watch_path_id"])))
    return refs


def _from_file_watch_paths(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    return [EntityRef(entity_type=FILE_WATCH_PATH, entity_key=file_watch_path_key(source_id))]


def _from_file_change_events(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    row = conn.execute("SELECT path, watch_path_id FROM file_change_events WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return []
    return [
        EntityRef(entity_type=FILE, entity_key=file_key(row["path"])),
        EntityRef(entity_type=FILE_WATCH_PATH, entity_key=file_watch_path_key(row["watch_path_id"])),
    ]


def _from_anomaly_events(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    # anomaly_events already carries its own entity_type/entity_key
    # columns directly (Phase 14) — the easiest, most exact case here:
    # no key-rebuilding needed, just read what's already stored.
    row = conn.execute(
        "SELECT entity_type, entity_key FROM anomaly_events WHERE id = ?", (source_id,)
    ).fetchone()
    if row is None:
        return []
    try:
        return [EntityRef(entity_type=row["entity_type"], entity_key=row["entity_key"])]
    except ValueError:
        return []  # an entity_type baseline recorded that investigate.entity doesn't (yet) recognize


def _from_forensic_collections(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    # Phase 24: forensic_collections already carries the exact EntityRef
    # it was collected ABOUT directly (its own entity_type/entity_key
    # columns) — same "already stored, just read it" case as
    # anomaly_events above, no key-rebuilding needed.
    row = conn.execute(
        "SELECT entity_type, entity_key FROM forensic_collections WHERE id = ?", (source_id,)
    ).fetchone()
    if row is None:
        return []
    try:
        return [EntityRef(entity_type=row["entity_type"], entity_key=row["entity_key"])]
    except ValueError:
        return []


def _from_forensic_evidence_items(conn: sqlite3.Connection, source_id: int) -> List[EntityRef]:
    # One join to the owning forensic_collections row for its
    # entity_type/entity_key — a normalized forensic evidence item has
    # no identity of its own beyond "one row this collection produced,"
    # the same "reach the entity through the collection, not the row
    # itself" relationship _from_file_change_events() already has to
    # file_watch_paths.
    row = conn.execute(
        "SELECT fc.entity_type AS entity_type, fc.entity_key AS entity_key "
        "FROM forensic_evidence_items fei JOIN forensic_collections fc ON fc.id = fei.collection_id "
        "WHERE fei.id = ?",
        (source_id,),
    ).fetchone()
    if row is None:
        return []
    try:
        return [EntityRef(entity_type=row["entity_type"], entity_key=row["entity_key"])]
    except ValueError:
        return []


_OBSERVATION_HANDLERS = {
    "process_entries": _from_process_entries,
    "persistence_entries": _from_persistence_entries,
    "listening_services": _from_listening_services,
    "wifi_networks": _from_wifi_networks,
    "bluetooth_devices": _from_bluetooth_devices,
    "ble_peripherals": _from_ble_peripherals,
    "devices": _from_devices,
    "process_destinations": _from_process_destinations,
    "remote_endpoints": _from_remote_endpoints,
    "connection_events": _from_connection_events,
    "file_entries": _from_file_entries,
    "file_watch_paths": _from_file_watch_paths,
    "file_change_events": _from_file_change_events,
    "anomaly_events": _from_anomaly_events,
    "forensic_collections": _from_forensic_collections,
    "forensic_evidence_items": _from_forensic_evidence_items,
}
