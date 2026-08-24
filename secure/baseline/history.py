"""
secure/baseline/history.py — the one file in secure/baseline/ allowed
to touch the database (mirrors secure/correlate/signals.py's role:
"the only file that touches the database directly", reading SQLite
instead of shelling out). Three jobs:

    1. unreviewed_alert_severities_for_entity() — look up, using
       CURRENT alert state, which severities of unresolved finding
       exist for one baseline entity right now. Feeds
       secure.baseline.eligibility.classify_eligibility().
    2. record_gap_observation() — the one call inventory/scanner.py and
       persistence/scanner.py each make once per scan, per entity, to
       close the two genuine historical gaps identified during Phase
       14 design review: devices and process executables have no
       existing append-only history table of their own (see
       database.py's schema comment on baseline_activity).
    3. read_entity_observations() — for every OTHER entity_type
       (connections/process_destination, listening, wifi, bluetooth,
       ble, persistence, file_watch_path), read raw observation
       timestamps directly from the existing *_events/*_observations
       table instead of duplicating them into baseline_activity — see
       the module docstring on baseline_activity in database.py for
       why. Used by secure/baseline/engine.py (added in a later stage)
       to compute lifetime/rolling feature statistics.

A note on backfilling vs. going forward: eligibility classification in
record_gap_observation() always uses the alert state AT THE MOMENT
this function is called — which is exactly correct for observations
recorded live, scan by scan, from now on (this is what makes
eligibility forward-only, per Phase 14 approval item 12). It is a
deliberate, documented simplification for BULK BACKFILL of
pre-existing history from the six entity_types read via
read_entity_observations(): those observations predate Phase 14 and
have no per-timestamp alert-state record to reconstruct from, so an
initial backfill classifies them using CURRENT alert state applied
once, rather than a full point-in-time walk of Phase 13's events-table
review-history — see docs/BASELINING.md's Limitations section.
"""

from __future__ import annotations

import sqlite3
from typing import List, Optional

from secure.baseline import maturity
from secure.baseline.constants import DEFAULT_ENTITY_CAP, ENTITY_CAPS
from secure.baseline.eligibility import classify_eligibility
from secure.storage.models import (
    add_baseline_activity,
    count_baseline_entities,
    delete_baseline_entity,
    find_device_by_identifier,
    get_or_create_baseline_entity,
    record_baseline_observation,
    set_baseline_entity_maturity,
)


def unreviewed_alert_severities_for_entity(
    conn: sqlite3.Connection, entity_type: str, entity_key: str
) -> List[str]:
    """Return the severities of every currently-unresolved (known=0)
    alert associated with this entity, across whichever alert table is
    relevant for this entity_type. Empty list if there's no matching
    alert table/row, or if this entity_type has no direct severity
    source (e.g. "listening" — see below).
    """
    if entity_type == "inventory":
        device = find_device_by_identifier(conn, entity_key)
        if device is None:
            return []
        rows = conn.execute(
            "SELECT severity FROM arp_alerts WHERE ip = ? AND known = 0",
            (device.ip,),
        ).fetchall()
        return [row["severity"] for row in rows]

    if entity_type in ("process", "process_destination"):
        if entity_type == "process_destination":
            # entity_key is "process_name::dest" — process_name, not a
            # path, so there's no direct persistence_alerts match by
            # path. Without a resolvable executable path there's
            # nothing to look up; treat as no direct severity signal.
            # (A user can still exclude/freeze the underlying process
            # entity itself, which indirectly protects its
            # destinations too.)
            return []
        rows = conn.execute(
            "SELECT severity FROM persistence_alerts "
            "WHERE target_type = 'process' AND identifier = ? AND known = 0",
            (entity_key,),
        ).fetchall()
        return [row["severity"] for row in rows]

    if entity_type == "wifi":
        rows = conn.execute(
            "SELECT severity FROM wifi_alerts WHERE ssid = ? AND known = 0",
            (entity_key,),
        ).fetchall()
        return [row["severity"] for row in rows]

    if entity_type == "bluetooth":
        rows = conn.execute(
            "SELECT severity FROM bluetooth_alerts WHERE identifier = ? AND known = 0",
            (entity_key,),
        ).fetchall()
        return [row["severity"] for row in rows]

    if entity_type == "ble":
        rows = conn.execute(
            "SELECT severity FROM ble_alerts WHERE cb_uuid = ? AND known = 0",
            (entity_key,),
        ).fetchall()
        return [row["severity"] for row in rows]

    if entity_type == "persistence":
        # entity_key is "kind::path_or_label" — match on the identifier
        # half; persistence_alerts.identifier holds exactly this.
        _, identifier = entity_key.split("::", 1) if "::" in entity_key else (None, entity_key)
        rows = conn.execute(
            "SELECT severity FROM persistence_alerts "
            "WHERE target_type != 'process' AND identifier = ? AND known = 0",
            (identifier,),
        ).fetchall()
        return [row["severity"] for row in rows]

    if entity_type == "file_watch_path":
        row = conn.execute(
            "SELECT path FROM file_watch_paths WHERE id = ?", (int(entity_key),)
        ).fetchone()
        if row is None:
            return []
        watch_path = row["path"]
        alert_rows = conn.execute(
            "SELECT severity FROM file_integrity_alerts "
            "WHERE known = 0 AND (path = ? OR path LIKE ?)",
            (watch_path, watch_path.rstrip("/") + "/%"),
        ).fetchall()
        return [r["severity"] for r in alert_rows]

    # "listening" has no dedicated severity-graded alert table today
    # (listening_services only carries a plain known/unknown flag, no
    # severity) — no direct severity signal exists to check.
    return []


def record_gap_observation(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    observed_at: str,
    *,
    partial_sensor_data: bool = False,
    counters: "Optional[BaselineRunCounters]" = None,
) -> None:
    """Record one observation for a gap-filling entity_type
    ("inventory" or "process" — see module docstring) and keep that
    entity's baseline_entities row and maturity_state in sync in one
    call. This is the single line inventory/scanner.py and
    persistence/scanner.py each add per observed entity per scan.

    Declines to create a genuinely NEW entity once its entity_type's
    cap (see ENTITY_CAPS in constants.py) is reached, without raising —
    the skip itself is never meant to be silent to the USER, since
    callers are expected to be driven by secure/baseline/engine.py's
    per-run bookkeeping (Stage 4B — pass `counters`, a
    secure.baseline.engine.BaselineRunCounters, and it's updated in
    place), which counts and surfaces skips via
    baseline_runs.entities_skipped_cap rather than dropping them
    unaccounted-for (approval item 5). An entity that already exists is
    never blocked by the cap — the cap only stops brand-new entities
    from being created. `counters` is accepted by plain duck typing
    (only .attribute += 1 is ever done to it) so this module never has
    to import secure.baseline.engine, which would create a cycle
    (engine.py already imports FROM this module).

    Respects EXCLUDE/FREEZE (Stage 4 approval item 8): an excluded
    entity's observation is still logged (weight 0, reason
    "excluded_entity" — see eligibility.py) but never folded into
    stats, same as any other zero-weight reason. A frozen entity's
    observation is also still logged, but baseline_entities' counters
    and maturity are deliberately NOT advanced — "continue observing,
    do not adapt current-normal statistics from new eligible
    observations" — so anomaly comparisons for this entity keep
    happening against whatever was frozen at freeze time.
    """
    existing = get_or_create_baseline_entity(conn, entity_type, entity_key)[0]
    is_new_entity = existing.observation_count == 0 and existing.maturity_state == maturity.NO_BASELINE

    if is_new_entity:
        cap = ENTITY_CAPS.get(entity_type, DEFAULT_ENTITY_CAP)
        if count_baseline_entities(conn, entity_type) > cap:
            # Cap already reached before this entity was created by
            # get_or_create above — remove the just-created empty row
            # so a future scan doesn't count it as "created but never
            # observed" noise. Only ever happens on an entity's very
            # first observation, when it has no history yet, so
            # removing it is safe.
            delete_baseline_entity(conn, entity_type, entity_key)
            if counters is not None:
                counters.entities_evaluated += 1
                counters.entities_skipped_cap += 1
            return

    frozen = existing.frozen
    unreviewed = (
        () if existing.excluded or partial_sensor_data
        else unreviewed_alert_severities_for_entity(conn, entity_type, entity_key)
    )
    reason, weight = classify_eligibility(
        excluded=existing.excluded,
        partial_sensor_data=partial_sensor_data,
        unreviewed_alert_severities=unreviewed,
    )

    add_baseline_activity(conn, run_id, entity_type, entity_key, reason, weight)

    if frozen:
        if counters is not None:
            counters.entities_evaluated += 1
            if partial_sensor_data:
                counters.incomplete_inputs += 1
            counters.comparisons_skipped += 1  # frozen -> never counted as "updated"
        return

    entity = record_baseline_observation(
        conn, entity_type, entity_key, observed_at, eligible=(weight > 0), weight=weight
    )

    new_state = maturity.compute_maturity(
        eligible_weight_total=entity.eligible_weight_total,
        eligible_distinct_days=entity.eligible_distinct_days,
        first_eligible_observed_at=entity.first_eligible_observed_at,
        last_eligible_observed_at=entity.last_eligible_observed_at,
        last_observed_at=entity.last_observed_at,
    )
    if new_state != entity.maturity_state:
        set_baseline_entity_maturity(conn, entity.id, new_state)

    if counters is not None:
        counters.entities_evaluated += 1
        if partial_sensor_data:
            counters.incomplete_inputs += 1
            counters.comparisons_skipped += 1
        elif weight <= 0:
            counters.comparisons_skipped += 1
        else:
            counters.entities_updated += 1


def record_entity_observation(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    observed_at: str,
    *,
    partial_sensor_data: bool = False,
    counters: "Optional[BaselineRunCounters]" = None,
) -> None:
    """Like record_gap_observation(), but for entity_types that ALREADY
    have their own raw history elsewhere (see read_entity_observations()
    below) — e.g. process_destination, backed by connection_events.
    Updates baseline_entities' lifetime/eligible counters and maturity
    exactly the same way, but deliberately does NOT write a
    baseline_activity row: that table exists only to fill the gap for
    entity_types with NO history table of their own (inventory/process
    — see database.py's schema comment on baseline_activity), and
    duplicating raw history that already exists elsewhere was
    explicitly ruled out (Phase 14 extension approval item 3: "do not
    duplicate raw feature history that already exists elsewhere" — the
    same principle applies one level up, at the entity level).

    `run_id` is accepted for signature symmetry with
    record_gap_observation() and so callers can log it alongside their
    own scan's run_id, but this function itself has nothing to write it
    into (baseline_entities carries no run_id column).

    Respects EXCLUDE/FREEZE the same way record_gap_observation() does
    (Stage 4 approval item 8) — see that function's docstring.
    """
    existing = get_or_create_baseline_entity(conn, entity_type, entity_key)[0]
    is_new_entity = existing.observation_count == 0 and existing.maturity_state == maturity.NO_BASELINE

    if is_new_entity:
        cap = ENTITY_CAPS.get(entity_type, DEFAULT_ENTITY_CAP)
        if count_baseline_entities(conn, entity_type) > cap:
            delete_baseline_entity(conn, entity_type, entity_key)
            if counters is not None:
                counters.entities_evaluated += 1
                counters.entities_skipped_cap += 1
            return

    frozen = existing.frozen
    unreviewed = (
        () if existing.excluded or partial_sensor_data
        else unreviewed_alert_severities_for_entity(conn, entity_type, entity_key)
    )
    reason, weight = classify_eligibility(
        excluded=existing.excluded,
        partial_sensor_data=partial_sensor_data,
        unreviewed_alert_severities=unreviewed,
    )

    if frozen:
        if counters is not None:
            counters.entities_evaluated += 1
            if partial_sensor_data:
                counters.incomplete_inputs += 1
            counters.comparisons_skipped += 1
        return

    entity = record_baseline_observation(
        conn, entity_type, entity_key, observed_at, eligible=(weight > 0), weight=weight
    )

    new_state = maturity.compute_maturity(
        eligible_weight_total=entity.eligible_weight_total,
        eligible_distinct_days=entity.eligible_distinct_days,
        first_eligible_observed_at=entity.first_eligible_observed_at,
        last_eligible_observed_at=entity.last_eligible_observed_at,
        last_observed_at=entity.last_observed_at,
    )
    if new_state != entity.maturity_state:
        set_baseline_entity_maturity(conn, entity.id, new_state)

    if counters is not None:
        counters.entities_evaluated += 1
        if partial_sensor_data:
            counters.incomplete_inputs += 1
            counters.comparisons_skipped += 1
        elif weight <= 0:
            counters.comparisons_skipped += 1
        else:
            counters.entities_updated += 1


# ---------- read adapters for entity_types with existing history ----------
#
# Every function below returns a plain list of ISO-8601 `created_at`
# timestamp strings — the raw observation moments for one entity —
# read directly from a table that already existed before Phase 14.
# Nothing here writes anything; secure/baseline/engine.py (added in a
# later stage) is what turns these into baseline_feature_stats /
# baseline_time_stats / baseline_entities updates, applying
# eligibility the same way record_gap_observation() does above (see
# this module's docstring for the backfill-vs-going-forward caveat).


def read_process_destination_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is "process_name::remote_addr:remote_port/proto" (see
    entities.process_destination_key()) — parsed back apart to filter
    connection_events, the append-only history table this entity_type
    reads from directly rather than duplicating into baseline_activity.
    """
    if "::" not in entity_key:
        return []
    process_name, dest = entity_key.split("::", 1)
    if process_name == "(unknown)":
        process_name = None
    try:
        addr_port, proto = dest.rsplit("/", 1)
        remote_addr, remote_port = addr_port.rsplit(":", 1)
    except ValueError:
        return []

    if process_name is None:
        rows = conn.execute(
            "SELECT created_at FROM connection_events "
            "WHERE process_name IS NULL AND remote_addr = ? AND remote_port = ? AND proto = ? "
            "ORDER BY created_at",
            (remote_addr, int(remote_port), proto),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT created_at FROM connection_events "
            "WHERE process_name = ? AND remote_addr = ? AND remote_port = ? AND proto = ? "
            "ORDER BY created_at",
            (process_name, remote_addr, int(remote_port), proto),
        ).fetchall()
    return [row["created_at"] for row in rows]


def read_listening_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is "process_name:identity_port/proto" (see
    entities.listening_key()). listening_events stores the raw
    local_port, not the resolved identity_port bucket — identity_port()
    is a scan-time derivation (see listening/bind_scope.py), reused
    here rather than re-implemented, so ephemeral-port bucketing
    behaves identically for baselining and for the listening audit
    itself. Imported locally (not at module load time): secure.listening
    (via its __init__.py, which eagerly imports scanner.py) ultimately
    imports secure.baseline.engine, which imports this module — a
    genuine package-level cycle that only a deferred import resolves.
    """
    from secure.listening.bind_scope import identity_port

    try:
        name_port, proto = entity_key.rsplit("/", 1)
        process_name, identity_port_bucket = name_port.rsplit(":", 1)
    except ValueError:
        return []
    if process_name == "(unknown)":
        process_name = None

    if process_name is None:
        rows = conn.execute(
            "SELECT created_at, local_port FROM listening_events "
            "WHERE process_name IS NULL AND proto = ? ORDER BY created_at",
            (proto,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT created_at, local_port FROM listening_events "
            "WHERE process_name = ? AND proto = ? ORDER BY created_at",
            (process_name, proto),
        ).fetchall()
    return [row["created_at"] for row in rows if identity_port(row["local_port"]) == identity_port_bucket]


def read_wifi_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is the SSID (see entities.wifi_key())."""
    rows = conn.execute(
        "SELECT created_at FROM wifi_observations WHERE ssid = ? ORDER BY created_at",
        (entity_key,),
    ).fetchall()
    return [row["created_at"] for row in rows]


def read_bluetooth_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is the Bluetooth identifier (see entities.bluetooth_key())."""
    rows = conn.execute(
        "SELECT created_at FROM bluetooth_observations WHERE identifier = ? ORDER BY created_at",
        (entity_key,),
    ).fetchall()
    return [row["created_at"] for row in rows]


def read_ble_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is the cb_uuid (see entities.ble_key())."""
    rows = conn.execute(
        "SELECT created_at FROM ble_observations WHERE cb_uuid = ? ORDER BY created_at",
        (entity_key,),
    ).fetchall()
    return [row["created_at"] for row in rows]


def read_persistence_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is "kind::path_or_label" (see entities.persistence_key()).
    persistence_observations rows are matched by kind + path (falling
    back to kind + label when path is empty), mirroring persistence_
    entries' own dedup rule in secure/storage/models.py.
    """
    if "::" not in entity_key:
        return []
    kind, path_or_label = entity_key.split("::", 1)
    rows = conn.execute(
        "SELECT created_at FROM persistence_observations "
        "WHERE kind = ? AND (path = ? OR (path IS NULL AND label = ?)) "
        "ORDER BY created_at",
        (kind, path_or_label, path_or_label),
    ).fetchall()
    return [row["created_at"] for row in rows]


def read_file_watch_path_observations(conn: sqlite3.Connection, entity_key: str) -> List[str]:
    """entity_key is the watch_path_id, stringified (see
    entities.file_watch_path_key()). Aggregated at the whole-path
    level — every change event under this watch path counts as one
    observation of "activity on this path," not per individual file.
    """
    try:
        watch_path_id = int(entity_key)
    except ValueError:
        return []
    rows = conn.execute(
        "SELECT created_at FROM file_change_events WHERE watch_path_id = ? ORDER BY created_at",
        (watch_path_id,),
    ).fetchall()
    return [row["created_at"] for row in rows]


_READERS = {
    "process_destination": read_process_destination_observations,
    "listening": read_listening_observations,
    "wifi": read_wifi_observations,
    "bluetooth": read_bluetooth_observations,
    "ble": read_ble_observations,
    "persistence": read_persistence_observations,
    "file_watch_path": read_file_watch_path_observations,
}


def read_entity_observations(conn: sqlite3.Connection, entity_type: str, entity_key: str) -> List[str]:
    """Dispatch to the right read_*_observations() function for one of
    the seven entity_types with an existing history table. Returns []
    for "inventory"/"process" (the two gap-filled types — read
    secure.storage.models.list_baseline_activity() for those instead)
    or any unrecognized entity_type.
    """
    reader = _READERS.get(entity_type)
    if reader is None:
        return []
    return reader(conn, entity_key)
