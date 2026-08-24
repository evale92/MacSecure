"""
secure/investigate/entity.py — Phase 23: the EntityRef vocabulary the
investigation engine pivots on. Pure, no I/O.

Every entity_type baseline already tracks (secure/baseline/entities.py)
is reused here VERBATIM — same constant, same *_key() function, same
canonical identity string. This is deliberate: a process investigated
here and a process baselined there must always agree on what "this
process" means, or "pivot to historical behavior" (one of the
instruction's own named pivots) would be comparing two different
identities without either side ever knowing it.

Three entity types are investigate-only — baseline has no reason to
track "normal" for them, since they're not behavioral baselines, but
the investigation engine needs a stable identity for them to pivot on:

    DESTINATION — a remote endpoint (remote_addr, remote_port, proto)
        on its own, independent of which process talked to it. Distinct
        from baseline's own PROCESS_DESTINATION (a (process, remote)
        PAIR, so one process's normal destinations never make the same
        destination look normal for a different process) — investigation
        sometimes wants the destination as a first-class pivot target
        ("what has EVER talked to 203.0.113.5"), which process_destination
        can't answer alone.
    FILE — one exact file path under file-integrity monitoring. Distinct
        from baseline's FILE_WATCH_PATH (aggregated at the watch-path
        level to avoid combinatorial entity growth for baselining
        purposes) — investigation wants to pivot on ONE specific file,
        not the whole watched directory it lives under.
    INDICATOR — a typed threat-intelligence indicator (hash/ip/domain),
        reusing secure/threatintel/indicators.py's own classification
        and normalization directly rather than reinventing indicator
        typing a second time.

Deliberately NOT modeled as entity types: YARA/Sigma/Suricata/Zeek
findings, anomalies, threat-intel lookup RESULTS, and correlated
findings. Those are EVIDENCE about an entity — reached via ObservationRef
and secure/evidence/'s own evidence_links graph (see resolve.py/
timeline.py) — not recurring real-world things with their own identity
to track "normal" for.
"""

from __future__ import annotations

from dataclasses import dataclass

from secure.baseline.entities import (
    BLE,
    BLUETOOTH,
    DNS_QUERY,
    FILE_WATCH_PATH,
    INVENTORY,
    LISTENING,
    PERSISTENCE,
    PROCESS,
    PROCESS_DESTINATION,
    TLS_SNI,
    WIFI,
    ble_key,
    bluetooth_key,
    dns_query_key,
    file_watch_path_key,
    inventory_key,
    listening_key,
    persistence_key,
    process_destination_key,
    process_key,
    tls_sni_key,
    wifi_key,
)
from secure.threatintel.indicators import classify_indicator, normalize_indicator

# ---------- investigate-only entity types ----------

DESTINATION = "destination"
FILE = "file"
INDICATOR = "indicator"

INVESTIGATE_ONLY_ENTITY_TYPES = (DESTINATION, FILE, INDICATOR)

# The full pivot vocabulary: every baseline entity_type, plus the three
# above. Order matches secure/baseline/entities.py's own ENTITY_TYPES
# tuple, investigate-only types appended after.
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
) + INVESTIGATE_ONLY_ENTITY_TYPES


@dataclass(frozen=True)
class EntityRef:
    """A durable, recurring real-world thing to pivot on —
    (entity_type, entity_key), the same shape baseline_entities already
    uses. Two EntityRefs are the same entity if and only if both fields
    are equal; nothing here does fuzzy/approximate matching.
    """

    entity_type: str
    entity_key: str

    def __post_init__(self) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(f"invalid EntityRef.entity_type: {self.entity_type!r}")
        if not self.entity_key:
            raise ValueError("EntityRef.entity_key must not be empty")

    def __str__(self) -> str:
        return f"{self.entity_type}:{self.entity_key}"


# ---------- investigate-only key builders ----------
#
# Same naming/shape convention as secure/baseline/entities.py's own
# *_key() functions — a thin, named wrapper per entity_type, never a
# bare string built ad hoc at a call site.


def destination_key(remote_addr: str, remote_port: int, proto: str) -> str:
    """(remote_addr, remote_port, proto) alone — matches
    remote_endpoints' own uniqueness (secure/storage/database.py's
    idx_remote_endpoints_identity), NOT baseline's process_destination_key
    (which also includes process_name). Use process_destination_key()
    directly (re-exported below) when the process matters too.
    """
    return f"{remote_addr}:{remote_port}/{proto}"


def file_key(path: str) -> str:
    """The file's own path — matches file_entries.path (UNIQUE)."""
    return path


def indicator_key(indicator_type: str, value: str) -> str:
    """`{type}:{normalized value}` — reuses
    secure/threatintel/indicators.py's own normalize_indicator()
    directly, so an INDICATOR entity's identity is byte-for-byte the
    same string threat_intel_lookups itself keys off, never a second,
    possibly-divergent normalization.
    """
    return f"{indicator_type}:{normalize_indicator(indicator_type, value)}"


def indicator_ref_for_value(value: str) -> "EntityRef | None":
    """Classify a raw candidate string and build its INDICATOR EntityRef
    in one step, or None if `value` isn't shaped like a hash/IP/domain
    at all (see threatintel.indicators.classify_indicator()) — the
    same "never guess, None means not usable" discipline that function
    already documents.
    """
    indicator_type = classify_indicator(value)
    if indicator_type is None:
        return None
    return EntityRef(entity_type=INDICATOR, entity_key=indicator_key(indicator_type, value))


# Re-exported so a caller only needs `from secure.investigate.entity
# import ...` for the full key-builder set, investigate-only and
# baseline-shared alike, without also reaching into
# secure.baseline.entities directly.
__all__ = [
    "INVENTORY", "PROCESS", "PROCESS_DESTINATION", "LISTENING", "WIFI",
    "BLUETOOTH", "BLE", "PERSISTENCE", "FILE_WATCH_PATH", "DNS_QUERY", "TLS_SNI",
    "DESTINATION", "FILE", "INDICATOR", "INVESTIGATE_ONLY_ENTITY_TYPES", "ENTITY_TYPES",
    "EntityRef",
    "inventory_key", "process_key", "process_destination_key", "listening_key",
    "wifi_key", "bluetooth_key", "ble_key", "persistence_key", "file_watch_path_key",
    "dns_query_key", "tls_sni_key",
    "destination_key", "file_key", "indicator_key", "indicator_ref_for_value",
]
