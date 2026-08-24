"""
integrations/osquery/crosscheck.py — compares this scan's osquery
observations against Secure's own native identity tables, and turns any
DISAGREEMENT into an integration_alerts row. A MATCH produces nothing at
all — no signal, no row, no trace beyond the underlying
integration_observations record itself.

This is the structural answer to Phase 15's explicit requirement:
"Prevent the same underlying observation from being interpreted as
independent corroboration merely because native Secure and osquery both
observed it." An earlier, weaker precedent for a similar problem exists
in secure/correlate/analysis.py (MEANINGFUL_MODULE_PAIRS deliberately
excludes {"file_integrity", "persistence"}) — but that only removes one
+4 combo bonus at the SCORING layer; the two signals still exist, still
count toward corroboration_bonus's distinct-module tally, and still
double the apparent evidence. That precedent isn't strong enough for
this phase's stricter wording ("...from being interpreted as independent
corroboration" at all), so this module fixes the problem one layer
earlier instead: a native/osquery MATCH never becomes a Signal in the
first place, because it never becomes an integration_alerts row in the
first place. secure/correlate/signals.py's future `_collect_integrations()`
(Stage 5) only ever reads FROM integration_alerts — so a fact both
sources agree on is structurally incapable of contributing two signals,
or even one extra signal, to correlation. Only genuine DISCREPANCIES
(something only one source saw) become alerts, and a discrepancy is, by
definition, not the same observation being double-counted — it's two
sources disagreeing, which is itself a new, real fact worth surfacing.

Severity convention for the discrepancy types this module raises
(deliberately asymmetric, not a coin flip):

    osquery_only — osquery observed something Secure's own native scan
        did not. Raised HIGH: this is the scenario an independent
        cross-check exists to catch — Secure's own collector missing
        something (different scan timing, a narrower scan scope, or
        conceivably a gap an attacker specifically exploited).
    native_only  — Secure's native scan observed something this osquery
        pass did not. Raised LOW: the finding is already tracked and
        already alertable through that native collector's own alert
        path (e.g. persistence_alerts' "new_persistence_entry") — this
        just notes osquery didn't independently confirm it this time,
        commonly explained by ordinary scan-to-scan timing/scope
        differences rather than anything Secure itself got wrong.

v1 scope, matching Phase 15's "small, high-value subset" instruction:
only LISTENING_PORTS and LAUNCHD are cross-checked here. PROCESSES and
PROCESS_OPEN_SOCKETS observations are still collected and persisted (see
scanner.py) for their own diagnostic value, but have no crosscheck_*
function yet — process identity/matching semantics differ enough
(process_entries dedupes by executable path across the whole history,
not "currently running") that folding them into this same native/
osquery equality check would need real design work of its own, left for
a later stage rather than rushed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from secure.integrations.base import ExternalObservation
from secure.integrations.osquery.queries import LAUNCHD, LISTENING_PORTS
from secure.storage.models import list_listening_services, list_persistence_entries

HIGH = "high"
LOW = "low"

OSQUERY_ONLY = "osquery_only"
NATIVE_ONLY = "native_only"

_LAUNCHD_PERSISTENCE_KINDS = ("launch_agent_user", "launch_agent_global", "launch_daemon")


@dataclass(frozen=True)
class Discrepancy:
    kind: str  # "listening_port" | "persistence"
    discrepancy_type: str  # OSQUERY_ONLY | NATIVE_ONLY
    severity: str
    identity_key: str
    label: "Optional[str]"
    message: str


def _native_listening_port_keys(conn) -> "set[tuple[str, int]]":
    """(proto, port) pairs for every listening service Secure's own
    scans currently know about. Built from listening_services (the
    deduped identity table, most-recently-seen state per service) — not
    every historical listening_events row, since this is a "what does
    Secure currently believe is listening" comparison, not a full
    history diff. Rows with no concrete local_port (rare — see
    bind_scope.identity_port()'s "ephemeral" bucket) can't be compared
    by exact port number and are skipped.
    """
    keys = set()
    for service in list_listening_services(conn):
        if service.local_port is None:
            continue
        keys.add((service.proto.upper(), service.local_port))
    return keys


def crosscheck_listening_ports(
    conn, observations: "list[ExternalObservation]"
) -> "list[Discrepancy]":
    """Compare this scan's osquery listening_ports observations against
    listening_services. Returns one Discrepancy per port osquery saw
    that Secure's native listening scan doesn't currently know about
    (osquery_only), plus one per port Secure natively knows about that
    this osquery pass didn't report (native_only). Ports both sides
    agree on produce nothing.
    """
    native_keys = _native_listening_port_keys(conn)

    osquery_rows = [o for o in observations if o.kind == LISTENING_PORTS]
    osquery_keys: "set[tuple[str, int]]" = set()
    discrepancies: "list[Discrepancy]" = []

    for obs in osquery_rows:
        proto = (obs.fields.get("proto") or "").upper()
        port = obs.fields.get("port")
        if port is None or proto not in ("TCP", "UDP"):
            continue
        key = (proto, port)
        osquery_keys.add(key)
        if key not in native_keys:
            process_name = obs.fields.get("process_name")
            discrepancies.append(
                Discrepancy(
                    kind="listening_port",
                    discrepancy_type=OSQUERY_ONLY,
                    severity=HIGH,
                    identity_key=obs.identity_key,
                    label=process_name,
                    message=(
                        f"osquery reports {proto} port {port} listening"
                        + (f" (process: {process_name})" if process_name else "")
                        + ", but Secure's own native listening scan does not "
                        "currently show it. This may just be scan-timing/scope "
                        "differences, but is worth a look — it's exactly the "
                        "kind of gap an independent cross-check exists to catch."
                    ),
                )
            )

    for proto, port in native_keys - osquery_keys:
        discrepancies.append(
            Discrepancy(
                kind="listening_port",
                discrepancy_type=NATIVE_ONLY,
                severity=LOW,
                identity_key=f"{proto.lower()}:{port}",
                label=None,
                message=(
                    f"Secure's native listening scan shows {proto} port {port} "
                    "listening, but this osquery pass did not independently "
                    "confirm it. Already tracked via Secure's own listening "
                    "audit; this just notes osquery didn't see it this time, "
                    "commonly explained by ordinary timing differences between "
                    "the two scans."
                ),
            )
        )

    return discrepancies


def _native_persistence_keys(conn) -> "dict[str, str]":
    """path (or, absent that, a label-based fallback key) -> kind, for
    every launchd-family persistence entry Secure's own scans currently
    know about. login_item entries are excluded — osquery's `launchd`
    table has no equivalent concept, so there's nothing to cross-check
    them against.
    """
    keys: "dict[str, str]" = {}
    for entry in list_persistence_entries(conn):
        if entry.kind not in _LAUNCHD_PERSISTENCE_KINDS:
            continue
        key = entry.path or (f"label:{entry.label}" if entry.label else None)
        if key:
            keys[key] = entry.kind
    return keys


def crosscheck_persistence(conn, observations: "list[ExternalObservation]") -> "list[Discrepancy]":
    """Compare this scan's osquery launchd observations against
    persistence_entries (launch_agent_user/launch_agent_global/
    launch_daemon rows only — see _native_persistence_keys()). Matched
    by plist path (falling back to a label-based key when no path is
    available on either side, the same nullable-identity fallback
    persistence_entries itself uses — see storage/models/persistence.py's
    upsert_persistence_entry()).
    """
    native_keys = _native_persistence_keys(conn)

    osquery_rows = [o for o in observations if o.kind == LAUNCHD]
    osquery_keys: "set[str]" = set()
    discrepancies: "list[Discrepancy]" = []

    for obs in osquery_rows:
        key = obs.identity_key
        osquery_keys.add(key)
        if key not in native_keys:
            label = obs.fields.get("label") or obs.fields.get("name")
            discrepancies.append(
                Discrepancy(
                    kind="persistence",
                    discrepancy_type=OSQUERY_ONLY,
                    severity=HIGH,
                    identity_key=key,
                    label=label,
                    message=(
                        f"osquery reports a launchd entry ('{label or key}') that "
                        "Secure's own native persistence scan does not currently "
                        "show. This may just be scan-timing differences, but any "
                        "persistence mechanism a second, independent engine sees "
                        "and Secure's own scan doesn't is worth a deliberate look."
                    ),
                )
            )

    for key, kind in native_keys.items():
        if key not in osquery_keys:
            discrepancies.append(
                Discrepancy(
                    kind="persistence",
                    discrepancy_type=NATIVE_ONLY,
                    severity=LOW,
                    identity_key=key,
                    label=None,
                    message=(
                        f"Secure's native persistence scan shows a {kind.replace('_', ' ')} "
                        f"entry ('{key}') that this osquery pass did not "
                        "independently confirm. Already tracked via Secure's own "
                        "persistence monitor; this just notes osquery didn't see "
                        "it this time."
                    ),
                )
            )

    return discrepancies


# ---------- Phase 21 (additive): surfacing the MATCH set ----------
#
# Everything below is new, additional to the two crosscheck_* functions
# above, and does not change their behavior, return values, or the
# match/discrepancy logic those functions already implement — those
# stay exactly as tested. A MATCH between osquery and Secure's own
# native collector still produces NO integration_alerts row (per this
# module's own founding docstring above) — that structural guarantee is
# untouched. What's new here is making the match itself a real,
# queryable fact instead of literally invisible: today, "native and
# osquery agreed" leaves no trace anywhere in this database at all.
# secure/integrations/osquery/scanner.py uses these to record a
# same_event_confirmation evidence_links row for each match — see that
# module's own module docstring for why this is the one Stage 3 wiring
# point that's a genuinely NEW behavior (new writes on a match, where
# today there are none) rather than a refactor of something already
# written elsewhere.


@dataclass(frozen=True)
class Match:
    kind: str  # "listening_port" | "persistence" — mirrors Discrepancy.kind
    identity_key: str  # the OSQUERY observation's own identity_key (matches ExternalObservation.identity_key)
    native_source_table: str  # "listening_services" | "persistence_entries"
    native_source_id: int
    detail: str


def find_listening_port_matches(conn, observations: "list[ExternalObservation]") -> "list[Match]":
    """Every LISTENING_PORTS observation this pass whose (proto, port)
    is ALSO currently known to listening_services — the exact MATCH set
    crosscheck_listening_ports() computes internally (native_keys &
    osquery_keys) but never returns, since a match is deliberately not
    a Discrepancy. Recomputes native_keys independently rather than
    sharing state with crosscheck_listening_ports() — keeps this
    function callable on its own, and keeps the existing function's own
    internals completely untouched.
    """
    native_keys = _native_listening_port_keys(conn)
    native_ids_by_key = {
        (service.proto.upper(), service.local_port): service.id
        for service in list_listening_services(conn)
        if service.local_port is not None
    }

    matches: "list[Match]" = []
    for obs in observations:
        if obs.kind != LISTENING_PORTS:
            continue
        proto = (obs.fields.get("proto") or "").upper()
        port = obs.fields.get("port")
        if port is None or proto not in ("TCP", "UDP"):
            continue
        key = (proto, port)
        if key not in native_keys:
            continue
        native_id = native_ids_by_key.get(key)
        if native_id is None:
            continue
        matches.append(
            Match(
                kind="listening_port",
                identity_key=obs.identity_key,
                native_source_table="listening_services",
                native_source_id=native_id,
                detail=(
                    f"osquery and Secure's own native listening scan both independently "
                    f"observed {proto} port {port} listening."
                ),
            )
        )
    return matches


def find_persistence_matches(conn, observations: "list[ExternalObservation]") -> "list[Match]":
    """Every LAUNCHD observation this pass whose own identity key is
    ALSO currently known to persistence_entries — the MATCH counterpart
    to find_listening_port_matches() above, same reasoning.
    """
    native_ids_by_key: "dict[str, int]" = {}
    for entry in list_persistence_entries(conn):
        if entry.kind not in _LAUNCHD_PERSISTENCE_KINDS:
            continue
        key = entry.path or (f"label:{entry.label}" if entry.label else None)
        if key:
            native_ids_by_key[key] = entry.id

    matches: "list[Match]" = []
    for obs in observations:
        if obs.kind != LAUNCHD:
            continue
        native_id = native_ids_by_key.get(obs.identity_key)
        if native_id is None:
            continue
        label = obs.fields.get("label") or obs.fields.get("name")
        matches.append(
            Match(
                kind="persistence",
                identity_key=obs.identity_key,
                native_source_table="persistence_entries",
                native_source_id=native_id,
                detail=(
                    f"osquery and Secure's own native persistence scan both independently "
                    f"observed a launchd entry ('{label or obs.identity_key}')."
                ),
            )
        )
    return matches
