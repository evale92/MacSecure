"""
integrations/base.py — the generic boundary every external
security-engine integration (osquery today, others later) is built on.

Deliberately minimal, per Phase 15's explicit instruction: "design the
smallest generic integration boundary needed for future engines... do
not prematurely build the entire future unified-evidence architecture."
No class hierarchies, no ABCs, no plugin registry — plain dataclasses
and plain string constants, matching every other package in this app
(see secure/listening/_shell.py's ShellResult, secure/persistence/
codesign.py's plain status strings, ...).

Five concepts, matching the Phase 15 request's own bullet list:

    1. Identity/version    — IntegrationIdentity: which integration this
       is, and this integration MODULE's own normalized-shape version
       (NOT the external tool's own version — that's
       IntegrationHealth.tool_version below, since it can only be
       discovered at runtime, may be unknown, and changes independently
       of this code).
    2. Health/availability — IntegrationHealth: whether the external
       tool was usable for one collection attempt, one of exactly four
       states (see STATUS_* below).
    3. Collection timestamp — both IntegrationHealth and
       ExternalObservation carry their own `collected_at`, not inferred
       later from "when this function happened to return."
    4. Normalized observations — ExternalObservation: one fact from the
       external tool, reshaped into a common (kind, identity_key,
       fields) shape so callers don't need to know any one integration's
       own table/column conventions.
    5. Exact source provenance — ExternalObservation.source_query
       records the exact query/command that produced it, not a
       paraphrase; once persisted, callers reference the real
       `integration_observations.id` row it became — never a
       deduplicated identity row — exactly the same discipline Phase
       14.5 Stage B established for connections/wifi/listening/
       persistence provenance.

A future second integration (e.g. a YARA-based scanner) reuses these
same two dataclasses unchanged; it does not require any change here or
to osquery's own submodules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ---------- Health/availability ----------
#
# Exactly four states — no fifth "silently fine" state that could mask
# a failure as a clean pass, per Phase 15's explicit instruction:
# "External-tool failure must appear as unavailable/degraded, never
# clean."
STATUS_OK = "ok"                    # ran, everything requested worked
STATUS_DEGRADED = "degraded"        # ran, but only part of what was
                                     # requested was usable
STATUS_UNAVAILABLE = "unavailable"  # the tool isn't installed/reachable
                                     # at all — routine, not an error
STATUS_ERROR = "error"              # the tool is present but this
                                     # attempt failed unexpectedly

_VALID_STATUSES = (STATUS_OK, STATUS_DEGRADED, STATUS_UNAVAILABLE, STATUS_ERROR)


@dataclass(frozen=True)
class IntegrationIdentity:
    """Which integration this is, and this integration module's own
    normalized-observation-shape version.

    `name` is a short stable identifier (e.g. "osquery") used as the
    `integration` column value everywhere it's persisted. `schema_version`
    should be bumped only when THIS integration's ExternalObservation
    `fields` shape changes in a way a caller would need to know about —
    it has nothing to do with the external tool's own version, which is
    discovered at runtime and lives on IntegrationHealth instead.
    """

    name: str
    schema_version: int


@dataclass(frozen=True)
class IntegrationHealth:
    """The result of one attempt to use an external tool.

    status is always exactly one of STATUS_OK / STATUS_DEGRADED /
    STATUS_UNAVAILABLE / STATUS_ERROR (enforced in __post_init__).
    `detail` is a short human-readable explanation — always populated,
    even for STATUS_OK, so a caller never has to guess why a given
    status was reached. `tool_version` is the external tool's own
    version string when it could be determined, independent of this
    integration module's `schema_version`; None when unknown (e.g. the
    tool is unavailable, or version discovery itself failed).
    """

    status: str
    detail: str
    collected_at: str
    tool_version: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"invalid IntegrationHealth.status: {self.status!r}")

    @property
    def available(self) -> bool:
        """True if this collection attempt produced at least some
        usable data (ok or degraded) — False for unavailable/error,
        where nothing from this attempt should be trusted.
        """
        return self.status in (STATUS_OK, STATUS_DEGRADED)


@dataclass(frozen=True)
class ExternalObservation:
    """One normalized fact from an external tool.

    Reshaped into a shape shared by every integration — NOT a 1:1
    mirror of the tool's own row/table shape (that stays private to
    each integration's own parser module).

    kind          — what KIND of fact this is within this integration
                    (e.g. "process", "listening_port", "persistence"
                    for osquery) — namespaced per-integration, not
                    global across integrations.
    identity_key  — a stable string identifying the underlying
                    real-world thing this observation is ABOUT (e.g.
                    "tcp:8080" for a listening port), used to cross-check
                    against Secure's own native identity tables — see
                    osquery/crosscheck.py. This is NOT a database row id.
    fields        — the normalized fact itself: integration- and
                    kind-specific, e.g. {"proto": "tcp", "port": 8080,
                    "pid": 123, "process_name": "..."}.
    source_query  — the exact query/command that produced this row (the
                    literal SQL text passed to osqueryi, for example) —
                    exact provenance, not a paraphrase.
    collected_at  — when THIS observation was collected, independent of
                    when it's later persisted or read back.
    """

    kind: str
    identity_key: str
    fields: dict
    source_query: str
    collected_at: str
