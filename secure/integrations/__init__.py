"""
secure/integrations/ — external security-engine integrations.

Phase 15 adds the first one, osquery (secure/integrations/osquery/).
Everything generic enough to be reused by a future second integration
lives in base.py: identity/version, health/availability, collection
timestamps, normalized observations, and exact source provenance. See
base.py's module docstring for the full design rationale.

Secure's own native collectors (connections/, listening/, persistence/,
...) are never replaced or disabled by an integration — an integration
is treated as an additional, cross-checking source only. See
secure/integrations/osquery/crosscheck.py for how a cross-check
discrepancy becomes an alert without ever double-counting an observation
that both a native collector and an integration independently agree on
— see that module's docstring for the full reasoning.
"""

from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    ExternalObservation,
    IntegrationHealth,
    IntegrationIdentity,
)

__all__ = [
    "STATUS_DEGRADED",
    "STATUS_ERROR",
    "STATUS_OK",
    "STATUS_UNAVAILABLE",
    "ExternalObservation",
    "IntegrationHealth",
    "IntegrationIdentity",
]
