"""
secure/integrations/osquery/ — Phase 15's first concrete integration:
osquery (https://osquery.io), queried read-only via its `osqueryi`
one-shot binary — never `osqueryd`, never any config install/modify.

    _shell.py       — the only file allowed to run a subprocess.
    availability.py — classifies osqueryi into one of
                       IntegrationHealth's four statuses.
    queries.py       — the exact SQL text this integration runs, and
                       nothing else.
    parser.py        — osqueryi JSON rows -> normalized
                       ExternalObservations (secure/integrations/base.py).
    crosscheck.py     — compares this scan's observations against
                       Secure's own native identity tables; only a
                       genuine DISCREPANCY becomes an alert (see its
                       module docstring for the double-counting design).
    scanner.py        — orchestrates one full pass and is the only file
                       here that touches the database.

Secure's own native collectors are never disabled, replaced, or blocked
by this package — osquery is an additional, cross-checking source only.
"""

from secure.integrations.osquery.availability import check_availability
from secure.integrations.osquery.crosscheck import (
    NATIVE_ONLY,
    OSQUERY_ONLY,
    Discrepancy,
    crosscheck_listening_ports,
    crosscheck_persistence,
)
from secure.integrations.osquery.scanner import INTEGRATION_NAME, OsqueryScanResult, scan_osquery

__all__ = [
    "check_availability",
    "NATIVE_ONLY",
    "OSQUERY_ONLY",
    "Discrepancy",
    "crosscheck_listening_ports",
    "crosscheck_persistence",
    "INTEGRATION_NAME",
    "OsqueryScanResult",
    "scan_osquery",
]
