"""
secure/persistence — Phase 10: Process and Persistence Monitor.

Inventories running processes and this Mac's common startup/
persistence mechanisms (LaunchAgents, LaunchDaemons, login items),
records executable paths and best-effort code-signing information, and
flags newly-appearing persistence entries plus unusual or unsigned
executables — all read-only, no sudo, and never automatically deleting
or quarantining anything. See PROJECT_NOTES.md's "Process and
Persistence Monitor" section for the full explanation, including what
this deliberately does not cover.
"""

from secure.persistence.scanner import PersistenceScanResult, scan_persistence

__all__ = ["scan_persistence", "PersistenceScanResult"]
