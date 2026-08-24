"""
integrations/yarax/targets.py — selects WHICH files get scanned,
answering Phase 16's explicit instruction to "avoid indiscriminate
whole-disk scanning; prioritize suspicious files, user-requested files,
and security-relevant FIM events." Nothing here scans anything — these
are pure read-only queries over already-stored alerts, returning a
bounded, explainable list of candidate paths with the reason each one
was selected.

Three sources, each its own function so a caller (CLI/scanner) can
choose exactly which to use rather than getting an undifferentiated
blob:

    - `fim_alert_targets()` — files File Integrity Monitoring already
      flagged as MEDIUM/HIGH severity created/modified/metadata_only/
      renamed (LOW severity and `deleted` are excluded — LOW isn't
      "security-relevant" by FIM's own severity model, see
      secure/fileintegrity/analysis.py, and a deleted file has nothing
      left to scan).
    - `persistence_suspicious_targets()` — executables Process and
      Persistence Monitoring already flagged as unusual/unsigned (the
      "suspicious files" bullet).
    - user-requested files are simply whatever paths a caller passes
      directly to scanner.scan_paths() — no helper needed here, that's
      the whole point of it being user-directed.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List, Optional

from secure.storage.models import list_file_integrity_alerts, list_persistence_alerts

_FIM_SCANNABLE_KINDS = ("created", "modified", "metadata_only", "renamed")
_FIM_SCANNABLE_SEVERITIES = ("medium", "high")


@dataclass(frozen=True)
class ScanTarget:
    path: str
    reason: str
    source_table: str
    source_id: int


def fim_alert_targets(
    conn: sqlite3.Connection, limit: int = 100, include_reviewed: bool = False
) -> List[ScanTarget]:
    """MEDIUM/HIGH file_integrity_alerts with a still-scannable path.
    `include_reviewed=False` (default) skips alerts already marked
    known — an already-reviewed, explained change doesn't need a fresh
    YARA pass every time this is run.
    """
    targets: List[ScanTarget] = []
    for alert in list_file_integrity_alerts(conn, limit=limit):
        if alert.severity not in _FIM_SCANNABLE_SEVERITIES:
            continue
        if alert.kind not in _FIM_SCANNABLE_KINDS:
            continue
        if not include_reviewed and alert.known:
            continue
        if not alert.path:
            continue
        targets.append(
            ScanTarget(
                path=alert.path,
                reason=f"file_integrity_alerts#{alert.id} ({alert.kind}, {alert.severity})",
                source_table="file_integrity_alerts",
                source_id=alert.id,
            )
        )
    return targets


def persistence_suspicious_targets(
    conn: sqlite3.Connection, limit: int = 100, include_reviewed: bool = False
) -> List[ScanTarget]:
    """persistence_alerts rows flagging an unusual/unsigned executable
    (kind="unusual_unsigned_process", target_type="process") — these
    already carry a resolvable executable path as `identifier`.
    """
    targets: List[ScanTarget] = []
    for alert in list_persistence_alerts(conn, limit=limit):
        if alert.kind != "unusual_unsigned_process" or alert.target_type != "process":
            continue
        if not include_reviewed and alert.known:
            continue
        if not alert.identifier:
            continue
        targets.append(
            ScanTarget(
                path=alert.identifier,
                reason=f"persistence_alerts#{alert.id} (unusual_unsigned_process)",
                source_table="persistence_alerts",
                source_id=alert.id,
            )
        )
    return targets
