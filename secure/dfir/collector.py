"""
secure/dfir/collector.py — Phase 24 Stage 5: the orchestration
entrypoint. This is the ONLY function in this whole codebase that ever
actually starts a Velociraptor collection — and it is only ever called
from `secure dfir collect`, one explicit, human-typed CLI command (see
secure/dfir/__init__.py's own rule 1). Nothing else in Secure — no
scan, no scheduled job, no correlation pass, no `run-all` — imports or
calls `collect_evidence()`.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from secure.config import AppConfig
from secure.dfir.velociraptor.collect import run_collection
from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE, EvidenceLink, ObservationRef
from secure.evidence.record import record_link
from secure.investigate.entity import EntityRef
from secure.investigate.resolve import resolve_entity
from secure.storage.models import (
    ForensicCollectionRecord,
    add_forensic_evidence_item,
    add_forensic_collection,
    find_forensic_collection_by_id,
)


class ArtifactNotAllowedError(ValueError):
    """Raised when `artifact_name` isn't in `AppConfig.
    dfir_artifact_allowlist` — the concrete enforcement of this
    package's own rule 4. Raised BEFORE any subprocess is started and
    BEFORE any forensic_collections row is written: a refused request
    leaves no trace in storage, because it never actually happened.
    """


@dataclass(frozen=True)
class CollectionRequest:
    """Everything an explicit `secure dfir collect` invocation
    supplies — plain data, so the CLI layer (secure/cli/dfir.py) stays
    thin and this orchestration function stays testable without
    argparse involved at all.
    """

    artifact_name: str
    parameters: Dict[str, str]
    reason: str
    entity: EntityRef
    source_table: "Optional[str]" = None
    source_id: "Optional[int]" = None


def collect_evidence(
    conn: sqlite3.Connection, cfg: AppConfig, request: CollectionRequest
) -> ForensicCollectionRecord:
    """Run one user-approved collection and persist its outcome (and
    every normalized evidence row it produced) in one call. Raises
    ArtifactNotAllowedError for an artifact outside the configured
    allowlist — the caller (the CLI) is expected to catch this and show
    the operator a clear refusal, never treat it as a collection that
    "failed."

    Every OTHER outcome — the binary missing, a timeout, a nonzero
    exit, zero result rows, partially malformed output, a clean success
    — is recorded via the SAME path: one forensic_collections row,
    whatever status secure/dfir/velociraptor/collect.py determined,
    plus zero-or-more forensic_evidence_items rows. There is no
    separate "the collection itself errored" code path outside normal
    storage — a failed collection is exactly as durably recorded as a
    successful one, per this package's own rule 3.
    """
    if request.artifact_name not in cfg.dfir_artifact_allowlist:
        raise ArtifactNotAllowedError(
            f"{request.artifact_name!r} is not in AppConfig.dfir_artifact_allowlist "
            f"({sorted(cfg.dfir_artifact_allowlist)!r}). Add it to config.json first if you "
            "intend to allow this artifact."
        )

    requested_at = datetime.now(timezone.utc).isoformat()
    outcome = run_collection(cfg, request.artifact_name, request.parameters)

    collection_id = add_forensic_collection(
        conn,
        requested_at=requested_at,
        started_at=outcome.started_at,
        completed_at=outcome.completed_at,
        artifact_name=request.artifact_name,
        parameters=request.parameters,
        reason=request.reason,
        entity_type=request.entity.entity_type,
        entity_key=request.entity.entity_key,
        source_table=request.source_table,
        source_id=request.source_id,
        status=outcome.status,
        detail=outcome.detail,
        tool_version=outcome.tool_version,
        evidence_item_count=len(outcome.rows),
    )

    collected_at = outcome.completed_at or requested_at
    for index, row in enumerate(outcome.rows):
        add_forensic_evidence_item(
            conn,
            collection_id=collection_id,
            kind=request.artifact_name,
            raw_row_index=index,
            fields=row,
            collected_at=collected_at,
        )

    # Closes the pipeline's own last step ("normalized forensic
    # evidence -> Secure investigation"): link this collection into
    # evidence_links (Phase 21) so build_timeline()/related_evidence()
    # (Phase 23) walk straight to it, exactly like every other
    # derived_evidence relationship already wired in Phase 22 Stage 1.
    # Two separate links, both best-effort and never fatal (the same
    # "enrichment must never fail the primary action" discipline that
    # wiring already established — a linking failure must never make an
    # otherwise-successful, or honestly-failed, collection look like it
    # didn't happen):
    #
    #   1. To the ENTITY's own anchor row(s) — guarantees this
    #      collection surfaces when investigating `request.entity`
    #      specifically, regardless of whether the motivating finding
    #      (if any) happens to itself be linked to that entity yet.
    #   2. To the motivating finding, when one was given — the "why"
    #      provenance a caller can trace independently of which entity
    #      happened to be under investigation at collection time.
    for anchor in resolve_entity(conn, request.entity).anchors:
        try:
            record_link(
                conn,
                EvidenceLink(
                    from_ref=ObservationRef(source_table="forensic_collections", source_id=collection_id),
                    to_ref=ObservationRef(source_table=anchor.source_table, source_id=anchor.source_id),
                    relationship=RELATIONSHIP_DERIVED_EVIDENCE,
                    match_basis="user_approved_collection",
                    detail=f"Collected {request.artifact_name!r} about this entity.",
                    created_by="dfir_collector",
                ),
            )
        except Exception:  # noqa: BLE001 — linking must never make a recorded collection look like it failed
            pass

    if request.source_table is not None and request.source_id is not None:
        try:
            record_link(
                conn,
                EvidenceLink(
                    from_ref=ObservationRef(source_table="forensic_collections", source_id=collection_id),
                    to_ref=ObservationRef(source_table=request.source_table, source_id=request.source_id),
                    relationship=RELATIONSHIP_DERIVED_EVIDENCE,
                    match_basis="user_approved_collection",
                    detail=f"Collected {request.artifact_name!r} because of this finding.",
                    created_by="dfir_collector",
                ),
            )
        except Exception:  # noqa: BLE001 — linking must never make a recorded collection look like it failed
            pass

    record = find_forensic_collection_by_id(conn, collection_id)
    assert record is not None  # the row we just inserted must be findable
    return record
