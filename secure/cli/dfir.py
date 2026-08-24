"""
secure/cli/dfir.py — Phase 24: `secure dfir ...`, the CLI front end for
secure/dfir/. `collect` is the ONLY command in this whole app that can
run an external forensic-collection tool against this Mac — see
secure/dfir/__init__.py's own rule 1 for why every other path into this
package (suggest, status, list, show, evidence) is strictly read-only.
Thin on purpose: every real decision (allowlist enforcement, what
counts as a candidate, how a collection's outcome is classified) lives
in secure/dfir/ itself; this module only parses arguments and formats
output.
"""

from __future__ import annotations

import argparse
from typing import Dict

from secure.dfir.collector import ArtifactNotAllowedError, CollectionRequest, collect_evidence
from secure.dfir.suggest import suggest_collections
from secure.dfir.velociraptor.availability import check_availability
from secure.investigate.entity import ENTITY_TYPES, EntityRef
from secure.storage.database import Database
from secure.storage.models import (
    find_forensic_collection_by_id,
    list_forensic_collections,
    list_forensic_evidence_items_for_collection,
)
from secure.cli import _bootstrap, logger


def cmd_dfir_status(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    health = check_availability(cfg)
    print(f"velociraptor: {health.status.upper()}")
    print(f"  {health.detail}")
    if health.tool_version:
        print(f"  version: {health.tool_version}")
    print()
    if cfg.dfir_artifact_allowlist:
        print("Allowed artifacts (AppConfig.dfir_artifact_allowlist):")
        for name in cfg.dfir_artifact_allowlist:
            print(f"  - {name}")
    else:
        print(
            "No artifacts are currently allowed — dfir_artifact_allowlist is empty. "
            "secure dfir collect will refuse every artifact until you add names to it "
            "in config.json."
        )
    return 0


def cmd_dfir_suggest(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    try:
        entity = EntityRef(entity_type=args.entity_type, entity_key=args.entity_key)
    except ValueError as exc:
        print(f"Invalid entity: {exc}")
        return 1

    with Database(cfg.database_path()) as db:
        candidates = suggest_collections(db.conn, entity)

    if not candidates:
        print(f"No collection candidates for {entity} — nothing on record clears the severity/confidence bar.")
        return 0

    print(f"Collection candidates for {entity}:\n")
    for candidate in candidates:
        print(f"  {candidate.source_table}#{candidate.source_id} — [{candidate.severity.upper()}/{candidate.confidence}]")
        print(f"    {candidate.summary}")
        print(f"    {candidate.reason}")
        print()

    if cfg.dfir_artifact_allowlist:
        print(f"Your allowed artifacts: {', '.join(cfg.dfir_artifact_allowlist)}")
        print(
            f"Review, then: secure dfir collect --artifact <name> --entity-type {entity.entity_type} "
            f"--entity-key {entity.entity_key!r} --reason \"...\" [--source-table T --source-id N]"
        )
    else:
        print("No artifacts are currently allowed (dfir_artifact_allowlist is empty) — "
              "add one to config.json before collecting.")
    return 0


def _parse_params(pairs) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"--param must be KEY=VALUE, got {pair!r}")
        key, _, value = pair.partition("=")
        params[key] = value
    return params


def cmd_dfir_collect(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    try:
        entity = EntityRef(entity_type=args.entity_type, entity_key=args.entity_key)
    except ValueError as exc:
        print(f"Invalid entity: {exc}")
        return 1

    try:
        parameters = _parse_params(args.param)
    except ValueError as exc:
        print(str(exc))
        return 1

    request = CollectionRequest(
        artifact_name=args.artifact,
        parameters=parameters,
        reason=args.reason,
        entity=entity,
        source_table=args.source_table,
        source_id=args.source_id,
    )

    with Database(cfg.database_path()) as db:
        try:
            record = collect_evidence(db.conn, cfg, request)
        except ArtifactNotAllowedError as exc:
            print(f"Refused: {exc}")
            return 1

    print(f"Collection #{record.id}: {record.artifact_name} — {record.status.upper()}")
    print(f"  {record.detail}")
    print(f"  entity: {record.entity_type}:{record.entity_key}")
    print(f"  reason: {record.reason}")
    if record.tool_version:
        print(f"  velociraptor version: {record.tool_version}")
    print(f"  evidence items: {record.evidence_item_count}")

    logger.info(
        "Ran a DFIR collection",
        extra={"event": "dfir_collect", "component": "cli"},
    )
    return 0 if record.status in ("ok", "degraded") else 1


def cmd_dfir_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        collections = list_forensic_collections(
            db.conn, entity_type=args.entity_type, entity_key=args.entity_key, limit=args.limit
        )

    if not collections:
        print("No forensic collections recorded yet. Run: secure dfir collect ...")
        return 0

    for record in collections:
        print(
            f"#{record.id:<4} [{record.status.upper():11}] {record.artifact_name} — "
            f"{record.entity_type}:{record.entity_key} — {record.created_at}"
        )
        print(f"      {record.detail}")

    return 0


def cmd_dfir_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        record = find_forensic_collection_by_id(db.conn, args.collection_id)
        if record is None:
            print(f"No forensic collection found with id {args.collection_id}. Run `secure dfir list`.")
            return 1

        print(f"Collection #{record.id}: {record.artifact_name} — {record.status.upper()}")
        print(f"  {record.detail}")
        print(f"  entity:       {record.entity_type}:{record.entity_key}")
        print(f"  reason:       {record.reason}")
        print(f"  parameters:   {record.parameters}")
        if record.source_table:
            print(f"  motivated by: {record.source_table}#{record.source_id}")
        print(f"  requested_at: {record.requested_at}")
        print(f"  started_at:   {record.started_at}")
        print(f"  completed_at: {record.completed_at}")
        if record.tool_version:
            print(f"  tool_version: {record.tool_version}")
        print(f"  evidence items: {record.evidence_item_count} (see `secure dfir evidence {record.id}`)")

    return 0


def cmd_dfir_evidence(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        record = find_forensic_collection_by_id(db.conn, args.collection_id)
        if record is None:
            print(f"No forensic collection found with id {args.collection_id}. Run `secure dfir list`.")
            return 1

        items = list_forensic_evidence_items_for_collection(db.conn, args.collection_id)

    if not items:
        print(f"Collection #{record.id} ({record.status.upper()}) has no evidence items recorded.")
        if record.status not in ("ok", "degraded"):
            print("This collection did not complete successfully — absence of evidence here means "
                  "unavailable/failed, not 'nothing found'. See `secure dfir show "
                  f"{record.id}` for why.")
        return 0

    print(f"Evidence items for collection #{record.id} ({record.artifact_name}):\n")
    for item in items:
        print(f"  [{item.raw_row_index}] {item.fields}")

    return 0
