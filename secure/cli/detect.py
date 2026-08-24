"""
secure/cli/detect.py — Phase 25: `secure detect ...`, the CLI front end
for secure/detect/. Thin on purpose: every real decision (discovery,
capability, validation, firing history) lives in secure/detect/ itself;
this module only parses arguments and formats output — the same split
secure/cli/dfir.py already established for its own package.
"""

from __future__ import annotations

import argparse

from secure.detect.firing_history import firing_history
from secure.detect.registry import FAMILY_CORRELATE, FAMILY_SURICATA, refresh_capability, sync_registry
from secure.detect.validate import validate_and_record
from secure.storage.database import Database
from secure.storage.models import (
    find_detection_rule_by_id,
    list_detection_rules,
    set_detection_rule_enabled,
    set_detection_rule_fp_notes,
)
from secure.cli import _bootstrap, logger

_TRACKING_ONLY_FAMILIES = (FAMILY_SURICATA, FAMILY_CORRELATE)


def cmd_detect_sync(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        result = sync_registry(db.conn, cfg)

    print(
        f"Synced detection rule catalog: {result.total_count} rule(s) "
        f"({result.new_count} new, {result.updated_count} updated)"
    )
    print(
        f"  sigma: {len(result.sigma)}   yarax: {len(result.yarax)}   "
        f"suricata: {len(result.suricata)}   correlate: {len(result.correlate)}"
    )
    for message in result.messages:
        print(f"  ! {message}")

    logger.info("Synced the detection rule catalog", extra={"event": "detect_sync", "component": "cli"})
    return 0


def cmd_detect_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    enabled_filter = None
    if args.enabled_only:
        enabled_filter = True
    elif args.disabled_only:
        enabled_filter = False

    with Database(cfg.database_path()) as db:
        rows = list_detection_rules(
            db.conn, family=args.family, enabled=enabled_filter,
            validation_status=args.validation_status, limit=args.limit,
        )

    if not rows:
        print("No detection rules match. Run `secure detect sync` if you haven't yet.")
        return 0

    for record in rows:
        state = "ENABLED " if record.enabled else "DISABLED"
        print(
            f"#{record.id:<4} [{record.family:<9}] {state} "
            f"[{record.capability_status:<14}] [{record.validation_status:<11}] "
            f"{record.rule_key} — {record.title}"
        )
    return 0


def cmd_detect_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        record = find_detection_rule_by_id(db.conn, args.rule_id)
        if record is None:
            print(f"No detection rule found with id {args.rule_id}. Run `secure detect list`.")
            return 1

        live_status, live_reason = refresh_capability(db.conn, cfg, record)

        print(f"Rule #{record.id}: [{record.family}] {record.rule_key}")
        print(f"  title:          {record.title}")
        print(f"  source:         {record.source}")
        print(f"  version:        {record.version_label}")
        print(f"  enabled:        {'yes' if record.enabled else 'no'}" + (
            " (tracking-only — Secure does not enforce this for this family)"
            if record.family in _TRACKING_ONLY_FAMILIES else ""
        ))
        print(f"  telemetry:      {record.required_telemetry}")
        print(f"  capability now: {live_status} — {live_reason}")
        if record.last_tested_at:
            print(f"  validation:     {record.validation_status} (last tested {record.last_tested_at})")
        else:
            print(f"  validation:     {record.validation_status} (never tested — run `secure detect test {record.id}`)")
        if record.false_positive_notes:
            print(f"  FP notes:       {record.false_positive_notes}")

        print()
        events = firing_history(db.conn, record, limit=args.limit)
        if not events:
            print("No recorded firings for this rule.")
        else:
            print(f"Recent firings ({len(events)}):")
            for event in events:
                label_part = f" {event.label}" if event.label else ""
                print(f"  {event.occurred_at} [{(event.severity or '?').upper()}]{label_part}")
                if event.explanation is not None:
                    print(f"    {event.explanation.summary}")

    return 0


def cmd_detect_enable(args: argparse.Namespace) -> int:
    return _set_enabled(args, True)


def cmd_detect_disable(args: argparse.Namespace) -> int:
    return _set_enabled(args, False)


def _set_enabled(args: argparse.Namespace, enabled: bool) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = set_detection_rule_enabled(db.conn, args.rule_id, enabled)
        if record is None:
            print(f"No detection rule found with id {args.rule_id}.")
            return 1
        word = "Enabled" if enabled else "Disabled"
        print(f"{word} rule #{record.id}: [{record.family}] {record.rule_key}")
        if record.family in _TRACKING_ONLY_FAMILIES:
            print(
                "  Note: enabled/disabled is tracking-only for this family — Secure never "
                "consults it when running a scan or a correlation pass."
            )
    return 0


def cmd_detect_test(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        if args.rule_id is not None:
            record = find_detection_rule_by_id(db.conn, args.rule_id)
            if record is None:
                print(f"No detection rule found with id {args.rule_id}.")
                return 1
            targets = [record]
        else:
            targets = list_detection_rules(db.conn, family=args.family, limit=1000)

        if not targets:
            print("No detection rules to test. Run `secure detect sync` if you haven't yet.")
            return 0

        overall_passed = True
        for record in targets:
            updated, outcomes = validate_and_record(db.conn, cfg, record)
            word = "PASSED" if updated.validation_status == "passed" else "FAILED"
            print(f"#{updated.id} [{updated.family}] {updated.rule_key}: {word}")
            for outcome in outcomes:
                mark = "ok  " if outcome.passed else "FAIL"
                print(f"    [{mark}] {outcome.fixture_name}: expected={outcome.expected} actual={outcome.actual}")
                print(f"           {outcome.detail}")
            if updated.validation_status != "passed":
                overall_passed = False

    logger.info("Ran detection rule validation", extra={"event": "detect_test", "component": "cli"})
    return 0 if overall_passed else 1


def cmd_detect_annotate(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    with Database(cfg.database_path()) as db:
        record = set_detection_rule_fp_notes(db.conn, args.rule_id, args.notes)
        if record is None:
            print(f"No detection rule found with id {args.rule_id}.")
            return 1
        print(f"Updated false-positive notes for rule #{record.id}: {record.false_positive_notes!r}")
    return 0
