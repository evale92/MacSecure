"""
secure/validate/scenarios/persistence.py — "persistence creation" and
part of "unusual process execution" from the instruction's own
behavior list, plus one deliberate sensor-failure and one deliberate
NOT_EVALUABLE case.

Injection boundary: `secure.persistence.launch_items._LAUNCH_ITEM_DIRECTORIES`
(so a REAL plist file is written to a REAL temp directory and genuinely
parsed by plistlib — full-fidelity, not a bypass) and
`secure.persistence.scanner.list_processes` / `.get_login_items` /
`.check_code_signing` — the exact same four patch points
tests/test_persistence.py already uses, applied here via
unittest.mock.patch instead of pytest's monkeypatch fixture (this
module runs at CLI-invocation time, not under pytest).
"""

from __future__ import annotations

import plistlib
from contextlib import ExitStack
from unittest.mock import patch

from secure.explain.dispatch import explain
from secure.persistence.codesign import SIGNED_APPLE, UNSIGNED
from secure.persistence.scanner import scan_persistence
from secure.storage.models import list_persistence_alerts
from secure.validate import (
    CATEGORY_PERSISTENCE,
    CATEGORY_PROCESS_EXECUTION,
    OUTCOME_MISS,
    OUTCOME_NOT_EVALUABLE,
    OUTCOME_PASS,
    OUTCOME_SENSOR_UNAVAILABLE,
)
from secure.validate.attck import T1204_002, T1547_011
from secure.validate.rubric import score_explanation
from secure.validate.sandbox import Sandbox
from secure.validate.scenario import ScenarioResult, timed


def _write_plist(path, label: str, program_path: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        plistlib.dump({"Label": label, "Program": program_path, "RunAtLoad": True}, f)


def _run_persistence_scan(sb: Sandbox, *, daemon_program_path=None, signing_map=None, ps_result=None):
    import secure.persistence.launch_items as launch_items_module
    import secure.persistence.scanner as scanner_module

    tmp_root = sb.cfg.app_dir_path() / "validate_fixtures"
    daemons_dir = tmp_root / "LaunchDaemons"
    agents_dir = tmp_root / "LaunchAgentsUser"
    global_agents_dir = tmp_root / "LaunchAgentsGlobal"

    if daemon_program_path is not None:
        _write_plist(daemons_dir / "com.secure.validate.test.plist", "com.secure.validate.test", daemon_program_path)

    fresh_dirs = {
        "launch_agent_user": [agents_dir],
        "launch_agent_global": [global_agents_dir],
        "launch_daemon": [daemons_dir],
    }
    signing_map = signing_map or {}

    with ExitStack() as stack:
        stack.enter_context(patch.object(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh_dirs))
        stack.enter_context(patch.object(scanner_module, "list_processes", lambda: ps_result or (True, [])))
        stack.enter_context(patch.object(scanner_module, "get_login_items", lambda: (True, [])))
        stack.enter_context(
            patch.object(scanner_module, "check_code_signing", lambda p: signing_map.get(p, UNSIGNED))
        )
        return scan_persistence(sb.conn)


def scenario_new_launch_daemon_unsigned(sb: Sandbox) -> ScenarioResult:
    def build():
        program_path = "/tmp/validate/sketchy-daemon-tool"
        result = _run_persistence_scan(
            sb, daemon_program_path=program_path, signing_map={program_path: UNSIGNED}
        )
        alerts = list_persistence_alerts(sb.conn)
        new_entry_alerts = [a for a in alerts if a.kind == "new_persistence_entry"]

        explanation = None
        if new_entry_alerts:
            explanation = explain(new_entry_alerts[0], "persistence_alerts")
        checklist = score_explanation(explanation)

        fired = len(new_entry_alerts) >= 1 and new_entry_alerts[0].severity == "high"
        outcome = OUTCOME_PASS if fired else OUTCOME_MISS

        return ScenarioResult(
            scenario_id="persistence_new_launch_daemon_unsigned",
            technique_id=T1547_011.technique_id,
            technique_name=T1547_011.name,
            category=CATEGORY_PERSISTENCE,
            description=(
                "A new LaunchDaemon plist appears, backed by an unsigned executable in an "
                "unexpected location — the representative shape of T1547.011."
            ),
            expected_result="A HIGH-severity 'new_persistence_entry' alert fires.",
            sensors_observed=["persistence"] if new_entry_alerts else [],
            findings=[
                {"table": "persistence_alerts", "id": a.id, "severity": a.severity, "kind": a.kind}
                for a in new_entry_alerts
            ],
            correlation_result=None,
            explanation_checklist=checklist,
            dedup_result=None,
            latency_ms=None,
            outcome=outcome,
            notes="" if fired else "Expected alert did not fire — see findings for what scan_persistence actually recorded.",
            started_at="",
            completed_at="",
        )

    return timed("persistence_new_launch_daemon_unsigned", build)


def scenario_new_launch_daemon_signed_benign(sb: Sandbox) -> ScenarioResult:
    def build():
        program_path = "/usr/local/bin/homebrew-service"
        result = _run_persistence_scan(
            sb, daemon_program_path=program_path, signing_map={program_path: SIGNED_APPLE}
        )
        alerts = list_persistence_alerts(sb.conn)
        new_entry_alerts = [a for a in alerts if a.kind == "new_persistence_entry"]
        # A signed, unremarkable new entry still raises a routine MEDIUM
        # "new persistence entry" alert (Secure surfaces every new entry,
        # just not at HIGH severity) — the false-positive bar here is
        # "did it get incorrectly escalated," not "did it get mentioned."
        escalated = [a for a in new_entry_alerts if a.severity == "high"]
        no_false_escalation = len(escalated) == 0

        return ScenarioResult(
            scenario_id="persistence_new_launch_daemon_signed_benign",
            technique_id=T1547_011.technique_id,
            technique_name=T1547_011.name,
            category=CATEGORY_PERSISTENCE,
            description="A new LaunchDaemon plist backed by a normally-signed executable — a false-positive check.",
            expected_result="No HIGH-severity alert (a routine MEDIUM new-entry alert is fine).",
            sensors_observed=["persistence"],
            findings=[
                {"table": "persistence_alerts", "id": a.id, "severity": a.severity, "kind": a.kind}
                for a in new_entry_alerts
            ],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if no_false_escalation else OUTCOME_MISS,
            notes="" if no_false_escalation else "A signed, unremarkable entry was incorrectly escalated to HIGH.",
            started_at="",
            completed_at="",
        )

    return timed("persistence_new_launch_daemon_signed_benign", build)


def scenario_unusual_unsigned_process(sb: Sandbox) -> ScenarioResult:
    def build():
        path = "/private/tmp/validate/unusual-tool"
        ps_result = (True, [{"pid": "4242", "ppid": "1", "user": "erick", "path_or_name": path}])
        _run_persistence_scan(sb, signing_map={path: UNSIGNED}, ps_result=ps_result)
        alerts = list_persistence_alerts(sb.conn)
        process_alerts = [a for a in alerts if a.kind == "unusual_unsigned_process"]

        explanation = explain(process_alerts[0], "persistence_alerts") if process_alerts else None
        checklist = score_explanation(explanation)
        fired = len(process_alerts) >= 1 and process_alerts[0].severity == "high"

        return ScenarioResult(
            scenario_id="persistence_unusual_unsigned_process",
            technique_id=T1204_002.technique_id,
            technique_name=T1204_002.name,
            category=CATEGORY_PROCESS_EXECUTION,
            description="A brand-new process, unsigned, running from an unusual location.",
            expected_result="A HIGH-severity 'unusual_unsigned_process' alert fires.",
            sensors_observed=["persistence"] if process_alerts else [],
            findings=[
                {"table": "persistence_alerts", "id": a.id, "severity": a.severity, "kind": a.kind}
                for a in process_alerts
            ],
            correlation_result=None,
            explanation_checklist=checklist,
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if fired else OUTCOME_MISS,
            notes="" if fired else "Expected alert did not fire.",
            started_at="",
            completed_at="",
        )

    return timed("persistence_unusual_unsigned_process", build)


def scenario_process_sensor_unavailable(sb: Sandbox) -> ScenarioResult:
    def build():
        result = _run_persistence_scan(sb, ps_result=(False, []))
        honestly_reported = result.processes_available is False and result.process_count == 0

        return ScenarioResult(
            scenario_id="persistence_process_sensor_unavailable",
            technique_id=None,
            technique_name=None,
            category=CATEGORY_PROCESS_EXECUTION,
            description="`ps` fails to run entirely (simulated tool-unavailable condition).",
            expected_result="Reported as processes_available=False, never silently treated as 'zero processes, all clean.'",
            sensors_observed=[],
            findings=[],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_SENSOR_UNAVAILABLE if honestly_reported else OUTCOME_MISS,
            notes=(
                "Correctly reported as unavailable, not as a clean scan."
                if honestly_reported
                else "Sensor failure was not honestly reported — this would be a serious false-negative risk."
            ),
            started_at="",
            completed_at="",
        )

    return timed("persistence_process_sensor_unavailable", build)


def scenario_background_items_not_evaluable(sb: Sandbox) -> ScenarioResult:
    """No fixture injection possible here at all — this is a
    permanent, already-documented capability boundary
    (secure/persistence/login_items.py's own docstring): modern macOS
    "Background Items" (ServiceManagement/SMAppService) are not
    enumerable via classic System Events login items, the only
    mechanism this module has. Included specifically because the
    instruction requires recording real limitations, not just passing
    scenarios.
    """

    def build():
        return ScenarioResult(
            scenario_id="persistence_background_items_not_evaluable",
            technique_id=T1547_011.technique_id,
            technique_name=T1547_011.name,
            category=CATEGORY_PERSISTENCE,
            description=(
                "A modern macOS 'Background Item' (ServiceManagement/SMAppService), as opposed "
                "to a classic System Events login item."
            ),
            expected_result="N/A — documented capability gap, not a fixture-testable behavior.",
            sensors_observed=[],
            findings=[],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_NOT_EVALUABLE,
            notes=(
                "secure/persistence/login_items.py only reads classic System Events login items. "
                "Background Items require `sfltool dumpbtm`, whose output format is undocumented "
                "and version-dependent; this project has never implemented it without a real Mac "
                "to verify against (see PROJECT_NOTES.md 'What's deliberately NOT here yet')."
            ),
            started_at="",
            completed_at="",
        )

    return timed("persistence_background_items_not_evaluable", build)


SCENARIOS = [
    scenario_new_launch_daemon_unsigned,
    scenario_new_launch_daemon_signed_benign,
    scenario_unusual_unsigned_process,
    scenario_process_sensor_unavailable,
    scenario_background_items_not_evaluable,
]
