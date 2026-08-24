"""
secure/validate/scenarios/listening.py — "new listeners" from the
instruction's own behavior list.

Same patch-target/honesty-note shape as connections.py — no dedicated
`*_alerts` table or explainer exists for this module either.
"""

from __future__ import annotations

from unittest.mock import patch

from secure.listening._shell import ShellResult
from secure.listening.scanner import scan_listening_services
from secure.storage.models import list_listening_services
from secure.validate import CATEGORY_LISTENER, OUTCOME_MISS, OUTCOME_PASS, OUTCOME_SENSOR_UNAVAILABLE
from secure.validate.attck import T1571
from secure.validate.sandbox import Sandbox
from secure.validate.scenario import ScenarioResult, timed

_LSOF_HEADER = "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"


def scenario_new_listener_on_nonstandard_port(sb: Sandbox) -> ScenarioResult:
    def build():
        import secure.listening.scanner as scanner_module

        stdout = _LSOF_HEADER + (
            "backdoor   6789  erick    4u  IPv4 0x5555555555555555      0t0  TCP *:31337 (LISTEN)\n"
        )
        fake = lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)
        with patch.object(scanner_module, "run", fake):
            result = scan_listening_services(sb.conn)

        services = list_listening_services(sb.conn)
        matched = [s for s in services if s.local_port == 31337]
        observed = result.lsof_available and len(result.new_services) == 1 and len(matched) == 1

        return ScenarioResult(
            scenario_id="listening_new_listener_nonstandard_port",
            technique_id=T1571.technique_id,
            technique_name=T1571.name,
            category=CATEGORY_LISTENER,
            description="A new process starts listening on a non-standard, high-numbered port.",
            expected_result="A new listening_services row is recorded and flagged as new.",
            sensors_observed=["listening"] if observed else [],
            findings=[{"table": "listening_services", "id": s.id, "port": s.local_port} for s in matched],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if observed else OUTCOME_MISS,
            notes="" if observed else "Expected new listening_services row was not recorded/flagged.",
            started_at="",
            completed_at="",
        )

    return timed("listening_new_listener_nonstandard_port", build)


def scenario_known_listener_not_reflagged(sb: Sandbox) -> ScenarioResult:
    def build():
        import secure.listening.scanner as scanner_module

        stdout = _LSOF_HEADER + "sshd         99   root    3u  IPv4 0x1111111111111111      0t0  TCP *:22 (LISTEN)\n"
        fake = lambda *a, **k: ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)
        with patch.object(scanner_module, "run", fake):
            scan_listening_services(sb.conn)
            second = scan_listening_services(sb.conn)

        no_false_reflag = len(second.new_services) == 0

        return ScenarioResult(
            scenario_id="listening_known_listener_not_reflagged",
            technique_id=T1571.technique_id,
            technique_name=T1571.name,
            category=CATEGORY_LISTENER,
            description="The same well-known service (sshd:22) seen on a second scan — a false-positive/noise check.",
            expected_result="Not flagged as new on the second scan.",
            sensors_observed=["listening"],
            findings=[],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if no_false_reflag else OUTCOME_MISS,
            notes="" if no_false_reflag else "An already-known listener was incorrectly re-flagged as new.",
            started_at="",
            completed_at="",
        )

    return timed("listening_known_listener_not_reflagged", build)


def scenario_lsof_sensor_unavailable(sb: Sandbox) -> ScenarioResult:
    def build():
        import secure.listening.scanner as scanner_module

        fake = lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)
        with patch.object(scanner_module, "run", fake):
            result = scan_listening_services(sb.conn)

        honestly_reported = result.lsof_available is False and result.entries == []

        return ScenarioResult(
            scenario_id="listening_lsof_sensor_unavailable",
            technique_id=None,
            technique_name=None,
            category=CATEGORY_LISTENER,
            description="`lsof` fails to run entirely (simulated tool-unavailable condition).",
            expected_result="Reported as lsof_available=False, never silently treated as 'no listeners, all clean.'",
            sensors_observed=[],
            findings=[],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_SENSOR_UNAVAILABLE if honestly_reported else OUTCOME_MISS,
            notes="" if honestly_reported else "Sensor failure was not honestly reported.",
            started_at="",
            completed_at="",
        )

    return timed("listening_lsof_sensor_unavailable", build)


SCENARIOS = [
    scenario_new_listener_on_nonstandard_port,
    scenario_known_listener_not_reflagged,
    scenario_lsof_sensor_unavailable,
]
