"""
secure/validate/scenarios/connections.py — "unusual outbound
connections" from the instruction's own behavior list.

Injection boundary: `secure.connections.scanner.run` (the `lsof`
subprocess wrapper) — same patch target
tests/test_connections.py already uses.

Honesty note carried into every result here: secure/connections/ has
no dedicated `*_alerts` table or explainer (see database.py — only
`remote_endpoints`/`connection_events` exist for this module) — "did
Secure observe it" is measured by a new `remote_endpoints` row
appearing, not by an alert firing, and explanation_checklist is left
empty ({}) rather than forced through secure/explain/, which has
nothing registered for this table.
"""

from __future__ import annotations

from unittest.mock import patch

from secure.connections._shell import ShellResult
from secure.connections.scanner import scan_connections
from secure.storage.models import list_remote_endpoints
from secure.validate import CATEGORY_OUTBOUND_CONNECTION, OUTCOME_MISS, OUTCOME_PASS, OUTCOME_SENSOR_UNAVAILABLE
from secure.validate.attck import T1071_001
from secure.validate.sandbox import Sandbox
from secure.validate.scenario import ScenarioResult, timed

_LSOF_HEADER = "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"


def _fake_lsof(entry_line: str) -> str:
    return _LSOF_HEADER + entry_line


def scenario_new_outbound_endpoint(sb: Sandbox) -> ScenarioResult:
    def build():
        import secure.connections.scanner as scanner_module

        line = (
            "curl       4321  erick   12u  IPv4 0x3333333333333333      0t0  TCP "
            "192.168.1.23:55555->203.0.113.9:8443 (ESTABLISHED)\n"
        )
        with patch.object(
            scanner_module, "run",
            lambda *a, **k: ShellResult(ok=True, stdout=_fake_lsof(line), stderr="", returncode=0),
        ):
            result = scan_connections(sb.conn)

        endpoints = list_remote_endpoints(sb.conn)
        matched = [e for e in endpoints if e.remote_addr == "203.0.113.9" and e.remote_port == 8443]
        observed = result.lsof_available and len(matched) == 1 and len(result.new_endpoints) == 1

        return ScenarioResult(
            scenario_id="connections_new_outbound_endpoint",
            technique_id=T1071_001.technique_id,
            technique_name=T1071_001.name,
            category=CATEGORY_OUTBOUND_CONNECTION,
            description="A previously-unseen outbound connection to a new remote destination.",
            expected_result="A new remote_endpoints row is recorded and flagged as new.",
            sensors_observed=["connections"] if observed else [],
            findings=[{"table": "remote_endpoints", "id": e.id, "remote_addr": e.remote_addr, "remote_port": e.remote_port} for e in matched],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if observed else OUTCOME_MISS,
            notes="" if observed else "Expected new remote_endpoints row was not recorded/flagged.",
            started_at="",
            completed_at="",
        )

    return timed("connections_new_outbound_endpoint", build)


def scenario_known_endpoint_not_reflagged(sb: Sandbox) -> ScenarioResult:
    def build():
        import secure.connections.scanner as scanner_module

        line = (
            "curl       4321  erick   12u  IPv4 0x3333333333333333      0t0  TCP "
            "192.168.1.23:55555->198.51.100.4:443 (ESTABLISHED)\n"
        )
        fake = lambda *a, **k: ShellResult(ok=True, stdout=_fake_lsof(line), stderr="", returncode=0)
        with patch.object(scanner_module, "run", fake):
            scan_connections(sb.conn)
            second = scan_connections(sb.conn)

        no_false_reflag = len(second.new_endpoints) == 0

        return ScenarioResult(
            scenario_id="connections_known_endpoint_not_reflagged",
            technique_id=T1071_001.technique_id,
            technique_name=T1071_001.name,
            category=CATEGORY_OUTBOUND_CONNECTION,
            description="The same destination seen on a second scan — a false-positive/noise check.",
            expected_result="Not flagged as new on the second scan.",
            sensors_observed=["connections"],
            findings=[],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if no_false_reflag else OUTCOME_MISS,
            notes="" if no_false_reflag else "An already-known destination was incorrectly re-flagged as new.",
            started_at="",
            completed_at="",
        )

    return timed("connections_known_endpoint_not_reflagged", build)


def scenario_lsof_sensor_unavailable(sb: Sandbox) -> ScenarioResult:
    def build():
        import secure.connections.scanner as scanner_module

        fake = lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)
        with patch.object(scanner_module, "run", fake):
            result = scan_connections(sb.conn)

        honestly_reported = result.lsof_available is False and result.entries == []

        return ScenarioResult(
            scenario_id="connections_lsof_sensor_unavailable",
            technique_id=None,
            technique_name=None,
            category=CATEGORY_OUTBOUND_CONNECTION,
            description="`lsof` fails to run entirely (simulated tool-unavailable condition).",
            expected_result="Reported as lsof_available=False, never silently treated as 'no connections, all clean.'",
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

    return timed("connections_lsof_sensor_unavailable", build)


SCENARIOS = [
    scenario_new_outbound_endpoint,
    scenario_known_endpoint_not_reflagged,
    scenario_lsof_sensor_unavailable,
]
