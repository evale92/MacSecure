"""
Tests for secure/explain/integration_explainer.py.

Named `test_explain_*` on purpose. `targeted_test_files()` in
secure/agent/tiers.py maps `secure/<package>/anything.py` to
`tests/test_<package>*.py`, so every file under secure/explain/ is
targeted by `tests/test_explain*.py` and nothing else. The ten existing
tests of this module live in tests/test_integrations_{yarax,sigma,
suricata}.py, which that glob never selects — measured 2026-09-11 by
mutating `attribution_established` to a constant `True`: the targeted
set (tests/test_explain.py) reported 22 passed while
tests/test_integrations_suricata.py caught it. This file closes that
blind spot; test_targeted_tier_selects_this_file_for_the_integration_explainer
below is what keeps it closed.

The Suricata pair build their alert message by calling
describe_correlation() rather than pasting a copy of its prose. The
explainer decides whether to claim process attribution by looking for a
substring of that sentence (integration_explainer.py:180), so a reworded
producer would otherwise flip an unattributed alert into one that claims
"a specific process was identified" with no test failing.
"""

from __future__ import annotations

from pathlib import Path

from secure.agent.tiers import targeted_test_files
from secure.explain.dispatch import explain
from secure.integrations.suricata.correlate import ProcessCorrelation, describe_correlation
from secure.storage.models import IntegrationAlertRecord

NOW = "2026-01-01T00:00:00+00:00"

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPLAINER = "secure/explain/integration_explainer.py"


def _record(**overrides) -> IntegrationAlertRecord:
    fields = dict(
        id=1, created_at=NOW, run_id="r1", integration="yarax", kind="yara_match",
        discrepancy="match", severity="high", identity_key="k", label="label",
        message="a message", source_observation_id=1, known=False,
    )
    fields.update(overrides)
    return IntegrationAlertRecord(**fields)


# ---------- the targeting rule itself ----------


def test_targeted_tier_selects_this_file_for_the_integration_explainer():
    targeted = targeted_test_files([EXPLAINER], REPO_ROOT)
    assert "tests/test_explain_integration.py" in targeted


def test_targeted_tier_does_not_select_the_integrations_test_files():
    # Not a wish: recording what the selection actually is, so that if
    # the mapping or the file names change, the claim in this module's
    # docstring stops being true loudly rather than quietly.
    targeted = targeted_test_files([EXPLAINER], REPO_ROOT)
    assert not any(t.startswith("tests/test_integrations_") for t in targeted)


# ---------- suricata: the producer/consumer string contract ----------


def test_suricata_unattributed_message_is_not_read_as_attributed():
    record = _record(
        integration="suricata", kind="network_alert", severity="medium",
        label="SECURE-TEST rule",
        message="Suricata signature fired. " + describe_correlation(None),
    )
    exp = explain(record, "integration_alerts")
    assert exp.degraded is False
    assert "No specific process could be identified" in exp.significance
    assert "identified as involved" not in exp.significance


def test_suricata_attributed_message_is_read_as_attributed():
    correlation = ProcessCorrelation(
        connection_event_id=1, pid=42, process_name="/usr/bin/curl",
        matched_side="dest", time_delta_seconds=0.0,
    )
    record = _record(
        integration="suricata", kind="network_alert", severity="high",
        label="SECURE-TEST rule",
        message="Suricata signature fired. " + describe_correlation(correlation),
    )
    exp = explain(record, "integration_alerts")
    assert "identified as involved" in exp.significance
    assert "No specific process could be identified" not in exp.significance


def test_suricata_never_claims_a_confirmed_compromise():
    record = _record(
        integration="suricata", kind="network_alert", severity="high",
        message="Suricata signature fired. " + describe_correlation(None),
    )
    exp = explain(record, "integration_alerts")
    assert exp.recommended_action == "REVIEW_NETWORK_DESTINATION"
    assert any("not, by itself, a confirmed compromise" in u for u in exp.uncertainty)


# ---------- the other three branches ----------


def test_yarax_passes_severity_through_and_recommends_inspecting_the_file():
    exp = explain(_record(integration="yarax", severity="low"), "integration_alerts")
    assert exp.severity == "low"
    assert exp.recommended_action == "INSPECT_FILE"


def test_sigma_process_creation_and_network_connection_differ_by_kind():
    process = explain(_record(integration="sigma", kind="process_creation"), "integration_alerts")
    network = explain(_record(integration="sigma", kind="network_connection"), "integration_alerts")
    assert process.recommended_action == "INSPECT_PROCESS"
    assert network.recommended_action == "REVIEW_NETWORK_DESTINATION"


def test_osquery_only_and_native_only_differ_in_recommended_action():
    osquery_only = explain(
        _record(integration="osquery", kind="listening_port", discrepancy="osquery_only"),
        "integration_alerts",
    )
    native_only = explain(
        _record(integration="osquery", kind="listening_port", discrepancy="native_only"),
        "integration_alerts",
    )
    assert osquery_only.recommended_action == "INVESTIGATE_NOW"
    assert native_only.recommended_action == "RESCAN"


def test_osquery_persistence_kind_recommends_reviewing_persistence():
    exp = explain(
        _record(integration="osquery", kind="persistence", discrepancy="osquery_only"),
        "integration_alerts",
    )
    assert exp.recommended_action == "REVIEW_PERSISTENCE"


def test_unrecognized_integration_degrades_rather_than_guessing():
    exp = explain(_record(integration="future_engine", severity="low"), "integration_alerts")
    assert exp.degraded is True
    assert exp.severity == "low"
