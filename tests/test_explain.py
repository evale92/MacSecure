"""
Tests for secure/explain/ (Product Phase 13 — Explainable Security UX).

secure/explain/ is pure Python (no I/O, no tkinter) and is exercised
two ways here: directly against hand-built *AlertRecord/
CorrelationAlertRecord dataclass instances (fast, no database needed —
mirrors tests/test_correlate.py's own "hand-built Signal objects"
pattern for the pure analysis.py functions), and, for correlation,
against a real temp database seeded through secure.storage.models
(the "seed a real temp DB" pattern tests/test_correlate.py and
tests/test_gui_components.py both already use).

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.correlate.analysis import MEANINGFUL_MODULE_PAIRS
from secure.storage.database import Database
from secure.storage.models import (
    ArpAlertRecord,
    BleAlertRecord,
    BluetoothAlertRecord,
    CorrelationAlertRecord,
    FileIntegrityAlertRecord,
    PersistenceAlertRecord,
    WifiAlertRecord,
    add_correlation_alert,
    list_correlation_alerts,
)
from secure.explain import vocab
from secure.explain.correlation_explainer import PAIR_RATIONALE, explain_correlation_alert
from secure.explain.dispatch import explain
from secure.explain.explanation import Explanation, generic_explanation


def _arp(kind="mac_changed", severity="low", ip="10.0.0.5", mac="aa:aa", previous_mac="bb:bb", message="msg"):
    return ArpAlertRecord(1, "2026-08-19T00:00:00", "run1", kind, severity, ip, mac, previous_mac, message, False)


def _wifi(kind="similar_ssid", severity="medium", ssid="HomeNet", bssid="aa:aa", message="msg"):
    return WifiAlertRecord(1, "2026-08-19T00:00:00", "run1", kind, severity, ssid, bssid, message, False)


def _bt(kind="new_pairing", severity="high", identifier="dev-1", name="AirPods", message="msg"):
    return BluetoothAlertRecord(1, "2026-08-19T00:00:00", "run1", kind, severity, identifier, name, message, False)


def _ble(kind="rssi_significant_change", severity="low", cb_uuid="uuid-1", name="Tile", message="msg"):
    return BleAlertRecord(1, "2026-08-19T00:00:00", "run1", kind, severity, cb_uuid, name, message, False)


def _persistence(kind="new_persistence_entry", severity="medium", target_type="launch_agent", identifier="com.x", label="X", message="msg"):
    return PersistenceAlertRecord(1, "2026-08-19T00:00:00", "run1", kind, severity, target_type, identifier, label, message, False)


def _fi(kind="modified", severity="high", path="/etc/hosts", message="msg", context_notes=None):
    return FileIntegrityAlertRecord(1, "2026-08-19T00:00:00", "run1", kind, severity, path, message, context_notes, False)


def _corr(members, severity="high", context_notes=None, module_count=2, signal_count=None, score=90):
    return CorrelationAlertRecord(
        1, "2026-08-19T00:00:00", "run1", "fp1", 300.0, "2026-08-19T00:00:00", "2026-08-19T00:05:00",
        module_count, signal_count if signal_count is not None else len(members), score, severity,
        "multi_module", context_notes, "explanation text", members, False,
    )


def _member(module="process", kind="new_process", strength="weak", identifier="x", label=None):
    return {
        "module": module, "kind": kind, "strength": strength, "identifier": identifier,
        "label": label, "source_table": "x", "source_id": 1, "timestamp": "2026-08-19T00:00:00",
    }


# ---------- confidence vs. severity separation ----------


def test_confidence_never_changes_severity_across_all_alert_types():
    records_and_tables = [
        (_arp(kind="gateway_mac_changed", severity="high"), "arp_alerts"),
        (_arp(kind="mac_changed", severity="low"), "arp_alerts"),
        (_arp(kind="ip_conflict", severity="medium"), "arp_alerts"),
        (_wifi(severity="medium"), "wifi_alerts"),
        (_bt(kind="new_pairing", severity="high"), "bluetooth_alerts"),
        (_bt(kind="persistent_unknown", severity="low"), "bluetooth_alerts"),
        (_ble(severity="low"), "ble_alerts"),
        (_persistence(kind="unusual_unsigned_process", severity="high"), "persistence_alerts"),
        (_persistence(kind="unusual_unsigned_process", severity="medium"), "persistence_alerts"),
        (_persistence(kind="signing_changed", severity="high"), "persistence_alerts"),
        (_fi(kind="modified", severity="high"), "file_integrity_alerts"),
        (_fi(kind="renamed", severity="medium"), "file_integrity_alerts"),
    ]
    for record, table in records_and_tables:
        exp = explain(record, table)
        assert exp.severity == record.severity, f"{table}/{record.kind} changed severity"


def test_confirmed_confidence_does_not_mean_confirmed_malicious():
    # The exact example from the approved spec: a hash change can be
    # CONFIRMED while the reason for the change is completely unknown.
    record = _fi(kind="modified", severity="high", message="hash changed")
    exp = explain(record, "file_integrity_alerts")
    assert exp.confidence == vocab.CONFIRMED
    # The uncertainty list must still include a benign explanation —
    # CONFIRMED observation does not collapse the interpretation space.
    assert any("update" in u.lower() or "install" in u.lower() or "edit" in u.lower() for u in exp.uncertainty)


def test_high_severity_can_carry_low_confidence():
    # A cluster with elevated severity but a context match (e.g. a
    # run-all sweep or recent-boot window) should show reduced
    # confidence without severity itself changing.
    members = [_member(module="process", strength="strong"), _member(module="connections", strength="weak")]
    record = _corr(members, severity="high", context_notes="Produced during a run-all sweep.")
    exp = explain_correlation_alert(record)
    assert exp.severity == "high"
    assert exp.confidence == vocab.UNCERTAIN


# ---------- uncertainty: honest, not boilerplate ----------


def test_generic_fallback_uncertainty_is_insufficient_information_not_boilerplate():
    exp = generic_explanation(source_table="arp_alerts", severity="low", message="", subject=None)
    assert exp.uncertainty_status == vocab.UNCERTAINTY_INSUFFICIENT_INFORMATION
    assert len(exp.uncertainty) == 1  # one honest statement, not a padded list


def test_uncertainty_status_vocabulary_has_all_three_documented_states():
    assert set(vocab.UNCERTAINTY_STATUSES.keys()) == {
        vocab.UNCERTAINTY_KNOWN,
        vocab.UNCERTAINTY_NONE_MATERIAL,
        vocab.UNCERTAINTY_INSUFFICIENT_INFORMATION,
    }


# ---------- evidence provenance ----------


def test_evidence_provenance_uses_documented_tags_only():
    valid = set(vocab.EVIDENCE_PROVENANCE.keys())
    exp = explain(_arp(kind="gateway_mac_changed"), "arp_alerts")
    for item in exp.evidence:
        assert item.provenance in valid


def test_wifi_alert_separates_observation_from_interpretation():
    exp = explain(_wifi(), "wifi_alerts")
    provenances = {item.provenance for item in exp.evidence}
    assert vocab.DIRECT_OBSERVATION in provenances
    assert vocab.SECURE_INTERPRETATION in provenances


# ---------- recommended action vocabulary ----------


def test_recommended_action_always_from_constrained_vocabulary():
    valid = set(vocab.RECOMMENDED_ACTIONS.keys())
    cases = [
        (_arp(kind="gateway_mac_changed"), "arp_alerts"),
        (_wifi(), "wifi_alerts"),
        (_bt(kind="persistent_unknown"), "bluetooth_alerts"),
        (_ble(kind="persistent_unknown"), "ble_alerts"),
        (_persistence(kind="signing_changed"), "persistence_alerts"),
        (_fi(kind="program_target_changed"), "file_integrity_alerts"),
    ]
    for record, table in cases:
        exp = explain(record, table)
        assert exp.recommended_action in valid


def test_finding_kind_drives_action_not_only_severity_confidence():
    # Two very different kinds, same severity — actions should differ,
    # showing kind (not just severity x confidence) determines the
    # recommended action.
    file_action = explain(_fi(kind="created", severity="high"), "file_integrity_alerts").recommended_action
    persistence_action = explain(_persistence(kind="signing_changed", severity="high"), "persistence_alerts").recommended_action
    assert file_action != persistence_action


# ---------- future compatibility / graceful failure ----------


def test_unknown_alert_kind_within_a_known_module_degrades_gracefully():
    record = _arp(kind="a_kind_from_a_future_phase")
    exp = explain(record, "arp_alerts")
    assert exp.degraded is False  # a recognized, expected gap — not a crash
    assert exp.confidence == vocab.INSUFFICIENT_EVIDENCE
    assert exp.severity == record.severity


def test_unknown_future_module_degrades_gracefully():
    record = _arp()
    exp = explain(record, "some_future_module_alerts")
    assert exp.degraded is True
    assert exp.severity == record.severity
    assert exp.confidence == vocab.INSUFFICIENT_EVIDENCE


class _BrokenRecord:
    """Stands in for a malformed/unexpected record shape — has
    severity/message but is missing everything else a real explainer
    needs (e.g. `.kind`), to force an AttributeError."""

    def __init__(self, severity, message):
        self.severity = severity
        self.message = message


def test_explanation_failure_falls_back_without_hiding_the_original_alert():
    broken = _BrokenRecord(severity="critical", message="Something the original scanner reported.")
    exp = explain(broken, "arp_alerts")
    assert exp.degraded is True
    assert exp.severity == "critical"  # original severity preserved
    assert "Something the original scanner reported." in exp.summary or exp.evidence[0].text == broken.message
    assert exp.confidence == vocab.INSUFFICIENT_EVIDENCE
    assert exp.degraded_reason  # explicit statement that richer explanation was unavailable


def test_missing_optional_structured_fields_does_not_crash():
    cases = [
        (_arp(kind="mac_changed", mac=None, previous_mac=None), "arp_alerts"),
        (_arp(kind="ip_conflict", mac=None, previous_mac=None), "arp_alerts"),
        (_bt(kind="new_pairing", name=None), "bluetooth_alerts"),
        (_ble(kind="persistent_unknown", name=None), "ble_alerts"),
        (_persistence(kind="new_persistence_entry", label=None), "persistence_alerts"),
        (_fi(kind="modified", context_notes=None), "file_integrity_alerts"),
    ]
    for record, table in cases:
        exp = explain(record, table)
        assert isinstance(exp, Explanation)
        assert exp.summary


def test_malformed_empty_correlation_members_does_not_crash():
    record = _corr([], severity="informational", module_count=0, signal_count=0, score=0)
    exp = explain_correlation_alert(record)
    assert isinstance(exp, Explanation)
    assert exp.confidence == vocab.INSUFFICIENT_EVIDENCE

    malformed_members = [{}, {"module": "process"}, {"strength": None, "module": None}]
    record2 = _corr(malformed_members, severity="low")
    exp2 = explain_correlation_alert(record2)
    assert isinstance(exp2, Explanation)
    assert exp2.severity == "low"


# ---------- correlation: evidence concentration ----------


def test_large_cluster_dominated_by_one_module_is_described_accurately():
    members = [_member(module="process", kind="new_process", strength="weak", identifier=f"p{i}") for i in range(612)]
    members += [_member(module="connections", kind="new_remote_endpoint", strength="strong", identifier=f"c{i}") for i in range(45)]
    record = _corr(members, severity="high", module_count=2, score=90)
    exp = explain_correlation_alert(record)

    assert exp.confidence == vocab.UNCERTAIN
    assert "process" in exp.confidence_reason
    assert "93%" in exp.confidence_reason or "93" in exp.confidence_reason

    concentration_evidence = [e.text for e in exp.evidence if "Largest contributor" in e.text]
    assert concentration_evidence, "no evidence item describes the dominant contributor"
    assert "process" in concentration_evidence[0]
    assert "612" in concentration_evidence[0]

    interpretation_notes = [e.text for e in exp.evidence if e.provenance == vocab.SECURE_INTERPRETATION]
    assert any("should not be interpreted as" in t and "independent" in t for t in interpretation_notes)


def test_balanced_cross_module_cluster_is_not_flagged_as_concentrated():
    members = [_member(module="process", strength="strong", identifier="p1"), _member(module="connections", strength="weak", identifier="c1")]
    record = _corr(members, severity="medium")
    exp = explain_correlation_alert(record)
    concentration_evidence = [e.text for e in exp.evidence if "Largest contributor" in e.text]
    assert not concentration_evidence


def test_correlation_distinguishes_raw_observations_distinct_behaviors_distinct_modules():
    members = [_member(module="process", kind="new_process", identifier=f"p{i}") for i in range(5)]
    members += [_member(module="process", kind="signing_changed", identifier="p_sign")]
    members += [_member(module="connections", kind="new_remote_endpoint", identifier="c1")]
    record = _corr(members, severity="medium", module_count=2)
    exp = explain_correlation_alert(record)

    raw_line = next(e.text for e in exp.evidence if "raw observation" in e.text)
    behavior_line = next(e.text for e in exp.evidence if "distinct behavior" in e.text)
    assert "7 raw observation" in raw_line
    assert "2 distinct module" in raw_line
    assert "3 distinct behavior" in behavior_line  # (process,new_process) (process,signing_changed) (connections,new_remote_endpoint)


# ---------- correlation: pair rationale documentation ----------


def test_every_meaningful_pair_has_a_documented_rationale():
    missing = MEANINGFUL_MODULE_PAIRS - set(PAIR_RATIONALE.keys())
    assert not missing, (
        f"MEANINGFUL_MODULE_PAIRS has pair(s) with no PAIR_RATIONALE entry: {missing} "
        "— add a rationale in secure/explain/correlation_explainer.py"
    )


def test_pair_rationale_does_not_contain_stale_entries():
    stale = set(PAIR_RATIONALE.keys()) - MEANINGFUL_MODULE_PAIRS
    assert not stale, f"PAIR_RATIONALE has entries for pairs no longer in MEANINGFUL_MODULE_PAIRS: {stale}"


def test_meaningful_pair_rationale_appears_in_explanation_evidence():
    members = [_member(module="process", strength="strong"), _member(module="connections", strength="weak")]
    record = _corr(members, severity="medium")
    exp = explain_correlation_alert(record)
    rationale_text = PAIR_RATIONALE[frozenset({"process", "connections"})]
    assert any(rationale_text in e.text for e in exp.evidence)


# ---------- correlation against a real seeded database ----------


def test_explain_correlation_alert_end_to_end_against_seeded_db(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_correlation_alert(
            db.conn, "run1", "fp1", 60.0, "2026-08-19T00:00:00", "2026-08-19T00:01:00",
            2, 3, 15, "high", "multi_module", None, "explanation",
            [
                _member(module="process", strength="strong", identifier="p1"),
                _member(module="connections", strength="weak", identifier="c1"),
                _member(module="connections", strength="weak", identifier="c2"),
            ],
        )
        rows = list_correlation_alerts(db.conn, limit=5)
        exp = explain(rows[0], "correlation_alerts")
        assert exp.severity == "high"
        assert exp.confidence in (vocab.LIKELY, vocab.UNCERTAIN, vocab.CONFIRMED, vocab.INSUFFICIENT_EVIDENCE)
        assert len(exp.correlated_events) == 3


# ---------- dispatch covers all 7 source tables ----------


def test_dispatch_has_an_explainer_for_every_alert_source_table():
    from secure.explain.dispatch import _EXPLAINERS

    expected = {
        "arp_alerts", "wifi_alerts", "bluetooth_alerts", "ble_alerts",
        "persistence_alerts", "file_integrity_alerts", "correlation_alerts",
        "integration_alerts", "correlation_chain_alerts",
    }
    assert set(_EXPLAINERS.keys()) == expected
