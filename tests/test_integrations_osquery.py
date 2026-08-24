"""
Tests for secure/integrations/ (Phase 15: External Telemetry Foundation
+ osquery).

Covers:
    - base.py: IntegrationHealth's four-status invariant, `available`.
    - availability.py: unavailable / error / ok classification, with
      subprocess mocked via monkeypatch on `subprocess.run` (the same
      "patch the wrapper" pattern every other package in this app uses
      — see e.g. tests/test_persistence.py's module docstring).
    - parser.py: pure JSON-row -> ExternalObservation normalization,
      including the pid->name join for sockets/listening ports.
    - crosscheck.py: the double-counting-prevention core — a
      native/osquery MATCH produces zero Discrepancies; a genuine
      mismatch produces exactly one, on the correct side, with the
      correct asymmetric severity.
    - scanner.py end-to-end: unavailable short-circuit never looks
      "clean"; a full pass persists integration_runs/
      integration_observations/integration_alerts correctly, with
      source_observation_id resolved for osquery_only discrepancies.
    - storage/models/integrations.py: per-row id integrity for
      add_integration_observations(), matching the same discipline
      Phase 14.5 Stage B established elsewhere in this app.
    - correlate wiring: classify_integration_alert_strength(), and that
      _collect_integrations() reads ONLY integration_alerts, never
      integration_observations — proving a native/osquery match can
      never reach collect_signals() at all.

Run with:  pytest
"""

from __future__ import annotations

import json
from pathlib import Path

from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    ExternalObservation,
    IntegrationHealth,
)
from secure.integrations.osquery import availability as availability_module
from secure.integrations.osquery import crosscheck
from secure.integrations.osquery import parser
from secure.integrations.osquery import scanner as scanner_module
from secure.integrations.osquery._shell import ShellResult
from secure.integrations.osquery.queries import LAUNCHD, LISTENING_PORTS
from secure.correlate.strength import STRONG, WEAK, classify_integration_alert_strength
from secure.correlate.signals import _collect_integrations, collect_signals
from secure.storage.database import Database
from secure.storage.models import (
    add_integration_alert,
    add_integration_observations,
    find_latest_integration_run,
    list_integration_alerts,
    list_integration_observations,
    list_integration_runs,
    upsert_listening_service,
    upsert_persistence_entry,
)

NOW = "2026-08-21T00:00:00+00:00"


# ---------- base.py ----------


def test_integration_health_rejects_invalid_status():
    raised = False
    try:
        IntegrationHealth(status="fine", detail="x", collected_at=NOW)
    except ValueError:
        raised = True
    assert raised


def test_integration_health_available_property():
    for status, expected in [
        (STATUS_OK, True),
        (STATUS_DEGRADED, True),
        (STATUS_UNAVAILABLE, False),
        (STATUS_ERROR, False),
    ]:
        health = IntegrationHealth(status=status, detail="x", collected_at=NOW)
        assert health.available is expected


# ---------- availability.py ----------


def test_check_availability_reports_unavailable_when_binary_missing(monkeypatch):
    def fake_run(args, capture_output, text, timeout):
        raise FileNotFoundError

    monkeypatch.setattr("subprocess.run", fake_run)
    health = availability_module.check_availability()
    assert health.status == STATUS_UNAVAILABLE
    assert health.tool_version is None


def test_check_availability_reports_error_on_nonzero_exit(monkeypatch):
    class R:
        returncode = 1
        stdout = ""
        stderr = "syntax error near..."

    monkeypatch.setattr("subprocess.run", lambda *a, **k: R())
    health = availability_module.check_availability()
    assert health.status == STATUS_ERROR


def test_check_availability_reports_error_on_unparseable_json(monkeypatch):
    class R:
        returncode = 0
        stdout = "not json"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *a, **k: R())
    health = availability_module.check_availability()
    assert health.status == STATUS_ERROR


def test_check_availability_reports_ok_with_version(monkeypatch):
    class R:
        returncode = 0
        stdout = json.dumps([{"version": "5.12.1"}])
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *a, **k: R())
    health = availability_module.check_availability()
    assert health.status == STATUS_OK
    assert health.tool_version == "5.12.1"


# ---------- parser.py ----------


def test_parse_processes_identity_key_prefers_path():
    rows = [{"pid": "1", "name": "sshd", "path": "/usr/sbin/sshd", "cmdline": "", "uid": "0", "parent": "0"}]
    observations = parser.parse_processes(rows, NOW)
    assert len(observations) == 1
    assert observations[0].identity_key == "/usr/sbin/sshd"
    assert observations[0].fields["pid"] == 1


def test_parse_processes_identity_key_falls_back_without_path():
    rows = [{"pid": "2", "name": "kernel_task", "path": "", "cmdline": "", "uid": "0", "parent": "0"}]
    observations = parser.parse_processes(rows, NOW)
    assert observations[0].identity_key == "name:kernel_task"


def test_build_pid_name_map():
    process_rows = [{"pid": "10", "name": "sshd"}, {"pid": "notanint", "name": "bad"}]
    mapping = parser.build_pid_name_map(process_rows)
    assert mapping == {10: "sshd"}


def test_parse_listening_ports_fills_process_name_from_pid_map():
    rows = [{"pid": "10", "port": "22", "protocol": "6", "address": "0.0.0.0", "family": "2"}]
    observations = parser.parse_listening_ports(rows, NOW, {10: "sshd"})
    assert observations[0].fields["process_name"] == "sshd"
    assert observations[0].fields["proto"] == "tcp"
    assert observations[0].identity_key == "tcp:22"


def test_parse_listening_ports_unknown_pid_leaves_process_name_none():
    rows = [{"pid": "999", "port": "22", "protocol": "6", "address": "0.0.0.0", "family": "2"}]
    observations = parser.parse_listening_ports(rows, NOW, {10: "sshd"})
    assert observations[0].fields["process_name"] is None


def test_parse_launchd_identity_key_prefers_path():
    rows = [
        {
            "name": "com.example.agent", "label": "com.example.agent",
            "path": "/Users/x/Library/LaunchAgents/com.example.agent.plist",
            "program": "/usr/bin/true", "program_arguments": "", "run_at_load": "1",
            "keep_alive": "0", "disabled": "0", "username": "x",
        }
    ]
    observations = parser.parse_launchd(rows, NOW)
    assert observations[0].identity_key == "/Users/x/Library/LaunchAgents/com.example.agent.plist"
    assert observations[0].fields["run_at_load"] is True
    assert observations[0].fields["keep_alive"] is False


def test_parse_rows_raises_on_non_array_json():
    raised = False
    try:
        parser.parse_rows(json.dumps({"not": "an array"}))
    except ValueError:
        raised = True
    assert raised


# ---------- crosscheck.py: the double-counting-prevention core ----------


def test_crosscheck_listening_ports_match_produces_no_discrepancy(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        observations = [
            ExternalObservation(
                kind=LISTENING_PORTS, identity_key="tcp:22",
                fields={"proto": "tcp", "port": 22, "process_name": "sshd"},
                source_query="SELECT ...", collected_at=NOW,
            )
        ]
        discrepancies = crosscheck.crosscheck_listening_ports(db.conn, observations)
    assert discrepancies == []


def test_crosscheck_listening_ports_osquery_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        # No native listening services recorded at all.
        observations = [
            ExternalObservation(
                kind=LISTENING_PORTS, identity_key="tcp:4444",
                fields={"proto": "tcp", "port": 4444, "process_name": "evil"},
                source_query="SELECT ...", collected_at=NOW,
            )
        ]
        discrepancies = crosscheck.crosscheck_listening_ports(db.conn, observations)
    assert len(discrepancies) == 1
    d = discrepancies[0]
    assert d.discrepancy_type == crosscheck.OSQUERY_ONLY
    assert d.severity == crosscheck.HIGH
    assert d.identity_key == "tcp:4444"


def test_crosscheck_listening_ports_native_only(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        # osquery observed nothing this pass.
        discrepancies = crosscheck.crosscheck_listening_ports(db.conn, [])
    assert len(discrepancies) == 1
    d = discrepancies[0]
    assert d.discrepancy_type == crosscheck.NATIVE_ONLY
    assert d.severity == crosscheck.LOW
    assert d.identity_key == "tcp:22"


def test_crosscheck_persistence_match_produces_no_discrepancy(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(
            db.conn, kind="launch_agent_user",
            path="/Users/x/Library/LaunchAgents/com.example.plist",
            label="com.example", program_path="/usr/bin/true", signing_status="signed_apple",
        )
        observations = [
            ExternalObservation(
                kind=LAUNCHD, identity_key="/Users/x/Library/LaunchAgents/com.example.plist",
                fields={"label": "com.example"}, source_query="SELECT ...", collected_at=NOW,
            )
        ]
        discrepancies = crosscheck.crosscheck_persistence(db.conn, observations)
    assert discrepancies == []


def test_crosscheck_persistence_login_items_excluded_from_native_side(tmp_path: Path):
    """login_item persistence entries have no osquery `launchd` equivalent
    — they must never generate a native_only discrepancy just because
    osquery structurally can't see them.
    """
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(
            db.conn, kind="login_item", path=None, label="Some App",
            program_path="/Applications/Some App.app", signing_status="signed_apple",
        )
        discrepancies = crosscheck.crosscheck_persistence(db.conn, [])
    assert discrepancies == []


# ---------- Phase 21 (additive): crosscheck.py's MATCH-surfacing functions ----------


def test_find_listening_port_matches_returns_native_id(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        service_record, _ = upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        service_id = service_record.id
        observations = [
            ExternalObservation(
                kind=LISTENING_PORTS, identity_key="tcp:22",
                fields={"proto": "tcp", "port": 22, "process_name": "sshd"},
                source_query="SELECT ...", collected_at=NOW,
            )
        ]
        matches = crosscheck.find_listening_port_matches(db.conn, observations)
    assert len(matches) == 1
    assert matches[0].kind == "listening_port"
    assert matches[0].native_source_table == "listening_services"
    assert matches[0].native_source_id == service_id
    assert matches[0].identity_key == "tcp:22"


def test_find_listening_port_matches_empty_when_no_native_match(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        observations = [
            ExternalObservation(
                kind=LISTENING_PORTS, identity_key="tcp:4444",
                fields={"proto": "tcp", "port": 4444, "process_name": "evil"},
                source_query="SELECT ...", collected_at=NOW,
            )
        ]
        assert crosscheck.find_listening_port_matches(db.conn, observations) == []


def test_find_persistence_matches_returns_native_id(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entry_record, _, _ = upsert_persistence_entry(
            db.conn, kind="launch_agent_user",
            path="/Users/x/Library/LaunchAgents/com.example.plist",
            label="com.example", program_path="/usr/bin/true", signing_status="signed_apple",
        )
        entry_id = entry_record.id
        observations = [
            ExternalObservation(
                kind=LAUNCHD, identity_key="/Users/x/Library/LaunchAgents/com.example.plist",
                fields={"label": "com.example"}, source_query="SELECT ...", collected_at=NOW,
            )
        ]
        matches = crosscheck.find_persistence_matches(db.conn, observations)
    assert len(matches) == 1
    assert matches[0].kind == "persistence"
    assert matches[0].native_source_table == "persistence_entries"
    assert matches[0].native_source_id == entry_id


def test_find_persistence_matches_login_items_never_match(tmp_path: Path):
    # login_item has no osquery launchd equivalent — mirrors
    # crosscheck_persistence's own exclusion for the discrepancy side.
    # Even though its own `path` could coincidentally equal an
    # osquery-reported identity_key, a login_item entry must never be
    # treated as a match.
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(
            db.conn, kind="login_item", path="/some/coincidental/path", label="Some App",
            program_path="/Applications/Some App.app", signing_status="signed_apple",
        )
        observations = [
            ExternalObservation(
                kind=LAUNCHD, identity_key="/some/coincidental/path",
                fields={"label": "Some App"}, source_query="SELECT ...", collected_at=NOW,
            )
        ]
        assert crosscheck.find_persistence_matches(db.conn, observations) == []


# ---------- scanner.py end-to-end ----------


def _fake_run_query_factory(payloads: dict):
    def fake_run(args, capture_output, text, timeout):
        class R:
            pass

        sql = args[-1]
        r = R()
        r.returncode = 0
        r.stderr = ""
        r.stdout = "[]"
        for marker, payload in payloads.items():
            if marker in sql:
                r.stdout = payload
                break
        return r

    return fake_run


def test_scan_osquery_unavailable_never_looks_clean(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError))
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_osquery(db.conn)
        assert result.health.status == STATUS_UNAVAILABLE
        assert result.available is False
        assert result.observations == []
        assert result.discrepancies == []

        runs = list_integration_runs(db.conn)
        assert len(runs) == 1
        assert runs[0].status == STATUS_UNAVAILABLE
        assert runs[0].observations_collected == 0
        assert runs[0].alerts_generated == 0


def test_scan_osquery_full_pass_persists_and_crosschecks(tmp_path: Path, monkeypatch):
    payloads = {
        "osquery_info": json.dumps([{"version": "5.12.1"}]),
        "FROM processes": json.dumps(
            [{"pid": "100", "name": "sshd", "path": "/usr/sbin/sshd", "cmdline": "", "uid": "0", "parent": "1"}]
        ),
        "FROM process_open_sockets": "[]",
        "FROM listening_ports": json.dumps(
            [{"pid": "100", "port": "22", "protocol": "6", "address": "0.0.0.0", "family": "2"}]
        ),
        "FROM launchd": "[]",
    }
    monkeypatch.setattr("subprocess.run", _fake_run_query_factory(payloads))

    with Database(tmp_path / "test.db") as db:
        # Native side already knows about sshd:22 — should match, no alert.
        upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        result = scanner_module.scan_osquery(db.conn)

        assert result.health.status == STATUS_OK
        assert len(result.observations) == 2  # 1 process + 1 listening port
        assert result.discrepancies == []

        runs = list_integration_runs(db.conn)
        assert runs[0].status == STATUS_OK
        assert runs[0].observations_collected == 2
        assert runs[0].alerts_generated == 0

        observations = list_integration_observations(db.conn)
        assert len(observations) == 2

        alerts = list_integration_alerts(db.conn)
        assert alerts == []


def test_scan_osquery_match_records_evidence_link(tmp_path: Path, monkeypatch):
    """Phase 21 (additive): the exact MATCH scenario above
    (test_scan_osquery_full_pass_persists_and_crosschecks — sshd:22
    agreed by both sides, zero discrepancies) now ALSO gets a formal
    same_event_confirmation evidence_links row, where before this stage
    the match left no trace anywhere.
    """
    from secure.evidence.model import RELATIONSHIP_SAME_EVENT_CONFIRMATION
    from secure.storage.models import list_evidence_links_for

    payloads = {
        "osquery_info": json.dumps([{"version": "5.12.1"}]),
        "FROM processes": json.dumps(
            [{"pid": "100", "name": "sshd", "path": "/usr/sbin/sshd", "cmdline": "", "uid": "0", "parent": "1"}]
        ),
        "FROM process_open_sockets": "[]",
        "FROM listening_ports": json.dumps(
            [{"pid": "100", "port": "22", "protocol": "6", "address": "0.0.0.0", "family": "2"}]
        ),
        "FROM launchd": "[]",
    }
    monkeypatch.setattr("subprocess.run", _fake_run_query_factory(payloads))

    with Database(tmp_path / "test.db") as db:
        service_record, _ = upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        service_id = service_record.id
        result = scanner_module.scan_osquery(db.conn)
        assert result.discrepancies == []  # unchanged: still zero alerts on a match
        assert result.evidence_links_recorded == 1

        links = list_evidence_links_for(db.conn, "listening_services", service_id)
        assert len(links) == 1
        assert links[0].relationship == RELATIONSHIP_SAME_EVENT_CONFIRMATION
        assert links[0].created_by == "osquery_crosscheck"
        assert links[0].from_source_table == "integration_observations"


def test_scan_osquery_rescan_does_not_duplicate_evidence_link(tmp_path: Path, monkeypatch):
    """Phase 21 Stage 3c correction (test 1 of the required set): osquery
    has no ingestion cursor, so a rescan of the SAME ongoing match still
    inserts a brand-new integration_observations row (untouched — see
    scan_osquery()'s own docstring: repeated observations remain useful
    historical evidence and are never suppressed). What must NOT happen
    is a second evidence_links row for the same logical relationship —
    record_link() now recognizes the repeat via ObservationRef.logical_key
    (osquery's own stable identity_key, not the ever-changing observation
    row id) and TOUCHES the existing link instead of duplicating it.
    """
    from secure.storage.models import list_evidence_links_for, list_integration_observations

    payloads = {
        "osquery_info": json.dumps([{"version": "5.12.1"}]),
        "FROM processes": json.dumps(
            [{"pid": "100", "name": "sshd", "path": "/usr/sbin/sshd", "cmdline": "", "uid": "0", "parent": "1"}]
        ),
        "FROM process_open_sockets": "[]",
        "FROM listening_ports": json.dumps(
            [{"pid": "100", "port": "22", "protocol": "6", "address": "0.0.0.0", "family": "2"}]
        ),
        "FROM launchd": "[]",
    }
    monkeypatch.setattr("subprocess.run", _fake_run_query_factory(payloads))

    with Database(tmp_path / "test.db") as db:
        service_record, _ = upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        service_id = service_record.id

        result1 = scanner_module.scan_osquery(db.conn)
        assert result1.evidence_links_recorded == 1  # brand-new logical relationship

        result2 = scanner_module.scan_osquery(db.conn)
        # No NEW logical relationship on the rescan — it's a repeat
        # confirmation of the one already on file, same counter
        # semantics Zeek/Suricata's own rescan tests already assert.
        assert result2.evidence_links_recorded == 0

        # integration_observations keeps logging every scan — history is
        # never suppressed just because the relationship is already known.
        # list_integration_observations() returns newest-first; sort
        # ascending by id so [0] is genuinely the FIRST scan's row and
        # [-1] the LATEST, unambiguously.
        sshd_port_observations = sorted(
            list_integration_observations(db.conn, kind="listening_ports"), key=lambda o: o.id
        )
        assert len(sshd_port_observations) == 2

        # But evidence_links itself stays at exactly ONE row — the
        # relationship, not the scan — regardless of how many times it's
        # reconfirmed (this is also test 6 of the required set: repeated
        # scans must not inflate future correlation as independent
        # evidence; a correlation pass reading evidence_links only ever
        # sees one same_event_confirmation fact here).
        links = list_evidence_links_for(db.conn, "listening_services", service_id)
        assert len(links) == 1
        link = links[0]
        assert link.times_seen == 2
        assert link.first_source_id == sshd_port_observations[0].id  # first scan's row, preserved
        assert link.from_source_id == sshd_port_observations[-1].id  # "latest" advances to the 2nd scan's row
        assert link.first_seen is not None
        assert link.last_seen >= link.first_seen  # advanced (or equal, if the same instant)

        # A third scan reconfirms again — still one link, still growing
        # times_seen, still no inflation.
        scanner_module.scan_osquery(db.conn)
        links_after_third = list_evidence_links_for(db.conn, "listening_services", service_id)
        assert len(links_after_third) == 1
        assert links_after_third[0].id == link.id
        assert links_after_third[0].times_seen == 3


def test_scan_osquery_discrepancy_gets_source_observation_id(tmp_path: Path, monkeypatch):
    payloads = {
        "osquery_info": json.dumps([{"version": "5.12.1"}]),
        "FROM processes": json.dumps(
            [{"pid": "200", "name": "evil", "path": "/tmp/evil", "cmdline": "", "uid": "501", "parent": "1"}]
        ),
        "FROM process_open_sockets": "[]",
        "FROM listening_ports": json.dumps(
            [{"pid": "200", "port": "4444", "protocol": "6", "address": "0.0.0.0", "family": "2"}]
        ),
        "FROM launchd": "[]",
    }
    monkeypatch.setattr("subprocess.run", _fake_run_query_factory(payloads))

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_osquery(db.conn)
        assert len(result.discrepancies) == 1
        assert result.discrepancies[0].discrepancy_type == crosscheck.OSQUERY_ONLY

        alerts = list_integration_alerts(db.conn)
        assert len(alerts) == 1
        assert alerts[0].source_observation_id is not None

        observations = list_integration_observations(db.conn, kind=LISTENING_PORTS)
        assert alerts[0].source_observation_id == observations[0].id


def test_scan_osquery_failed_query_marks_degraded_and_skips_its_crosscheck(tmp_path: Path, monkeypatch):
    def fake_run(args, capture_output, text, timeout):
        class R:
            pass

        sql = args[-1]
        r = R()
        if "osquery_info" in sql:
            r.returncode, r.stderr, r.stdout = 0, "", json.dumps([{"version": "5.12.1"}])
        elif "FROM listening_ports" in sql:
            r.returncode, r.stderr, r.stdout = 1, "permission denied", ""
        else:
            r.returncode, r.stderr, r.stdout = 0, "", "[]"
        return r

    monkeypatch.setattr("subprocess.run", fake_run)

    with Database(tmp_path / "test.db") as db:
        # Native side has a listening service — if the failed query were
        # wrongly treated as "osquery saw nothing," this would incorrectly
        # produce a native_only discrepancy. It must not.
        upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        result = scanner_module.scan_osquery(db.conn)

        assert result.health.status == STATUS_DEGRADED
        assert "listening_ports" in result.failed_queries
        assert result.discrepancies == []  # listening crosscheck skipped entirely


# ---------- storage/models/integrations.py ----------


def test_add_integration_observations_returns_unique_real_ids(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("processes", f"/usr/bin/tool{i}", {"pid": i}, "SELECT * FROM processes", NOW)
            for i in range(4)
        ]
        ids = add_integration_observations(db.conn, run_id="run1", integration="osquery", rows=rows)
        assert len(ids) == 4
        assert len(set(ids)) == 4
        stored = list_integration_observations(db.conn)
        assert len(stored) == 4
        assert stored[0].fields["pid"] in range(4)


# ---------- correlate wiring ----------


def test_classify_integration_alert_strength():
    assert classify_integration_alert_strength("osquery_only") == STRONG
    assert classify_integration_alert_strength("native_only") == WEAK


def test_collect_integrations_reads_only_alerts_table(tmp_path: Path):
    """The structural double-counting guarantee: even if
    integration_observations has many rows (raw osquery data, including
    facts that matched native state and produced no alert), only rows
    that reached integration_alerts ever become correlation Signals.
    """
    with Database(tmp_path / "test.db") as db:
        # Raw observations only — no alert. Must never surface as a signal.
        add_integration_observations(
            db.conn, run_id="run1", integration="osquery",
            rows=[("listening_ports", "tcp:22", {"port": 22}, "SELECT ...", NOW)],
        )
        signals_before = collect_signals(db.conn, lookback_hours=999)
        assert not any(s.module == "integrations" for s in signals_before)

        # A genuine discrepancy DOES surface as exactly one signal.
        add_integration_alert(
            db.conn, run_id="run1", integration="osquery", kind="listening_port",
            discrepancy="osquery_only", severity="high", identity_key="tcp:4444",
            label="evil", message="osquery saw a port Secure's native scan didn't.",
        )
        signals_after = collect_signals(db.conn, lookback_hours=999)
        integration_signals = [s for s in signals_after if s.module == "integrations"]
        assert len(integration_signals) == 1
        assert integration_signals[0].strength == STRONG
        assert integration_signals[0].source_table == "integration_alerts"


def test_collect_integrations_native_only_is_weak(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="run1", integration="osquery", kind="persistence",
            discrepancy="native_only", severity="low", identity_key="/some/path",
            label=None, message="Secure saw this, osquery didn't confirm it.",
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
    assert len(signals) == 1
    assert signals[0].strength == WEAK
