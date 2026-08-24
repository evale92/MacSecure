"""
Tests for secure/integrations/suricata/ (Phase 18: Suricata network IDS
integration).

Unlike YARA-X/Sigma, this integration has no third-party library seam
to mock — it's plain stdlib `json` over a log file Suricata itself
(running entirely outside Secure) already writes, so these tests
exercise the real parsing/availability/correlation/scanner logic
directly, no mocking needed beyond the optional `suricata -V` version
subprocess (mocked only where its exact value matters to a test).

Uses a static fixture file (tests/fixtures/suricata/eve/sample_eve.jsonl)
for pure parsing-shape tests, where "is this timestamp fresh" doesn't
matter — plus dynamically-built EVE content (current wall-clock
timestamps) for availability/scanner tests, where staleness/packet-
visibility logic is inherently relative to "now." All IPs in fixtures
are IANA-reserved documentation ranges (TEST-NET-1/2/3:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and every signature
string is prefixed "SECURE-TEST" — never a real-world IOC.

Run with:  pytest
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.config import AppConfig
from secure.correlate.signals import _classify_integration_signal_strength, _collect_integrations
from secure.correlate.strength import MEDIUM, STRONG, WEAK, classify_suricata_finding_strength
from secure.explain.dispatch import explain
from secure.integrations.base import STATUS_DEGRADED, STATUS_OK, STATUS_UNAVAILABLE
from secure.integrations.suricata import _eve as eve_module
from secure.integrations.suricata import _shell as shell_module
from secure.integrations.suricata import _timeutil
from secure.integrations.suricata import analysis as analysis_module
from secure.integrations.suricata import availability as availability_module
from secure.integrations.suricata import correlate as correlate_module
from secure.integrations.suricata import parser as parser_module
from secure.integrations.suricata import scanner as scanner_module
from secure.storage.database import Database
from secure.storage.models import (
    add_connection_events,
    add_integration_observations,
    list_integration_alerts,
    list_integration_observations,
    list_integration_runs,
)

FIXTURES = Path(__file__).parent / "fixtures" / "suricata" / "eve"
SAMPLE_EVE = FIXTURES / "sample_eve.jsonl"

NOW = "2026-08-21T00:00:00+00:00"


def _now_suricata_ts(dt=None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def _write_eve(path: Path, records: "list[dict]") -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")


def _alert_record(
    timestamp,
    flow_id=111,
    src_ip="192.0.2.10",
    src_port=51000,
    dest_ip="203.0.113.5",
    dest_port=4444,
    proto="TCP",
    signature="SECURE-TEST rule",
    severity=1,
    signature_id=2100498,
    rev=7,
) -> dict:
    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "in_iface": "en0",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": signature_id,
            "rev": rev,
            "signature": signature,
            "category": "Potentially Bad Traffic",
            "severity": severity,
        },
    }


def _stats_record(timestamp, kernel_packets=15234, kernel_drops=0, decoder_pkts=15234) -> dict:
    return {
        "timestamp": timestamp,
        "event_type": "stats",
        "stats": {
            "capture": {"kernel_packets": kernel_packets, "kernel_drops": kernel_drops},
            "decoder": {"pkts": decoder_pkts},
        },
    }


# ---------- _eve.py ----------


def test_read_eve_lines_from_fixture():
    records, malformed = eve_module.read_eve_lines(SAMPLE_EVE)
    assert malformed == 1  # the one deliberately invalid line
    event_types = [r.get("event_type") for r in records]
    assert event_types.count("alert") == 2
    assert event_types.count("stats") == 1
    assert event_types.count("flow") == 1


def test_read_eve_lines_missing_file_returns_empty(tmp_path: Path):
    records, malformed = eve_module.read_eve_lines(tmp_path / "does_not_exist.json")
    assert records == []
    assert malformed == 0


def test_read_eve_lines_respects_max_lines_tail(tmp_path: Path):
    path = tmp_path / "eve.json"
    lines = [json.dumps({"event_type": "flow", "n": i}) for i in range(10)]
    path.write_text("\n".join(lines) + "\n")
    records, _ = eve_module.read_eve_lines(path, max_lines=3)
    assert [r["n"] for r in records] == [7, 8, 9]  # only the LAST 3 lines


def test_iter_by_event_type_filters():
    records, _ = eve_module.read_eve_lines(SAMPLE_EVE)
    alerts = list(eve_module.iter_by_event_type(records, "alert"))
    assert len(alerts) == 2


# ---------- _timeutil.py ----------


def test_parse_suricata_timestamp_no_colon_offset():
    dt = _timeutil.parse_suricata_timestamp("2026-01-01T10:00:00.000000+0000")
    assert dt is not None
    assert dt.year == 2026 and dt.month == 1 and dt.day == 1


def test_parse_suricata_timestamp_colon_offset_also_works():
    dt = _timeutil.parse_suricata_timestamp("2026-01-01T10:00:00.000000+00:00")
    assert dt is not None


def test_parse_suricata_timestamp_invalid_returns_none():
    assert _timeutil.parse_suricata_timestamp("not-a-timestamp") is None
    assert _timeutil.parse_suricata_timestamp(None) is None
    assert _timeutil.parse_suricata_timestamp("") is None


# ---------- parser.py ----------


def test_parse_alert_record_normalizes_expected_fields():
    records, _ = eve_module.read_eve_lines(SAMPLE_EVE)
    alert_records = list(eve_module.iter_by_event_type(records, "alert"))
    obs = parser_module.parse_alert_record(alert_records[0], NOW, str(SAMPLE_EVE))
    assert obs is not None
    assert obs.kind == parser_module.ALERT_KIND
    assert obs.fields["signature"] == "SECURE-TEST GPL ATTACK_RESPONSE id check returned root"
    assert obs.fields["signature_id"] == 2100498
    assert obs.fields["gid"] == 1
    assert obs.fields["rev"] == 7
    assert obs.fields["severity"] == 1
    assert obs.fields["src_ip"] == "192.0.2.10"
    assert obs.fields["dest_port"] == 4444
    assert obs.fields["proto"] == "TCP"
    assert obs.identity_key == "111:1:2100498:7:2026-01-01T10:00:00.000000+0000"
    assert str(SAMPLE_EVE) in obs.source_query


def test_parse_alert_record_rejects_non_alert_event_type():
    assert parser_module.parse_alert_record({"event_type": "flow"}, NOW, "x") is None


def test_parse_alert_record_rejects_missing_signature():
    record = {"event_type": "alert", "timestamp": NOW, "alert": {"gid": 1}}
    assert parser_module.parse_alert_record(record, NOW, "x") is None


def test_parse_alert_record_rejects_missing_timestamp():
    record = {"event_type": "alert", "alert": {"signature": "x"}}
    assert parser_module.parse_alert_record(record, NOW, "x") is None


def test_extract_latest_capture_stats_from_fixture():
    records, _ = eve_module.read_eve_lines(SAMPLE_EVE)
    stats = parser_module.extract_latest_capture_stats(records)
    assert stats == {
        "timestamp": "2026-01-01T10:00:10.000000+0000",
        "kernel_packets": 98765,
        "kernel_drops": 12,
        "decoder_pkts": 98765,
    }


def test_extract_latest_capture_stats_none_when_absent():
    assert parser_module.extract_latest_capture_stats([{"event_type": "alert"}]) is None


def test_extract_latest_capture_stats_picks_the_last_one():
    records = [
        _stats_record("2026-01-01T10:00:00.000000+0000", kernel_packets=10),
        _stats_record("2026-01-01T10:00:05.000000+0000", kernel_packets=20),
    ]
    stats = parser_module.extract_latest_capture_stats(records)
    assert stats["kernel_packets"] == 20


# ---------- analysis.py ----------


def test_classify_suricata_severity_direction():
    # Suricata's own convention: LOWER number = MORE severe.
    assert analysis_module.classify_suricata_severity(1) == analysis_module.HIGH
    assert analysis_module.classify_suricata_severity(2) == analysis_module.MEDIUM
    assert analysis_module.classify_suricata_severity(3) == analysis_module.LOW
    assert analysis_module.classify_suricata_severity(4) == analysis_module.LOW


def test_classify_suricata_severity_defaults_when_missing_or_unusable():
    assert analysis_module.classify_suricata_severity(None) == analysis_module.DEFAULT_SEVERITY
    assert analysis_module.classify_suricata_severity("not a number") == analysis_module.DEFAULT_SEVERITY
    assert analysis_module.classify_suricata_severity(analysis_module.DEFAULT_SEVERITY) == analysis_module.DEFAULT_SEVERITY == analysis_module.LOW


def test_classify_suricata_severity_accepts_numeric_strings():
    assert analysis_module.classify_suricata_severity("1") == analysis_module.HIGH


# ---------- availability.py ----------


def _cfg_for(tmp_path: Path, eve_path: "Path | None" = None) -> AppConfig:
    cfg = AppConfig(app_dir=str(tmp_path))
    if eve_path is not None:
        cfg.suricata_eve_log_path = str(eve_path)
    return cfg


def test_check_availability_unconfigured_is_unavailable(tmp_path: Path):
    health = availability_module.check_availability(_cfg_for(tmp_path))
    assert health.status == STATUS_UNAVAILABLE


def test_check_availability_missing_file_is_unavailable(tmp_path: Path):
    cfg = _cfg_for(tmp_path, tmp_path / "nope.json")
    health = availability_module.check_availability(cfg)
    assert health.status == STATUS_UNAVAILABLE
    assert "not found" in health.detail


def test_check_availability_empty_log_is_degraded(tmp_path: Path):
    eve = tmp_path / "eve.json"
    eve.write_text("")
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.status == STATUS_DEGRADED


def test_check_availability_no_stats_event_is_degraded(tmp_path: Path):
    eve = tmp_path / "eve.json"
    _write_eve(eve, [_alert_record(_now_suricata_ts())])
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.status == STATUS_DEGRADED
    assert "no stats event" in health.detail.lower()


def test_check_availability_zero_packets_is_degraded_never_ok(tmp_path: Path):
    eve = tmp_path / "eve.json"
    _write_eve(eve, [_stats_record(_now_suricata_ts(), kernel_packets=0, decoder_pkts=0)])
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.status == STATUS_DEGRADED
    assert "ZERO packets" in health.detail


def test_check_availability_stale_stats_is_degraded(tmp_path: Path):
    eve = tmp_path / "eve.json"
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    _write_eve(eve, [_stats_record(_now_suricata_ts(old), kernel_packets=500)])
    health = availability_module.check_availability(_cfg_for(tmp_path, eve), stale_after_seconds=600.0)
    assert health.status == STATUS_DEGRADED
    assert "old" in health.detail.lower() or "may not be running" in health.detail


def test_check_availability_healthy_is_ok(tmp_path: Path):
    eve = tmp_path / "eve.json"
    _write_eve(eve, [_stats_record(_now_suricata_ts(), kernel_packets=15234, kernel_drops=3)])
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.status == STATUS_OK
    assert "15234" in health.detail


def test_check_availability_missing_read_permission_is_error(tmp_path: Path, monkeypatch):
    eve = tmp_path / "eve.json"
    eve.write_text("{}\n")

    def boom(path, max_lines):
        raise OSError("permission denied")

    monkeypatch.setattr(availability_module, "read_eve_lines", boom)
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.status == "error"


def test_check_availability_attaches_tool_version_when_available(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(availability_module, "try_get_version", lambda: "7.0.3")
    eve = tmp_path / "eve.json"
    _write_eve(eve, [_stats_record(_now_suricata_ts(), kernel_packets=1)])
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.tool_version == "7.0.3"


def test_check_availability_missing_binary_never_blocks_ok_status(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(availability_module, "try_get_version", lambda: None)
    eve = tmp_path / "eve.json"
    _write_eve(eve, [_stats_record(_now_suricata_ts(), kernel_packets=1)])
    health = availability_module.check_availability(_cfg_for(tmp_path, eve))
    assert health.status == STATUS_OK
    assert health.tool_version is None


# ---------- _shell.py ----------


def test_try_get_version_returns_none_when_binary_missing(monkeypatch):
    monkeypatch.setattr(
        shell_module, "run", lambda args, timeout=5.0: shell_module.ShellResult(
            ok=False, stdout="", stderr="command not found", returncode=None
        )
    )
    assert shell_module.try_get_version() is None


def test_try_get_version_extracts_semver(monkeypatch):
    monkeypatch.setattr(
        shell_module, "run", lambda args, timeout=5.0: shell_module.ShellResult(
            ok=True, stdout="This is Suricata version 7.0.3 RELEASE", stderr="", returncode=0
        )
    )
    assert shell_module.try_get_version() == "7.0.3"


# ---------- correlate.py ----------


def test_find_process_correlation_matches_dest_side(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "203.0.113.5", 4444, "ESTABLISHED", 1234, "/usr/bin/evil")],
        )
        alert_fields = {
            "timestamp": _now_suricata_ts(now), "proto": "TCP",
            "src_ip": "10.0.0.5", "src_port": 51000,
            "dest_ip": "203.0.113.5", "dest_port": 4444,
        }
        corr = correlate_module.find_process_correlation(db.conn, alert_fields)
        assert corr is not None
        assert corr.matched_side == "dest"
        assert corr.process_name == "/usr/bin/evil"
        assert corr.pid == 1234
        assert "attributed to /usr/bin/evil" in correlate_module.describe_correlation(corr)


def test_find_process_correlation_matches_src_side(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 22, "198.51.100.9", 51000, "ESTABLISHED", 42, "sshd")],
        )
        alert_fields = {
            "timestamp": _now_suricata_ts(now), "proto": "TCP",
            "src_ip": "198.51.100.9", "src_port": 51000,
            "dest_ip": "10.0.0.5", "dest_port": 22,
        }
        corr = correlate_module.find_process_correlation(db.conn, alert_fields)
        assert corr is not None
        assert corr.matched_side == "src"
        assert corr.process_name == "sshd"


def test_find_process_correlation_no_match_returns_none_honestly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "203.0.113.5", 4444, "ESTABLISHED", 1234, "/usr/bin/evil")],
        )
        alert_fields = {
            "timestamp": _now_suricata_ts(now), "proto": "TCP",
            "src_ip": "10.0.0.5", "src_port": 51000,
            "dest_ip": "203.0.113.5", "dest_port": 9999,  # different port -> no match
        }
        corr = correlate_module.find_process_correlation(db.conn, alert_fields)
        assert corr is None
        assert "not established" in correlate_module.describe_correlation(corr)


def test_find_process_correlation_outside_time_window_is_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "203.0.113.5", 4444, "ESTABLISHED", 1234, "/usr/bin/evil")],
        )
        far_future = datetime.now(timezone.utc) + timedelta(seconds=10_000)
        alert_fields = {
            "timestamp": _now_suricata_ts(far_future), "proto": "TCP",
            "src_ip": "10.0.0.5", "src_port": 51000,
            "dest_ip": "203.0.113.5", "dest_port": 4444,
        }
        corr = correlate_module.find_process_correlation(db.conn, alert_fields, window_seconds=300.0)
        assert corr is None


def test_find_process_correlation_unparseable_timestamp_is_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        alert_fields = {"timestamp": "garbage", "proto": "TCP", "dest_ip": "203.0.113.5", "dest_port": 4444}
        assert correlate_module.find_process_correlation(db.conn, alert_fields) is None


def test_find_process_correlation_unsupported_protocol_is_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        alert_fields = {
            "timestamp": _now_suricata_ts(), "proto": "ICMP",
            "src_ip": "10.0.0.5", "src_port": 0, "dest_ip": "203.0.113.5", "dest_port": 0,
        }
        assert correlate_module.find_process_correlation(db.conn, alert_fields) is None


# ---------- scanner.py: end-to-end persistence ----------


def test_scan_suricata_unavailable_short_circuits(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        cfg = _cfg_for(tmp_path)  # no log path configured
        result = scanner_module.scan_suricata(db.conn, cfg)
        assert result.available is False
        assert list_integration_observations(db.conn, integration="suricata") == []
        runs = list_integration_runs(db.conn, integration="suricata")
        assert len(runs) == 1
        assert runs[0].status == "unavailable"


def test_scan_suricata_degraded_zero_packets_still_ingests_existing_alerts(tmp_path: Path):
    """The behavior this phase's 'handle unavailable packet visibility
    honestly' requirement implies: a DEGRADED health (zero packets right
    now) must not suppress alerts that are already genuinely logged —
    it only means an ABSENCE of alerts can't be trusted, not that
    existing ones should be hidden.
    """
    with Database(tmp_path / "test.db") as db:
        eve = tmp_path / "eve.json"
        now = _now_suricata_ts()
        _write_eve(eve, [_alert_record(now), _stats_record(now, kernel_packets=0, decoder_pkts=0)])
        cfg = _cfg_for(tmp_path, eve)
        result = scanner_module.scan_suricata(db.conn, cfg)
        assert result.health.status == STATUS_DEGRADED
        assert len(result.findings) == 1  # still ingested despite degraded visibility


def test_scan_suricata_healthy_ingests_and_correlates(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "203.0.113.5", 4444, "ESTABLISHED", 1234, "/usr/bin/evil")],
        )
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts(now)
        _write_eve(
            eve,
            [
                _alert_record(ts, src_ip="10.0.0.5", src_port=51000, dest_ip="203.0.113.5", dest_port=4444),
                _stats_record(ts, kernel_packets=15234),
            ],
        )
        cfg = _cfg_for(tmp_path, eve)
        result = scanner_module.scan_suricata(db.conn, cfg)

        assert result.health.status == STATUS_OK
        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"
        assert "attributed to /usr/bin/evil" in result.findings[0].message

        alerts = list_integration_alerts(db.conn, integration="suricata")
        assert len(alerts) == 1
        assert alerts[0].kind == scanner_module.NETWORK_ALERT
        assert alerts[0].discrepancy == "match"
        assert alerts[0].source_observation_id is not None

        observations = list_integration_observations(db.conn, integration="suricata")
        kinds = sorted(o.kind for o in observations)
        assert kinds == ["capture_stats", "eve_alert"]


# ---------- Phase 21: evidence_links wiring (additive) ----------


def test_scan_suricata_process_match_records_evidence_link(tmp_path: Path):
    from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE
    from secure.storage.models import list_evidence_links_for

    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        conn_ids = add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "203.0.113.5", 4444, "ESTABLISHED", 1234, "/usr/bin/evil")],
        )
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts(now)
        _write_eve(
            eve,
            [_alert_record(ts, src_ip="10.0.0.5", src_port=51000, dest_ip="203.0.113.5", dest_port=4444)],
        )
        cfg = _cfg_for(tmp_path, eve)
        result = scanner_module.scan_suricata(db.conn, cfg)
        assert result.evidence_links_recorded == 1

        alerts = list_integration_alerts(db.conn, integration="suricata")
        links = list_evidence_links_for(db.conn, "integration_alerts", alerts[0].id)
        assert len(links) == 1
        assert links[0].relationship == RELATIONSHIP_DERIVED_EVIDENCE
        assert links[0].created_by == "suricata_correlate"
        assert links[0].to_source_table == "connection_events"
        assert links[0].to_source_id == conn_ids[0]
        assert links[0].time_delta_seconds is not None


def test_scan_suricata_no_correlation_records_no_evidence_link(tmp_path: Path):
    from secure.storage.models import list_evidence_links_for

    with Database(tmp_path / "test.db") as db:
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts()
        # No matching connection_events row exists at all.
        _write_eve(eve, [_alert_record(ts, src_ip="192.0.2.50", dest_ip="203.0.113.50")])
        cfg = _cfg_for(tmp_path, eve)
        result = scanner_module.scan_suricata(db.conn, cfg)
        assert result.evidence_links_recorded == 0

        alerts = list_integration_alerts(db.conn, integration="suricata")
        assert list_evidence_links_for(db.conn, "integration_alerts", alerts[0].id) == []


def test_scan_suricata_rescan_does_not_duplicate_evidence_link(tmp_path: Path):
    """A second scan pass over the same eve.json only ever ingests
    genuinely NEW alert records (via the timestamp cursor) — so this
    confirms the evidence_links write path never fires twice for the
    same alert, without needing record_link()'s own idempotence check
    to ever actually be exercised by a duplicate write attempt here.
    """
    from secure.storage.models import list_evidence_links_for

    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "203.0.113.5", 4444, "ESTABLISHED", 1234, "/usr/bin/evil")],
        )
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts(now)
        _write_eve(
            eve,
            [_alert_record(ts, src_ip="10.0.0.5", src_port=51000, dest_ip="203.0.113.5", dest_port=4444)],
        )
        cfg = _cfg_for(tmp_path, eve)
        scanner_module.scan_suricata(db.conn, cfg)
        result2 = scanner_module.scan_suricata(db.conn, cfg)
        assert result2.evidence_links_recorded == 0

        alerts = list_integration_alerts(db.conn, integration="suricata")
        assert len(alerts) == 1
        links = list_evidence_links_for(db.conn, "integration_alerts", alerts[0].id)
        assert len(links) == 1


def test_scan_suricata_second_scan_does_not_reingest_same_alert(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts()
        _write_eve(eve, [_alert_record(ts), _stats_record(ts, kernel_packets=100)])
        cfg = _cfg_for(tmp_path, eve)

        result1 = scanner_module.scan_suricata(db.conn, cfg)
        assert len(result1.findings) == 1

        result2 = scanner_module.scan_suricata(db.conn, cfg)
        assert len(result2.findings) == 0

        alerts = list_integration_alerts(db.conn, integration="suricata")
        assert len(alerts) == 1  # not duplicated


def test_scan_suricata_new_alert_appended_later_is_ingested(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        eve = tmp_path / "eve.json"
        t1 = _now_suricata_ts()
        _write_eve(eve, [_alert_record(t1, flow_id=1), _stats_record(t1, kernel_packets=100)])
        cfg = _cfg_for(tmp_path, eve)
        scanner_module.scan_suricata(db.conn, cfg)

        t2 = _now_suricata_ts(datetime.now(timezone.utc) + timedelta(seconds=5))
        _write_eve(
            eve,
            [
                _alert_record(t1, flow_id=1),
                _alert_record(t2, flow_id=2, signature="SECURE-TEST second rule"),
                _stats_record(t2, kernel_packets=200),
            ],
        )
        result2 = scanner_module.scan_suricata(db.conn, cfg)
        assert len(result2.findings) == 1
        assert result2.findings[0].signature == "SECURE-TEST second rule"


def test_scan_suricata_malformed_lines_and_skipped_records_counted(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts()
        eve.write_text(
            "\n".join(
                [
                    json.dumps(_alert_record(ts)),
                    "not valid json {{{",
                    json.dumps({"timestamp": ts, "event_type": "alert", "alert": {"gid": 1}}),  # missing signature
                    json.dumps(_stats_record(ts, kernel_packets=50)),
                ]
            )
            + "\n"
        )
        cfg = _cfg_for(tmp_path, eve)
        result = scanner_module.scan_suricata(db.conn, cfg)
        assert result.malformed_lines == 1
        assert result.skipped_records == 1
        assert len(result.findings) == 1


def test_scan_suricata_records_run_with_correct_counts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        eve = tmp_path / "eve.json"
        ts = _now_suricata_ts()
        _write_eve(eve, [_alert_record(ts), _stats_record(ts, kernel_packets=100)])
        cfg = _cfg_for(tmp_path, eve)
        result = scanner_module.scan_suricata(db.conn, cfg)
        runs = list_integration_runs(db.conn, integration="suricata")
        assert len(runs) == 1
        assert runs[0].observations_collected == 2  # eve_alert + capture_stats
        assert runs[0].alerts_generated == 1
        assert runs[0].run_id == result.run_id


# ---------- correlate wiring ----------


def test_classify_suricata_finding_strength():
    assert classify_suricata_finding_strength("high") == STRONG
    assert classify_suricata_finding_strength("medium") == MEDIUM
    assert classify_suricata_finding_strength("low") == WEAK


def test_classify_integration_signal_strength_dispatches_suricata():
    assert _classify_integration_signal_strength("suricata", "match", "high") == STRONG
    assert _classify_integration_signal_strength("suricata", "match", "low") == WEAK


def test_collect_integrations_reads_suricata_alert_kind_unsuffixed(tmp_path: Path):
    from secure.storage.models import add_integration_alert

    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="suricata", kind="network_alert", discrepancy="match",
            severity="high", identity_key="x", label="SECURE-TEST rule", message="m",
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert len(signals) == 1
        assert signals[0].kind == "network_alert"
        assert signals[0].strength == STRONG
        assert signals[0].module == "integrations"


def test_collect_integrations_never_reads_capture_stats_observations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_observations(
            db.conn, run_id="r1", integration="suricata",
            rows=[("capture_stats", "ts", {"kernel_packets": 0}, "q", NOW)],
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert signals == []


# ---------- explain wiring ----------


def test_explain_integration_alert_suricata_attributed(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=1, created_at=NOW, run_id="r1", integration="suricata", kind="network_alert",
        discrepancy="match", severity="high", identity_key="x", label="SECURE-TEST rule",
        message=(
            "Suricata signature fired. Correlated with Secure's own native connection "
            "observation (#1, 0s from this alert's timestamp), attributed to /usr/bin/evil."
        ),
        source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert exp.degraded is False
    assert exp.severity == "high"
    assert exp.recommended_action == "REVIEW_NETWORK_DESTINATION"
    assert "identified as involved" in exp.significance


def test_explain_integration_alert_suricata_unattributed(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=2, created_at=NOW, run_id="r1", integration="suricata", kind="network_alert",
        discrepancy="match", severity="medium", identity_key="x", label="SECURE-TEST rule",
        message=(
            "Suricata signature fired. No matching native connection observation was found "
            "near this alert's timestamp — process attribution is not established for this "
            "alert."
        ),
        source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert "No specific process could be identified" in exp.significance
    assert any("confirmed compromise" in u for u in exp.uncertainty)


def test_explain_integration_alert_yarax_sigma_osquery_still_work_after_suricata_added(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    yarax_record = IntegrationAlertRecord(
        id=3, created_at=NOW, run_id="r1", integration="yarax", kind="yara_match",
        discrepancy="match", severity="high", identity_key="abc", label="rule",
        message="A YARA rule matched.", source_observation_id=1, known=False,
    )
    assert explain(yarax_record, "integration_alerts").recommended_action == "INSPECT_FILE"

    sigma_record = IntegrationAlertRecord(
        id=4, created_at=NOW, run_id="r1", integration="sigma", kind="process_creation",
        discrepancy="match", severity="high", identity_key="rule-1", label="Suspicious curl",
        message="A Sigma rule matched.", source_observation_id=1, known=False,
    )
    assert explain(sigma_record, "integration_alerts").recommended_action == "INSPECT_PROCESS"

    osquery_record = IntegrationAlertRecord(
        id=5, created_at=NOW, run_id="r1", integration="osquery", kind="listening_port",
        discrepancy="osquery_only", severity="high", identity_key="tcp:4444", label="evil",
        message="osquery saw a port native did not.", source_observation_id=1, known=False,
    )
    assert explain(osquery_record, "integration_alerts").degraded is False
