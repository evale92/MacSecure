"""
Tests for secure/integrations/zeek/ (Phase 19: Zeek behavioral network
telemetry integration).

Like Suricata (Phase 18), this integration has no third-party library
seam to mock — it's plain stdlib `json` over log files Zeek itself
(running entirely outside Secure) already writes, so these tests
exercise the real parsing/availability/dedup/scanner/baseline logic
directly, no mocking needed beyond the optional `zeek --version`
subprocess.

Uses a static fixture directory (tests/fixtures/zeek/logs/) for pure
parsing-shape tests, where "is this timestamp fresh" doesn't matter —
plus dynamically-built log content (current wall-clock timestamps) for
availability/dedup/scanner/baseline tests, where staleness/timing logic
is inherently relative to "now". All IPs in fixtures are IANA-reserved
documentation ranges (TEST-NET-1/2/3: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and every synthetic domain/signature is prefixed
"secure-test"/"SECURE-TEST" — never a real-world IOC.

Run with:  pytest
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.baseline.entities import DNS_QUERY, TLS_SNI
from secure.config import AppConfig
from secure.correlate.signals import _classify_integration_signal_strength, _collect_integrations, collect_signals
from secure.integrations.base import STATUS_DEGRADED, STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE
from secure.integrations.zeek import _logs as logs_module
from secure.integrations.zeek import _shell as shell_module
from secure.integrations.zeek import _timeutil
from secure.integrations.zeek import availability as availability_module
from secure.integrations.zeek import dedup as dedup_module
from secure.integrations.zeek import identity as identity_module
from secure.integrations.zeek import parser as parser_module
from secure.integrations.zeek import scanner as scanner_module
from secure.storage.database import Database
from secure.storage.models import (
    add_connection_events,
    add_integration_observations,
    add_integration_run,
    find_baseline_entity,
    list_integration_observations,
    list_integration_runs,
)

FIXTURES = Path(__file__).parent / "fixtures" / "zeek" / "logs"

NOW = "2026-08-21T00:00:00+00:00"


def _cfg_for(tmp_path: Path, log_dir: "Path | None" = None) -> AppConfig:
    cfg = AppConfig(app_dir=str(tmp_path))
    if log_dir is not None:
        cfg.zeek_log_dir = str(log_dir)
    return cfg


def _write_log(path: Path, records: "list[dict]") -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")


def _touch_fresh(*paths: Path) -> None:
    now = time.time()
    for p in paths:
        import os

        os.utime(p, (now, now))


def _conn_record(ts, uid="Cuid1", orig_h="192.0.2.10", orig_p=51000, resp_h="198.51.100.7",
                  resp_p=443, proto="tcp") -> dict:
    return {
        "ts": ts, "uid": uid,
        "id": {"orig_h": orig_h, "orig_p": orig_p, "resp_h": resp_h, "resp_p": resp_p},
        "proto": proto, "service": "ssl", "duration": 1.0, "orig_bytes": 100,
        "resp_bytes": 200, "conn_state": "SF",
    }


def _dns_record(ts, uid="Cuid2", query="secure-test.example.com.", orig_h="192.0.2.11",
                 resp_h="203.0.113.5") -> dict:
    return {
        "ts": ts, "uid": uid,
        "id": {"orig_h": orig_h, "orig_p": 52000, "resp_h": resp_h, "resp_p": 53},
        "proto": "udp", "query": query, "qtype_name": "A", "rcode_name": "NOERROR",
        "answers": ["203.0.113.9"],
    }


def _ssl_record(ts, uid="Cuid1", server_name="Secure-Test.example.com", orig_h="192.0.2.10",
                 resp_h="198.51.100.7") -> dict:
    return {
        "ts": ts, "uid": uid,
        "id": {"orig_h": orig_h, "orig_p": 51000, "resp_h": resp_h, "resp_p": 443},
        "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
        "server_name": server_name, "established": True,
    }


def _http_record(ts, uid="Cuid3", host="secure-test.example.org") -> dict:
    return {
        "ts": ts, "uid": uid,
        "id": {"orig_h": "192.0.2.12", "orig_p": 53000, "resp_h": "198.51.100.20", "resp_p": 80},
        "method": "GET", "host": host, "uri": "/", "status_code": 200,
        "user_agent": "SECURE-TEST-agent/1.0",
    }


# ---------- _logs.py ----------


def test_read_zeek_log_lines_from_fixture():
    records, malformed = logs_module.read_zeek_log_lines(FIXTURES / "conn.log")
    assert malformed == 1  # the one deliberately invalid line
    assert len(records) == 3


def test_read_zeek_log_lines_missing_file_returns_empty(tmp_path: Path):
    records, malformed = logs_module.read_zeek_log_lines(tmp_path / "does_not_exist.log")
    assert records == []
    assert malformed == 0


def test_read_zeek_log_lines_respects_max_lines_tail(tmp_path: Path):
    path = tmp_path / "conn.log"
    lines = [json.dumps({"ts": i, "uid": f"u{i}"}) for i in range(10)]
    path.write_text("\n".join(lines) + "\n")
    records, _ = logs_module.read_zeek_log_lines(path, max_lines=3)
    assert [r["uid"] for r in records] == ["u7", "u8", "u9"]


# ---------- _timeutil.py ----------


def test_parse_zeek_timestamp_float():
    dt = _timeutil.parse_zeek_timestamp(1755781000.123456)
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_zeek_timestamp_int():
    dt = _timeutil.parse_zeek_timestamp(1755781000)
    assert dt is not None


def test_parse_zeek_timestamp_numeric_string():
    dt = _timeutil.parse_zeek_timestamp("1755781000.5")
    assert dt is not None


def test_parse_zeek_timestamp_invalid_returns_none():
    assert _timeutil.parse_zeek_timestamp("not-a-timestamp") is None
    assert _timeutil.parse_zeek_timestamp(None) is None
    assert _timeutil.parse_zeek_timestamp("") is None
    assert _timeutil.parse_zeek_timestamp(True) is None  # bool must never be treated as epoch 1


# ---------- parser.py ----------


def test_parse_conn_record_normalizes_expected_fields():
    records, _ = logs_module.read_zeek_log_lines(FIXTURES / "conn.log")
    obs = parser_module.parse_conn_record(records[0], NOW, str(FIXTURES / "conn.log"))
    assert obs is not None
    assert obs.kind == parser_module.CONN_KIND
    assert obs.identity_key == "CZeekConn1"
    assert obs.fields["orig_h"] == "192.0.2.10"
    assert obs.fields["resp_h"] == "198.51.100.7"
    assert obs.fields["resp_p"] == 443
    assert obs.fields["proto"] == "tcp"
    assert str(FIXTURES / "conn.log") in obs.source_query


def test_parse_conn_record_rejects_missing_ts_or_uid():
    assert parser_module.parse_conn_record({"uid": "x"}, NOW, "p") is None
    assert parser_module.parse_conn_record({"ts": 1.0}, NOW, "p") is None


def test_parse_conn_record_supports_flattened_dotted_id_fields():
    record = {
        "ts": 1.0, "uid": "u1",
        "id.orig_h": "192.0.2.10", "id.orig_p": 1000,
        "id.resp_h": "198.51.100.7", "id.resp_p": 443,
        "proto": "tcp",
    }
    obs = parser_module.parse_conn_record(record, NOW, "p")
    assert obs is not None
    assert obs.fields["orig_h"] == "192.0.2.10"
    assert obs.fields["resp_p"] == 443


def test_parse_dns_record_normalizes_and_rejects_missing_query():
    records, _ = logs_module.read_zeek_log_lines(FIXTURES / "dns.log")
    dns_records = [r for r in records if "query" in r]
    obs = parser_module.parse_dns_record(dns_records[0], NOW, str(FIXTURES / "dns.log"))
    assert obs is not None
    assert obs.kind == parser_module.DNS_KIND
    assert obs.fields["query"] == "secure-test.example.com."
    assert parser_module.parse_dns_record({"ts": 1.0, "uid": "u1"}, NOW, "p") is None


def test_parse_ssl_record_allows_missing_server_name():
    records, _ = logs_module.read_zeek_log_lines(FIXTURES / "ssl.log")
    obs_with_sni = parser_module.parse_ssl_record(records[0], NOW, str(FIXTURES / "ssl.log"))
    assert obs_with_sni.fields["server_name"] == "Secure-Test.example.com"
    obs_without_sni = parser_module.parse_ssl_record(records[1], NOW, str(FIXTURES / "ssl.log"))
    assert obs_without_sni is not None
    assert obs_without_sni.fields["server_name"] is None


def test_parse_http_record_normalizes_expected_fields():
    records, _ = logs_module.read_zeek_log_lines(FIXTURES / "http.log")
    obs = parser_module.parse_http_record(records[0], NOW, str(FIXTURES / "http.log"))
    assert obs is not None
    assert obs.kind == parser_module.HTTP_KIND
    assert obs.fields["host"] == "secure-test.example.org"
    assert obs.fields["status_code"] == 200


# ---------- identity.py ----------


def test_dns_query_domain_normalizes_case_and_trailing_dot():
    assert identity_module.dns_query_domain({"query": "Example.COM."}) == "example.com"


def test_dns_query_domain_none_when_missing_or_empty():
    assert identity_module.dns_query_domain({}) is None
    assert identity_module.dns_query_domain({"query": "   "}) is None


def test_tls_sni_hostname_normalizes_case():
    assert identity_module.tls_sni_hostname({"server_name": "Example.COM"}) == "example.com"


def test_tls_sni_hostname_none_when_absent():
    assert identity_module.tls_sni_hostname({}) is None
    assert identity_module.tls_sni_hostname({"server_name": None}) is None


# ---------- availability.py ----------


def test_check_availability_unconfigured_is_unavailable(tmp_path: Path):
    health = availability_module.check_availability(_cfg_for(tmp_path))
    assert health.status == STATUS_UNAVAILABLE


def test_check_availability_missing_dir_is_unavailable(tmp_path: Path):
    cfg = _cfg_for(tmp_path, tmp_path / "nope")
    health = availability_module.check_availability(cfg)
    assert health.status == STATUS_UNAVAILABLE
    assert "not found" in health.detail


def test_check_availability_empty_dir_is_degraded(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir))
    assert health.status == STATUS_DEGRADED
    assert "none of the recognized" in health.detail


def test_check_availability_stale_logs_is_degraded(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    conn_log = log_dir / "conn.log"
    conn_log.write_text(json.dumps(_conn_record(1.0)) + "\n")
    old = time.time() - 3600
    import os

    os.utime(conn_log, (old, old))
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir), stale_after_seconds=600.0)
    assert health.status == STATUS_DEGRADED
    assert "stopped writing" in health.detail or "not been updated" in health.detail


def test_check_availability_fresh_log_is_ok(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    conn_log = log_dir / "conn.log"
    conn_log.write_text(json.dumps(_conn_record(1.0)) + "\n")
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir))
    assert health.status == STATUS_OK
    assert "conn.log" in health.detail


def test_check_availability_partial_logs_still_ok_when_one_fresh(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(json.dumps(_conn_record(1.0)) + "\n")
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir))
    assert health.status == STATUS_OK


def test_check_availability_unreadable_dir_is_error(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    def boom(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(availability_module.Path, "is_file", boom)
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir))
    assert health.status == STATUS_ERROR


def test_check_availability_attaches_tool_version_when_available(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(availability_module, "try_get_version", lambda: "6.0.1")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(json.dumps(_conn_record(1.0)) + "\n")
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir))
    assert health.tool_version == "6.0.1"


def test_check_availability_missing_binary_never_blocks_ok_status(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(availability_module, "try_get_version", lambda: None)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(json.dumps(_conn_record(1.0)) + "\n")
    health = availability_module.check_availability(_cfg_for(tmp_path, log_dir))
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
            ok=True, stdout="zeek version 6.0.1", stderr="", returncode=0
        )
    )
    assert shell_module.try_get_version() == "6.0.1"


# ---------- dedup.py ----------


def test_classify_conn_dedup_matches_native_connection(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "198.51.100.7", 443, "ESTABLISHED", 111, "TestProc")],
        )
        now = datetime.now(timezone.utc)
        db.conn.execute("UPDATE connection_events SET created_at = ?", (now.isoformat(),))
        db.conn.commit()

        fields = {
            "ts": now.timestamp(), "orig_h": "192.0.2.10", "orig_p": 51000,
            "resp_h": "198.51.100.7", "resp_p": 443, "proto": "tcp",
        }
        result = dedup_module.classify_conn_dedup(db.conn, fields)
        assert result.status == dedup_module.MATCHES_NATIVE_CONNECTION
        assert result.matched_source_table == "connection_events"


def test_classify_conn_dedup_matches_suricata_alert(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        add_integration_run(
            db.conn, run_id="sur1", integration="suricata", started_at=now.isoformat(),
            completed_at=now.isoformat(), status="ok", detail="seed",
        )
        suricata_ts = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        add_integration_observations(
            db.conn, run_id="sur1", integration="suricata",
            rows=[
                (
                    "eve_alert", "flow1",
                    {
                        "timestamp": suricata_ts, "src_ip": "192.0.2.11", "src_port": 52000,
                        "dest_ip": "203.0.113.5", "dest_port": 53, "proto": "UDP",
                        "signature": "SECURE-TEST SIG",
                    },
                    "seed", now.isoformat(),
                ),
            ],
        )
        fields = {
            "ts": now.timestamp(), "orig_h": "192.0.2.11", "orig_p": 52000,
            "resp_h": "203.0.113.5", "resp_p": 53, "proto": "udp",
        }
        result = dedup_module.classify_conn_dedup(db.conn, fields)
        assert result.status == dedup_module.MATCHES_SURICATA_ALERT
        assert result.matched_source_table == "integration_observations"


def test_classify_conn_dedup_novel_when_no_match(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc)
        fields = {
            "ts": now.timestamp(), "orig_h": "192.0.2.20", "orig_p": 9999,
            "resp_h": "203.0.113.20", "resp_p": 9999, "proto": "tcp",
        }
        result = dedup_module.classify_conn_dedup(db.conn, fields)
        assert result.status == dedup_module.NOVEL


def test_classify_conn_dedup_unparseable_timestamp_is_novel(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        fields = {"ts": "garbage", "orig_h": "192.0.2.20", "orig_p": 1, "resp_h": "1.2.3.4", "resp_p": 1, "proto": "tcp"}
        result = dedup_module.classify_conn_dedup(db.conn, fields)
        assert result.status == dedup_module.NOVEL


def test_classify_conn_dedup_no_endpoint_identity_is_novel(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        fields = {"ts": 1.0, "proto": "tcp"}
        result = dedup_module.classify_conn_dedup(db.conn, fields)
        assert result.status == dedup_module.NOVEL


# ---------- scanner.py: end-to-end ----------


def test_scan_zeek_unavailable_short_circuits(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        cfg = _cfg_for(tmp_path)  # no log dir configured
        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.available is False
        assert list_integration_observations(db.conn, integration="zeek") == []
        runs = list_integration_runs(db.conn, integration="zeek")
        assert len(runs) == 1
        assert runs[0].status == "unavailable"
        assert runs[0].alerts_generated == 0


def test_scan_zeek_healthy_ingests_all_four_log_types(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "conn.log", [_conn_record(now)])
        _write_log(log_dir / "dns.log", [_dns_record(now)])
        _write_log(log_dir / "ssl.log", [_ssl_record(now)])
        _write_log(log_dir / "http.log", [_http_record(now)])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.health.status == STATUS_OK
        counts = result.counts_by_kind
        assert counts == {"conn": 1, "dns": 1, "ssl": 1, "http": 1}

        observations = list_integration_observations(db.conn, integration="zeek")
        assert len(observations) == 4

        runs = list_integration_runs(db.conn, integration="zeek")
        assert len(runs) == 1
        assert runs[0].alerts_generated == 0  # Zeek never produces alerts
        assert runs[0].observations_collected == 4


def test_scan_zeek_never_writes_integration_alerts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "conn.log", [_conn_record(now)])
        cfg = _cfg_for(tmp_path, log_dir)
        scanner_module.scan_zeek(db.conn, cfg)

        from secure.storage.models import list_integration_alerts

        assert list_integration_alerts(db.conn, integration="zeek") == []


def test_scan_zeek_conn_dedup_status_embedded_in_observation(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        now_dt = datetime.now(timezone.utc)
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "198.51.100.7", 443, "ESTABLISHED", 111, "TestProc")],
        )
        db.conn.execute("UPDATE connection_events SET created_at = ?", (now_dt.isoformat(),))
        db.conn.commit()

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _write_log(log_dir / "conn.log", [_conn_record(now_dt.timestamp())])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        conn_obs = [o for o in result.observations if o.kind == "conn"][0]
        assert conn_obs.fields["dedup_status"] == dedup_module.MATCHES_NATIVE_CONNECTION
        assert result.dedup_counts.get(dedup_module.MATCHES_NATIVE_CONNECTION) == 1


# ---------- Phase 21: evidence_links wiring (additive) ----------


def test_scan_zeek_matches_native_connection_records_evidence_link(tmp_path: Path):
    from secure.evidence.model import RELATIONSHIP_SAME_EVENT_CONFIRMATION
    from secure.storage.models import list_evidence_links_for

    with Database(tmp_path / "test.db") as db:
        now_dt = datetime.now(timezone.utc)
        conn_ids = add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "198.51.100.7", 443, "ESTABLISHED", 111, "TestProc")],
        )
        db.conn.execute("UPDATE connection_events SET created_at = ?", (now_dt.isoformat(),))
        db.conn.commit()

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _write_log(log_dir / "conn.log", [_conn_record(now_dt.timestamp())])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.evidence_links_recorded == 1

        links = list_evidence_links_for(db.conn, "connection_events", conn_ids[0])
        assert len(links) == 1
        assert links[0].relationship == RELATIONSHIP_SAME_EVENT_CONFIRMATION
        assert links[0].created_by == "zeek_dedup"
        assert links[0].from_source_table == "integration_observations"


def test_scan_zeek_novel_record_creates_no_evidence_link(tmp_path: Path):
    from secure.storage.models import list_integration_observations as _list_obs

    with Database(tmp_path / "test.db") as db:
        now = datetime.now(timezone.utc).timestamp()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _write_log(log_dir / "conn.log", [_conn_record(now, orig_h="192.0.2.99", resp_h="203.0.113.99")])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.evidence_links_recorded == 0

        obs = [o for o in _list_obs(db.conn, integration="zeek", kind="conn")][0]
        from secure.storage.models import list_evidence_links_for

        assert list_evidence_links_for(db.conn, "integration_observations", obs.id) == []


def test_scan_zeek_rescan_does_not_duplicate_evidence_link(tmp_path: Path):
    from secure.storage.models import list_evidence_links_for

    with Database(tmp_path / "test.db") as db:
        now_dt = datetime.now(timezone.utc)
        conn_ids = add_connection_events(
            db.conn, run_id="r1",
            rows=[("TCP", "10.0.0.5", 51000, "198.51.100.7", 443, "ESTABLISHED", 111, "TestProc")],
        )
        db.conn.execute("UPDATE connection_events SET created_at = ?", (now_dt.isoformat(),))
        db.conn.commit()

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _write_log(log_dir / "conn.log", [_conn_record(now_dt.timestamp())])
        cfg = _cfg_for(tmp_path, log_dir)

        scanner_module.scan_zeek(db.conn, cfg)
        # Second scan: the conn.log record was already ingested (cursor
        # advances past it), so nothing new is classified or linked —
        # confirms idempotence holds across a full rescan, not just a
        # direct record_link() call.
        result2 = scanner_module.scan_zeek(db.conn, cfg)
        assert result2.evidence_links_recorded == 0

        links = list_evidence_links_for(db.conn, "connection_events", conn_ids[0])
        assert len(links) == 1


def test_scan_zeek_second_scan_does_not_reingest_same_records(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "conn.log", [_conn_record(now)])
        cfg = _cfg_for(tmp_path, log_dir)

        result1 = scanner_module.scan_zeek(db.conn, cfg)
        assert len(result1.observations) == 1

        result2 = scanner_module.scan_zeek(db.conn, cfg)
        assert len(result2.observations) == 0

        observations = list_integration_observations(db.conn, integration="zeek")
        assert len(observations) == 1  # not duplicated


def test_scan_zeek_new_record_appended_later_is_ingested(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        t1 = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "conn.log", [_conn_record(t1, uid="Cuid1")])
        cfg = _cfg_for(tmp_path, log_dir)
        scanner_module.scan_zeek(db.conn, cfg)

        t2 = t1 + 5
        _write_log(log_dir / "conn.log", [_conn_record(t1, uid="Cuid1"), _conn_record(t2, uid="Cuid2")])
        result2 = scanner_module.scan_zeek(db.conn, cfg)
        assert len(result2.observations) == 1
        assert result2.observations[0].identity_key == "Cuid2"


def test_scan_zeek_malformed_lines_counted(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        (log_dir / "conn.log").write_text(
            "\n".join([json.dumps(_conn_record(now)), "not valid json {{{"]) + "\n"
        )
        cfg = _cfg_for(tmp_path, log_dir)
        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.malformed_lines_by_log.get("conn.log") == 1
        assert len(result.observations) == 1


def test_scan_zeek_degraded_still_ingests_present_logs(tmp_path: Path):
    """A DEGRADED health (the one present log is stale) must not
    suppress ingestion of whatever that log still contains — same
    "partial/stale coverage is not the same as nothing happened"
    discipline Suricata's own DEGRADED-still-ingests behavior
    establishes. Availability freshness is a MTIME check only (see
    availability.py); it never gates scanner.py's own read of the log's
    actual content.
    """
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        conn_log = log_dir / "conn.log"
        _write_log(conn_log, [_conn_record(now)])
        old = time.time() - 3600
        import os

        os.utime(conn_log, (old, old))
        # dns.log/ssl.log/http.log absent, and the one present log is
        # stale -> overall DEGRADED, per availability.py.
        cfg = _cfg_for(tmp_path, log_dir)
        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.health.status == STATUS_DEGRADED
        assert len(result.observations) == 1  # conn.log still ingested despite staleness


# ---------- scanner.py: baseline-layer wiring ----------


def test_scan_zeek_feeds_dns_query_baseline(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "dns.log", [_dns_record(now, query="Secure-Test.example.com.")])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.baseline_entities_updated == 1

        entity = find_baseline_entity(db.conn, DNS_QUERY, "secure-test.example.com")
        assert entity is not None
        assert entity.observation_count == 1


def test_scan_zeek_feeds_tls_sni_baseline(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "ssl.log", [_ssl_record(now, server_name="Secure-Test.example.com")])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.baseline_entities_updated == 1

        entity = find_baseline_entity(db.conn, TLS_SNI, "secure-test.example.com")
        assert entity is not None


def test_scan_zeek_ssl_record_without_sni_does_not_touch_baseline(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        record = _ssl_record(now)
        del record["server_name"]
        _write_log(log_dir / "ssl.log", [record])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.baseline_entities_updated == 0


def test_scan_zeek_conn_and_http_never_feed_baseline(tmp_path: Path):
    """conn.log/http.log observations are deliberately excluded from the
    baseline layer this phase (see scanner.py's own module docstring) —
    only dns_query/tls_sni entity_types should ever appear.
    """
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "conn.log", [_conn_record(now)])
        _write_log(log_dir / "http.log", [_http_record(now)])
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert result.baseline_entities_updated == 0


def test_scan_zeek_bulk_dns_queries_in_one_pass_count_as_one_observation(tmp_path: Path):
    """Phase 19's own explicit dampening requirement: many raw dns.log
    records for the SAME domain within one scan pass must fold into
    exactly one baseline observation, not one per raw record — mirrors
    connections/scanner.py's own process_destination dedup-within-a-
    scan discipline.
    """
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        records = [
            _dns_record(now + i, uid=f"Cuidbulk{i}", query="secure-test.example.com.")
            for i in range(50)
        ]
        _write_log(log_dir / "dns.log", records)
        cfg = _cfg_for(tmp_path, log_dir)

        result = scanner_module.scan_zeek(db.conn, cfg)
        assert len(result.observations) == 50  # every raw record still persisted as its own observation
        assert result.baseline_entities_updated == 1  # but only ONE baseline observation this pass

        entity = find_baseline_entity(db.conn, DNS_QUERY, "secure-test.example.com")
        assert entity.observation_count == 1  # not 50


def test_scan_zeek_baseline_maturity_requires_distinct_calendar_days_not_just_volume(tmp_path: Path):
    """Even across many scan passes in the same moment, an entity's
    maturity can only advance in eligible_distinct_days once per real
    calendar day — bulk traffic within one day, across any number of
    scans, can never fast-forward toward ESTABLISHED. This is Phase 14's
    own existing maturity rule, simply verified here as the mechanism
    that satisfies Phase 19's "no bulk noise -> mature baseline" ask.
    """
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        cfg = _cfg_for(tmp_path, log_dir)

        now = datetime.now(timezone.utc).timestamp()
        for i in range(5):
            _write_log(log_dir / "dns.log", [_dns_record(now + i, uid=f"Cuidday1-{i}")])
            scanner_module.scan_zeek(db.conn, cfg)

        entity = find_baseline_entity(db.conn, DNS_QUERY, "secure-test.example.com")
        assert entity.eligible_distinct_days == 1  # still just today, no matter how many scans


# ---------- correlate wiring: Zeek contributes zero alert signals ----------


def test_zeek_produces_no_correlation_signals(tmp_path: Path):
    """Structural verification of the phase's own "Zeek = behavioral
    telemetry, not detection" requirement: even with Zeek observations
    present, collect_signals() must never surface a "zeek" module
    signal, because _collect_integrations() only ever reads
    integration_alerts (which Zeek never writes).
    """
    with Database(tmp_path / "test.db") as db:
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        now = datetime.now(timezone.utc).timestamp()
        _write_log(log_dir / "conn.log", [_conn_record(now)])
        _write_log(log_dir / "dns.log", [_dns_record(now)])
        cfg = _cfg_for(tmp_path, log_dir)
        scanner_module.scan_zeek(db.conn, cfg)

        signals = collect_signals(db.conn, lookback_hours=24.0)
        assert all(s.module != "zeek" for s in signals)

        integration_signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert not any(s.identifier for s in integration_signals if "zeek" in str(s.identifier).lower())


def test_classify_integration_signal_strength_has_no_zeek_branch():
    """Documents (rather than silently relying on) the fact that zeek
    falls through to the generic osquery-style default if it were ever
    called here — it never should be, since Zeek writes no
    integration_alerts rows for this classifier to be invoked on.
    """
    # Falls through to the conservative default rather than raising.
    assert _classify_integration_signal_strength("zeek", "match", "high") is not None
