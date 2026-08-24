"""
Tests for secure/correlate/chain_scanner.py (Phase 22 Stage 4:
run_chain_correlation(), the batch orchestration entry point CLI's
`secure correlate chains run` calls).

Same Database/tmp_path convention as tests/test_correlate_chains.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.correlate.chain_scanner import run_chain_correlation
from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE, RELATIONSHIP_SAME_EVENT_CONFIRMATION, EvidenceLink, ObservationRef
from secure.evidence.record import record_link
from secure.storage.database import Database
from secure.storage.models import list_correlation_chain_alerts


def _seed_connection_event(conn, *, created_at="2026-01-01T12:00:00+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO connection_events (created_at, run_id, proto, local_addr, local_port, "
        "remote_addr, remote_port, state, pid, process_name) VALUES (?, 'r', 'tcp', '10.0.0.1', "
        "51000, '203.0.113.5', 443, 'ESTABLISHED', 100, 'curl')",
        (created_at,),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_integration_observation(conn, *, collected_at="2026-01-01T12:00:05+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
        "fields_json, source_query, collected_at) VALUES (?, 'r', 'zeek', 'conn', 'k', '{}', 'q', ?)",
        (collected_at, collected_at),
    )
    conn.commit()
    return cursor.lastrowid


def _link(conn, from_table, from_id, to_table, to_id, relationship, detail="test"):
    record_link(
        conn,
        EvidenceLink(
            from_ref=ObservationRef(source_table=from_table, source_id=from_id),
            to_ref=ObservationRef(source_table=to_table, source_id=to_id),
            relationship=relationship, match_basis="identity+timing", detail=detail, created_by="test",
        ),
    )


def test_no_evidence_links_produces_no_chains(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        _seed_connection_event(db.conn)  # unlinked observation — never a candidate start
        result = run_chain_correlation(db.conn)
        assert result.candidate_start_count == 0
        assert result.chains_scored == 0
        assert result.new_alerts == []


def test_one_linked_pair_produces_exactly_one_chain(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        result = run_chain_correlation(db.conn)
        assert result.candidate_start_count == 2  # both endpoints are candidates
        assert result.chains_scored == 1          # but they're the SAME connected component
        assert len(result.new_alerts) == 1
        assert list_correlation_chain_alerts(db.conn)[0].raw_observation_count == 2


def test_two_disjoint_components_produce_two_chains(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_a = _seed_connection_event(db.conn, created_at="2026-01-01T12:00:00+00:00")
        obs_a = _seed_integration_observation(db.conn, collected_at="2026-01-01T12:00:01+00:00")
        _link(db.conn, "integration_observations", obs_a, "connection_events", conn_a,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION, detail="component A")

        conn_b = _seed_connection_event(db.conn, created_at="2026-01-02T12:00:00+00:00")
        obs_b = _seed_integration_observation(db.conn, collected_at="2026-01-02T12:00:01+00:00")
        _link(db.conn, "integration_observations", obs_b, "connection_events", conn_b,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION, detail="component B")

        result = run_chain_correlation(db.conn)
        assert result.chains_scored == 2
        assert len(result.new_alerts) == 2


def test_rerun_over_same_history_is_idempotent(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        first = run_chain_correlation(db.conn)
        assert len(first.new_alerts) == 1
        assert first.already_known_chains == 0

        second = run_chain_correlation(db.conn)
        assert len(second.new_alerts) == 0
        assert second.already_known_chains == 1
        assert len(list_correlation_chain_alerts(db.conn)) == 1


def test_lookback_hours_excludes_stale_links(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        conn_id = _seed_connection_event(db.conn, created_at=old_time)
        obs_id = _seed_integration_observation(db.conn, collected_at=old_time)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)
        # record_link() stamps last_seen with "now" regardless of the
        # linked rows' own created_at, so directly age the evidence_links
        # row itself to simulate genuinely old evidence.
        db.conn.execute("UPDATE evidence_links SET last_seen = ?", (old_time,))
        db.conn.commit()

        result = run_chain_correlation(db.conn, lookback_hours=1.0)
        assert result.candidate_start_count == 0
        assert result.chains_scored == 0


def test_run_id_is_present_and_distinct_per_pass(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        first = run_chain_correlation(db.conn)
        second = run_chain_correlation(db.conn)
        assert first.run_id != second.run_id
