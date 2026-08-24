"""
Tests for secure/evidence/chain.py (Phase 22 Stage 2: the chain-walking
read layer over evidence_links).

Pure traversal logic exercised against a real temp SQLite database
(same Database/tmp_path convention as tests/test_evidence.py) — nodes
are seeded via direct minimal INSERTs (this file only cares about
chain.py's own graph-walking behavior, not any particular scanner's
output shape) and edges via record_link(), the same real write path
Stage 3 wiring already uses.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.evidence.chain import walk_chain
from secure.evidence.model import (
    RELATIONSHIP_DERIVED_EVIDENCE,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    EvidenceLink,
    ObservationRef,
)
from secure.evidence.record import record_link
from secure.storage.database import Database


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


def _seed_integration_alert(conn, *, created_at="2026-01-01T12:00:10+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO integration_alerts (created_at, run_id, integration, kind, discrepancy, severity, "
        "identity_key, label, message, source_observation_id, known) VALUES "
        "(?, 'r', 'suricata', 'network_alert', 'match', 'medium', 'k', 'l', 'm', NULL, 0)",
        (created_at,),
    )
    conn.commit()
    return cursor.lastrowid


def test_walk_chain_single_node_no_links(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        chain = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert len(chain.nodes) == 1
        assert chain.edges == []
        assert chain.hop_count == 0
        assert chain.nodes[0].source_table == "connection_events"
        assert chain.nodes[0].source_id == conn_id


def test_walk_chain_resolves_known_timestamp(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn, created_at="2026-03-01T00:00:00+00:00")
        chain = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert chain.nodes[0].timestamp is not None
        assert chain.nodes[0].timestamp.year == 2026
        assert chain.nodes[0].timestamp.month == 3


def test_walk_chain_unknown_table_resolves_timestamp_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        chain = walk_chain(db.conn, ObservationRef(source_table="devices", source_id=999999))
        assert chain.nodes[0].timestamp is None  # "devices" isn't in the timestamp-column map


def test_walk_chain_single_edge(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        record_link(
            db.conn,
            EvidenceLink(
                from_ref=ObservationRef(source_table="integration_observations", source_id=obs_id),
                to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
                relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                match_basis="identity+timing",
                detail="test",
                created_by="test",
            ),
        )
        chain = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert len(chain.nodes) == 2
        assert chain.hop_count == 1
        edge = chain.edges[0]
        assert edge.from_node.source_table == "integration_observations"
        assert edge.from_node.source_id == obs_id
        assert edge.to_node.source_table == "connection_events"
        assert edge.to_node.source_id == conn_id


def test_walk_chain_finds_same_edge_regardless_of_starting_side(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        record_link(
            db.conn,
            EvidenceLink(
                from_ref=ObservationRef(source_table="integration_observations", source_id=obs_id),
                to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
                relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                match_basis="identity+timing",
                detail="test",
                created_by="test",
            ),
        )
        from_the_from_side = walk_chain(
            db.conn, ObservationRef(source_table="integration_observations", source_id=obs_id)
        )
        from_the_to_side = walk_chain(
            db.conn, ObservationRef(source_table="connection_events", source_id=conn_id)
        )
        assert from_the_from_side.hop_count == 1
        assert from_the_to_side.hop_count == 1
        assert {(n.source_table, n.source_id) for n in from_the_from_side.nodes} == {
            (n.source_table, n.source_id) for n in from_the_to_side.nodes
        }
        # direction is preserved correctly regardless of which side we started from
        assert from_the_from_side.edges[0].from_node.source_id == obs_id
        assert from_the_to_side.edges[0].from_node.source_id == obs_id


def test_walk_chain_follows_multiple_hops(tmp_path: Path):
    # conn -> obs -> alert, a 3-node, 2-edge line
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        alert_id = _seed_integration_alert(db.conn)

        record_link(
            db.conn,
            EvidenceLink(
                from_ref=ObservationRef(source_table="integration_observations", source_id=obs_id),
                to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
                relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                match_basis="identity+timing", detail="hop1", created_by="test",
            ),
        )
        record_link(
            db.conn,
            EvidenceLink(
                from_ref=ObservationRef(source_table="integration_alerts", source_id=alert_id),
                to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
                relationship=RELATIONSHIP_DERIVED_EVIDENCE,
                match_basis="identity+timing", detail="hop2", created_by="test",
            ),
        )

        chain = walk_chain(db.conn, ObservationRef(source_table="integration_observations", source_id=obs_id))
        assert len(chain.nodes) == 3
        assert chain.hop_count == 2
        node_keys = {(n.source_table, n.source_id) for n in chain.nodes}
        assert node_keys == {
            ("integration_observations", obs_id),
            ("connection_events", conn_id),
            ("integration_alerts", alert_id),
        }


def test_walk_chain_respects_max_hops(tmp_path: Path):
    # A -> B -> C -> D chain; capping at 1 hop should only reach B.
    with Database(tmp_path / "test.db") as db:
        a = _seed_connection_event(db.conn, created_at="2026-01-01T00:00:00+00:00")
        b = _seed_integration_observation(db.conn, collected_at="2026-01-01T00:01:00+00:00")
        c = _seed_integration_alert(db.conn, created_at="2026-01-01T00:02:00+00:00")
        d = _seed_connection_event(db.conn, created_at="2026-01-01T00:03:00+00:00")

        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="integration_observations", source_id=b),
            to_ref=ObservationRef(source_table="connection_events", source_id=a),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x", detail="ab", created_by="t",
        ))
        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="integration_alerts", source_id=c),
            to_ref=ObservationRef(source_table="integration_observations", source_id=b),
            relationship=RELATIONSHIP_DERIVED_EVIDENCE, match_basis="x", detail="bc", created_by="t",
        ))
        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="connection_events", source_id=d),
            to_ref=ObservationRef(source_table="integration_alerts", source_id=c),
            relationship=RELATIONSHIP_DERIVED_EVIDENCE, match_basis="x", detail="cd", created_by="t",
        ))

        full_walk = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=a), max_hops=6)
        assert len(full_walk.nodes) == 4

        capped_walk = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=a), max_hops=1)
        assert len(capped_walk.nodes) == 2  # a, b only
        assert capped_walk.hop_count == 1


def test_walk_chain_cycle_does_not_infinite_loop(tmp_path: Path):
    # A confirms B, B confirms A (a real cycle) — must terminate and
    # visit each node exactly once.
    with Database(tmp_path / "test.db") as db:
        a = _seed_connection_event(db.conn)
        b = _seed_integration_observation(db.conn)

        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="integration_observations", source_id=b),
            to_ref=ObservationRef(source_table="connection_events", source_id=a),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x", detail="ab", created_by="t",
        ))
        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="connection_events", source_id=a),
            to_ref=ObservationRef(source_table="integration_observations", source_id=b),
            relationship=RELATIONSHIP_DERIVED_EVIDENCE, match_basis="x", detail="ba", created_by="t",
        ))

        chain = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=a))
        assert len(chain.nodes) == 2  # not duplicated despite two links between the same pair
        assert chain.hop_count == 2  # both distinct link rows are still reported


def test_walk_chain_branches_to_multiple_neighbors(tmp_path: Path):
    # One connection_events row confirmed by TWO independent
    # integration_observations rows (fan-out, not a line).
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs1 = _seed_integration_observation(db.conn, collected_at="2026-01-01T00:00:01+00:00")
        obs2 = _seed_integration_observation(db.conn, collected_at="2026-01-01T00:00:02+00:00")

        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="integration_observations", source_id=obs1),
            to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x", detail="d1", created_by="t",
        ))
        record_link(db.conn, EvidenceLink(
            from_ref=ObservationRef(source_table="integration_observations", source_id=obs2),
            to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x", detail="d2", created_by="t",
        ))

        chain = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert len(chain.nodes) == 3
        assert chain.hop_count == 2
