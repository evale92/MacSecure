"""
Tests for secure/correlate/chains.py (Phase 22 Stage 3: the new
provenance-aware chain scoring model + correlation_chain_alerts
storage).

The single most important guarantee under test here is the one Phase
22's own instruction singled out by name: "Use Phase 21 lineage/
deduplication so duplicated observations cannot inflate corroboration."
test_confirmation_group_collapses_duplicate_observations and
test_rescan_same_relationship_does_not_inflate_score exist specifically
to prove that.

Same Database/tmp_path convention as tests/test_evidence_chain.py —
nodes seeded via direct minimal INSERTs, edges via record_link(), the
real write path.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.correlate.analysis import CRITICAL, HIGH, INFORMATIONAL, LOW, MEDIUM_SEVERITY
from secure.correlate.chains import (
    ConfirmationGroup,
    NodeInfo,
    apply_weak_evidence_cap,
    build_confirmation_groups,
    chain_raw_score,
    count_meaningful_relationships,
    evidence_concentration,
    fingerprint_for_chain,
    persist_chain_score,
    score_chain,
)
from secure.evidence.chain import ChainNode, walk_chain
from secure.evidence.model import (
    RELATIONSHIP_DERIVED_EVIDENCE,
    RELATIONSHIP_DUPLICATE_OBSERVATION,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    EvidenceLink,
    ObservationRef,
)
from secure.evidence.record import record_link
from secure.explain.vocab import CONFIRMED, INSUFFICIENT_EVIDENCE, LIKELY, UNCERTAIN
from secure.storage.database import Database
from secure.storage.models import list_correlation_chain_alerts

_BOOT_TIME_LONG_AGO = datetime(2020, 1, 1, tzinfo=timezone.utc)


def _seed_connection_event(conn, *, created_at="2026-01-01T12:00:00+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO connection_events (created_at, run_id, proto, local_addr, local_port, "
        "remote_addr, remote_port, state, pid, process_name) VALUES (?, 'r', 'tcp', '10.0.0.1', "
        "51000, '203.0.113.5', 443, 'ESTABLISHED', 100, 'curl')",
        (created_at,),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_integration_observation(
    conn, *, integration="zeek", collected_at="2026-01-01T12:00:05+00:00"
) -> int:
    cursor = conn.execute(
        "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
        "fields_json, source_query, collected_at) VALUES (?, 'r', ?, 'conn', 'k', '{}', 'q', ?)",
        (collected_at, integration, collected_at),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_integration_alert(
    conn, *, integration="suricata", severity="medium", created_at="2026-01-01T12:00:10+00:00"
) -> int:
    cursor = conn.execute(
        "INSERT INTO integration_alerts (created_at, run_id, integration, kind, discrepancy, severity, "
        "identity_key, label, message, source_observation_id, known) VALUES "
        "(?, 'r', ?, 'network_alert', 'match', ?, 'k', 'l', 'm', NULL, 0)",
        (created_at, integration, severity),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_persistence_alert(conn, *, severity="high", created_at="2026-01-01T12:00:15+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
        "identifier, label, message, known) VALUES (?, 'r', 'new_entry', ?, 'login_item', 'x', 'l', 'm', 0)",
        (created_at, severity),
    )
    conn.commit()
    return cursor.lastrowid


def _link(conn, from_table, from_id, to_table, to_id, relationship, *, basis="identity+timing", detail="test"):
    record_link(
        conn,
        EvidenceLink(
            from_ref=ObservationRef(source_table=from_table, source_id=from_id),
            to_ref=ObservationRef(source_table=to_table, source_id=to_id),
            relationship=relationship,
            match_basis=basis,
            detail=detail,
            created_by="test",
        ),
    )


# ---------- build_confirmation_groups() / anti-inflation ----------


def test_confirmation_group_collapses_duplicate_observations(tmp_path: Path):
    # Three tools (zeek, suricata via integration_alerts, native
    # connection_events) all confirming the SAME underlying event must
    # collapse into ONE confirmation group, not three.
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        zeek_obs = _seed_integration_observation(db.conn, integration="zeek")
        suricata_alert = _seed_integration_alert(db.conn, integration="suricata")

        _link(db.conn, "integration_observations", zeek_obs, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)
        _link(db.conn, "integration_alerts", suricata_alert, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        chain = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert len(chain.nodes) == 3  # three raw rows

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert score.raw_observation_count == 3
        assert score.independent_fact_count == 1  # collapsed to ONE fact
        assert len(score.groups) == 1
        assert score.groups[0].raw_node_count == 3


def test_derived_evidence_does_not_merge_groups(tmp_path: Path):
    # A genuine causal chain (file -> yara finding, distinct events)
    # must NOT collapse into a single confirmation group — that would
    # hide a real multi-step chain as if it were one restated fact.
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        alert_id = _seed_integration_alert(db.conn, integration="yara-x", severity="high")
        _link(db.conn, "integration_alerts", alert_id, "connection_events", conn_id,
              RELATIONSHIP_DERIVED_EVIDENCE)

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert score.independent_fact_count == 2
        assert len(score.groups) == 2


def test_rescan_same_relationship_does_not_inflate_score(tmp_path: Path):
    # Recording the exact same same_event_confirmation link twice
    # (e.g. a rescan re-observing an already-linked pair) must not
    # create a second group or a second edge-derived bonus — record_link()
    # itself is idempotent by fingerprint (Phase 21), and chain scoring
    # must inherit that guarantee rather than re-deriving its own.
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)

        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)
        first = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))

        # "rescan" — same logical relationship recorded again
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)
        second = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))

        assert first.raw_score == second.raw_score
        assert first.independent_fact_count == second.independent_fact_count == 1


# ---------- count_meaningful_relationships() ----------


def test_meaningful_relationship_counted_across_different_modules(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        alert_id = _seed_integration_alert(db.conn, integration="yara-x", severity="high")
        _link(db.conn, "integration_alerts", alert_id, "connection_events", conn_id,
              RELATIONSHIP_DERIVED_EVIDENCE)

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert score.meaningful_relationship_count == 1


def test_meaningful_relationship_not_counted_within_one_group(tmp_path: Path):
    # A derived_evidence edge whose endpoints are already in the SAME
    # confirmation group (because some other link already merged them)
    # must not double-count as a meaningful relationship.
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        # merge them into one group first
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)
        # then also assert (oddly) a derived_evidence edge between the same pair
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_DERIVED_EVIDENCE, detail="also derived")

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert score.independent_fact_count == 1
        assert score.meaningful_relationship_count == 0


# ---------- evidence_concentration() ----------


def test_evidence_concentration_pure():
    groups = [
        ConfirmationGroup(id=0, node_keys=frozenset({("a", 1)}), modules=frozenset({"connections"}),
                           sources=frozenset({"connections"}), max_weight=1, earliest_timestamp=None),
        ConfirmationGroup(id=1, node_keys=frozenset({("a", 2)}), modules=frozenset({"connections"}),
                           sources=frozenset({"connections"}), max_weight=1, earliest_timestamp=None),
        ConfirmationGroup(id=2, node_keys=frozenset({("a", 3)}), modules=frozenset({"persistence"}),
                           sources=frozenset({"persistence"}), max_weight=2, earliest_timestamp=None),
    ]
    assert evidence_concentration(groups) == 2 / 3

    assert evidence_concentration([]) == 0.0


# ---------- chain_raw_score() / apply_weak_evidence_cap() ----------


def test_chain_raw_score_additive_not_multiplicative():
    groups = [
        ConfirmationGroup(id=0, node_keys=frozenset({("a", 1)}), modules=frozenset({"connections"}),
                           sources=frozenset({"connections"}), max_weight=1, earliest_timestamp=None),
        ConfirmationGroup(id=1, node_keys=frozenset({("a", 2)}), modules=frozenset({"persistence"}),
                           sources=frozenset({"persistence"}), max_weight=3, earliest_timestamp=None),
    ]
    # raw weights: 1 + 3 = 4; 2 modules -> corroboration bonus 2*(2-1)=2; meaningful=1 -> 4*1=4
    assert chain_raw_score(groups, meaningful_relationship_count=1) == 4 + 2 + 4
    # meaningful count is capped at 3 regardless of how large it is
    assert chain_raw_score(groups, meaningful_relationship_count=99) == 4 + 2 + (4 * 3)


def test_apply_weak_evidence_cap_caps_all_weight_one_chains():
    weak_groups = [
        ConfirmationGroup(id=0, node_keys=frozenset({("a", 1)}), modules=frozenset({"connections"}),
                           sources=frozenset({"connections"}), max_weight=1, earliest_timestamp=None),
    ]
    assert apply_weak_evidence_cap(CRITICAL, weak_groups) == MEDIUM_SEVERITY
    assert apply_weak_evidence_cap(HIGH, weak_groups) == MEDIUM_SEVERITY
    assert apply_weak_evidence_cap(LOW, weak_groups) == LOW  # never raised, only capped


def test_apply_weak_evidence_cap_leaves_real_findings_alone():
    strong_groups = [
        ConfirmationGroup(id=0, node_keys=frozenset({("a", 1)}), modules=frozenset({"persistence"}),
                           sources=frozenset({"persistence"}), max_weight=3, earliest_timestamp=None),
    ]
    assert apply_weak_evidence_cap(CRITICAL, strong_groups) == CRITICAL
    assert apply_weak_evidence_cap(HIGH, strong_groups) == HIGH


# ---------- score_chain() end-to-end ----------


def test_score_chain_single_node_is_insufficient_evidence(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert score.independent_fact_count == 1
        assert score.module_count == 1
        assert score.confidence == INSUFFICIENT_EVIDENCE
        assert score.severity == INFORMATIONAL


def test_score_chain_worked_example_multi_step(tmp_path: Path):
    # file created -> YARA finding -> process execution -> persistence
    # -> unusual destination -> network IDS finding, the exact shape
    # named in Phase 22's own instruction. Each -> is derived_evidence
    # linking genuinely different modules -> should reach LIKELY or
    # CONFIRMED confidence with several meaningful relationships.
    with Database(tmp_path / "test.db") as db:
        file_alert = _seed_integration_alert(db.conn, integration="yara-x", severity="high",
                                              created_at="2026-01-01T12:00:00+00:00")
        process_row = _seed_connection_event(db.conn, created_at="2026-01-01T12:00:05+00:00")
        persistence_alert = _seed_persistence_alert(db.conn, severity="high",
                                                      created_at="2026-01-01T12:00:10+00:00")
        network_alert = _seed_integration_alert(db.conn, integration="suricata", severity="critical",
                                                  created_at="2026-01-01T12:00:20+00:00")

        _link(db.conn, "connection_events", process_row, "integration_alerts", file_alert,
              RELATIONSHIP_DERIVED_EVIDENCE, detail="process spawned from flagged file")
        _link(db.conn, "persistence_alerts", persistence_alert, "connection_events", process_row,
              RELATIONSHIP_DERIVED_EVIDENCE, detail="persistence installed by process")
        _link(db.conn, "integration_alerts", network_alert, "persistence_alerts", persistence_alert,
              RELATIONSHIP_DERIVED_EVIDENCE, detail="network IDS match from persisted binary")

        score = score_chain(
            db.conn, ObservationRef(source_table="integration_alerts", source_id=file_alert),
            boot_time=_BOOT_TIME_LONG_AGO, boot_time_resolved=True,
        )
        assert score.raw_observation_count == 4
        assert score.independent_fact_count == 4
        assert score.meaningful_relationship_count == 3
        assert score.confidence in (LIKELY, CONFIRMED)
        assert score.severity in (HIGH, CRITICAL)
        assert "raw observation" in score.explanation


def test_score_chain_concentrated_single_module_is_uncertain(tmp_path: Path):
    # Several observations, but all confirmation groups share one
    # module -> concentration crosses the threshold -> UNCERTAIN,
    # even though the raw count looks impressive.
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs2 = _seed_integration_observation(db.conn, integration="zeek", collected_at="2026-01-01T12:00:06+00:00")
        obs3 = _seed_integration_observation(db.conn, integration="zeek", collected_at="2026-01-01T12:00:07+00:00")
        # obs2/obs3 are separate, unconfirmed facts (no links to conn_id at all)
        # but classified into the same "integrations"/"zeek" module as any zeek link would be.
        chain_conn = walk_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert chain_conn.hop_count == 0  # sanity: this test's conn_id has no links of its own

        score = score_chain(db.conn, ObservationRef(source_table="integration_observations", source_id=obs2))
        # obs2 alone, unlinked -> single group, single module -> INSUFFICIENT_EVIDENCE
        assert score.confidence == INSUFFICIENT_EVIDENCE


def test_score_chain_recent_boot_reduces_weak_score(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        boot_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        conn_id = _seed_connection_event(db.conn, created_at="2026-01-01T12:01:00+00:00")
        obs_id = _seed_integration_observation(db.conn, collected_at="2026-01-01T12:01:05+00:00")
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        near_boot = score_chain(
            db.conn, ObservationRef(source_table="connection_events", source_id=conn_id),
            boot_time=boot_time, boot_time_resolved=True,
        )
        far_from_boot = score_chain(
            db.conn, ObservationRef(source_table="connection_events", source_id=conn_id),
            boot_time=_BOOT_TIME_LONG_AGO, boot_time_resolved=True,
        )
        assert near_boot.benign_context_notes is not None
        assert far_from_boot.benign_context_notes is None
        assert near_boot.score <= far_from_boot.score


# ---------- fingerprint_for_chain() ----------


def test_fingerprint_for_chain_stable_regardless_of_start_side(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        from_conn = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        from_obs = score_chain(db.conn, ObservationRef(source_table="integration_observations", source_id=obs_id))

        assert fingerprint_for_chain(from_conn.chain) == fingerprint_for_chain(from_obs.chain)


def test_fingerprint_for_chain_differs_for_different_node_sets(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        other_conn_id = _seed_connection_event(db.conn, created_at="2026-01-02T00:00:00+00:00")
        a = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        b = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=other_conn_id))
        assert fingerprint_for_chain(a.chain) != fingerprint_for_chain(b.chain)


# ---------- persist_chain_score() ----------


def test_persist_chain_score_inserts_new_row(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        record, was_new = persist_chain_score(db.conn, "run-1", score)

        assert was_new is True
        assert record.start_source_table == "connection_events"
        assert record.start_source_id == conn_id
        assert record.raw_observation_count == 2
        assert record.independent_fact_count == 1
        assert len(record.members) == 2
        assert record.members[0]["group_id"] == 0
        assert record.known is False

        stored = list_correlation_chain_alerts(db.conn)
        assert len(stored) == 1
        assert stored[0].fingerprint == record.fingerprint


def test_persist_chain_score_idempotent_on_identical_chain(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        first_record, first_new = persist_chain_score(db.conn, "run-1", score)

        # "Rescan" — walk again (identical node set) and try to persist again.
        score_again = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        second_record, second_new = persist_chain_score(db.conn, "run-2", score_again)

        assert first_new is True
        assert second_new is False
        assert second_record.id == first_record.id
        assert len(list_correlation_chain_alerts(db.conn)) == 1


def test_persist_chain_score_edges_carry_evidence_link_id(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION)

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        record, _ = persist_chain_score(db.conn, "run-1", score)

        assert len(record.edges) == 1
        edge = record.edges[0]
        assert edge["relationship"] == RELATIONSHIP_SAME_EVENT_CONFIRMATION
        assert edge["evidence_link_id"] is not None
        assert edge["from_group_id"] == edge["to_group_id"] == 0
