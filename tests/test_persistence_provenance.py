"""
Tests for the persistence-domain provenance fix (Phase 14.5 Stage B):
signing_status anomaly provenance now references the exact underlying
persistence_observations row (source_table="persistence_observations",
source_id=persistence_observations.id) instead of
persistence_entries.id.

Background: add_persistence_observations() previously used one
conn.executemany() call for the whole scan's rows and returned
nothing — cursor.lastrowid after executemany() is not a reliable
per-row id in Python's sqlite3 module, the same gap
add_connection_events()/add_listening_events() had. Fixed by inserting
one row at a time (still one commit for the whole batch) and returning
the real ids in insertion order — see
add_persistence_observations()'s docstring in
secure/storage/models.py. secure/persistence/scanner.py was then wired
to reference the exact observation row behind each entry's
signing_status evaluation, instead of persistence_entries.id (a
DEDUPED identity row updated in place across every scan of the same
entry).

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import PERSISTENCE, persistence_key
from secure.persistence.codesign import SIGNED_ADHOC, UNSIGNED
from secure.storage.database import Database
from secure.storage.models import (
    add_persistence_observations,
    list_anomaly_events,
    list_persistence_alerts,
    set_persistence_alert_known,
)

NOW = "2026-08-19T12:00:00+00:00"


def _patch_launch_dirs(monkeypatch, tmp_path: Path, **overrides):
    import secure.persistence.launch_items as launch_items_module

    fresh = {kind: [tmp_path / f"_unused_{kind}"] for kind in launch_items_module._LAUNCH_ITEM_DIRECTORIES}
    fresh.update(overrides)
    monkeypatch.setattr(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh)


def _patch_scanner(monkeypatch, ps_result=None, login_items_result=None, signing_map=None):
    import secure.persistence.scanner as scanner_module

    if ps_result is not None:
        monkeypatch.setattr(scanner_module, "list_processes", lambda: ps_result)
    if login_items_result is not None:
        monkeypatch.setattr(scanner_module, "get_login_items", lambda: login_items_result)
    if signing_map is not None:
        from secure.persistence.codesign import UNKNOWN
        monkeypatch.setattr(
            scanner_module, "check_code_signing", lambda path: signing_map.get(path, UNKNOWN)
        )
    return scanner_module


# ---------- add_persistence_observations(): real per-row ids ----------


def test_add_persistence_observations_returns_unique_ids_matching_row_count(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("login_item", f"App{i}", None, f"/Applications/App{i}.app", None, None)
            for i in range(5)
        ]
        ids = add_persistence_observations(db.conn, run_id="run1", rows=rows)

    assert len(ids) == 5
    assert len(set(ids)) == 5
    assert all(isinstance(i, int) for i in ids)


def test_add_persistence_observations_ids_correspond_to_the_right_rows(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [
            ("launch_agent_user", "com.example.agent", "/path/to.plist", "/usr/local/bin/agent", True, False),
            ("login_item", "Dropbox", None, "/Applications/Dropbox.app", None, None),
        ]
        ids = add_persistence_observations(db.conn, run_id="run1", rows=rows)
        stored = {
            r["id"]: r
            for r in db.conn.execute("SELECT * FROM persistence_observations").fetchall()
        }

    assert stored[ids[0]]["label"] == "com.example.agent"
    assert stored[ids[0]]["kind"] == "launch_agent_user"
    assert stored[ids[1]]["label"] == "Dropbox"
    assert stored[ids[1]]["kind"] == "login_item"


def test_add_persistence_observations_empty_rows_returns_empty_list(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        ids = add_persistence_observations(db.conn, run_id="run1", rows=[])
    assert ids == []


def test_add_persistence_observations_sequential_batches_never_collide(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        rows = [("login_item", "Dropbox", None, "/Applications/Dropbox.app", None, None)]
        ids1 = add_persistence_observations(db.conn, run_id="run1", rows=rows)
        ids2 = add_persistence_observations(db.conn, run_id="run2", rows=rows)
    assert set(ids1).isdisjoint(set(ids2))


# ---------- end-to-end scanner wiring: exact provenance ----------


def test_scan_persistence_signing_status_references_real_observation(tmp_path: Path, monkeypatch):
    _patch_launch_dirs(monkeypatch, tmp_path)
    scanner_module = _patch_scanner(
        monkeypatch,
        ps_result=(True, []),
        login_items_result=(True, [{"name": "Dropbox", "path": "/Applications/Dropbox.app"}]),
        signing_map={"/Applications/Dropbox.app": UNSIGNED},
    )
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        scanner_module.scan_persistence(db.conn)

        key = persistence_key("login_item", "/Applications/Dropbox.app")
        events = list_anomaly_events(db.conn, PERSISTENCE, key)
        assert len(events) == 1
        event = events[0]

        assert event.source_table == "persistence_observations"
        assert event.source_id is not None

        # The referenced row must be the EXACT scan observation, not
        # persistence_entries.id — an aggregate identity row updated in
        # place across every scan of this entry.
        row = db.conn.execute(
            "SELECT kind, label, path FROM persistence_observations WHERE id = ?",
            (event.source_id,),
        ).fetchone()
        assert row is not None
        assert row["kind"] == "login_item"
        assert row["label"] == "Dropbox"
        assert row["path"] == "/Applications/Dropbox.app"


def test_scan_persistence_two_scans_each_reference_their_own_observation(tmp_path: Path, monkeypatch):
    # persistence_entries upserts the SAME identity row in place across
    # both scans — but each scan's signing_status evaluation must still
    # reference its OWN distinct persistence_observations row.
    _patch_launch_dirs(monkeypatch, tmp_path)
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        scanner_module = _patch_scanner(
            monkeypatch,
            ps_result=(True, []),
            login_items_result=(True, [{"name": "Dropbox", "path": "/Applications/Dropbox.app"}]),
            signing_map={"/Applications/Dropbox.app": UNSIGNED},
        )
        scanner_module.scan_persistence(db.conn)

        # The first scan's "new_persistence_entry" alert is still
        # unreviewed at this point, and an unreviewed medium+ alert
        # forces eligible_weight to 0 for this entity's OWN feature
        # evaluations too (see evaluate_and_record_feature_observation's
        # docstring) — not a provenance concern, just how eligibility
        # gating works, so it's cleared here to keep this test isolated
        # to what it's actually checking.
        for alert in list_persistence_alerts(db.conn):
            set_persistence_alert_known(db.conn, alert.id, True)

        # signed_adhoc, not signed_developer: is_unsigned stays True on
        # both scans (see persistence/scanner.py's is_unsigned check),
        # so both observations are flagged, keeping this test focused
        # on provenance rather than on the scoring model's thresholds.
        scanner_module = _patch_scanner(
            monkeypatch,
            ps_result=(True, []),
            login_items_result=(True, [{"name": "Dropbox", "path": "/Applications/Dropbox.app"}]),
            signing_map={"/Applications/Dropbox.app": SIGNED_ADHOC},
        )
        scanner_module.scan_persistence(db.conn)

        key = persistence_key("login_item", "/Applications/Dropbox.app")
        events = list_anomaly_events(db.conn, PERSISTENCE, key)
        assert len(events) == 2

        source_ids = [e.source_id for e in events]
        assert len(set(source_ids)) == 2  # distinct observation rows, never reused

        all_ids = {
            r["id"] for r in db.conn.execute("SELECT id FROM persistence_observations").fetchall()
        }
        assert set(source_ids) <= all_ids


# ---------- idempotence: same run_id, repeat call ----------


def test_repeated_evaluation_same_run_and_source_does_not_duplicate_anomaly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        ids = add_persistence_observations(
            db.conn, run_id="run1",
            rows=[("login_item", "Dropbox", None, "/Applications/Dropbox.app", None, None)],
        )
        observation_id = ids[0]
        key = persistence_key("login_item", "/Applications/Dropbox.app")

        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", PERSISTENCE, key, "signing_status", "unsigned", NOW,
            is_unsigned=True,
            source_table="persistence_observations", source_id=observation_id,
        )
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", PERSISTENCE, key, "signing_status", "unsigned", NOW,
            is_unsigned=True,
            source_table="persistence_observations", source_id=observation_id,
        )

        events = list_anomaly_events(db.conn, PERSISTENCE, key)

    assert len(events) == 1
    assert events[0].source_id == observation_id


# ---------- historical/pre-migration honesty ----------


def test_evaluation_without_known_source_stores_null_not_fabricated(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = persistence_key("login_item", "/Applications/Dropbox.app")
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", PERSISTENCE, key, "signing_status", "unsigned", NOW,
            is_unsigned=True,
        )

        events = list_anomaly_events(db.conn, PERSISTENCE, key)

    assert len(events) == 1
    assert events[0].source_table is None
    assert events[0].source_id is None
