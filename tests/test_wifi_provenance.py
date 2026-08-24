"""
Tests for the Wi-Fi anomaly-provenance fix (Phase 14.5 Stage B):
security-feature anomaly provenance now references the exact
underlying wifi_observations row (source_table="wifi_observations",
source_id=wifi_observations.id) instead of wifi_networks.id.

Background: add_wifi_observation() has always inserted one row per
call and returned a real id directly from cursor.lastrowid — a Wi-Fi
scan is never a batch insert, so it never had the executemany()
id-surfacing gap connection_events/listening_events/
persistence_observations had. The gap here was purely in
secure/wifi/scanner.py: it captured that real observation_id but then
passed wifi_networks.id (a DEDUPED identity row, updated in place
across every scan of the same SSID/BSSID) to
evaluate_and_record_feature_observation() as source_id instead. Fixed
by passing observation_id itself.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import WIFI, wifi_key
from secure.wifi.scanner import scan_wifi
from secure.wifi.status import WifiStatus
from secure.storage.database import Database
from secure.storage.models import list_anomaly_events

NOW = "2026-08-19T12:00:00+00:00"


def _connected_status(ssid="HomeNetwork", bssid="aa:bb:cc:dd:ee:ff", security="WPA2 Personal"):
    return WifiStatus(
        connected=True,
        status_unknown=False,
        interface="en0",
        ssid=ssid,
        bssid=bssid,
        bssid_available=True,
        channel="36",
        phy_mode="ac",
        security=security,
        rssi=-50,
        noise=-90,
    )


def _patch_status(monkeypatch, status):
    import secure.wifi.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "get_wifi_status", lambda: status)
    return scanner_module


# ---------- end-to-end scanner wiring: exact provenance ----------


def test_scan_wifi_security_anomaly_references_real_wifi_observation(tmp_path: Path, monkeypatch):
    _patch_status(monkeypatch, _connected_status(security="None"))  # open network → weak security

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        scan_wifi(db.conn)

        key = wifi_key("HomeNetwork")
        events = list_anomaly_events(db.conn, WIFI, key)
        assert len(events) == 1
        event = events[0]

        assert event.source_table == "wifi_observations"
        assert event.source_id is not None

        # The referenced row must be the EXACT scan observation that
        # produced this anomaly — not wifi_networks.id, a deduped
        # identity row updated in place across every scan of this SSID.
        row = db.conn.execute(
            "SELECT ssid, bssid, security FROM wifi_observations WHERE id = ?",
            (event.source_id,),
        ).fetchone()
        assert row is not None
        assert row["ssid"] == "HomeNetwork"
        assert row["security"] == "None"

        # The provenance row itself (fetched above from
        # wifi_observations, matching the exact scan's ssid/security)
        # is the real proof of exact-observation provenance; there's
        # nothing further to assert about wifi_networks.id here.


def test_scan_wifi_same_ssid_two_scans_each_reference_their_own_observation(tmp_path: Path, monkeypatch):
    # wifi_networks upserts the SAME identity row in place across both
    # scans (one SSID/BSSID pair) — but each scan's anomaly evaluation
    # must still reference its OWN distinct wifi_observations row, not
    # a shared/ambiguous identity reference.
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _patch_status(monkeypatch, _connected_status(security="None"))
        scan_wifi(db.conn)

        _patch_status(monkeypatch, _connected_status(security="WEP"))
        scan_wifi(db.conn)

        key = wifi_key("HomeNetwork")
        events = list_anomaly_events(db.conn, WIFI, key)
        assert len(events) == 2

        source_ids = [e.source_id for e in events]
        assert len(set(source_ids)) == 2  # distinct observation rows, never reused

        rows = {
            r["id"]: r["security"]
            for r in db.conn.execute("SELECT id, security FROM wifi_observations").fetchall()
        }
        observed_securities = {rows[sid] for sid in source_ids}
        assert observed_securities == {"None", "WEP"}


# ---------- idempotence: same run_id, repeat call ----------


def test_repeated_evaluation_same_run_and_source_does_not_duplicate_anomaly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        from secure.storage.models import add_wifi_observation

        observation_id = add_wifi_observation(
            db.conn, run_id="run1", ssid="HomeNetwork", bssid="aa:bb:cc:dd:ee:ff",
            channel="36", phy_mode="ac", security="None", rssi=-50, noise=-90,
        )
        key = wifi_key("HomeNetwork")

        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", WIFI, key, "security", "None", NOW,
            is_weak_wifi_security=True,
            source_table="wifi_observations", source_id=observation_id,
        )
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", WIFI, key, "security", "None", NOW,
            is_weak_wifi_security=True,
            source_table="wifi_observations", source_id=observation_id,
        )

        events = list_anomaly_events(db.conn, WIFI, key)

    assert len(events) == 1
    assert events[0].source_id == observation_id


# ---------- historical/pre-migration honesty ----------


def test_evaluation_without_known_source_stores_null_not_fabricated(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        key = wifi_key("HomeNetwork")
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", WIFI, key, "security", "None", NOW,
            is_weak_wifi_security=True,
        )

        events = list_anomaly_events(db.conn, WIFI, key)

    assert len(events) == 1
    assert events[0].source_table is None
    assert events[0].source_id is None
