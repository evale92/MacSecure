"""
Tests for what secure/storage/models/arpwatch.py returns and stores
that the existing suite never distinguished (J-0336).

Measured 2026-09-12 at 0828ea3 against a scratch copy of the tree.
The 14 test files that reach this module (395 tests; test_storage.py
alone has five direct tests of it) stayed at 3 failed / 392 passed —
byte-identical to the unmutated control, the 3 being pre-existing wifi
debris — under each of these rewrites:

  - list_arp_alerts() `ORDER BY id DESC` -> `ASC`
  - list_arp_alerts() ignoring its `limit`
  - set_arp_alert_known(..., False) writing 1 anyway
  - upsert_arp_mapping() overwriting `first_seen` on update
  - upsert_arp_mapping() not updating `is_gateway` on update

while the positive control (the UPDATE no longer setting `mac`) failed
test_upsert_arp_mapping_insert_then_update, so the file was reached.

The reason is the same shape each time. No test records more than one
arp alert, so newest-first and oldest-first are the same list. No test
passes `limit=`. No test marks an alert back to unknown. And the one
upsert test passes is_gateway=True twice and asserts nothing about
first_seen.

The first two cost something real. `secure arpwatch list`, the GUI's
alert feed and the AI context (secure/ai/context.py passes
per_table_limit) all read list_arp_alerts() with a limit, so past that
many alerts an oldest-first list would silently drop the newest ones —
including a high-severity gateway_mac_changed. The third makes
cmd_arpwatch_mark report "Marked #N as unknown" and write an audit-trail
review change while the stored row stays known.

Named test_storage_models_arpwatch.py because targeted_test_files()
maps secure/storage/... to tests/test_storage*.py.

Run with:  pytest tests/test_storage_models_arpwatch.py
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import (
    add_arp_alert,
    find_arp_alert_by_id,
    list_arp_alerts,
    list_arp_mappings,
    set_arp_alert_known,
    upsert_arp_mapping,
)


def _add_alert(conn, ip: str) -> int:
    return add_arp_alert(
        conn, run_id="run-1", kind="mac_changed", severity="low",
        ip=ip, mac="bb:bb:bb:bb:bb:bb", previous_mac="aa:aa:aa:aa:aa:aa",
        message=f"MAC changed for {ip}",
    )


def test_list_arp_alerts_returns_newest_first(tmp_path: Path):
    """Three alerts come back in reverse insertion order.

    Three rather than two so the middle element pins the whole order,
    not just which end comes first.
    """
    with Database(tmp_path / "test.db") as db:
        ids = [_add_alert(db.conn, f"192.168.1.{n}") for n in (10, 20, 30)]

        listed = [a.id for a in list_arp_alerts(db.conn)]

    assert listed == list(reversed(ids))


def test_list_arp_alerts_limit_keeps_the_newest(tmp_path: Path):
    """A limit drops the oldest alerts, never the newest.

    This is the case every caller that passes a limit depends on: the
    most recent alert must survive the cut.
    """
    with Database(tmp_path / "test.db") as db:
        ids = [_add_alert(db.conn, f"192.168.1.{n}") for n in (10, 20, 30)]

        listed = [a.id for a in list_arp_alerts(db.conn, limit=2)]

    assert listed == [ids[2], ids[1]]


def test_set_arp_alert_known_can_mark_an_alert_unknown_again(tmp_path: Path):
    """known -> unknown is stored, not just known -> ... known.

    The neighbouring alert is the control for the WHERE clause: marking
    one alert must leave the other exactly as it was.
    """
    with Database(tmp_path / "test.db") as db:
        target = _add_alert(db.conn, "192.168.1.10")
        other = _add_alert(db.conn, "192.168.1.20")
        set_arp_alert_known(db.conn, other, True)

        set_arp_alert_known(db.conn, target, True)
        assert find_arp_alert_by_id(db.conn, target).known is True

        set_arp_alert_known(db.conn, target, False)

        assert find_arp_alert_by_id(db.conn, target).known is False
        assert find_arp_alert_by_id(db.conn, other).known is True


def test_upsert_arp_mapping_update_keeps_first_seen_and_moves_last_seen(tmp_path: Path):
    """An update touches last_seen and leaves first_seen alone.

    first_seen is pinned to a fixed old value first, so the assertion
    does not depend on two calls landing in different microseconds.
    """
    old = "2020-01-01T00:00:00+00:00"
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_arp_mapping(
            db.conn, ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=True
        )
        db.conn.execute(
            "UPDATE arp_mappings SET first_seen = ?, last_seen = ? WHERE id = ?",
            (old, old, record.id),
        )
        db.conn.commit()

        updated, was_new = upsert_arp_mapping(
            db.conn, ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=True
        )

    assert was_new is False
    assert updated.first_seen == old
    assert updated.last_seen != old


def test_upsert_arp_mapping_update_changes_is_gateway(tmp_path: Path):
    """An IP that stops being the gateway is stored as no longer the gateway.

    Both directions, so a change that froze the flag at either value fails.
    """
    with Database(tmp_path / "test.db") as db:
        upsert_arp_mapping(db.conn, ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=True)
        demoted, _ = upsert_arp_mapping(
            db.conn, ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=False
        )
        promoted, _ = upsert_arp_mapping(
            db.conn, ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=True
        )
        mappings = list_arp_mappings(db.conn)

    assert demoted.is_gateway is False
    assert promoted.is_gateway is True
    assert [(m.ip, m.is_gateway) for m in mappings] == [("192.168.1.1", True)]
