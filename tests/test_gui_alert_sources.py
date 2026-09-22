"""
The Alerts window's two newest sources (docs/GUI_ROADMAP.md G3):
integration alerts and correlation chain alerts, and the argv contract for
marking every kind of row the window can show.

Integration alerts share one table across engines, so their mark command
comes from the row's own integration through an allowlist
(INTEGRATION_MARK_COMMANDS), never by putting the stored string into argv.
An engine without mark-alert (zeek), or an unexpected stored value, gives
a row that is shown but cannot be marked. The CLI also refuses another
integration's alert (G2.5), as a second line of defence.

Run with:  pytest tests/test_gui_alert_sources.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure import cli as secure_cli
from secure.cli import build_parser
from secure.storage.database import Database
from secure.storage.models import add_integration_alert, set_integration_alert_known
from secure_gui.data_access import ALERT_MARK_COMMANDS, list_all_alerts
from secure_gui.view_models import alert_mark_request
from tests.test_gui_components import _add_chain_alert, _seed_one_of_each

_MARKABLE_INTEGRATIONS = ("osquery", "yarax", "sigma", "suricata")

# source table -> the handler its mark command must reach
_TABLE_HANDLERS = {
    "arp_alerts": "cmd_arpwatch_mark",
    "wifi_alerts": "cmd_wifi_mark_alert",
    "bluetooth_alerts": "cmd_bluetooth_mark_alert",
    "ble_alerts": "cmd_bluetooth_ble_mark_alert",
    "persistence_alerts": "cmd_persistence_mark_alert",
    "file_integrity_alerts": "cmd_fileintegrity_mark_alert",
    "correlation_alerts": "cmd_correlate_mark_alert",
    "correlation_chain_alerts": "cmd_correlate_chains_mark_alert",
}


def _add_integration(conn, integration: str, *, identity: str = "k") -> int:
    return add_integration_alert(
        conn, run_id="run1", integration=integration, kind="k", discrepancy="d",
        severity="high", identity_key=f"{integration}-{identity}", label=f"{integration} label",
        message=f"{integration} alert message",
    )


def _rows(tmp_path: Path, seed):
    with Database(tmp_path / "t.db") as db:
        seed(db.conn)
        return list_all_alerts(db.conn, limit=100)


def _resolves(argv, handler_name: str) -> None:
    try:
        ns = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse reports errors by exiting
        pytest.fail(f"mark argv {argv} does not parse (exit {exc.code})")
    assert ns.func is getattr(secure_cli, handler_name), argv


# ---------- the argv contract ----------


def test_every_table_keyed_mark_command_parses_and_reaches_its_handler(tmp_path: Path):
    rows = [r for r in _rows(tmp_path, _seed_one_of_each) if r.source_table != "integration_alerts"]
    assert {r.source_table for r in rows} == set(_TABLE_HANDLERS)
    assert set(ALERT_MARK_COMMANDS) == set(_TABLE_HANDLERS)
    for row in rows:
        _resolves([*row.mark_command, str(row.source_id), "known"], _TABLE_HANDLERS[row.source_table])


@pytest.mark.parametrize("integration", _MARKABLE_INTEGRATIONS)
def test_an_integration_row_is_marked_by_its_own_engine(tmp_path: Path, integration):
    (row,) = _rows(tmp_path, lambda conn: _add_integration(conn, integration))
    assert row.integration == integration
    assert row.mark_command == ("integrations", integration, "mark-alert")
    _resolves([*row.mark_command, str(row.source_id), "known"], f"cmd_integrations_{integration}_mark_alert")
    req = alert_mark_request(row)
    assert req.args == ("integrations", integration, "mark-alert", str(row.source_id), "known")
    assert integration in req.confirm_body.lower() or row.module in req.confirm_body


@pytest.mark.parametrize("stored", ["zeek", "yarax; rm -rf /", "unknown-engine"])
def test_an_integration_row_without_a_mark_command_is_shown_but_not_markable(tmp_path: Path, stored):
    (row,) = _rows(tmp_path, lambda conn: _add_integration(conn, stored))
    assert row.summary
    assert row.mark_command is None
    assert alert_mark_request(row) is None


# ---------- the data layer ----------


def test_both_new_sources_carry_summary_raw_explanation_and_known(tmp_path: Path):
    def seed(conn):
        alert_id = _add_integration(conn, "sigma")
        set_integration_alert_known(conn, alert_id, True)
        _add_chain_alert(conn)

    rows = {r.source_table: r for r in _rows(tmp_path, seed)}
    assert set(rows) == {"integration_alerts", "correlation_chain_alerts"}
    for row in rows.values():
        assert row.summary
        assert isinstance(row.raw, dict) and row.raw
        assert row.explanation is not None
    assert rows["integration_alerts"].known is True
    assert rows["correlation_chain_alerts"].known is False


def test_each_engine_shows_its_own_label(tmp_path: Path):
    def seed(conn):
        for name in _MARKABLE_INTEGRATIONS:
            _add_integration(conn, name)

    labels = {r.integration: r.module for r in _rows(tmp_path, seed)}
    assert len(set(labels.values())) == len(_MARKABLE_INTEGRATIONS)
    assert all(label.startswith("Integration: ") for label in labels.values())
