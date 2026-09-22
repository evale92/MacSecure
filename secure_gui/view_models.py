"""
Tk-free view logic for the secure_gui windows.

The windows in this package build most of their decisions inside
`open_*_window()` closures, where no test can reach them (see
docs/GUI_EXTRACTION_AUDIT.md). This module is where those decisions move
once they are extracted: the text an operator is shown, and the exact
CLI argv a button sends.

Everything here is pure: no tkinter, no secure.storage, no subprocess,
no I/O. tests/test_gui_view_models.py enforces that, so every function
can be tested under any interpreter, including one without _tkinter.
Row types from secure_gui.data_access are used by attribute only.

This is deliberately separate from data_access.py, which is the GUI's
read-only display-data layer and the only module that reads storage.
Functions here decide what to *do*; data_access decides what to *show*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:  # attribute access only; never imported at runtime
    from secure_gui.data_access import AlertRow, AnomalyRow


@dataclass(frozen=True)
class MarkRequest:
    """Everything a Mark Known/Unknown button needs before it dispatches:
    the status it will set, the confirmation it must show first, the
    argv (after `secure`) it will send, and the console label."""

    new_status: str
    confirm_title: str
    confirm_body: str
    args: Tuple[str, ...]
    label: str


def _toggled_status(known: bool) -> str:
    return "unknown" if known else "known"


def anomaly_mark_request(row: "AnomalyRow") -> MarkRequest:
    """The Baseline & Anomalies window's Mark request for one anomaly."""
    new_status = _toggled_status(row.known)
    return MarkRequest(
        new_status=new_status,
        confirm_title="Mark anomaly",
        confirm_body=(
            f"Mark anomaly #{row.id} ({row.entity_type}/{row.entity_key}, "
            f"{row.feature_name}) as {new_status.upper()}?"
        ),
        args=(*row.mark_command, str(row.id), new_status),
        label=f"Mark Anomaly Known/Unknown… (#{row.id}, via Baseline & Anomalies table)",
    )


def alert_mark_request(row: "AlertRow") -> Optional[MarkRequest]:
    """The Alerts window's Mark request for one alert, or None when the
    alert's source table has no CLI mark command."""
    command = row.mark_command
    if command is None:
        return None
    new_status = _toggled_status(row.known)
    return MarkRequest(
        new_status=new_status,
        confirm_title="Mark alert",
        confirm_body=f"Mark this {row.module} alert as {new_status.upper()}?",
        args=(*command, str(row.source_id), new_status),
        label=f"Mark Alert Known/Unknown… ({row.module}, via Alerts table)",
    )
