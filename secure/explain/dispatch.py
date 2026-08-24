"""Single entry point for explanation generation.

`explain(record, source_table)` is the one function callers (the GUI's
`secure_gui/data_access.py`, and later the CLI/exports/API) need —
they never have to branch on alert type themselves, which keeps them
thin presentation/plumbing layers rather than accumulating their own
copy of "which explainer goes with which table."

This is also where refinement #9's "explanation failures must fail
gracefully" is enforced structurally: every explainer call is wrapped,
and an unrecognized `source_table` never raises — both paths degrade
to `generic_explanation()` with the record's real severity/message
intact and `degraded=True`, so a single explainer bug (or a future,
not-yet-supported module) can never take down the Alerts table.
"""

from __future__ import annotations

from secure.explain import alert_explainers, chain_explainer, correlation_explainer, integration_explainer
from secure.explain.explanation import Explanation, generic_explanation

_EXPLAINERS = {
    "arp_alerts": alert_explainers.explain_arp_alert,
    "wifi_alerts": alert_explainers.explain_wifi_alert,
    "bluetooth_alerts": alert_explainers.explain_bluetooth_alert,
    "ble_alerts": alert_explainers.explain_ble_alert,
    "persistence_alerts": alert_explainers.explain_persistence_alert,
    "file_integrity_alerts": alert_explainers.explain_file_integrity_alert,
    "correlation_alerts": correlation_explainer.explain_correlation_alert,
    "integration_alerts": integration_explainer.explain_integration_alert,
    "correlation_chain_alerts": chain_explainer.explain_chain_alert,
}


def explain(record, source_table: str) -> Explanation:
    explainer = _EXPLAINERS.get(source_table)
    if explainer is None:
        return generic_explanation(
            source_table=source_table,
            severity=getattr(record, "severity", "unknown"),
            message=getattr(record, "message", "") or getattr(record, "explanation", "") or "",
            subject=None,
            degraded=True,
            degraded_reason=f"No explainer is registered for source table {source_table!r}.",
        )
    try:
        return explainer(record)
    except Exception as exc:  # noqa: BLE001 — must never break the Alerts table
        return generic_explanation(
            source_table=source_table,
            severity=getattr(record, "severity", "unknown"),
            message=getattr(record, "message", "") or getattr(record, "explanation", "") or "",
            subject=None,
            degraded=True,
            degraded_reason=f"Explanation generation raised {type(exc).__name__}: {exc}",
        )
