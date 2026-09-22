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


def agent_approve_args(run_id: str, cr_id: str) -> Tuple[str, ...]:
    """argv for approving an agent-originated change request through the
    revalidation gate, bound to the request the operator was shown: the
    CLI refuses if the run no longer links `cr_id`. Shared by the Change
    Request Center and Agent -> Repairs."""
    return ("agent", "approve", run_id, "--cr-id", cr_id)


@dataclass(frozen=True)
class ApproveRequest:
    """What the Change Request Center's Approve button shows and sends."""

    confirm_title: str
    confirm_body: str
    args: Tuple[str, ...]
    label: str


def cr_approve_request(view) -> ApproveRequest:
    """The Center's Approve request for one pending change request.

    A request a repair run proposed (run_id set) goes through
    `secure agent approve <run_id>`, the same revalidation gate
    agent_view uses: it re-checks the worktree diff and supersedes a
    drifted request instead of approving it. Any other request is
    approved at exactly its revision hash. Each dialog describes only
    the check its own route performs.
    """
    classification = view.classification or "(unclassified)"
    closing = "\n\nA passing test result is not authorization. Have you read the diff?"
    if view.run_id:
        return ApproveRequest(
            confirm_title="Approve change request",
            confirm_body=(
                f"Approve {view.cr_id}?\n\n"
                f"Classification: {classification}\n"
                f"Proposed by:    agent repair run {view.run_id}\n\n"
                "Secure will first re-check that the repair worktree's current diff still\n"
                "matches what was proposed. If it has drifted, it will refuse to approve, and\n"
                "instead supersede this change request and (if the current worktree still\n"
                "passes re-verification) propose a fresh one for you to review.\n\n"
                "Approving only records authorization; nothing is applied to the live checkout."
                + closing
            ),
            args=agent_approve_args(view.run_id, view.cr_id),
            label=f"Approve Agent Repair Change Request ({view.cr_id})",
        )
    return ApproveRequest(
        confirm_title="Approve change request",
        confirm_body=(
            f"Approve {view.cr_id}?\n\n"
            f"Classification: {classification}\n"
            f"Revision hash:  {view.revision_hash}\n\n"
            "This approves EXACTLY the revision above. If the change request has been\n"
            "revised since this window loaded, the approval is refused."
            + closing
        ),
        args=("ai", "changes", "approve", view.cr_id, view.revision_hash),
        label=f"secure ai changes approve {view.cr_id} {view.revision_hash}",
    )


# ---------- command catalog (docs/GUI_ROADMAP.md) ----------

# The GUI kills a job whose timeout expires. Every command not in the
# catalog keeps this, which is what the GUI always used.
DEFAULT_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class CatalogCommand:
    """One GUI button's contract with the CLI: its label, the argv after
    `secure`, whether exit 1 means "found something" rather than
    "failed", and how long the GUI waits before killing it.
    tests/test_gui_command_catalog.py parses every entry with the real
    CLI parser."""

    label: str
    args: Tuple[str, ...]
    category: str
    nonzero_is_finding: bool = False
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


_DOWNLOADS_LOGS = "Downloads & Logs"
_INTEGRATIONS = "Integrations"
_CORRELATION_CHAINS = "Correlation Chains"
_VALIDATION_DETECTION = "Validation & Detection"
_THREATINTEL_DFIR = "Threat Intel & DFIR"
_AI_PERFORMANCE = "AI & Performance"

# Integration scans exit 0 clean / 1 findings / 2 unavailable or error
# (docs/INTEGRATIONS.md "Exit codes"); zeek never exits 1. Their runtimes
# are unmeasured on the target Mac, hence a conservative 300 s. status,
# rules, rulesets and alerts only read: exit 1 there is a failure. No
# mark-alert here: it looks alerts up by id alone (docs/GUI_ROADMAP.md G2.5).
_SCAN_TIMEOUT = 300


def _integration(label: str, *args: str, scan: bool = False, finding: bool = False) -> CatalogCommand:
    return CatalogCommand(
        label, ("integrations", *args), _INTEGRATIONS,
        nonzero_is_finding=finding,
        timeout_seconds=_SCAN_TIMEOUT if scan else DEFAULT_TIMEOUT_SECONDS,
    )


COMMAND_CATALOG: Tuple[CatalogCommand, ...] = (
    # Read-only. Exit 1 means the quarantine history could not be read.
    CatalogCommand("Download Provenance (last 30 days)", ("downloads",), _DOWNLOADS_LOGS),
    CatalogCommand("Flagged Downloads Only", ("downloads", "--flagged"), _DOWNLOADS_LOGS),
    # Read-only. Exit 1/2 means a hunt failed. A default 24 h hunt took
    # 51 s on the target Mac, so it needs more than the default.
    CatalogCommand("Log Hunt (last 24 hours)", ("loghunt",), _DOWNLOADS_LOGS, timeout_seconds=300),
    _integration("osquery Status", "osquery", "status"),
    _integration("osquery Cross-Check Scan", "osquery", "scan", scan=True, finding=True),
    _integration("osquery Alerts", "osquery", "alerts"),
    _integration("YARA-X Status", "yarax", "status"),
    _integration("YARA-X Rulesets", "yarax", "rulesets"),
    _integration("YARA-X Scan File Integrity Alerts", "yarax", "scan-fim-alerts", scan=True, finding=True),
    _integration("YARA-X Scan Suspicious Persistence", "yarax", "scan-suspicious", scan=True, finding=True),
    _integration("YARA-X Alerts", "yarax", "alerts"),
    _integration("Sigma Status", "sigma", "status"),
    _integration("Sigma Rules", "sigma", "rules"),
    _integration("Sigma Scan", "sigma", "scan", scan=True, finding=True),
    _integration("Sigma Alerts", "sigma", "alerts"),
    _integration("Suricata Status", "suricata", "status"),
    _integration("Suricata Scan", "suricata", "scan", scan=True, finding=True),
    _integration("Suricata Alerts", "suricata", "alerts"),
    _integration("Zeek Status", "zeek", "status"),
    _integration("Zeek Scan", "zeek", "scan", scan=True),
    # `chains run` exits 1 only when it records new chain alerts. It writes,
    # and was not measured against the real database, so 300 s.
    CatalogCommand("Find Correlation Chains", ("correlate", "chains", "run"), _CORRELATION_CHAINS,
                   nonzero_is_finding=True, timeout_seconds=_SCAN_TIMEOUT),
    CatalogCommand("List Correlation Chains", ("correlate", "chains", "list"), _CORRELATION_CHAINS),
    # G4. validate run exits 1 exactly on a MISS (a detection gap to
    # review); it records a run and took 1.2 s. Every other command here
    # only reads and returns 0. Not here on purpose: `detect sync` (writes
    # the rule registry) and `threatintel lookup` (network egress, Q2).
    CatalogCommand("Run Validation Suite", ("validate", "run"), _VALIDATION_DETECTION, nonzero_is_finding=True),
    CatalogCommand("List Validation Runs", ("validate", "list"), _VALIDATION_DETECTION),
    CatalogCommand("List Detection Rules", ("detect", "list"), _VALIDATION_DETECTION),
    CatalogCommand("Threat Intel Providers", ("threatintel", "providers"), _THREATINTEL_DFIR),
    CatalogCommand("Threat Intel Lookup History", ("threatintel", "history"), _THREATINTEL_DFIR),
    CatalogCommand("DFIR Tool Status", ("dfir", "status"), _THREATINTEL_DFIR),
    CatalogCommand("List Forensic Collections", ("dfir", "list"), _THREATINTEL_DFIR),
    CatalogCommand("AI Provider Status", ("ai", "status"), _AI_PERFORMANCE),
    CatalogCommand("AI Role Assignments", ("ai", "roles"), _AI_PERFORMANCE),
    CatalogCommand("AI Query History", ("ai", "history"), _AI_PERFORMANCE),
    CatalogCommand("Performance Milestones", ("diagnostics", "history"), _AI_PERFORMANCE),
)


PRUNE_CONFIRM_TITLE = "Prune junk inventory entries"
PRUNE_CONFIRM_BODY = (
    "Delete the inventory's junk device records (empty, broadcast and "
    "multicast entries)?\n\nThis removes rows from the database and cannot "
    "be undone from the GUI."
)


def confirmed_args(confirm, title: str, body: str, args):
    """`args` if `confirm(title, body)` returns True, else None (the GUI
    treats None from a button's argv builder as "cancelled")."""
    return args if confirm(title, body) else None
