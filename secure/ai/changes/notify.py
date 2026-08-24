"""
secure/ai/changes/notify.py — sends the one email the governing
instruction requires for every AI-generated change request, to
`cfg.ai_notify_email`. Gated by `cfg.smtp_host` exactly like every
other optional network integration in this project (empty string
means "not configured," checked first, before any I/O) — an operator
who hasn't set up SMTP still gets a fully-functional, fully-persisted
change request; they just won't get emailed about it.

"Email delivery is notification only. It does not authorize
execution." — nothing in this module writes to the database. It only
ever returns a (status, detail) pair for the caller (workflow.py) to
record via `mark_ai_change_request_notified()`.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Optional

from secure.config import AppConfig
from secure.storage.models.ai import AiChangeRequestRecord

NOTIFY_SKIPPED = "skipped"
NOTIFY_SENT = "sent"
NOTIFY_FAILED = "failed"


def build_email_body(record: AiChangeRequestRecord, *, verification_summary: "Optional[str]" = None) -> str:
    """Every field the governing instruction lists as required, in a
    fixed, predictable order, so a human skimming the email always
    finds the same information in the same place."""
    lines = [
        f"Secure — new AI-proposed change request: {record.cr_id}",
        "",
        "This is a NOTIFICATION ONLY. It does not authorize anything. Nothing has been changed.",
        f"To approve: secure ai changes approve {record.cr_id} {record.revision_hash}",
        f"To reject:  secure ai changes reject {record.cr_id}",
        "",
        f"Change request ID: {record.cr_id}",
        f"Revision hash:     {record.revision_hash}",
        f"Title:             {record.title}",
        "",
        "Proposed change:",
        record.proposed_change,
        "",
        "Reason:",
        record.reason,
        "",
        f"Affected component: {record.affected_component}",
        "",
        "Risks (from Model B's adversarial review):",
        record.risks,
        "",
        "Verification results:",
        verification_summary or "(no automated verification run was attached to this proposal)",
        "",
        "Model A (Analyst) opinion:",
        record.model_a_opinion,
        "",
        "Model B (Verifier) opinion:",
        record.model_b_opinion,
    ]
    return "\n".join(lines)


def send_plaintext_email(cfg: AppConfig, *, subject: str, body: str) -> "tuple[str, str]":
    """The one place this project actually talks to an SMTP relay.

    Extracted (Phase 41) so the agent-side consequential-change
    notifier can reuse the exact same gating, transport, and
    failure-reporting rather than growing a second copy of it. The
    behavior is unchanged from what send_change_request_notification()
    did inline before: empty `smtp_host`/`ai_notify_email` means "not
    configured," checked before any I/O, and every failure is returned
    as a (status, detail) pair rather than raised — a notification
    problem must never block or fail a change request that is already
    safely persisted.

    Writes nothing to the database, and there is no argument here that
    could make an email authorize anything.
    """
    if not cfg.smtp_host or not cfg.ai_notify_email:
        return NOTIFY_SKIPPED, "SMTP relay or notify-email is not configured — notification skipped, not blocking."

    try:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = cfg.smtp_from_addr or cfg.smtp_username or "secure@localhost"
        message["To"] = cfg.ai_notify_email
        message.set_content(body)

        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as server:
            if cfg.smtp_use_tls:
                server.starttls()
            if cfg.smtp_username:
                server.login(cfg.smtp_username, cfg.smtp_password)
            server.send_message(message)
        return NOTIFY_SENT, f"Sent to {cfg.ai_notify_email} via {cfg.smtp_host}:{cfg.smtp_port}."
    except Exception as exc:
        return NOTIFY_FAILED, f"{type(exc).__name__}: {exc}"


def send_change_request_notification(
    cfg: AppConfig, record: AiChangeRequestRecord, *, verification_summary: "Optional[str]" = None
) -> "tuple[str, str]":
    return send_plaintext_email(
        cfg,
        subject=f"Secure: new AI change request {record.cr_id} — pending your approval",
        body=build_email_body(record, verification_summary=verification_summary),
    )
