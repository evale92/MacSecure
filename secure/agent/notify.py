"""
secure/agent/notify.py — Phase 41 (Part 2: Supervised Agentic
Development & Self-Healing — "Email Change Notifications").

Notifies the operator when a CONSEQUENTIAL change reaches
AWAITING_APPROVAL. Governing text, verbatim

    "Reuse existing Secure notification/email infrastructure where
    possible... Email is notification only. Email replies must NEVER
    authorize execution. Never include secrets or sensitive model
    context."

    "ACCEPTANCE: Tests prove the correct approval states generate
    sanitized notifications, ordinary SAFE_PROJECT_CODE does not
    unnecessarily notify, secrets cannot enter the generated email, and
    email has no authorization path."

REUSE

Transport is `secure/ai/changes/notify.py`'s `send_plaintext_email()`
— the same SMTP gating (empty `smtp_host`/`ai_notify_email` means "not
configured," checked before any I/O), the same never-raise contract,
the same (status, detail) return. No second SMTP client exists.

WHY THIS BODY IS NOT PHASE 28'S BODY

Phase 28's `build_email_body()` includes `proposed_change` verbatim,
which for an agent repair contains up to 6000 characters of raw diff,
plus both models' full opinions. That was appropriate when the only
sender was a human-authored proposal. It is not appropriate here: a
diff is arbitrary source text that can contain anything the repository
contains, and model opinions are exactly the "sensitive model context"
this phase says not to send. So this module builds its own deliberately
THIN body — identifiers, classification, status, and a pointer back
into Secure — and every field that goes into it is passed through
`sanitize()` first.

The email is a doorbell, not a document. The document is in Secure.

NO AUTHORIZATION PATH

There is no reply-to address, no token, no link, and no instruction
that could be followed by replying. The only action the email names is
a command the operator types into their own terminal, and Phase 28's
`approve_change()` independently re-verifies the revision hash when
they do. Nothing in this module writes to the database or changes a
change request's status.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from secure.agent.classify import (
    CLASS_DEPENDENCY_CHANGE,
    CLASS_PRIVILEGED_CHANGE,
    CLASS_SECURITY_SEMANTIC_CHANGE,
    CLASS_SYSTEM_CHANGE,
    requires_human_approval,
)
from secure.ai.changes.notify import NOTIFY_SKIPPED, send_plaintext_email
from secure.config import AppConfig

# The four classes the governing text names explicitly. Written as the
# four rather than as "everything except SAFE_PROJECT_CODE" so a class
# added later must be considered deliberately instead of silently
# joining the notify list — but see should_notify(), which ALSO
# notifies for any unrecognized class, so the failure direction is
# still "notify too much" rather than "stay silent."
NOTIFY_CLASSES = (
    CLASS_DEPENDENCY_CHANGE,
    CLASS_SECURITY_SEMANTIC_CHANGE,
    CLASS_SYSTEM_CHANGE,
    CLASS_PRIVILEGED_CHANGE,
)

# Reuses Phase 31.5's own secret-shaped-token pattern rather than
# inventing a second one that could drift from it.
from secure.agent.audit import _SECRET_TOKEN_PATTERN  # noqa: E402

# Belt-and-braces on top of the keyword pattern: long opaque strings
# that look like credentials even without a giveaway keyword nearby.
_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

_MAX_FIELD_CHARS = 300

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class NotificationDecision:
    """Whether to notify, and why — recorded so a silent decision is
    still an inspectable one."""

    should_notify: bool
    reason: str


def should_notify(classification: "Optional[str]") -> NotificationDecision:
    """Consequential changes notify; ordinary SAFE_PROJECT_CODE does
    not. An unclassified or unrecognized class notifies, because not
    knowing what something is has never been a reason to stay quiet
    about it in this project.
    """
    if classification in NOTIFY_CLASSES:
        return NotificationDecision(True, f"{classification} requires human approval")
    if classification is None or classification == "":
        return NotificationDecision(True, "change is unclassified — notifying rather than assuming it is ordinary")
    if requires_human_approval(classification):
        return NotificationDecision(
            True, f"unrecognized class {classification!r} is approval-gated by default — notifying"
        )
    return NotificationDecision(
        False, f"{classification} is ordinary project code and does not require a notification"
    )


def sanitize(value: "Optional[str]", *, limit: int = _MAX_FIELD_CHARS) -> str:
    """Every field that enters an email goes through this.

    Three rules, in order: a value containing a secret-shaped keyword
    is withheld entirely rather than partially masked (a partial mask
    of an unknown format leaks the format); any long opaque token is
    replaced; and whatever survives is length-bounded, because a field
    that can grow without limit is a field that can smuggle a diff into
    a notification.
    """
    if not value:
        return ""
    text = str(value)
    if _SECRET_TOKEN_PATTERN.search(text):
        return "[withheld: contained a secret-shaped token]"
    text = _HIGH_ENTROPY_RE.sub(REDACTED, text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + f"...[truncated, {len(text)} chars — see Secure for the full text]"
    return text


def build_notification_email(view) -> "tuple[str, str]":
    """Returns (subject, body) for one change request awaiting
    approval. `view` is a Phase 40 ChangeRequestView, taken
    duck-typed so this module does not depend on that dataclass's
    exact identity.

    Deliberately absent: the diff, the proposed-action text, the
    reviewer's prose rationale, both models' opinions, and the raw
    risks paragraph. Those live in Secure. Note that the revision hash
    is also absent — it is long and opaque enough to be caught by the
    entropy rule anyway, and including it would invite approving from
    the email rather than from the tool.
    """
    subject = (
        f"Secure: {sanitize(view.classification, limit=60) or 'unclassified'} change "
        f"{sanitize(view.cr_id, limit=40)} awaiting your approval"
    )

    reviewer = "(no independent review recorded)"
    if getattr(view, "review_status", None):
        blocking = list(getattr(view, "review_blocking", []) or [])
        reviewer = (
            f"{sanitize(view.review_status, limit=40)}"
            + (f" — BLOCKING: {sanitize(', '.join(blocking), limit=200)}" if blocking else " — no blocking findings")
        )

    body = "\n".join([
        f"Secure has a change request awaiting your approval: {sanitize(view.cr_id, limit=40)}",
        "",
        "THIS EMAIL IS A NOTIFICATION ONLY.",
        "It does not authorize anything, and nothing has been changed on this machine.",
        "Replying to this email does nothing at all — there is no approval path through email.",
        "",
        f"Request ID:        {sanitize(view.cr_id, limit=40)}",
        f"Status:            {sanitize(view.status, limit=40)}",
        f"Classification:    {sanitize(view.classification, limit=60) or '(unclassified)'}",
        f"Requesting agent:  {sanitize(getattr(view, 'requesting_tool', ''), limit=60) or '(none)'}",
        f"Requesting model:  {sanitize(getattr(view, 'requesting_model', ''), limit=60) or '(none)'}",
        f"Reviewer result:   {reviewer}",
        "",
        "Reason:",
        f"  {sanitize(view.reason)}",
        "",
        "Requested action:",
        f"  {sanitize(getattr(view, 'affected_component', ''))}",
        "",
        "Review it inside Secure before deciding — the diff, the full test output, the",
        "independent reviewer's assessment, and the rollback strategy are all there:",
        "",
        f"  secure agent center show {sanitize(view.cr_id, limit=40)} --diff --tests",
        "",
        "Approve or reject from that screen, or from the Agent — Change Requests window.",
        "A passing test result is not authorization. A second model agreeing is not approval.",
    ])
    return subject, body


def notify_if_consequential(cfg: AppConfig, view) -> "tuple[str, str]":
    """The one entry point. Returns the same (status, detail) pair
    every notification path in this project returns; never raises, and
    never writes to the database.

    A SAFE_PROJECT_CODE change returns NOTIFY_SKIPPED with a reason
    rather than sending — "ordinary SAFE_PROJECT_CODE does not
    unnecessarily notify" is implemented as a decision that is
    recorded, not as a silent absence.
    """
    decision = should_notify(getattr(view, "classification", None))
    if not decision.should_notify:
        return NOTIFY_SKIPPED, decision.reason
    subject, body = build_notification_email(view)
    return send_plaintext_email(cfg, subject=subject, body=body)
