"""
secure/agent/memory.py — Phase 45 (Part 2: Supervised Agentic
Development & Self-Healing — "Maintenance Memory").

Structured engineering/repair history. Governing text, verbatim
(docs/ROADMAP_PART2_PHASES_38_47.md):

    "Do not use unrestricted chat history as the primary memory
    system... Allow future failures to search prior validated repairs.
    Previous repairs are evidence, not authority. Never blindly replay
    an old patch against changed code."

    "ACCEPTANCE: A later matching failure can retrieve relevant
    historical repair evidence while preserving revision/context
    differences and without automatically applying the old solution."

WHAT IS AND IS NOT STORED

Every column is a structured fact already established deterministically
by an earlier phase: what failed, which component, what changed, which
framework and model, the diff's identity, what verification said, what
the reviewer's COMPUTED blocking list said, how it was classified,
whether a human approved, and how it ended. Nothing here stores
conversation text, a model's prose, or a transcript. The transcript
already exists on disk with its own hash (Phase 31) for anyone who
wants to read it; duplicating it into a searchable table would make
this "unrestricted chat history" under a different name.

FAILURES ARE REMEMBERED TOO

`outcome` records what actually happened, including rejected,
escalated, and failed repairs. A memory that remembered only successes
would systematically mislead whatever reads it — the reader would
conclude this system always works.

EVIDENCE, NOT AUTHORITY

`recall()` returns prior records and, alongside each one, an explicit
statement of how the current situation DIFFERS from it (different base
commit, different changed files, stale diff). There is deliberately no
function in this module that applies, re-applies, or even reconstructs
an old patch. The phase says never to blindly replay one; the way to
guarantee that is to ship no replay mechanism at all — the same
"enforced by absence" reasoning Phase 42 applies to launchd
installation.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from secure.storage.models import (
    MaintenanceMemoryRecord,
    add_maintenance_memory,
    find_maintenance_memory_by_component,
    find_maintenance_memory_by_signature,
    find_maintenance_memory_for_run,
    list_maintenance_memory,
)

# Outcomes. Mapped from a run's terminal status rather than invented,
# so the memory cannot disagree with the run it describes.
OUTCOME_VERIFIED = "verified"
OUTCOME_ESCALATED = "escalated_for_review"
OUTCOME_VERIFICATION_FAILED = "verification_failed"
OUTCOME_INCONCLUSIVE = "verification_inconclusive"
OUTCOME_REJECTED_BY_DENYLIST = "rejected_by_denylist"
OUTCOME_NO_DIFF = "no_diff"
OUTCOME_TIMED_OUT = "timed_out"
OUTCOME_ERROR = "error"
OUTCOME_UNKNOWN = "unknown"

_STATUS_TO_OUTCOME = {
    "verified": OUTCOME_VERIFIED,
    "escalated_for_review": OUTCOME_ESCALATED,
    "verification_failed": OUTCOME_VERIFICATION_FAILED,
    "verification_inconclusive": OUTCOME_INCONCLUSIVE,
    "rejected_by_denylist": OUTCOME_REJECTED_BY_DENYLIST,
    "no_diff": OUTCOME_NO_DIFF,
    "timed_out": OUTCOME_TIMED_OUT,
    "error": OUTCOME_ERROR,
}

APPROVAL_NONE = "none"

_MAX_FIELD_CHARS = 2000

# Volatile fragments stripped before a failure signature is hashed.
# Without this, every occurrence of the same failure would produce a
# unique signature and the table would be unsearchable — which is the
# main way a "memory" quietly becomes useless.
_VOLATILE_PATTERNS = (
    re.compile(r"0x[0-9a-fA-F]+"),                     # memory addresses
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*"),  # timestamps
    re.compile(r"/(?:Users|home|tmp|var|private)/[^\s'\"]+"),        # absolute paths
    re.compile(r"\bAR-\d+\b"),                          # run ids
    re.compile(r"\bCR-\d+\b"),                          # change request ids
    re.compile(r"\b[0-9a-f]{7,40}\b"),                  # commit hashes / sha fragments
    re.compile(r"\b\d+\.\d+s\b"),                       # durations
    re.compile(r"\bline \d+\b"),                        # line numbers
)


def _normalize_for_signature(text: str) -> str:
    out = text or ""
    for pattern in _VOLATILE_PATTERNS:
        out = pattern.sub("", out)
    out = " ".join(out.split())
    return out.lower()


def failure_signature(trigger_kind: str, trigger_ref: str, trigger_detail: str = "") -> str:
    """A stable fingerprint of WHAT failed, not of one occurrence.

    Built from the trigger kind and ref (both already stable) plus a
    volatility-stripped prefix of the detail. Two runs of the same
    failing test on different days produce the same signature; two
    genuinely different failures do not.

    Returns a hex digest rather than raw text so it is safe to index,
    compare, and print without ever leaking a path or a payload.
    """
    normalized_detail = _normalize_for_signature(trigger_detail)[:500]
    material = f"{trigger_kind}\n{trigger_ref}\n{normalized_detail}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _truncate(text: str, limit: int = _MAX_FIELD_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated, {len(text)} chars]"


def _root_cause(record) -> str:
    """A factual statement of what the deterministic layers observed —
    NOT a model's explanation. Phase 45 stores what Secure knows, and
    Secure does not know the semantic root cause; it knows which check
    failed and which files changed."""
    parts = []
    if getattr(record, "trigger_detail", ""):
        parts.append(_truncate(record.trigger_detail, 800))
    files = list(getattr(record, "changed_files", []) or [])
    if files:
        parts.append("Files the repair touched: " + ", ".join(files))
    if getattr(record, "denylist_violation", None):
        parts.append(f"Denylist violation: {record.denylist_violation}")
    return "\n".join(parts) or "(no deterministic detail was recorded)"


def _repair_strategy(record) -> str:
    files = list(getattr(record, "changed_files", []) or [])
    return (
        f"{getattr(record, 'tool_name', '') or 'unknown tool'} edited "
        f"{len(files)} file(s) inside an isolated worktree at base commit "
        f"{getattr(record, 'base_commit', '') or '(unrecorded)'}; Secure computed the diff itself."
    )


def _reviewer_assessment(record) -> str:
    status = getattr(record, "review_status", None)
    if not status:
        return "(no independent review was recorded)"
    blocking = list(getattr(record, "review_blocking", []) or [])
    return (
        f"{getattr(record, 'review_provider', '') or '(none)'}/"
        f"{getattr(record, 'review_model', '') or '(none)'} status={status} "
        f"blocking={', '.join(blocking) if blocking else '(none)'}"
    )


def _verification_summary(record) -> str:
    return (
        f"pytest={getattr(record, 'pytest_status', None)}/"
        f"reproduced={getattr(record, 'reproduced', None)} "
        f"validate={getattr(record, 'validate_status', None)} "
        f"overall_passed={getattr(record, 'verification_passed', None)}"
    )


def record_run(
    conn: sqlite3.Connection,
    record,
    *,
    approval_decision: str = APPROVAL_NONE,
    rollback: str = "",
    recorded_at: "Optional[str]" = None,
) -> int:
    """Writes one maintenance-memory row for a COMPLETED run.

    Called after a run reaches a terminal status. Records outcomes of
    every kind, not just successes.
    """
    outcome = _STATUS_TO_OUTCOME.get(getattr(record, "status", ""), OUTCOME_UNKNOWN)
    return add_maintenance_memory(
        conn,
        recorded_at=recorded_at or datetime.now(timezone.utc).isoformat(),
        run_id=getattr(record, "run_id", ""),
        failure_signature=failure_signature(
            getattr(record, "trigger_kind", ""),
            getattr(record, "trigger_ref", ""),
            getattr(record, "trigger_detail", ""),
        ),
        trigger_kind=getattr(record, "trigger_kind", ""),
        trigger_ref=getattr(record, "trigger_ref", ""),
        affected_component=", ".join(getattr(record, "changed_files", []) or []),
        root_cause=_root_cause(record),
        repair_strategy=_repair_strategy(record),
        framework=getattr(record, "tool_name", ""),
        model_name=getattr(record, "model_name", ""),
        files_changed=list(getattr(record, "changed_files", []) or []),
        base_commit=getattr(record, "base_commit", ""),
        diff_hash=getattr(record, "diff_hash", None),
        verification_summary=_verification_summary(record),
        verified=getattr(record, "verification_passed", None),
        reviewer_assessment=_reviewer_assessment(record),
        classification=getattr(record, "classification", None),
        approval_decision=approval_decision,
        change_request_id=getattr(record, "change_request_id", None),
        outcome=outcome,
        rollback=rollback,
    )


# ---------------------------------------------------------------------
# Recall — evidence, with its differences stated
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class RecalledRepair:
    """One prior repair, plus an explicit account of how the current
    situation differs from it. The differences are not decoration:
    they are the reason this is evidence rather than an instruction."""

    record: MaintenanceMemoryRecord
    match_kind: str            # "signature" | "component"
    differences: "tuple[str, ...]" = field(default_factory=tuple)

    @property
    def safe_to_replay(self) -> bool:
        """Always False. There is no code path in this module that
        replays a patch, and this property exists to make that explicit
        to any caller that goes looking for one."""
        return False


MATCH_SIGNATURE = "signature"
MATCH_COMPONENT = "component"


def _differences(memory: MaintenanceMemoryRecord, *, base_commit: str, changed_files: "list[str]") -> "tuple[str, ...]":
    diffs: "list[str]" = []
    if base_commit and memory.base_commit and base_commit != memory.base_commit:
        diffs.append(
            f"different base commit (prior repair was against {memory.base_commit}, "
            f"current checkout is {base_commit}) — the code it patched may no longer exist as it was"
        )
    if not memory.base_commit:
        diffs.append("the prior repair recorded no base commit, so its context cannot be compared")
    prior_files = set(memory.files_changed or [])
    current_files = set(changed_files or [])
    if current_files and prior_files and prior_files != current_files:
        diffs.append(
            f"different files (prior repair touched {', '.join(sorted(prior_files))}; "
            f"current scope is {', '.join(sorted(current_files))})"
        )
    if memory.outcome != OUTCOME_VERIFIED:
        diffs.append(f"the prior repair did NOT reach a verified outcome (it ended {memory.outcome!r})")
    if memory.approval_decision != "approved":
        diffs.append(f"the prior repair was never approved by a human (approval: {memory.approval_decision})")
    if memory.regression_run_id:
        diffs.append(
            f"a later failure ({memory.regression_run_id}) was linked to this repair as a regression"
        )
    return tuple(diffs)


def recall(
    conn: sqlite3.Connection,
    *,
    trigger_kind: str,
    trigger_ref: str,
    trigger_detail: str = "",
    base_commit: str = "",
    changed_files: "Optional[list]" = None,
    limit: int = 10,
) -> "list[RecalledRepair]":
    """Finds prior repair evidence for a failure happening now.

    Exact signature matches first, then looser matches on the affected
    component. Every result carries its differences from the current
    situation, and nothing here returns a patch to apply.
    """
    signature = failure_signature(trigger_kind, trigger_ref, trigger_detail)
    results: "list[RecalledRepair]" = []
    seen_ids: "set[int]" = set()

    for memory in find_maintenance_memory_by_signature(conn, signature, limit=limit):
        seen_ids.add(memory.id)
        results.append(RecalledRepair(
            record=memory, match_kind=MATCH_SIGNATURE,
            differences=_differences(memory, base_commit=base_commit, changed_files=changed_files or []),
        ))

    if len(results) < limit and trigger_ref:
        component = trigger_ref.split("::")[0]
        for memory in find_maintenance_memory_by_component(conn, component, limit=limit):
            if memory.id in seen_ids:
                continue
            seen_ids.add(memory.id)
            results.append(RecalledRepair(
                record=memory, match_kind=MATCH_COMPONENT,
                differences=_differences(memory, base_commit=base_commit, changed_files=changed_files or []),
            ))
            if len(results) >= limit:
                break

    return results


def describe_recall(results: "list[RecalledRepair]") -> str:
    """Rendered for a human, and safe to include in a repair prompt.

    The header is not politeness — a coding agent reading this must not
    treat a prior repair as an instruction, and the differences below
    each entry are why.
    """
    if not results:
        return "No prior repair evidence was found for this failure."
    lines = [
        f"{len(results)} prior repair(s) relate to this failure.",
        "",
        "These are EVIDENCE, NOT AUTHORITY. Do not re-apply an old patch: the code has moved,",
        "and a patch that fitted a different revision may be wrong or harmful now. Read them for",
        "context, then decide independently.",
        "",
    ]
    for item in results:
        m = item.record
        lines.append(f"--- {m.run_id} ({m.recorded_at}, matched by {item.match_kind}) ---")
        lines.append(f"  outcome:        {m.outcome}    verified={m.verified}    approval={m.approval_decision}")
        lines.append(f"  classification: {m.classification or '(unclassified)'}")
        lines.append(f"  component:      {m.affected_component or '(none recorded)'}")
        lines.append(f"  strategy:       {m.repair_strategy}")
        lines.append(f"  verification:   {m.verification_summary}")
        lines.append(f"  reviewer:       {m.reviewer_assessment}")
        if item.differences:
            lines.append("  DIFFERENCES from the current situation:")
            for d in item.differences:
                lines.append(f"    - {d}")
        else:
            lines.append("  (no differences from the current situation were detected — still not authority)")
        lines.append("")
    return "\n".join(lines)
