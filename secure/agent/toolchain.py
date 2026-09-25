"""
secure/agent/toolchain.py — Phase 46 (Part 2: Supervised Agentic
Development & Self-Healing — "Dependency & Security Tool Maintenance").

Extends the supervised workflow to external tooling and dependencies.

    "Never silently update the live security stack. Package
    installation/update remains approval-gated. Do not install tools
    merely because they appear in this phase. Reuse installed tools and
    simulate/mimic update scenarios in tests where appropriate."

    "ACCEPTANCE: Secure can identify and analyze representative
    dependency/tool maintenance situations and produce a verified
    proposal/change request without silently altering the live
    environment."

THERE IS NO UPDATE FUNCTION IN THIS MODULE. NOT A DISABLED ONE.

Same reasoning as Phase 42's launchd installation, and the same
enforcement: absence. This module surveys, analyses, and proposes. It
contains no code that runs a package manager, no code that downloads
anything, and no code that writes to `requirements.txt`. When the
operator approves a proposal, they run the update themselves.

An update path that exists is an update path a bug can reach — and the
thing it would reach into is this machine's security stack.

WHAT "MAINTENANCE SITUATION" MEANS HERE

Five deterministic conditions, each derived from data Secure already
collects:

  - a configured integration reporting UNAVAILABLE (it was set up, and
    now it is not answering)
  - a configured integration reporting DEGRADED or ERROR
  - an observed tool version that differs from the last one recorded
    (drift — the thing under Secure changed without Secure asking)
  - a runtime dependency declared without a version floor
  - the local-model backend configured but not reachable

None of these involves asking a model whether something looks
outdated. Phase 39's rule applies here too: a model's opinion may not
lower the required approval level, and the cleanest way to honor that
is not to consult one.

REUSE

Health comes from Phase 30's `collect_integration_health()`, which
itself reuses each integration's own `check_availability()` and the
Phase 15-19 STATUS_OK/DEGRADED/UNAVAILABLE/ERROR vocabulary. Proposals
go through Phase 28's `propose_change()`, classified by Phase 39, and
notified by Phase 41's sanitized path. Nothing here reimplements any
of that.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure.agent.classify import (
    CLASS_DEPENDENCY_CHANGE,
    CLASS_SYSTEM_CHANGE,
    Classification,
)
from secure.config import AppConfig

# Situation kinds.
SITUATION_UNAVAILABLE = "integration_unavailable"
SITUATION_DEGRADED = "integration_degraded"
SITUATION_ERROR = "integration_error"
SITUATION_VERSION_DRIFT = "tool_version_drift"
SITUATION_UNPINNED_DEPENDENCY = "unpinned_runtime_dependency"
SITUATION_MODEL_BACKEND_UNREACHABLE = "model_backend_unreachable"

ALL_SITUATION_KINDS = (
    SITUATION_UNAVAILABLE,
    SITUATION_DEGRADED,
    SITUATION_ERROR,
    SITUATION_VERSION_DRIFT,
    SITUATION_UNPINNED_DEPENDENCY,
    SITUATION_MODEL_BACKEND_UNREACHABLE,
)

# Which class each situation proposes under. A situation that would
# require touching an OS-level service is a SYSTEM_CHANGE; the rest are
# DEPENDENCY_CHANGE. Both are approval-gated, so the distinction is
# about accuracy in the record, not about whether a human is asked.
_SITUATION_CLASS = {
    SITUATION_UNAVAILABLE: CLASS_DEPENDENCY_CHANGE,
    SITUATION_DEGRADED: CLASS_DEPENDENCY_CHANGE,
    SITUATION_ERROR: CLASS_DEPENDENCY_CHANGE,
    SITUATION_VERSION_DRIFT: CLASS_DEPENDENCY_CHANGE,
    SITUATION_UNPINNED_DEPENDENCY: CLASS_DEPENDENCY_CHANGE,
    SITUATION_MODEL_BACKEND_UNREACHABLE: CLASS_SYSTEM_CHANGE,
}

# A requirements line that declares a package with no version floor.
_REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9._\-]+)\s*(?P<spec>[<>=!~].*)?\s*$")


@dataclass(frozen=True)
class MaintenanceSituation:
    """One thing worth a human's attention about the toolchain.

    `evidence` is always populated from something Secure actually
    observed — never from a guess about what version "should" be
    current, which Secure has no way to know without a network lookup
    it deliberately does not perform.
    """

    kind: str
    component: str
    summary: str
    evidence: str
    observed_version: "Optional[str]" = None
    previous_version: "Optional[str]" = None

    @property
    def classification(self) -> str:
        return _SITUATION_CLASS.get(self.kind, CLASS_DEPENDENCY_CHANGE)

    @property
    def requires_approval(self) -> bool:
        """Always True. Every situation this module can report resolves
        into a package or service operation, and all of those are
        approval-gated."""
        return True


# ---------------------------------------------------------------------
# Survey
# ---------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def survey_integrations(
    conn: sqlite3.Connection, cfg: AppConfig, *, health=None, now: "Optional[str]" = None
) -> "list[MaintenanceSituation]":
    """Phase 30's health collector, read and interpreted — never
    re-implemented. `health` is injectable so a test can simulate an
    update/compatibility scenario without needing the real tools
    installed, which is exactly what the governing text asks for.
    """
    from secure.integrations.base import (
        STATUS_DEGRADED,
        STATUS_ERROR,
        STATUS_OK,
        STATUS_UNAVAILABLE,
    )
    from secure.storage.models import latest_tool_version, record_tool_version

    if health is None:
        from secure.diagnostics.integrations_health import collect_integration_health

        health = collect_integration_health(cfg)

    now = now or _now()
    situations: "list[MaintenanceSituation]" = []

    for name, item in health:
        status = getattr(item, "status", None)
        detail = getattr(item, "detail", "") or ""
        version = getattr(item, "tool_version", None)

        if status == STATUS_UNAVAILABLE:
            situations.append(MaintenanceSituation(
                kind=SITUATION_UNAVAILABLE, component=name,
                summary=f"{name} is configured but reports UNAVAILABLE",
                evidence=detail,
            ))
        elif status == STATUS_ERROR:
            situations.append(MaintenanceSituation(
                kind=SITUATION_ERROR, component=name,
                summary=f"{name} is present but erroring",
                evidence=detail, observed_version=version,
            ))
        elif status == STATUS_DEGRADED:
            situations.append(MaintenanceSituation(
                kind=SITUATION_DEGRADED, component=name,
                summary=f"{name} is only partly working",
                evidence=detail, observed_version=version,
            ))

        # Version drift is checked independently of status: a tool can
        # be perfectly healthy and still have changed underneath us,
        # which is precisely the compatibility situation this phase
        # exists to surface.
        if version:
            previous = latest_tool_version(conn, name)
            if previous is not None and previous.tool_version != version:
                situations.append(MaintenanceSituation(
                    kind=SITUATION_VERSION_DRIFT, component=name,
                    summary=f"{name} version changed from {previous.tool_version} to {version}",
                    evidence=(
                        f"Secure last observed {previous.tool_version} at {previous.last_seen}; it now "
                        f"reports {version}. Secure did not perform this change and does not know who "
                        "did. Its detection content and output format should be re-validated."
                    ),
                    observed_version=version, previous_version=previous.tool_version,
                ))
            record_tool_version(conn, component=name, tool_version=version, seen_at=now)

    return situations


def survey_model_backend(cfg: AppConfig, *, reachable: "Optional[bool]" = None) -> "list[MaintenanceSituation]":
    """A local-model backend that is configured but not answering. The
    check is injectable (`reachable`) so tests never make a network
    call; when it is None, this reports nothing rather than guessing.
    """
    host = getattr(cfg, "ollama_host", "") or ""
    if not host:
        return []
    if reachable is None:
        return []
    if reachable:
        return []
    return [MaintenanceSituation(
        kind=SITUATION_MODEL_BACKEND_UNREACHABLE, component="ollama",
        summary="the local model backend is configured but not reachable",
        evidence=f"AppConfig.ollama_host is {host!r} but the backend did not answer.",
    )]


def survey_dependencies(*, requirements_path: "Optional[Path]" = None) -> "list[MaintenanceSituation]":
    """Reads `requirements.txt` and reports any package declared with
    no version floor. Read-only; this function never writes that file.
    """
    from secure.agent.worktree import project_root

    path = requirements_path or (project_root() / "requirements.txt")
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    situations: "list[MaintenanceSituation]" = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _REQUIREMENT_RE.match(line)
        if not match:
            continue
        if match.group("spec"):
            continue
        situations.append(MaintenanceSituation(
            kind=SITUATION_UNPINNED_DEPENDENCY, component=match.group(1),
            summary=f"{match.group(1)} is declared with no version floor",
            evidence=(
                f"requirements.txt line {raw_line.strip()!r} names a package without a version "
                "constraint, so a fresh install could pick up an untested release."
            ),
        ))
    return situations


def survey(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    health=None,
    model_reachable: "Optional[bool]" = None,
    requirements_path: "Optional[Path]" = None,
) -> "list[MaintenanceSituation]":
    """Everything, in one call. Observes only."""
    return [
        *survey_integrations(conn, cfg, health=health),
        *survey_model_backend(cfg, reachable=model_reachable),
        *survey_dependencies(requirements_path=requirements_path),
    ]


# ---------------------------------------------------------------------
# Analysis and proposal
# ---------------------------------------------------------------------


def analyze(situation: MaintenanceSituation) -> str:
    """The written analysis that accompanies a proposal. Deterministic
    text derived from the situation kind — not a model's opinion, and
    not a claim about what version is 'current' (Secure has no way to
    know that without a network lookup it does not perform)."""
    common = (
        "\nSecure has NOT changed anything. This is an observation and a proposal. "
        "Any package or service operation is approval-gated, and Secure ships no code that "
        "performs one — if you approve this, you run the command yourself."
    )
    if situation.kind == SITUATION_UNAVAILABLE:
        return (
            f"{situation.component} was configured at some point but is not answering now. Either it "
            "was removed or moved, or its path in Secure's config is stale. Until it is resolved, "
            f"Secure reports {situation.component}'s findings as UNAVAILABLE rather than as clean — "
            "no detection is silently lost, but coverage is genuinely reduced." + common
        )
    if situation.kind == SITUATION_ERROR:
        return (
            f"{situation.component} is installed but failing when used. This is the state most likely "
            "to be mistaken for 'working', so it is worth resolving promptly; Secure reports it as "
            "ERROR and does not treat its silence as a clean result." + common
        )
    if situation.kind == SITUATION_DEGRADED:
        return (
            f"{situation.component} is returning only part of what was requested. Partial coverage is "
            "reported honestly rather than as a pass, but the gap is real." + common
        )
    if situation.kind == SITUATION_VERSION_DRIFT:
        return (
            f"{situation.component} changed from {situation.previous_version} to "
            f"{situation.observed_version} without Secure asking. A version change in a detection tool "
            "can alter rule syntax, output format, or default behavior, so its integration and "
            "fixtures should be re-validated before the new version is relied on. Secure has not "
            "adjusted anything to accommodate it." + common
        )
    if situation.kind == SITUATION_UNPINNED_DEPENDENCY:
        return (
            f"{situation.component} is declared without a version floor, so a fresh install on another "
            "machine could resolve to a release this project has never been tested against. Adding a "
            "floor is a one-line change to requirements.txt — which Secure does not make itself, "
            "because editing the dependency manifest is a DEPENDENCY_CHANGE." + common
        )
    if situation.kind == SITUATION_MODEL_BACKEND_UNREACHABLE:
        return (
            "The local model backend is configured but not answering. Secure degrades honestly when "
            "this happens — the reviewer reports `unavailable` and repairs proceed without a second "
            "opinion rather than pretending one was obtained — but the supervision this project "
            "depends on is weaker until it is back." + common
        )
    return "No analysis is defined for this situation kind." + common


def propose_maintenance(
    conn: sqlite3.Connection, cfg: AppConfig, situation: MaintenanceSituation
):
    """Creates a PENDING change request for one situation and returns
    it. Installs nothing, updates nothing, writes no manifest.

    Reuses Phase 28's `propose_change()`, Phase 39's classification
    vocabulary, and Phase 41's sanitized notification — none of them
    modified.
    """
    from secure.ai.changes.workflow import propose_change
    from secure.storage.models import (
        find_ai_change_request,
        mark_ai_change_request_notified,
        set_ai_change_request_classification,
    )

    classification = Classification(
        classification=situation.classification,
        reasons=(
            f"{situation.kind} affects an external dependency or service",
            "package installation/update and service configuration are approval-gated",
            "Secure ships no code that performs the operation — the operator does it",
        ),
    )

    cr = propose_change(
        conn, cfg,
        title=f"Toolchain maintenance: {situation.summary}",
        proposed_change=(
            f"{classification.describe()}\n\n"
            f"Component: {situation.component}\n"
            f"Situation: {situation.kind}\n"
            f"Observed version: {situation.observed_version or '(unknown)'}\n"
            f"Previously observed: {situation.previous_version or '(none recorded)'}\n\n"
            f"Evidence Secure actually observed:\n{situation.evidence}\n\n"
            f"Analysis:\n{analyze(situation)}"
        ),
        reason=situation.summary,
        affected_component=situation.component,
        risks=(
            "Secure has not altered the live environment in any way. Approving this change request "
            "does not install, update, or remove anything: this project contains no code that runs a "
            "package manager or a service-management tool. You perform the operation yourself, then "
            "re-run `secure agent toolchain` to confirm the situation is resolved.\n\n"
            + classification.describe()
        ),
        model_a_opinion="(no model was involved — this proposal is generated deterministically by secure/agent/toolchain.py)",
        model_b_opinion="(no model was involved)",
        notify=False,
    )
    set_ai_change_request_classification(conn, cr_id=cr.cr_id, classification=situation.classification)

    try:
        from secure.agent.center import build_change_request_view
        from secure.agent.notify import notify_if_consequential

        view = build_change_request_view(conn, cr.cr_id)
        if view is not None:
            status, _detail = notify_if_consequential(cfg, view)
            mark_ai_change_request_notified(conn, cr_id=cr.cr_id, notified_at=_now(), notify_status=status)
    except Exception:  # noqa: BLE001 — a notification problem never blocks a persisted proposal
        pass

    return find_ai_change_request(conn, cr.cr_id) or cr


def describe(situations: "list[MaintenanceSituation]") -> str:
    if not situations:
        return "No toolchain maintenance situations were found."
    lines = [f"{len(situations)} toolchain maintenance situation(s):", ""]
    for s in situations:
        lines.append(f"  {s.component}: {s.summary}")
        lines.append(f"    kind:           {s.kind}")
        lines.append(f"    classification: {s.classification} (approval required: {s.requires_approval})")
        lines.append(f"    evidence:       {s.evidence}")
        lines.append("")
    lines.append("Secure has changed nothing. Propose any of these with `secure agent toolchain --propose`.")
    return "\n".join(lines)
