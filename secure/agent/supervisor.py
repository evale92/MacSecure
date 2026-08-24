"""
secure/agent/supervisor.py — Phase 42 (Part 2: Supervised Agentic
Development & Self-Healing — "Background Supervisor").

Lightweight periodic supervision using launchd, the standard macOS
mechanism. Governing text, verbatim
(docs/ROADMAP_PART2_PHASES_38_47.md):

    "Add lightweight background scheduling using a standard macOS
    mechanism such as launchd. Do not build a custom daemon framework
    if launchd provides the lifecycle management needed... Resource use
    must remain conservative. Do not continuously run the full
    regression suite. Do not let ordinary GUI launch trigger autonomous
    repairs."

    "IMPORTANT: Installing/modifying an actual launchd job on the live
    Mac is a SYSTEM_CHANGE. Implement and test the scheduling machinery
    without installing it. Generate a change request and STOP before
    live launchd installation unless I explicitly approve it."

THERE IS NO INSTALL FUNCTION IN THIS MODULE. NOT A DISABLED ONE.

This module can GENERATE the exact plist text a human would install and
can PROPOSE a change request describing that installation. It contains
no code that writes to ~/Library/LaunchAgents and no code that invokes
the launchd control tool — not behind a flag, not behind a config
field, not behind an `if approved:` branch. An install path that exists
is an install path that can be reached by a bug, and Phase 29's own
static test (no module under secure/ may contain a service-management
tool name in argv position) is a real invariant this module is
deliberately built to satisfy rather than tiptoe around.

When the operator approves the change request, they run the two
documented commands themselves. That is the whole approval gate, and
it is enforced by absence, which is the only enforcement that cannot
be bypassed.

WHAT THE SUPERVISOR ACTUALLY DOES

Bounded, cheap, read-only jobs — the five the governing text lists.
Every one of them is a fixed argv into Secure's own CLI, timeout-bound,
`shell=False`, and audited through Phase 31.5's existing
`record_action()`. The supervisor never invokes a coding agent, never
creates a worktree, and never proposes a repair. It observes and
reports; if it finds something, a human (or a later phase, explicitly)
decides what to do about it.

The full regression suite is deliberately NOT among the jobs. FAST
verification (Phase 36's cheapest tier) is, because it is seconds of
compileall plus an import check.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.audit import now_iso, record_action
from secure.config import AppConfig

# ---------------------------------------------------------------------
# State vocabulary (the governing text's own list, verbatim)
# ---------------------------------------------------------------------

STATE_IDLE = "IDLE"
STATE_CHECKING = "CHECKING"
STATE_TESTING = "TESTING"
STATE_DIAGNOSING = "DIAGNOSING"
STATE_REPAIRING_IN_SANDBOX = "REPAIRING_IN_SANDBOX"
STATE_VERIFYING = "VERIFYING"
STATE_AWAITING_APPROVAL = "AWAITING_APPROVAL"
STATE_HEALTHY = "HEALTHY"
STATE_FAILED = "FAILED"

ALL_STATES = (
    STATE_IDLE, STATE_CHECKING, STATE_TESTING, STATE_DIAGNOSING,
    STATE_REPAIRING_IN_SANDBOX, STATE_VERIFYING, STATE_AWAITING_APPROVAL,
    STATE_HEALTHY, STATE_FAILED,
)

# States this phase's supervisor can actually reach. The other four
# belong to the repair pipeline, which the supervisor does not run —
# they are defined here because Phase 47 integrates both into one
# vocabulary, and defining them now avoids two competing spellings
# later. `reachable_states()` states the boundary explicitly rather
# than leaving it implied.
SUPERVISOR_REACHABLE_STATES = (
    STATE_IDLE, STATE_CHECKING, STATE_TESTING, STATE_HEALTHY, STATE_FAILED,
)


def reachable_states() -> "tuple[str, ...]":
    """The states a supervisor cycle can end in. DIAGNOSING,
    REPAIRING_IN_SANDBOX, VERIFYING, and AWAITING_APPROVAL are
    unreachable from here by design: this phase's supervisor does not
    diagnose, repair, verify a repair, or propose anything."""
    return SUPERVISOR_REACHABLE_STATES


# ---------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------

JOB_HEALTH_CHECK = "health_check"
JOB_INTEGRATION_HEALTH = "integration_health"
JOB_FAST_VERIFICATION = "fast_verification"
JOB_FAILURE_REVIEW = "failure_review"
JOB_INTERRUPTED_RUN_REVIEW = "interrupted_run_review"


@dataclass(frozen=True)
class SupervisorJob:
    """One bounded job. `args` are appended to `python3 -m secure`, so
    every job goes through the same CLI a human would type — there is
    no private back door into the library for the supervisor."""

    name: str
    args: "tuple[str, ...]"
    timeout_seconds: float
    state: str
    description: str
    # Several Secure commands exit 1 to mean "findings worth reviewing"
    # rather than "failed" — the CLI contract that keeps them
    # cron-scriptable. A job that follows that contract must not be
    # reported as a supervisor failure just for finding something.
    nonzero_is_finding: bool = False


DEFAULT_JOBS = (
    SupervisorJob(
        name=JOB_HEALTH_CHECK,
        args=("status",),
        timeout_seconds=60.0,
        state=STATE_CHECKING,
        description="Secure's own paths, config, and stored-event summary.",
    ),
    SupervisorJob(
        name=JOB_INTEGRATION_HEALTH,
        args=("agent", "status"),
        timeout_seconds=60.0,
        state=STATE_CHECKING,
        description="Whether the agent's tool/model/git preconditions still hold.",
    ),
    SupervisorJob(
        name=JOB_FAST_VERIFICATION,
        args=("self", "--help"),
        timeout_seconds=120.0,
        state=STATE_TESTING,
        description="Cheapest possible signal that the installed package still imports and parses.",
    ),
    SupervisorJob(
        name=JOB_FAILURE_REVIEW,
        args=("agent", "list"),
        timeout_seconds=60.0,
        state=STATE_CHECKING,
        description="Recent repair runs and their terminal statuses.",
    ),
    SupervisorJob(
        name=JOB_INTERRUPTED_RUN_REVIEW,
        args=("agent", "center"),
        timeout_seconds=60.0,
        state=STATE_CHECKING,
        description="Change requests still awaiting a human, and runs left mid-flight.",
    ),
)

# Guard against the single most consequential mistake this module could
# make: scheduling something that repairs. Enforced at construction
# time by validate_jobs(), and tested.
FORBIDDEN_JOB_ARGS = (
    ("agent", "run"),
    ("agent", "approve"),
    ("agent", "resume"),
    ("ai", "changes", "approve"),
    ("ai", "changes", "reject"),
)


class UnsafeSupervisorJob(RuntimeError):
    """Raised when a job would trigger a repair, an approval, or any
    other consequential action. The supervisor observes; it does not
    act."""


def validate_jobs(jobs: "tuple[SupervisorJob, ...]") -> None:
    for job in jobs:
        for forbidden in FORBIDDEN_JOB_ARGS:
            if tuple(job.args[: len(forbidden)]) == forbidden:
                raise UnsafeSupervisorJob(
                    f"supervisor job {job.name!r} would run {' '.join(job.args)!r}, which is a "
                    "consequential action — the background supervisor may only observe"
                )
        if job.timeout_seconds <= 0 or job.timeout_seconds > _MAX_JOB_TIMEOUT_SECONDS:
            raise UnsafeSupervisorJob(
                f"supervisor job {job.name!r} has timeout {job.timeout_seconds} — jobs must be "
                f"bounded between 0 and {_MAX_JOB_TIMEOUT_SECONDS} seconds"
            )


_MAX_JOB_TIMEOUT_SECONDS = 300.0
_MAX_OUTPUT_CHARS = 2000


@dataclass(frozen=True)
class JobResult:
    name: str
    status: str  # "ok" | "finding" | "fail" | "timeout" | "error"
    exit_code: "Optional[int]"
    summary: str
    duration_seconds: float


@dataclass(frozen=True)
class SupervisorCycle:
    started_at: str
    completed_at: str
    state: str
    results: "tuple[JobResult, ...]" = field(default_factory=tuple)

    @property
    def healthy(self) -> bool:
        return self.state == STATE_HEALTHY


def _truncate(text: str) -> str:
    if len(text) <= _MAX_OUTPUT_CHARS:
        return text
    return text[:_MAX_OUTPUT_CHARS] + f"\n...[{len(text) - _MAX_OUTPUT_CHARS} more characters truncated]"


def run_job(job: SupervisorJob, *, cwd: "Optional[Path]" = None, audit_trail: "Optional[list]" = None) -> JobResult:
    """Runs one bounded job. Never raises: every failure mode becomes a
    status, the same discipline every subprocess seam in this package
    follows."""
    argv = [sys.executable, "-m", "secure", *job.args]
    started_at = now_iso()
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
            timeout=job.timeout_seconds, shell=False,
        )
    except FileNotFoundError as exc:
        duration = time.monotonic() - started
        record_action(
            audit_trail, component="agent.supervisor", action=f"job {job.name}", argv=argv,
            cwd=str(cwd) if cwd else "", target=job.name, mutating=False, started_at=started_at,
            exit_code=None, result_summary="could not launch", duration_seconds=duration,
        )
        return JobResult(job.name, "error", None, f"could not launch: {exc}", duration)
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - started
        record_action(
            audit_trail, component="agent.supervisor", action=f"job {job.name}", argv=argv,
            cwd=str(cwd) if cwd else "", target=job.name, mutating=False, started_at=started_at,
            exit_code=None, result_summary=f"timed out after {job.timeout_seconds}s",
            duration_seconds=duration,
        )
        return JobResult(job.name, "timeout", None, f"timed out after {job.timeout_seconds}s", duration)

    duration = time.monotonic() - started
    record_action(
        audit_trail, component="agent.supervisor", action=f"job {job.name}", argv=argv,
        cwd=str(cwd) if cwd else "", target=job.name, mutating=False, started_at=started_at,
        exit_code=proc.returncode, result_summary=f"exit {proc.returncode}", duration_seconds=duration,
    )

    output = _truncate((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))
    if proc.returncode == 0:
        return JobResult(job.name, "ok", 0, output, duration)
    if job.nonzero_is_finding and proc.returncode == 1:
        return JobResult(job.name, "finding", 1, output, duration)
    return JobResult(job.name, "fail", proc.returncode, output, duration)


def run_supervisor_cycle(
    cfg: AppConfig,
    *,
    jobs: "Optional[tuple[SupervisorJob, ...]]" = None,
    cwd: "Optional[Path]" = None,
    audit_trail: "Optional[list]" = None,
) -> SupervisorCycle:
    """One supervision pass. Observes only.

    This function contains no branch that starts a repair. It cannot
    reach DIAGNOSING, REPAIRING_IN_SANDBOX, VERIFYING, or
    AWAITING_APPROVAL, because it never does any of those things — see
    reachable_states().
    """
    jobs = jobs if jobs is not None else DEFAULT_JOBS
    validate_jobs(jobs)

    started_at = now_iso()
    results = tuple(run_job(job, cwd=cwd, audit_trail=audit_trail) for job in jobs)
    state = STATE_HEALTHY if all(r.status in ("ok", "finding") for r in results) else STATE_FAILED
    return SupervisorCycle(
        started_at=started_at, completed_at=now_iso(), state=state, results=results
    )


# ---------------------------------------------------------------------
# launchd plist GENERATION (text only — nothing here installs anything)
# ---------------------------------------------------------------------

DEFAULT_LABEL = "com.securemb.supervisor"
DEFAULT_INTERVAL_SECONDS = 3600
_MIN_INTERVAL_SECONDS = 900


def launchd_plist_path(label: str = DEFAULT_LABEL) -> Path:
    """Where such a job WOULD live. Returning a path is not creating
    one; nothing in this module writes to it."""
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def build_launchd_plist(
    cfg: AppConfig,
    *,
    label: str = DEFAULT_LABEL,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    working_directory: "Optional[Path]" = None,
    python_executable: "Optional[str]" = None,
) -> str:
    """Generates the exact plist text a human would install.

    Conservative by construction: `StartInterval` is floored at 15
    minutes, `RunAtLoad` is false (so installing the job does not
    immediately run it), `Nice` is positive (the supervisor yields to
    everything the operator is actually doing), and the program is a
    fixed argv into Secure's own read-only supervisor command.
    """
    if interval_seconds < _MIN_INTERVAL_SECONDS:
        interval_seconds = _MIN_INTERVAL_SECONDS

    python_executable = python_executable or sys.executable
    workdir = str(working_directory) if working_directory else str(Path.cwd())
    log_dir = cfg.app_dir_path() / "logs"

    program_args = "".join(
        f"        <string>{arg}</string>\n"
        for arg in (python_executable, "-m", "secure", "agent", "supervise")
    )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "    <key>Label</key>\n"
        f"    <string>{label}</string>\n"
        "    <key>ProgramArguments</key>\n"
        "    <array>\n"
        f"{program_args}"
        "    </array>\n"
        "    <key>WorkingDirectory</key>\n"
        f"    <string>{workdir}</string>\n"
        "    <key>StartInterval</key>\n"
        f"    <integer>{interval_seconds}</integer>\n"
        "    <key>RunAtLoad</key>\n"
        "    <false/>\n"
        "    <key>Nice</key>\n"
        "    <integer>10</integer>\n"
        "    <key>ProcessType</key>\n"
        "    <string>Background</string>\n"
        "    <key>StandardOutPath</key>\n"
        f"    <string>{log_dir / 'supervisor.out.log'}</string>\n"
        "    <key>StandardErrorPath</key>\n"
        f"    <string>{log_dir / 'supervisor.err.log'}</string>\n"
        "</dict>\n"
        "</plist>\n"
    )


def installation_status(label: str = DEFAULT_LABEL) -> "tuple[bool, str]":
    """Read-only: does such a plist file already exist? Checked with a
    filesystem stat, never by asking the service-management tool,
    because this module does not invoke it."""
    path = launchd_plist_path(label)
    if path.is_file():
        return True, f"a plist already exists at {path}"
    return False, f"no plist at {path} — the supervisor is not installed"


def installation_instructions(label: str = DEFAULT_LABEL) -> str:
    """The commands a human runs THEMSELVES after approving. Written as
    prose deliberately: this project does not ship a code path that
    executes them."""
    path = launchd_plist_path(label)
    return (
        f"1. Save the generated plist to {path}\n"
        f"2. Load it with the macOS service-management tool, targeting {path}\n"
        "\n"
        "Secure does not perform either step. Installing a launchd job is a SYSTEM_CHANGE, "
        "and this project has no code that writes to LaunchAgents or invokes the "
        "service-management tool — the gate is enforced by absence, not by a flag."
    )


def propose_supervisor_installation(
    conn,
    cfg: AppConfig,
    *,
    label: str = DEFAULT_LABEL,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    working_directory: "Optional[Path]" = None,
):
    """Creates a PENDING change request describing the installation,
    classified SYSTEM_CHANGE, and returns it. Installs nothing.

    Reuses Phase 28's `propose_change()` and Phase 39's classifier
    unchanged. `notify=False` because Phase 41's sanitized notifier
    handles the email for consequential changes.
    """
    from secure.agent.classify import CLASS_SYSTEM_CHANGE, Classification
    from secure.ai.changes.workflow import propose_change
    from secure.storage.models import set_ai_change_request_classification

    plist = build_launchd_plist(
        cfg, label=label, interval_seconds=interval_seconds, working_directory=working_directory
    )
    already, status_detail = installation_status(label)

    classification = Classification(
        classification=CLASS_SYSTEM_CHANGE,
        reasons=(
            "installing a launchd job changes host service configuration",
            "the operator must perform the installation themselves — Secure ships no code that does it",
        ),
    )

    cr = propose_change(
        conn, cfg,
        title=f"Install the Secure background supervisor as a launchd job ({label})",
        proposed_change=(
            f"{classification.describe()}\n\n"
            f"Current state: {status_detail}\n\n"
            f"Proposed StartInterval: {max(interval_seconds, _MIN_INTERVAL_SECONDS)} seconds "
            f"(RunAtLoad false, Nice 10, ProcessType Background)\n\n"
            f"Steps for the operator:\n{installation_instructions(label)}\n\n"
            f"--- plist to be installed ---\n{plist}"
        ),
        reason=(
            "Phase 42 asks for lightweight periodic supervision using a standard macOS mechanism. "
            "The scheduling machinery is implemented and tested; only the installation itself is "
            "outstanding, and it is a SYSTEM_CHANGE requiring explicit human approval."
        ),
        affected_component=str(launchd_plist_path(label)),
        risks=(
            "Installing a launchd job means Secure's supervisor runs periodically without further "
            "prompting. The supervisor only observes — it runs bounded, read-only CLI commands and "
            "cannot start a repair, approve a change, or run the full regression suite. Approving "
            "this change request does NOT install anything: Secure has no code that writes to "
            "LaunchAgents or invokes the service-management tool. You install it yourself, and you "
            "remove it yourself.\n\n"
            + classification.describe()
        ),
        model_a_opinion="(no model was involved — this proposal is generated deterministically by secure/agent/supervisor.py)",
        model_b_opinion="(no model was involved)",
        notify=False,
    )
    set_ai_change_request_classification(conn, cr_id=cr.cr_id, classification=CLASS_SYSTEM_CHANGE)

    from secure.agent.center import build_change_request_view
    from secure.agent.notify import notify_if_consequential
    from secure.storage.models import find_ai_change_request, mark_ai_change_request_notified

    try:
        view = build_change_request_view(conn, cr.cr_id)
        if view is not None:
            status, _detail = notify_if_consequential(cfg, view)
            mark_ai_change_request_notified(
                conn, cr_id=cr.cr_id, notified_at=now_iso(), notify_status=status
            )
    except Exception:  # noqa: BLE001 — a notification problem never blocks a persisted proposal
        pass

    return find_ai_change_request(conn, cr.cr_id) or cr
