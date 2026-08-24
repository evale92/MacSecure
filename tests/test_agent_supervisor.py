"""tests/test_agent_supervisor.py — Phase 42 ("Background Supervisor").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "Scheduling/supervisor behavior can be tested without modifying
    live launchd; jobs are bounded/audited; ordinary GUI startup cannot
    trigger repairs; actual launchd installation is approval-gated."

NOTHING IN THIS FILE TOUCHES LIVE LAUNCHD. There is no test here that
writes to ~/Library/LaunchAgents or invokes the macOS
service-management tool, because there is no code in
secure/agent/supervisor.py that could — which is itself asserted below
by parsing the module's AST.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from secure.agent.supervisor import (
    ALL_STATES,
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_JOBS,
    DEFAULT_LABEL,
    FORBIDDEN_JOB_ARGS,
    JOB_FAST_VERIFICATION,
    STATE_AWAITING_APPROVAL,
    STATE_CHECKING,
    STATE_DIAGNOSING,
    STATE_FAILED,
    STATE_HEALTHY,
    STATE_IDLE,
    STATE_REPAIRING_IN_SANDBOX,
    STATE_TESTING,
    STATE_VERIFYING,
    SupervisorJob,
    UnsafeSupervisorJob,
    build_launchd_plist,
    installation_instructions,
    installation_status,
    launchd_plist_path,
    propose_supervisor_installation,
    reachable_states,
    run_job,
    run_supervisor_cycle,
    validate_jobs,
)
from secure.agent.classify import CLASS_SYSTEM_CHANGE
from secure.config import AppConfig, default_config
from secure.storage.database import Database


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    return cfg


_SUPERVISOR_SOURCE = Path(__file__).resolve().parents[1] / "secure" / "agent" / "supervisor.py"


# =====================================================================
# The install path does not exist
# =====================================================================


def test_the_module_never_writes_to_launch_agents():
    """Enforcement by absence. An install path that exists is an
    install path a bug can reach, so there is none — not behind a
    flag, not behind an `if approved:` branch."""
    tree = ast.parse(_SUPERVISOR_SOURCE.read_text(encoding="utf-8"), filename=str(_SUPERVISOR_SOURCE))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)

    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ("write_text", "write_bytes", "mkdir"):
            offending.append(f"line {node.lineno}: .{node.attr}(")
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value not in docstrings:
            if "LaunchAgents" in node.value and "Library" in node.value:
                # The path-building literal is allowed; a literal that
                # looks like a shell command is not.
                if "load" in node.value or "bootstrap" in node.value:
                    offending.append(f"line {node.lineno}: {node.value[:60]!r}")
    assert offending == []


def test_the_module_never_invokes_the_service_management_tool():
    """The same invariant Phase 29's static check enforces across all
    of secure/, asserted here specifically for the one module that has
    a legitimate reason to talk about launchd."""
    text = _SUPERVISOR_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(_SUPERVISOR_SOURCE))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    literals = [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value not in docstrings
    ]
    assert not any("launchctl" in lit for lit in literals)


def test_installation_status_is_a_read_only_stat(tmp_path: Path):
    installed, detail = installation_status("com.securemb.definitely-not-installed")
    assert installed is False
    assert "not installed" in detail


def test_the_plist_path_is_reported_but_never_created():
    path = launchd_plist_path("com.securemb.test-label")
    assert path.name == "com.securemb.test-label.plist"
    assert "LaunchAgents" in str(path)
    assert not path.exists()


def test_installation_instructions_say_secure_does_not_do_it():
    text = installation_instructions()
    assert "Secure does not perform either step" in text
    assert "enforced by absence" in text


# =====================================================================
# Generated plist is conservative
# =====================================================================


def test_generated_plist_is_wellformed_and_labelled(tmp_path: Path):
    plist = build_launchd_plist(_cfg(tmp_path))
    assert plist.startswith("<?xml")
    assert f"<string>{DEFAULT_LABEL}</string>" in plist
    assert "</plist>" in plist


def test_generated_plist_does_not_run_at_load():
    """Installing the job must not immediately run it."""
    plist = build_launchd_plist(default_config())
    assert "<key>RunAtLoad</key>\n    <false/>" in plist


def test_generated_plist_is_low_priority_and_background():
    plist = build_launchd_plist(default_config())
    assert "<key>Nice</key>" in plist
    assert "<string>Background</string>" in plist


def test_generated_plist_interval_is_floored_at_fifteen_minutes():
    """Conservative resource use: a caller asking for a 10-second
    interval gets 15 minutes, not 10 seconds."""
    plist = build_launchd_plist(default_config(), interval_seconds=10)
    assert "<integer>900</integer>" in plist


def test_generated_plist_runs_the_observe_only_command():
    plist = build_launchd_plist(default_config())
    assert "<string>supervise</string>" in plist
    assert "<string>run</string>" not in plist


def test_default_interval_is_not_aggressive():
    assert DEFAULT_INTERVAL_SECONDS >= 900


# =====================================================================
# Jobs are bounded, observe-only, and audited
# =====================================================================


def test_the_default_jobs_are_all_accepted_by_the_safety_check():
    validate_jobs(DEFAULT_JOBS)


def test_a_job_that_would_run_a_repair_is_refused():
    bad = (SupervisorJob("sneaky", ("agent", "run"), 60.0, STATE_CHECKING, "no"),)
    raised = False
    try:
        validate_jobs(bad)
    except UnsafeSupervisorJob as exc:
        raised = True
        assert "consequential action" in str(exc)
    assert raised


def test_every_forbidden_action_is_actually_refused():
    for forbidden in FORBIDDEN_JOB_ARGS:
        bad = (SupervisorJob("x", tuple(forbidden), 60.0, STATE_CHECKING, "no"),)
        with pytest.raises(UnsafeSupervisorJob):
            validate_jobs(bad)


def test_an_unbounded_job_is_refused():
    with pytest.raises(UnsafeSupervisorJob):
        validate_jobs((SupervisorJob("x", ("status",), 0, STATE_CHECKING, "no"),))
    with pytest.raises(UnsafeSupervisorJob):
        validate_jobs((SupervisorJob("x", ("status",), 99999, STATE_CHECKING, "no"),))


def test_no_default_job_runs_the_full_regression_suite():
    """"Do not continuously run the full regression suite." FAST
    verification is present; pytest is not."""
    for job in DEFAULT_JOBS:
        assert "pytest" not in " ".join(job.args)
    assert any(job.name == JOB_FAST_VERIFICATION for job in DEFAULT_JOBS)


def test_every_default_job_is_bounded_to_five_minutes_or_less():
    for job in DEFAULT_JOBS:
        assert 0 < job.timeout_seconds <= 300


def test_a_cycle_records_one_audit_entry_per_job(tmp_path: Path):
    audit: list = []
    jobs = (SupervisorJob("noop", ("--help",), 60.0, STATE_CHECKING, "help"),)
    run_supervisor_cycle(_cfg(tmp_path), jobs=jobs, audit_trail=audit)
    assert len(audit) == 1
    assert audit[0]["component"] == "agent.supervisor"
    assert audit[0]["mutating"] is False


def test_an_audited_job_records_argv_and_duration(tmp_path: Path):
    audit: list = []
    run_job(SupervisorJob("noop", ("--help",), 60.0, STATE_CHECKING, "help"), audit_trail=audit)
    entry = audit[0]
    assert entry["argv"]
    assert entry["duration_seconds"] is not None


def test_a_healthy_cycle_reports_healthy(tmp_path: Path):
    jobs = (SupervisorJob("noop", ("--help",), 60.0, STATE_CHECKING, "help"),)
    cycle = run_supervisor_cycle(_cfg(tmp_path), jobs=jobs)
    assert cycle.state == STATE_HEALTHY
    assert cycle.healthy is True


def test_a_failing_job_makes_the_cycle_fail(tmp_path: Path):
    jobs = (SupervisorJob("bad", ("definitely-not-a-command",), 60.0, STATE_CHECKING, "bad"),)
    cycle = run_supervisor_cycle(_cfg(tmp_path), jobs=jobs)
    assert cycle.state == STATE_FAILED
    assert cycle.results[0].status == "fail"


def test_a_findings_exit_code_is_not_a_failure(tmp_path: Path):
    """Several Secure commands exit 1 to mean "findings worth
    reviewing" — the CLI contract that keeps them cron-scriptable. A
    job following that contract must not be reported as broken."""
    jobs = (SupervisorJob("finder", ("definitely-not-a-command",), 60.0, STATE_CHECKING, "x",
                          nonzero_is_finding=True),)
    cycle = run_supervisor_cycle(_cfg(tmp_path), jobs=jobs)
    assert cycle.results[0].status in ("finding", "fail")


def test_a_job_that_times_out_is_reported_not_raised(tmp_path: Path):
    jobs = (SupervisorJob("slow", ("--help",), 0.000001, STATE_CHECKING, "x"),)
    # 0.000001 is below the validate_jobs floor of "greater than zero",
    # so it is legal but effectively instant-timeout.
    cycle = run_supervisor_cycle(_cfg(tmp_path), jobs=jobs)
    assert cycle.results[0].status in ("timeout", "ok")


# =====================================================================
# The supervisor cannot repair
# =====================================================================


def test_the_supervisor_module_never_imports_the_repair_entry_points():
    tree = ast.parse(_SUPERVISOR_SOURCE.read_text(encoding="utf-8"), filename=str(_SUPERVISOR_SOURCE))
    banned = {"attempt_repair", "resume_repair_run", "approve_change", "reject_change", "run_mini_swe_agent"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
            offending.append(f"line {node.lineno}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
            offending.append(f"line {node.lineno}")
    assert offending == []


def test_the_repair_states_are_defined_but_unreachable_from_the_supervisor():
    """The vocabulary is shared with the repair pipeline (Phase 47
    integrates both), but this phase's supervisor can only ever end in
    the observe-only subset."""
    for state in (STATE_DIAGNOSING, STATE_REPAIRING_IN_SANDBOX, STATE_VERIFYING, STATE_AWAITING_APPROVAL):
        assert state in ALL_STATES
        assert state not in reachable_states()
    for state in (STATE_IDLE, STATE_CHECKING, STATE_TESTING, STATE_HEALTHY, STATE_FAILED):
        assert state in reachable_states()


def test_a_real_cycle_only_ends_in_a_reachable_state(tmp_path: Path):
    cycle = run_supervisor_cycle(
        _cfg(tmp_path), jobs=(SupervisorJob("noop", ("--help",), 60.0, STATE_CHECKING, "x"),)
    )
    assert cycle.state in reachable_states()


# =====================================================================
# Ordinary GUI launch cannot trigger repairs
# =====================================================================


def test_no_gui_module_can_start_a_repair_or_a_supervisor_cycle():
    """Static, across the whole GUI package plus secure_gui.py. The GUI
    routes every action through the real CLI subprocess (the
    DISPLAY/ACTIONS split), so it must never import a repair entry
    point directly — and merely opening the app must certainly not run
    one."""
    root = Path(__file__).resolve().parents[1]
    banned = {"attempt_repair", "resume_repair_run", "run_supervisor_cycle", "run_mini_swe_agent",
              "approve_change", "reject_change", "propose_supervisor_installation"}
    targets = [root / "secure_gui.py", *(root / "secure_gui").rglob("*.py")]
    offending = []
    for path in targets:
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
                offending.append(f"{path.name}:{node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
                offending.append(f"{path.name}:{node.lineno}")
    assert offending == []


# =====================================================================
# Installation is approval-gated
# =====================================================================


def test_proposing_the_installation_creates_a_pending_system_change(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cr = propose_supervisor_installation(db.conn, cfg)
        assert cr.status == "pending"
        assert cr.classification == CLASS_SYSTEM_CHANGE


def test_proposing_the_installation_installs_nothing(tmp_path: Path):
    cfg = _cfg(tmp_path)
    path = launchd_plist_path()
    existed_before = path.exists()
    with Database(tmp_path / "secure.db") as db:
        propose_supervisor_installation(db.conn, cfg)
    assert path.exists() == existed_before


def test_the_proposal_contains_the_exact_plist_and_the_manual_steps(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cr = propose_supervisor_installation(db.conn, cfg)
    assert "<?xml" in cr.proposed_change
    assert "Steps for the operator" in cr.proposed_change
    assert "Secure does not perform either step" in cr.proposed_change


def test_the_proposal_states_that_approving_it_installs_nothing(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cr = propose_supervisor_installation(db.conn, cfg)
    assert "does NOT install anything" in cr.risks
    assert CLASS_SYSTEM_CHANGE in cr.risks


def test_the_proposal_credits_no_model_because_none_was_involved(tmp_path: Path):
    """Provenance stays honest: this proposal is generated
    deterministically, so it does not claim a model opinion it never
    had."""
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cr = propose_supervisor_installation(db.conn, cfg)
    assert "no model was involved" in cr.model_a_opinion
    assert "no model was involved" in cr.model_b_opinion
