"""
secure/agent/runner.py — Phase 31: the ONLY place this package invokes
an external coding-agent tool. Fixed argv, never `shell=True`, cwd
pinned to an isolated git worktree (secure/agent/worktree.py), HOME
pinned to a throwaway per-run directory, stdin closed (non-interactive),
and a hard wall-clock timeout independent of the tool's own limits.

Tool choice: mini-SWE-agent only, per the governing instruction ("Do
not add Aider or OpenHands during Phase 31"). Secure owns policy,
isolation, evidence, verification, approval, and auditability; this
module's only job is constructing the exact command line and config
file that hand the coding-agent LOOP itself — reading files, deciding
what to change, running commands, writing a diff — entirely to
mini-SWE-agent. Nothing in this module parses, edits, or reasons about
source code.

Invocation shape (verified against mini-SWE-agent v2's own documented
CLI — https://mini-swe-agent.com/latest/usage/mini/):

    mini -y --exit-immediately -t "<task>" -c <generated_config.yaml> -o <transcript.traj.json>

`-y`/`--yolo` plus `--exit-immediately` is what makes this
non-interactive at all: without them `mini` prompts a human on every
action and again when it wants to finish. Combined with a closed
stdin, a run that exceeds its own step/cost limits stops cleanly with
`exit_status: "LimitsExceeded"` recorded in the trajectory instead of
blocking on a prompt mini's own interactive-agent code cannot show —
see InteractiveAgent._stdin_is_interactive() in mini-SWE-agent's own
source. That is the concrete mechanism behind "bounded retries and
stop on architectural ambiguity."

Ollama compatibility costs no new provider code: mini-SWE-agent's
model backend is litellm, and litellm's own Ollama chat provider is
selected with a `ollama/<model>` model name plus `api_base` in
`model_kwargs` — both sourced directly from the AppConfig fields
Phase 28 already added (`ollama_host`, `ollama_model`).

KNOWN LIMITATION (documented here on purpose, not glossed over):
Phase 31 does not implement OS-level network isolation (no container,
no network namespace — that is exactly what Docker/OpenHands would
add, and the governing instruction explicitly excludes both this
phase). Pointing the model backend at a local-only Ollama instance
means model INFERENCE makes no external network call, but a shell
command the agent itself chooses to run inside the worktree could
still reach the network if this host permits it. True network
sandboxing is deferred to a later phase — see docs/AGENT_FOUNDATION.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from secure.agent.audit import now_iso, record_action
from secure.agent.context import RepairContext, render_context_block
from secure.agent.policy import RepairCandidate
from secure.agent.worktree import RepairWorktree
from secure.config import AppConfig

MINI_CONFIG_FILENAME = "mini_config.yaml"
TRANSCRIPT_FILENAME = "transcript.traj.json"

_DEFAULT_PER_COMMAND_TIMEOUT = 60.0

_SYSTEM_TEMPLATE = (
    "You are a careful software maintenance engineer working inside an isolated git "
    "worktree. You can execute bash commands and edit files. Make the smallest change "
    "that fixes the described failure without breaking anything else. Do not modify "
    "tests unless the failure is itself in a test file. Do not modify configuration, "
    "database schema, or anything under secure/validate/, secure/ai/, or secure/agent/ "
    "— those enforce the rules you are being graded against and are off-limits. When "
    "you are done, finish with exactly: echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"
)

_INSTANCE_TEMPLATE = (
    "A deterministic check is currently failing.\n\n"
    "kind: {{task_kind}}\n"
    "reference: {{task_ref}}\n\n"
    "detail:\n{{task_detail}}\n\n"
    "Investigate the codebase, make the smallest correct change to fix this, and verify "
    "your fix. Then finish with exactly: echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"
)


class RunnerUnavailable(RuntimeError):
    """Raised when the configured tool binary can't be resolved at all
    — the same honest-unavailable convention every other optional
    external tool in this app already follows (never a crash, never a
    silent no-op)."""


@dataclass
class MiniRunResult:
    status: str  # "completed" | "timed_out" | "unavailable" | "error"
    returncode: "Optional[int]"
    exit_status: "Optional[str]"  # mini's own info.exit_status, e.g. "Submitted", "LimitsExceeded"
    submission: "Optional[str]"  # mini's own self-reported diff text — supplementary only, never trusted
    mini_version: "Optional[str]"
    instance_cost: "Optional[float]"
    transcript_path: "Optional[Path]"
    model_name: str
    error: "Optional[str]" = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    # Reproducibility fields (Phase 31 guardrail, explicit user
    # instruction): the exact argv this run was invoked with, the exact
    # YAML text handed to `mini -c`, and a sha256 of the raw transcript
    # file bytes actually read back — so a completed run's inputs can
    # be inspected/replayed later and a transcript altered on disk
    # after the fact is detectable. None/empty when the tool was never
    # actually invoked (status == "unavailable").
    argv: "Optional[list]" = None
    config_yaml: "Optional[str]" = None
    transcript_hash: "Optional[str]" = None


def resolve_tool_binary(cfg: AppConfig) -> "Optional[str]":
    """Empty-gate discipline identical to velociraptor_binary_resolved()
    — an explicit configured path wins, else fall back to resolving
    the bare tool name on PATH, else None (unavailable)."""
    if cfg.agent_tool_binary:
        return cfg.agent_tool_binary
    return shutil.which("mini")


def tool_available(cfg: AppConfig) -> bool:
    binary = resolve_tool_binary(cfg)
    return bool(binary) and (Path(binary).is_file() or shutil.which(binary) is not None)


def _model_spec(cfg: AppConfig) -> "tuple[str, dict]":
    """Returns (litellm model_name, model_kwargs). Ollama-only in Phase
    31 — cfg.ollama_host/ollama_model are Phase 28's own fields,
    reused unchanged."""
    model_name = f"ollama/{cfg.ollama_model}"
    model_kwargs = {"api_base": cfg.ollama_host} if cfg.ollama_host else {}
    return model_name, model_kwargs


def build_mini_config(cfg: AppConfig, worktree: RepairWorktree) -> dict:
    """The YAML config handed to `mini -c`. Every field here traces to
    an explicit AppConfig value or a fixed, reviewed template — never
    free-form text assembled from unreviewed sources."""
    model_name, model_kwargs = _model_spec(cfg)
    return {
        "agent": {
            "system_template": _SYSTEM_TEMPLATE,
            "instance_template": _INSTANCE_TEMPLATE,
            "step_limit": cfg.agent_step_limit,
            "cost_limit": 0,  # local model, no meaningful dollar cost to bound by
            "mode": "yolo",
            "confirm_exit": False,
        },
        "environment": {
            "environment_class": "local",
            "cwd": str(worktree.worktree_path),
            "timeout": _DEFAULT_PER_COMMAND_TIMEOUT,
        },
        "model": {
            "model_name": model_name,
            "model_kwargs": model_kwargs,
            "cost_tracking": "ignore_errors",
        },
    }


def write_mini_config(config: dict, worktree: RepairWorktree) -> Path:
    """Written to <run_dir>/mini_config.yaml — a sibling of `repo/`,
    deliberately NOT inside the worktree itself, so it never shows up
    as a stray file in the diff Secure later computes."""
    path = worktree.run_dir / MINI_CONFIG_FILENAME
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return path


def _build_task_text(candidate: RepairCandidate, *, context: "Optional[RepairContext]" = None) -> str:
    """Renders the {{task}} variable `mini -t` fills into
    instance_template — kept here (not left to mini's own Jinja
    rendering of our custom variables) so the exact text handed to the
    model is one plain string this module fully controls.

    `context` (Phase 33, optional, additive): when a caller supplies a
    secure.agent.context.RepairContext, its rendered block (bounded
    relevant files, recent history, policy excerpts, workspace note —
    see secure/agent/context.py) is appended after the failure detail.
    When None (the default — every pre-Phase-33 call site), the task
    text is byte-for-byte identical to before this phase."""
    text = (
        f"kind: {candidate.trigger_kind}\n"
        f"reference: {candidate.trigger_ref}\n\n"
        f"detail:\n{candidate.trigger_detail}\n\n"
        "Investigate the codebase, make the smallest correct change to fix this, and "
        "verify your fix. Then finish with exactly: echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"
    )
    if context is not None:
        block = render_context_block(context)
        if block:
            text = text + "\n\n" + block
    return text


def _read_transcript(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def hash_transcript(path: "Optional[Path]") -> "Optional[str]":
    """sha256 of the raw transcript file bytes — computed once, right
    after a run, and re-derivable later from the same file to detect
    whether it was altered on disk after the fact. None when there is
    no transcript file to hash."""
    if path is None or not path.is_file():
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def build_mini_argv(
    cfg: AppConfig, worktree: RepairWorktree, candidate: RepairCandidate, *, context: "Optional[RepairContext]" = None
) -> "Optional[list]":
    """The exact argv `mini` is/was invoked with, given the same
    (cfg, worktree, candidate, context) inputs — a pure function of
    those four things (config_path/transcript_path are always
    <run_dir>/... and the task text is a deterministic rendering of
    `candidate` plus whatever `context` was supplied), so
    secure/agent/orchestrator.py's resume_repair_run() can reconstruct
    exactly what a prior run used without needing to re-invoke
    anything. `context` is freshly rebuilt from the live checkout at
    reconstruction time (secure/agent/context.py's own
    build_repair_context()) rather than persisted separately — an
    honest approximation when repo history has advanced since the
    original run, the same discipline this function's docstring already
    applied to `cfg`. Returns None if the tool binary can't be resolved
    at all (nothing meaningful to reconstruct)."""
    binary = resolve_tool_binary(cfg)
    if not binary:
        return None
    config_path = worktree.run_dir / MINI_CONFIG_FILENAME
    transcript_path = worktree.run_dir / TRANSCRIPT_FILENAME
    task_text = _build_task_text(candidate, context=context)
    return [binary, "-y", "--exit-immediately", "-t", task_text, "-c", str(config_path), "-o", str(transcript_path)]


def run_mini_swe_agent(
    cfg: AppConfig,
    worktree: RepairWorktree,
    candidate: RepairCandidate,
    *,
    audit_trail: "Optional[list]" = None,
    context: "Optional[RepairContext]" = None,
) -> MiniRunResult:
    """Invokes `mini` exactly once against `worktree`, non-interactively,
    with a hard wall-clock timeout. Always returns a MiniRunResult —
    never raises for an ordinary unavailable/timeout/tool-error
    outcome; RunnerUnavailable is reserved for a caller that wants to
    check availability before even attempting a run (see
    secure/agent/orchestrator.py).

    `audit_trail` (Phase 31.5, optional, additive): when supplied by a
    caller with a real database connection (secure/agent/orchestrator.py),
    the exact argv actually invoked is recorded via
    secure/agent/audit.py's record_action() — with the `-t "<task
    text>"` prompt argument redacted/truncated by that module's own
    rules, never logged verbatim. This is the single highest-value
    audit site in the package: it is the only place this app ever
    invokes an external coding-agent tool capable of freely modifying
    files inside the worktree. When None (the default), behavior is
    identical to before this phase.

    `context` (Phase 33, optional, additive): a
    secure.agent.context.RepairContext the caller already built for
    `candidate` — passed straight through to build_mini_argv(). When
    None (the default), the task text is unchanged from before Phase
    33."""
    model_name, _ = _model_spec(cfg)
    binary = resolve_tool_binary(cfg)
    if not binary:
        return MiniRunResult(
            status="unavailable", returncode=None, exit_status=None, submission=None,
            mini_version=None, instance_cost=None, transcript_path=None, model_name=model_name,
            error="agent_tool_binary is not configured and 'mini' is not on PATH",
        )

    config = build_mini_config(cfg, worktree)
    config_yaml_text = yaml.safe_dump(config, sort_keys=False)
    config_path = write_mini_config(config, worktree)
    transcript_path = worktree.run_dir / TRANSCRIPT_FILENAME
    argv = build_mini_argv(cfg, worktree, candidate, context=context)

    # HOME pinned to the throwaway agent-home directory so mini's own
    # global config/state directory (global_config_dir) is never the
    # operator's real home — the same isolation goal
    # secure/agent/verify.py applies to the post-run pytest/validate
    # subprocess calls.
    env = dict(os.environ)
    env["HOME"] = str(worktree.agent_home_path)

    started_at = now_iso()
    started_mono = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(worktree.worktree_path),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=cfg.agent_timeout_seconds,
            shell=False,
        )
    except FileNotFoundError as exc:
        record_action(
            audit_trail, component="agent.runner", action="mini-swe-agent invocation", argv=argv,
            cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=True,
            started_at=started_at, exit_code=None, result_summary="could not launch binary",
            duration_seconds=time.monotonic() - started_mono,
        )
        return MiniRunResult(
            status="unavailable", returncode=None, exit_status=None, submission=None,
            mini_version=None, instance_cost=None, transcript_path=None, model_name=model_name,
            error=f"could not launch {binary!r}: {exc}",
        )
    except subprocess.TimeoutExpired:
        record_action(
            audit_trail, component="agent.runner", action="mini-swe-agent invocation", argv=argv,
            cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=True,
            started_at=started_at, exit_code=None,
            result_summary=f"timed out after {cfg.agent_timeout_seconds}s",
            duration_seconds=time.monotonic() - started_mono,
        )
        transcript = _read_transcript(transcript_path)
        info = transcript.get("info", {}) if transcript else {}
        resolved_transcript_path = transcript_path if transcript_path.is_file() else None
        return MiniRunResult(
            status="timed_out", returncode=None,
            exit_status=info.get("exit_status", "TimedOut"),
            submission=info.get("submission"),
            mini_version=info.get("mini_version"),
            instance_cost=(info.get("model_stats") or {}).get("instance_cost"),
            transcript_path=resolved_transcript_path,
            model_name=model_name,
            error=f"mini did not finish within {cfg.agent_timeout_seconds}s",
            argv=argv, config_yaml=config_yaml_text, transcript_hash=hash_transcript(resolved_transcript_path),
        )

    record_action(
        audit_trail, component="agent.runner", action="mini-swe-agent invocation", argv=argv,
        cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=True,
        started_at=started_at, exit_code=proc.returncode, result_summary=f"exit {proc.returncode}",
        duration_seconds=time.monotonic() - started_mono,
    )

    transcript = _read_transcript(transcript_path)
    info = transcript.get("info", {}) if transcript else {}
    resolved_transcript_path = transcript_path if transcript_path.is_file() else None

    return MiniRunResult(
        status="completed",
        returncode=proc.returncode,
        exit_status=info.get("exit_status"),
        submission=info.get("submission"),
        mini_version=info.get("mini_version"),
        instance_cost=(info.get("model_stats") or {}).get("instance_cost"),
        transcript_path=resolved_transcript_path,
        model_name=model_name,
        error=None if proc.returncode == 0 else f"mini exited {proc.returncode}",
        stdout_tail=proc.stdout[-4000:],
        stderr_tail=proc.stderr[-4000:],
        argv=argv, config_yaml=config_yaml_text, transcript_hash=hash_transcript(resolved_transcript_path),
    )
