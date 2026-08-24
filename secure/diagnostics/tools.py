"""
diagnostics/tools.py — Phase 30 requirement 5 ("Claude Development
Impact", generalized): a generic external-process resource aggregate,
driven entirely by `cfg.dev_tool_process_patterns` (a comma-separated
list of substrings to match against running processes' command names —
"Claude" by default).

Deliberately generic, per this phase's own instruction ("keep Claude
monitoring optional and generic enough that other development tools
could later be monitored too") — nothing in this file's code mentions
Claude by name; the pattern comes entirely from config.

Explicitly bounded, per the same instruction's privacy limit: this
reads only `ps`'s own pid/rss/%cpu/command-name columns — never a full
command line (arguments), never open files, never network connections,
never environment variables. `comm` in `ps -axo pid,rss,pcpu,comm` is
the process's short command name, not its full invocation — the
process-level equivalent of "which programs are running and how much
they're using," not "what are they doing."
"""

from __future__ import annotations

from dataclasses import dataclass

from secure.diagnostics._shell import run


@dataclass
class DevToolUsage:
    pattern: str
    process_count: int
    total_cpu_percent: float
    total_rss_bytes: int


def _parse_patterns(raw: str) -> "list[str]":
    return [p.strip() for p in raw.split(",") if p.strip()]


def _parse_ps_output(text: str) -> "list[tuple[int, int, float, str]]":
    """Pure parser for `ps -axo pid,rss,pcpu,comm` output — returns
    (pid, rss_kb, cpu_percent, comm) tuples. `comm` is intentionally
    the LAST column (unbounded, may contain spaces if a command path
    does) so `split(None, 3)` never misparses it the way putting a
    variable-width column before a fixed one would.
    """
    lines = text.splitlines()
    if not lines:
        return []
    rows = []
    for line in lines[1:]:  # skip the header row
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        pid_str, rss_str, cpu_str, comm = parts
        try:
            pid = int(pid_str)
            rss_kb = int(rss_str)
            cpu_percent = float(cpu_str)
        except ValueError:
            continue
        rows.append((pid, rss_kb, cpu_percent, comm))
    return rows


def collect_dev_tool_usage(patterns_raw: str) -> "list[DevToolUsage]":
    """One aggregate per configured pattern. An empty `patterns_raw`
    (or a `ps` call that fails — e.g. not on macOS) returns an empty
    list, never a fabricated zero-usage row for a pattern that was
    never actually checked.
    """
    patterns = _parse_patterns(patterns_raw)
    if not patterns:
        return []

    result = run(["ps", "-axo", "pid,rss,pcpu,comm"], timeout=5.0)
    if not result.ok:
        return []

    rows = _parse_ps_output(result.stdout)

    usages = []
    for pattern in patterns:
        matching = [r for r in rows if pattern in r[3]]
        usages.append(DevToolUsage(
            pattern=pattern,
            process_count=len(matching),
            total_cpu_percent=sum(r[2] for r in matching),
            total_rss_bytes=sum(r[1] for r in matching) * 1024,
        ))
    return usages
