"""
cli/diagnostics.py — `secure diagnostics ...` (Phase 30: Performance &
Diagnostics). Ordinary, always-on behavior — no enable/disable flag,
no "Developer Mode" (an earlier draft of this phase had one; the
approved design removed it — see PROJECT_NOTES.md's Phase 30 entry).

Every command here is read-only and diagnostic-only: nothing in this
file writes to any severity/anomaly/correlation/explanation table, and
nothing here can change what any scanner detects (see
secure/diagnostics/instrument.py's own docstring for the structural
reason why not).
"""

from __future__ import annotations

import argparse

from secure.diagnostics.budgets import evaluate_budgets
from secure.diagnostics.hardware import collect_hardware_specs
from secure.diagnostics.integrations_health import collect_integration_health
from secure.diagnostics.milestones import previous_db_size_bytes, record_milestone
from secure.diagnostics.report import write_report
from secure.diagnostics.self_usage import collect_self_usage
from secure.diagnostics.system import collect_system_health
from secure.diagnostics.tools import collect_dev_tool_usage
from secure.storage.database import Database
from secure.storage.models import list_perf_milestones, list_perf_module_runs_for_group, list_recent_perf_module_runs
from secure.cli import _bootstrap, logger


def _fmt_bytes(n) -> str:
    if n is None:
        return "(unavailable)"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024:
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}{unit}"
        value /= 1024
    return f"{value:.1f}PB"


def cmd_diagnostics_performance(args: argparse.Namespace) -> int:
    """Concise one-screen summary — system + Secure + any budget
    warnings. Detailed views: `secure diagnostics system/modules/tools`.
    """
    cfg = _bootstrap()

    hardware = collect_hardware_specs()
    system_health = collect_system_health(disk_path=cfg.app_dir_path())

    with Database(cfg.database_path()) as db:
        self_usage = collect_self_usage(db.conn, db_path=cfg.database_path(), log_path=cfg.log_path())
        recent_runs = list_recent_perf_module_runs(db.conn, limit=20)
        warnings = evaluate_budgets(
            cfg, self_usage=self_usage, system_health=system_health, recent_module_runs=recent_runs,
            previous_db_size_bytes=previous_db_size_bytes(db.conn),
        )

    print(f"Secure {hardware.secure_version} — {hardware.mac_model or 'unknown Mac'} "
          f"({hardware.architecture}), macOS {hardware.macos_version or 'unknown'}")
    print(
        f"Load avg: {system_health.load_avg_1m or '?'} / {system_health.load_avg_5m or '?'} / "
        f"{system_health.load_avg_15m or '?'}   Disk free: {_fmt_bytes(system_health.disk_free_bytes)}"
    )
    print(
        f"Secure: {_fmt_bytes(self_usage.peak_rss_bytes)} peak RSS, "
        f"{self_usage.cpu_time_seconds:.2f}s CPU time, db {_fmt_bytes(self_usage.db_size_bytes)}, "
        f"{self_usage.events_count} events, {self_usage.findings_count} findings"
    )
    print()

    if warnings:
        print(f"WARNINGS ({len(warnings)}) — diagnostics, not security alerts:")
        for w in warnings:
            print(f"  [{w.kind}] {w.message}")
    else:
        print("No configured performance budget exceeded.")

    print()
    print(
        "Details: secure diagnostics system | secure diagnostics modules | "
        "secure diagnostics tools | secure diagnostics history"
    )

    logger.info(
        "Displayed performance diagnostics",
        extra={"event": "diagnostics_performance", "component": "cli"},
    )
    return 0


def cmd_diagnostics_system(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    hardware = collect_hardware_specs()
    system_health = collect_system_health(disk_path=cfg.app_dir_path())

    print("Hardware:")
    print(f"  Mac model:      {hardware.mac_model or '(unavailable)'}")
    print(f"  Architecture:   {hardware.architecture}")
    print(f"  CPU:            {hardware.cpu_brand or '(unavailable)'}")
    print(f"  Cores:          {hardware.logical_cores or '?'} logical / {hardware.physical_cores or '?'} physical")
    print(f"  RAM:            {_fmt_bytes(hardware.total_ram_bytes)}")
    print(f"  macOS:          {hardware.macos_version or '(unavailable)'}")
    print(f"  Python:         {hardware.python_version}")
    print(f"  Secure version: {hardware.secure_version}")
    print()
    print("Live health:")
    print(
        f"  Load average:   {system_health.load_avg_1m or '?'} / "
        f"{system_health.load_avg_5m or '?'} / {system_health.load_avg_15m or '?'} (1/5/15m)"
    )
    print(f"  Memory free:    {_fmt_bytes(system_health.mem_free_bytes)}")
    print(f"  Memory total:   {_fmt_bytes(system_health.mem_total_bytes)}")
    print(f"  Memory pressure:{system_health.mem_pressure or ' (unavailable)'}")
    print(
        f"  Swap:           {_fmt_bytes(system_health.swap_used_bytes)} used / "
        f"{_fmt_bytes(system_health.swap_total_bytes)} total"
    )
    print(f"  Disk free:      {_fmt_bytes(system_health.disk_free_bytes)} of {_fmt_bytes(system_health.disk_total_bytes)}")
    print(f"  Battery/AC:     {system_health.battery_state or '(unavailable)'}")
    print(f"  Thermal:        {system_health.thermal_pressure or '(unavailable)'}")

    all_unavailable = sorted(set(hardware.unavailable) | set(system_health.unavailable))
    if all_unavailable:
        print()
        print(f"Unavailable on this platform (never fabricated): {', '.join(all_unavailable)}")

    logger.info(
        "Displayed system diagnostics",
        extra={"event": "diagnostics_system", "component": "cli"},
    )
    return 0


def cmd_diagnostics_modules(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        runs = list_recent_perf_module_runs(db.conn, limit=args.limit, module=args.module)

    if not runs:
        print("No instrumented scan/integration runs recorded yet. Run: secure run-all")
        return 0

    if args.sort_by_duration:
        runs = sorted(runs, key=lambda r: r.duration_seconds, reverse=True)

    print(f"{'Module':<16} {'Op':<8} {'Duration':>10} {'CPU':>8} {'Obs':>6} {'Find':>6}  Completed")
    for r in runs:
        cpu = f"{r.cpu_time_seconds:.3f}s" if r.cpu_time_seconds is not None else "?"
        obs = r.observations_processed if r.observations_processed is not None else "?"
        find = r.findings_produced if r.findings_produced is not None else "?"
        error_note = f"  ERROR: {r.error}" if r.error else ""
        print(
            f"{r.module:<16} {r.operation:<8} {r.duration_seconds:>9.3f}s {cpu:>8} "
            f"{str(obs):>6} {str(find):>6}  {r.completed_at}{error_note}"
        )

    logger.info(
        "Displayed module performance diagnostics",
        extra={"event": "diagnostics_modules", "component": "cli"},
    )
    return 0


def cmd_diagnostics_tools(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    integration_health = collect_integration_health(cfg)
    dev_tool_usage = collect_dev_tool_usage(cfg.dev_tool_process_patterns)

    print("External integrations:")
    for name, health in integration_health:
        version_note = f" (v{health.tool_version})" if health.tool_version else ""
        print(f"  {name:<14} {health.status.upper():<12}{version_note} — {health.detail}")

    print()
    print("Development tools (process-level OS observation — command name, CPU%, RSS only):")
    if not dev_tool_usage:
        print(f"  No patterns configured or `ps` unavailable (dev_tool_process_patterns={cfg.dev_tool_process_patterns!r}).")
    else:
        for usage in dev_tool_usage:
            if usage.process_count == 0:
                print(f"  {usage.pattern:<14} not currently running")
            else:
                print(
                    f"  {usage.pattern:<14} {usage.process_count} process(es), "
                    f"{usage.total_cpu_percent:.1f}% CPU, {_fmt_bytes(usage.total_rss_bytes)} RSS"
                )

    logger.info(
        "Displayed integrations/tools diagnostics",
        extra={"event": "diagnostics_tools", "component": "cli"},
    )
    return 0


def cmd_diagnostics_history(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        milestones = list_perf_milestones(db.conn, limit=args.limit)

    if not milestones:
        print('No milestones recorded yet. Run: secure diagnostics milestone record "<label>"')
        return 0

    for m in milestones:
        duration_note = f"{m.run_all_duration_seconds:.1f}s" if m.run_all_duration_seconds is not None else "?"
        print(f"{m.recorded_at}  [{m.label}] (Secure {m.secure_version})")
        print(
            f"    run-all: {duration_note}   peak RSS: {_fmt_bytes(m.secure_peak_rss_bytes)}   "
            f"db size: {_fmt_bytes(m.db_size_bytes)}"
        )
        if m.notes:
            print(f"    {m.notes}")

    return 0


def cmd_diagnostics_milestone_record(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        self_usage = collect_self_usage(db.conn, db_path=cfg.database_path(), log_path=cfg.log_path())

        run_all_duration_seconds = None
        latest_run = list_recent_perf_module_runs(db.conn, limit=1)
        if latest_run:
            group_runs = list_perf_module_runs_for_group(db.conn, latest_run[0].run_group_id)
            if group_runs:
                run_all_duration_seconds = sum(r.duration_seconds for r in group_runs)

        new_id = record_milestone(
            db.conn,
            label=args.label,
            self_usage=self_usage,
            run_all_duration_seconds=run_all_duration_seconds,
            notes=args.notes or "",
        )

    print(f"Recorded milestone #{new_id}: {args.label}")
    if run_all_duration_seconds is not None:
        print(f"  (using the most recent instrumented run's total duration: {run_all_duration_seconds:.1f}s)")
    else:
        print("  (no instrumented run found yet — run_all_duration_seconds left blank; run `secure run-all` first)")

    logger.info(
        "Recorded a performance milestone",
        extra={"event": "diagnostics_milestone_record", "component": "cli"},
    )
    return 0


def cmd_diagnostics_report(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    from pathlib import Path

    output_dir = Path(args.output_dir) if args.output_dir else None

    with Database(cfg.database_path()) as db:
        md_path, json_path = write_report(db.conn, cfg, output_dir=output_dir, write_json=not args.no_json)

    print(f"Wrote {md_path}")
    if json_path:
        print(f"Wrote {json_path}")

    logger.info(
        "Generated a performance diagnostics report",
        extra={"event": "diagnostics_report", "component": "cli"},
    )
    return 0
