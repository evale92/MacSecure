"""
diagnostics/report.py — Phase 30 requirement 9: a sanitized performance/
diagnostics report, reusing secure/validate/report.py's own
Markdown-plus-optional-JSON dual-format pattern (same "pure formatting
only, no DB writes, no interpretation logic" separation that module's
own docstring establishes).

Sanitization: this report is built entirely from already-collected
diagnostic measurements (hardware/system/self-usage/module-timing/
integration-health/budget-warning objects) — it never reads
`AppConfig` fields directly, so there is no raw config dict to
accidentally leak a secret from. The one place a secret COULD appear
is via `dev_tool_process_patterns`/threshold values, which are plain
non-secret tuning numbers/substrings, never credentials — `_SAFE
_CONFIG_FIELDS` documents this decision explicitly rather than leaving
it implicit.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure import __version__ as SECURE_VERSION
from secure.config import AppConfig
from secure.diagnostics.budgets import PerfWarning, evaluate_budgets
from secure.diagnostics.hardware import HardwareSpecs, collect_hardware_specs
from secure.diagnostics.integrations_health import collect_integration_health
from secure.diagnostics.self_usage import SecureSelfUsage, collect_self_usage
from secure.diagnostics.system import SystemHealth, collect_system_health
from secure.storage.models import list_recent_perf_module_runs
from secure.storage.models.perf import PerfModuleRunRecord

_DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent.parent / "docs" / "generated"

# Every config field this report is willing to surface. Deliberately an
# allowlist, not a denylist — a new secret field added to AppConfig
# later is excluded by default, not accidentally included.
_SAFE_CONFIG_FIELDS = ("dev_tool_process_patterns",)


def _fmt_bytes(n: "Optional[int]") -> str:
    if n is None:
        return "(unavailable)"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def generate_markdown_report(
    hardware: HardwareSpecs,
    system_health: SystemHealth,
    self_usage: SecureSelfUsage,
    module_runs: "list[PerfModuleRunRecord]",
    integration_health: "list[tuple[str, object]]",
    warnings: "list[PerfWarning]",
) -> str:
    lines: "list[str]" = []
    lines.append("# Secure — Performance & Diagnostics Report")
    lines.append("")
    lines.append(f"- **Secure version:** {SECURE_VERSION}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    lines.append("## System")
    lines.append("")
    lines.append(f"- Mac model: {hardware.mac_model or '(unavailable)'}")
    lines.append(f"- Architecture: {hardware.architecture}")
    lines.append(f"- CPU: {hardware.cpu_brand or '(unavailable)'}")
    lines.append(
        f"- Cores: {hardware.logical_cores or '?'} logical / "
        f"{hardware.physical_cores or '?'} physical"
    )
    lines.append(f"- RAM: {_fmt_bytes(hardware.total_ram_bytes)}")
    lines.append(f"- macOS: {hardware.macos_version or '(unavailable)'}")
    lines.append(f"- Python: {hardware.python_version}")
    lines.append(
        f"- Load average (1/5/15m): "
        f"{system_health.load_avg_1m or '?'} / {system_health.load_avg_5m or '?'} / "
        f"{system_health.load_avg_15m or '?'}"
    )
    lines.append(f"- Memory free: {_fmt_bytes(system_health.mem_free_bytes)}")
    lines.append(f"- Disk free: {_fmt_bytes(system_health.disk_free_bytes)}")
    lines.append(f"- Battery/AC: {system_health.battery_state or '(unavailable)'}")
    lines.append(f"- Thermal pressure: {system_health.thermal_pressure or '(unavailable)'}")
    if hardware.unavailable or system_health.unavailable:
        lines.append("")
        lines.append(
            "Unavailable metrics (never fabricated — genuinely could not be measured "
            "on this platform): "
            + ", ".join(sorted(set(hardware.unavailable) | set(system_health.unavailable)))
        )
    lines.append("")

    lines.append("## Secure")
    lines.append("")
    lines.append(f"- PID: {self_usage.pid}")
    lines.append(f"- CPU time (this process, so far): {self_usage.cpu_time_seconds:.2f}s")
    lines.append(f"- Peak RSS: {_fmt_bytes(self_usage.peak_rss_bytes)}")
    lines.append(f"- Runtime: {self_usage.runtime_seconds:.2f}s")
    lines.append(f"- Thread count (Python-level): {self_usage.thread_count}")
    lines.append(f"- Database size: {_fmt_bytes(self_usage.db_size_bytes)}")
    lines.append(f"- Log size: {_fmt_bytes(self_usage.log_size_bytes)}")
    lines.append(f"- Total events recorded: {self_usage.events_count}")
    lines.append(f"- Total findings recorded: {self_usage.findings_count}")
    lines.append("")

    lines.append("## Modules")
    lines.append("")
    if not module_runs:
        lines.append("No instrumented scan/integration runs recorded yet — run `secure run-all`.")
    else:
        lines.append("| Module | Operation | Duration (s) | CPU (s) | Observations | Findings | Error |")
        lines.append("|---|---|---|---|---|---|---|")
        for run in module_runs:
            lines.append(
                f"| {run.module} | {run.operation} | {run.duration_seconds:.3f} | "
                f"{run.cpu_time_seconds if run.cpu_time_seconds is not None else '?'} | "
                f"{run.observations_processed if run.observations_processed is not None else '?'} | "
                f"{run.findings_produced if run.findings_produced is not None else '?'} | "
                f"{run.error or ''} |"
            )
    lines.append("")

    lines.append("## Integrations / Tools")
    lines.append("")
    for name, health in integration_health:
        lines.append(f"- **{name}**: {health.status.upper()} — {health.detail}")
    lines.append("")

    lines.append("## Warnings")
    lines.append("")
    lines.append(
        "These are diagnostics describing measured behavior, never security alerts — "
        "never fed into severity, anomaly scoring, correlation, or explainability."
    )
    lines.append("")
    if not warnings:
        lines.append("No configured performance budget was exceeded this run.")
    else:
        for w in warnings:
            lines.append(f"- **[{w.kind}]** {w.message}")
    lines.append("")

    return "\n".join(lines)


def sanitized_config_summary(cfg: AppConfig) -> dict:
    """Only the allowlisted, definitely-non-secret config fields
    relevant to a diagnostics report — see _SAFE_CONFIG_FIELDS above.
    Everything else on AppConfig (API keys, SMTP credentials, etc.)
    never reaches this report at all.
    """
    return {name: getattr(cfg, name) for name in _SAFE_CONFIG_FIELDS}


def generate_json_report(
    hardware: HardwareSpecs,
    system_health: SystemHealth,
    self_usage: SecureSelfUsage,
    module_runs: "list[PerfModuleRunRecord]",
    integration_health: "list[tuple[str, object]]",
    warnings: "list[PerfWarning]",
    config_summary: "Optional[dict]" = None,
) -> dict:
    return {
        "secure_version": SECURE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config_summary": config_summary or {},
        "hardware": asdict(hardware),
        "system_health": asdict(system_health),
        "secure_self_usage": {k: v for k, v in asdict(self_usage).items() if k != "findings_by_table"},
        "findings_by_table": self_usage.findings_by_table,
        "module_runs": [asdict(r) for r in module_runs],
        "integration_health": [
            {"name": name, "status": health.status, "detail": health.detail, "tool_version": health.tool_version}
            for name, health in integration_health
        ],
        "warnings": [asdict(w) for w in warnings],
        "notes": {
            "warnings_are_diagnostics_not_alerts": (
                "Every entry in 'warnings' describes measured behavior against a "
                "configured threshold — never a security finding."
            ),
        },
    }


def write_report(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    output_dir: "Optional[Path]" = None,
    *,
    write_json: bool = True,
) -> "tuple[Path, Optional[Path]]":
    """Collects one fresh snapshot of everything this report covers and
    writes docs/generated/PERFORMANCE_REPORT.md (always) and
    performance_report.json (unless write_json=False). Returns
    (markdown_path, json_path_or_None).
    """
    hardware = collect_hardware_specs()
    system_health = collect_system_health(disk_path=cfg.app_dir_path())
    self_usage = collect_self_usage(conn, db_path=cfg.database_path(), log_path=cfg.log_path())
    module_runs = list_recent_perf_module_runs(conn, limit=50)
    integration_health = collect_integration_health(cfg)
    warnings = evaluate_budgets(
        cfg,
        self_usage=self_usage,
        system_health=system_health,
        recent_module_runs=module_runs,
    )

    out_dir = output_dir or _DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / "PERFORMANCE_REPORT.md"
    md_path.write_text(generate_markdown_report(
        hardware, system_health, self_usage, module_runs, integration_health, warnings
    ))

    json_path = None
    if write_json:
        json_path = out_dir / "performance_report.json"
        json_path.write_text(json.dumps(
            generate_json_report(
                hardware, system_health, self_usage, module_runs, integration_health, warnings,
                config_summary=sanitized_config_summary(cfg),
            ),
            indent=2, sort_keys=True,
        ))

    return md_path, json_path
