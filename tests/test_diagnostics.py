"""
Tests for Phase 30 (Performance & Diagnostics): secure/diagnostics/.

Covers, per the phase's own testing requirements: metric parsing/
calculation, unavailable states, module instrumentation, threshold
warnings, tool aggregation, report sanitization, and — the phase's own
hard architectural rule — that performance measurement never alters
security results.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import secure.diagnostics.hardware as hardware_module
import secure.diagnostics.system as system_module
import secure.diagnostics.tools as tools_module
from secure.config import default_config
from secure.diagnostics._shell import ShellResult
from secure.diagnostics.budgets import (
    BUDGET_DB_GROWTH,
    BUDGET_DISK_FREE,
    BUDGET_SCAN_DURATION,
    BUDGET_SECURE_RSS,
    evaluate_budgets,
)
from secure.diagnostics.hardware import collect_hardware_specs
from secure.diagnostics.instrument import best_effort_counts, instrument_module
from secure.diagnostics.milestones import latest_milestone, record_milestone
from secure.diagnostics.report import generate_json_report, sanitized_config_summary, write_report
from secure.diagnostics.self_usage import SecureSelfUsage, collect_self_usage
from secure.diagnostics.system import (
    _parse_battery,
    _parse_swapusage,
    _parse_thermal,
    _parse_vm_stat,
    collect_system_health,
)
from secure.diagnostics.tools import DevToolUsage, _parse_ps_output, collect_dev_tool_usage
from secure.storage.database import Database
from secure.storage.models.perf import PerfModuleRunRecord


# =========================================================================
# Metric parsing/calculation — pure functions, no subprocess
# =========================================================================


def test_parse_vm_stat_extracts_page_size_and_free_pages():
    text = (
        "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
        "Pages free:                              123456.\n"
        "Pages active:                            234567.\n"
    )
    assert _parse_vm_stat(text) == (4096, 123456)


def test_parse_vm_stat_returns_none_on_unrecognized_output():
    assert _parse_vm_stat("garbage, not vm_stat output at all") is None


def test_parse_swapusage_extracts_total_and_used_bytes():
    text = "vm.swapusage: total = 2048.00M  used = 512.00M  free = 1536.00M  (encrypted)"
    total, used = _parse_swapusage(text)
    assert total == 2048 * 1024 * 1024
    assert used == 512 * 1024 * 1024


def test_parse_swapusage_returns_none_on_unrecognized_output():
    assert _parse_swapusage("no swap info here") is None


def test_parse_battery_laptop_on_battery_reports_percent():
    text = (
        "Now drawing from 'Battery Power'\n"
        " -InternalBattery-0 (id=123)\t87%; discharging; 2:00 remaining present: true\n"
    )
    assert _parse_battery(text) == "Battery Power, battery 87%"


def test_parse_battery_desktop_mac_reports_no_battery_not_unavailable():
    text = "Now drawing from 'AC Power'\n"
    result = _parse_battery(text)
    assert result is not None
    assert "no battery" in result.lower()


def test_parse_battery_returns_none_on_unrecognized_output():
    assert _parse_battery("nonsense") is None


def test_parse_thermal_nominal():
    assert _parse_thermal("No thermal warning level has been recorded") == "nominal"


def test_parse_thermal_empty_is_unavailable():
    assert _parse_thermal("") is None
    assert _parse_thermal("   ") is None


def test_parse_ps_output_handles_multiword_comm():
    sample = (
        "  PID    RSS %CPU COMMAND\n"
        "    1   1234  0.1 launchd\n"
        "  200  56000  2.5 Claude Helper (Renderer)\n"
    )
    rows = _parse_ps_output(sample)
    assert rows == [(1, 1234, 0.1, "launchd"), (200, 56000, 2.5, "Claude Helper (Renderer)")]


def test_parse_ps_output_empty_text_returns_empty_list():
    assert _parse_ps_output("") == []


# =========================================================================
# Unavailable states — hardware/system honestly report what they can't
# measure, never a fabricated value
# =========================================================================


def test_hardware_specs_reports_unavailable_when_sysctl_fails(monkeypatch):
    monkeypatch.setattr(
        hardware_module, "run", lambda *a, **k: ShellResult(ok=False, stdout="", stderr="not found", returncode=None)
    )
    specs = collect_hardware_specs()
    # architecture/python_version/secure_version come from the stdlib,
    # never from sysctl — they must still be populated.
    assert specs.architecture
    assert specs.python_version
    assert specs.secure_version
    # Every sysctl-derived field must be honestly None + flagged.
    assert specs.mac_model is None
    assert "mac_model" in specs.unavailable
    assert specs.cpu_brand is None
    assert "cpu_brand" in specs.unavailable
    assert specs.total_ram_bytes is None
    assert "total_ram_bytes" in specs.unavailable


def test_hardware_specs_never_fabricates_a_nonzero_value_when_unavailable(monkeypatch):
    """Adversarial check: even when every subprocess call fails, no
    numeric field is ever a fabricated 0 — it's None, distinguishable
    from a genuinely-measured zero.
    """
    def always_fail(*a, **k):
        return ShellResult(ok=False, stdout="", stderr="nope", returncode=None)

    # hardware.py binds `run` at import, so the seam is its own name —
    # rebinding secure.diagnostics._shell.run would let real sysctl run.
    monkeypatch.setattr(hardware_module, "run", always_fail)
    specs = collect_hardware_specs()
    assert specs.total_ram_bytes is None  # never 0
    assert specs.physical_cores is None  # never 0


def test_system_health_reports_unavailable_when_all_commands_fail(monkeypatch):
    monkeypatch.setattr(
        system_module, "run", lambda *a, **k: ShellResult(ok=False, stdout="", stderr="nope", returncode=None)
    )
    health = collect_system_health(disk_path=Path("/tmp"))
    assert health.mem_free_bytes is None
    assert "mem_free_bytes" in health.unavailable
    assert health.battery_state is None
    assert "battery_state" in health.unavailable
    # disk usage is stdlib (shutil.disk_usage), not subprocess-based —
    # must still succeed even when every subprocess call fails.
    assert health.disk_free_bytes is not None


def test_system_health_load_average_is_real_when_available():
    health = collect_system_health(disk_path=Path("/tmp"))
    # This sandbox is a real Unix host — os.getloadavg() should succeed.
    assert health.load_avg_1m is not None
    assert "load_average" not in health.unavailable


# =========================================================================
# Module instrumentation — the per-operation timing wrapper
# =========================================================================


def test_instrument_module_writes_one_row_on_success(tmp_path):
    with Database(tmp_path / "t.db") as db:
        with instrument_module(db.conn, run_group_id="g1", module="connections", operation="scan") as rec:
            time.sleep(0.001)
            rec.observations_processed = 5
            rec.findings_produced = 2

        from secure.storage.models import list_recent_perf_module_runs

        rows = list_recent_perf_module_runs(db.conn)
        assert len(rows) == 1
        row = rows[0]
        assert row.module == "connections"
        assert row.operation == "scan"
        assert row.duration_seconds > 0
        assert row.observations_processed == 5
        assert row.findings_produced == 2
        assert row.error is None


def test_instrument_module_records_error_and_reraises(tmp_path):
    """The wrapped call's exception must propagate unchanged — this
    context manager is a diagnostic observer, never an error handler.
    """
    with Database(tmp_path / "t.db") as db:
        raised = False
        try:
            with instrument_module(db.conn, run_group_id="g1", module="wifi", operation="scan") as rec:
                raise RuntimeError("simulated scan failure")
        except RuntimeError as exc:
            raised = True
            assert "simulated scan failure" in str(exc)
        assert raised, "the original exception must not be swallowed"

        from secure.storage.models import list_recent_perf_module_runs

        rows = list_recent_perf_module_runs(db.conn)
        assert len(rows) == 1
        assert rows[0].error is not None
        assert "simulated scan failure" in rows[0].error


def test_best_effort_counts_reads_alerts_and_entries():
    class FakeResult:
        alerts = [1, 2, 3]
        entries = ["a", "b"]

    obs, findings = best_effort_counts(FakeResult())
    assert obs == 2
    assert findings == 3


def test_best_effort_counts_returns_none_for_missing_fields():
    class Empty:
        pass

    obs, findings = best_effort_counts(Empty())
    assert obs is None
    assert findings is None


def test_instrumentation_does_not_alter_the_wrapped_scan_result(tmp_path):
    """The phase's own hard rule: performance measurement must not
    change any scan's own detection/scoring behavior. Proven by
    running the identical pure function both instrumented and not, and
    asserting the return value is byte-for-byte identical.
    """

    def fake_scan():
        return {"alerts": [1, 2, 3], "computed": sum(range(1000))}

    direct_result = fake_scan()

    with Database(tmp_path / "t.db") as db:
        with instrument_module(db.conn, run_group_id="g1", module="fake", operation="scan") as rec:
            instrumented_result = fake_scan()
            rec.findings_produced = len(instrumented_result["alerts"])

    assert instrumented_result == direct_result


# =========================================================================
# Threshold warnings — plain diagnostics, never security alerts
# =========================================================================


def test_evaluate_budgets_no_warnings_when_everything_is_healthy():
    cfg = default_config()
    su = SecureSelfUsage(
        pid=1, cpu_time_seconds=0.1, peak_rss_bytes=10 * 1024 * 1024, runtime_seconds=0.1,
        thread_count=1, db_size_bytes=100, log_size_bytes=10, events_count=0, findings_count=0,
        findings_by_table={},
    )
    assert evaluate_budgets(cfg, self_usage=su) == []


def test_evaluate_budgets_flags_excessive_secure_rss():
    cfg = default_config()
    su = SecureSelfUsage(
        pid=1, cpu_time_seconds=0.1, peak_rss_bytes=600 * 1024 * 1024, runtime_seconds=0.1,
        thread_count=1, db_size_bytes=100, log_size_bytes=10, events_count=0, findings_count=0,
        findings_by_table={},
    )
    warnings = evaluate_budgets(cfg, self_usage=su)
    assert len(warnings) == 1
    assert warnings[0].kind == BUDGET_SECURE_RSS
    assert "500" in warnings[0].message  # the configured budget appears in the message


def test_evaluate_budgets_flags_unusually_long_scan():
    cfg = default_config()
    run = PerfModuleRunRecord(
        id=1, run_group_id="g", module="fileintegrity", operation="scan", external_tool=None,
        started_at="t0", completed_at="t1", duration_seconds=999.0, cpu_time_seconds=1.0,
        rss_bytes_at_end=1, observations_processed=1, findings_produced=0, error=None, timed_out=False,
    )
    warnings = evaluate_budgets(cfg, recent_module_runs=[run])
    assert len(warnings) == 1
    assert warnings[0].kind == BUDGET_SCAN_DURATION


def test_evaluate_budgets_flags_low_disk_space():
    cfg = default_config()
    from secure.diagnostics.system import SystemHealth

    sh = SystemHealth(
        collected_at="t", load_avg_1m=None, load_avg_5m=None, load_avg_15m=None,
        mem_total_bytes=None, mem_free_bytes=None, mem_pressure=None, swap_total_bytes=None,
        swap_used_bytes=None, disk_total_bytes=100, disk_free_bytes=1024 ** 3,  # 1GB free
        battery_state=None, thermal_pressure=None,
    )
    warnings = evaluate_budgets(cfg, system_health=sh)
    assert len(warnings) == 1
    assert warnings[0].kind == BUDGET_DISK_FREE


def test_evaluate_budgets_flags_rapid_db_growth():
    cfg = default_config()
    su = SecureSelfUsage(
        pid=1, cpu_time_seconds=0.1, peak_rss_bytes=1, runtime_seconds=0.1, thread_count=1,
        db_size_bytes=200 * 1024 * 1024, log_size_bytes=10, events_count=0, findings_count=0,
        findings_by_table={},
    )
    warnings = evaluate_budgets(cfg, self_usage=su, previous_db_size_bytes=100 * 1024 * 1024)
    assert len(warnings) == 1
    assert warnings[0].kind == BUDGET_DB_GROWTH


def test_evaluate_budgets_never_produces_a_severity_field():
    """These are diagnostics, not security findings — PerfWarning has
    no severity/confidence/score field for anything to misinterpret as
    one.
    """
    cfg = default_config()
    su = SecureSelfUsage(
        pid=1, cpu_time_seconds=0.1, peak_rss_bytes=600 * 1024 * 1024, runtime_seconds=0.1,
        thread_count=1, db_size_bytes=100, log_size_bytes=10, events_count=0, findings_count=0,
        findings_by_table={},
    )
    warnings = evaluate_budgets(cfg, self_usage=su)
    from dataclasses import fields

    field_names = {f.name for f in fields(warnings[0])}
    assert field_names == {"kind", "message"}
    assert "severity" not in field_names


# =========================================================================
# Tool aggregation — generic external-process resource aggregate
# =========================================================================


def test_collect_dev_tool_usage_aggregates_matching_processes(monkeypatch):
    sample = (
        "  PID    RSS %CPU COMMAND\n"
        "    1   1000  1.0 Claude\n"
        "    2   2000  2.0 Claude Helper\n"
        "    3   3000  3.0 unrelated_process\n"
    )
    monkeypatch.setattr(
        tools_module, "run", lambda *a, **k: ShellResult(ok=True, stdout=sample, stderr="", returncode=0)
    )
    usages = collect_dev_tool_usage("Claude,unrelated_process")
    by_pattern = {u.pattern: u for u in usages}
    assert by_pattern["Claude"].process_count == 2
    assert by_pattern["Claude"].total_cpu_percent == 3.0
    assert by_pattern["Claude"].total_rss_bytes == 3000 * 1024
    assert by_pattern["unrelated_process"].process_count == 1


def test_collect_dev_tool_usage_empty_patterns_returns_empty_list():
    assert collect_dev_tool_usage("") == []
    assert collect_dev_tool_usage("   ,  ,") == []


def test_collect_dev_tool_usage_ps_failure_returns_empty_not_fabricated(monkeypatch):
    monkeypatch.setattr(
        tools_module, "run", lambda *a, **k: ShellResult(ok=False, stdout="", stderr="no ps", returncode=None)
    )
    assert collect_dev_tool_usage("Claude") == []


def test_collect_dev_tool_usage_zero_matches_reports_zero_not_missing(monkeypatch):
    sample = "  PID    RSS %CPU COMMAND\n    1   1000  1.0 something_else\n"
    monkeypatch.setattr(
        tools_module, "run", lambda *a, **k: ShellResult(ok=True, stdout=sample, stderr="", returncode=0)
    )
    usages = collect_dev_tool_usage("Claude")
    assert len(usages) == 1
    assert usages[0].process_count == 0


# =========================================================================
# Report sanitization
# =========================================================================


def test_sanitized_config_summary_excludes_every_secret_field():
    cfg = default_config()
    cfg.smtp_password = "super-secret"
    cfg.virustotal_api_key = "vt-key-12345"
    cfg.local_llm_api_key = "llm-key-67890"

    summary = sanitized_config_summary(cfg)
    summary_text = str(summary)
    assert "super-secret" not in summary_text
    assert "vt-key-12345" not in summary_text
    assert "llm-key-67890" not in summary_text
    assert "smtp_password" not in summary
    assert "virustotal_api_key" not in summary
    assert "local_llm_api_key" not in summary


def test_write_report_output_never_contains_configured_secrets(tmp_path):
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    cfg.smtp_password = "super-secret-password"
    cfg.virustotal_api_key = "vt-super-secret-key"

    with Database(tmp_path / "secure.db") as db:
        md_path, json_path = write_report(db.conn, cfg, output_dir=tmp_path / "out")

    md_text = md_path.read_text()
    json_text = json_path.read_text()
    assert "super-secret-password" not in md_text
    assert "super-secret-password" not in json_text
    assert "vt-super-secret-key" not in md_text
    assert "vt-super-secret-key" not in json_text


def test_generate_json_report_is_json_serializable(tmp_path):
    cfg = default_config()
    with Database(tmp_path / "t.db") as db:
        self_usage = collect_self_usage(db.conn, db_path=tmp_path / "t.db", log_path=None)
        hardware = collect_hardware_specs()
        system_health = collect_system_health(disk_path=tmp_path)
        from secure.storage.models import list_recent_perf_module_runs

        module_runs = list_recent_perf_module_runs(db.conn)

    import json

    data = generate_json_report(
        hardware, system_health, self_usage, module_runs, integration_health=[], warnings=[],
        config_summary=sanitized_config_summary(cfg),
    )
    json.dumps(data)  # must not raise


# =========================================================================
# Milestones
# =========================================================================


def test_record_and_read_back_milestone(tmp_path):
    with Database(tmp_path / "t.db") as db:
        su = SecureSelfUsage(
            pid=1, cpu_time_seconds=0.1, peak_rss_bytes=12345, runtime_seconds=0.1, thread_count=1,
            db_size_bytes=999, log_size_bytes=1, events_count=0, findings_count=0, findings_by_table={},
        )
        record_milestone(db.conn, label="Phase 30", self_usage=su, run_all_duration_seconds=4.2, notes="test")
        m = latest_milestone(db.conn)
        assert m is not None
        assert m.label == "Phase 30"
        assert m.run_all_duration_seconds == 4.2
        assert m.secure_peak_rss_bytes == 12345
        assert m.notes == "test"


def test_latest_milestone_none_when_empty(tmp_path):
    with Database(tmp_path / "t.db") as db:
        assert latest_milestone(db.conn) is None


# =========================================================================
# Self usage — never overstates what it measured
# =========================================================================


def test_collect_self_usage_without_conn_leaves_counts_none():
    usage = collect_self_usage()
    assert usage.events_count is None
    assert usage.findings_count is None
    assert usage.findings_by_table == {}
    # But process-level measurements (always available) must be real.
    assert usage.peak_rss_bytes > 0
    assert usage.pid > 0


def test_collect_self_usage_missing_db_log_paths_are_none(tmp_path):
    usage = collect_self_usage(db_path=tmp_path / "does_not_exist.db", log_path=tmp_path / "does_not_exist.log")
    assert usage.db_size_bytes is None
    assert usage.log_size_bytes is None
