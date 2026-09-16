"""The DB_GROWTH budget warning, end to end through every caller that
can reach it.

`evaluate_budgets()` has always been able to produce a
`db_growth` warning, and tests/test_diagnostics.py pins that logic by
calling it directly with `previous_db_size_bytes=`. What nothing pinned
was that a *production* caller ever supplies that argument: all three of
them (`secure diagnostics performance`, `write_report()`, and the GUI's
`fetch_performance_overview_now()`) omitted it, so the guard at
budgets.py could not pass outside the test that passed it by hand — the
"rapidly growing DB/log files" check the module docstring promises was
structurally unreachable (J-0547).

Every test below therefore asserts through a real caller, and each
warning assertion is paired with a no-milestone control run, so a caller
that silently stopped passing the argument again would fail here rather
than quietly go back to never warning.
"""

from __future__ import annotations

import json

from secure.config import default_config
from secure.diagnostics.budgets import BUDGET_DB_GROWTH
from secure.diagnostics.milestones import previous_db_size_bytes, record_milestone
from secure.diagnostics.report import write_report
from secure.diagnostics.self_usage import SecureSelfUsage
from secure.storage.database import Database


def _zero_db_usage() -> SecureSelfUsage:
    """A self-usage snapshot whose recorded db size is 0, so that any
    real database on disk counts as growth against it.
    """
    return SecureSelfUsage(
        pid=1, cpu_time_seconds=0.0, peak_rss_bytes=1, runtime_seconds=0.0, thread_count=1,
        db_size_bytes=0, log_size_bytes=0, events_count=0, findings_count=0, findings_by_table={},
    )


def _config_for(tmp_path):
    """A config rooted at tmp_path whose growth threshold is 0MB, so the
    handful of KB a fresh schema occupies is enough to cross it. The
    threshold is what the operator configures; the wiring under test is
    whether the comparison happens at all.
    """
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    cfg.perf_budget_db_growth_warn_mb_per_run = 0.0
    return cfg


def _db_growth_warnings(warnings):
    return [w for w in warnings if w.kind == BUDGET_DB_GROWTH]


# =========================================================================
# The reader itself
# =========================================================================


def test_previous_db_size_bytes_is_none_before_any_milestone(tmp_path):
    """No milestone means no baseline, and None is the honest answer —
    not 0, which would make the whole current db size look like growth.
    """
    with Database(tmp_path / "t.db") as db:
        assert previous_db_size_bytes(db.conn) is None


def test_previous_db_size_bytes_returns_the_latest_milestones_size(tmp_path):
    with Database(tmp_path / "t.db") as db:
        record_milestone(db.conn, label="first", self_usage=_zero_db_usage())
        assert previous_db_size_bytes(db.conn) == 0

        later = SecureSelfUsage(
            pid=1, cpu_time_seconds=0.0, peak_rss_bytes=1, runtime_seconds=0.0, thread_count=1,
            db_size_bytes=4096, log_size_bytes=0, events_count=0, findings_count=0, findings_by_table={},
        )
        record_milestone(db.conn, label="second", self_usage=later)
        assert previous_db_size_bytes(db.conn) == 4096


# =========================================================================
# Caller 1 — secure/diagnostics/report.py's write_report()
# =========================================================================


def test_write_report_warns_about_db_growth_since_the_last_milestone(tmp_path):
    cfg = _config_for(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        record_milestone(db.conn, label="baseline", self_usage=_zero_db_usage())
        _, json_path = write_report(db.conn, cfg, output_dir=tmp_path / "out")

    report = json.loads(json_path.read_text())
    kinds = [w["kind"] for w in report["warnings"]]
    assert BUDGET_DB_GROWTH in kinds, f"expected a db_growth warning, got {kinds}"


def test_write_report_reports_no_db_growth_when_no_milestone_exists(tmp_path):
    """The control for the test above: same config, same database, no
    milestone. Without this pair, a report that warned unconditionally
    would pass the first test.
    """
    cfg = _config_for(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        _, json_path = write_report(db.conn, cfg, output_dir=tmp_path / "out")

    report = json.loads(json_path.read_text())
    assert BUDGET_DB_GROWTH not in [w["kind"] for w in report["warnings"]]


# =========================================================================
# Caller 2 — secure/cli/diagnostics.py's `secure diagnostics performance`
# =========================================================================


def test_cmd_diagnostics_performance_prints_the_db_growth_warning(tmp_path, monkeypatch, capsys):
    import secure.cli.diagnostics as cli_diagnostics

    cfg = _config_for(tmp_path)
    monkeypatch.setattr(cli_diagnostics, "_bootstrap", lambda: cfg)

    with Database(cfg.database_path()) as db:
        record_milestone(db.conn, label="baseline", self_usage=_zero_db_usage())

    assert cli_diagnostics.cmd_diagnostics_performance(object()) == 0
    out = capsys.readouterr().out
    assert f"[{BUDGET_DB_GROWTH}]" in out, out


def test_cmd_diagnostics_performance_says_nothing_about_growth_with_no_milestone(
    tmp_path, monkeypatch, capsys
):
    import secure.cli.diagnostics as cli_diagnostics

    cfg = _config_for(tmp_path)
    monkeypatch.setattr(cli_diagnostics, "_bootstrap", lambda: cfg)

    with Database(cfg.database_path()):
        pass

    assert cli_diagnostics.cmd_diagnostics_performance(object()) == 0
    assert f"[{BUDGET_DB_GROWTH}]" not in capsys.readouterr().out


# =========================================================================
# Caller 3 — secure_gui/data_access.py (no Tkinter; see the module's own
# docstring — this is the GUI's testable read-only layer)
# =========================================================================


def test_fetch_performance_overview_now_includes_the_db_growth_warning(tmp_path, monkeypatch):
    import secure_gui.data_access as data_access

    cfg = _config_for(tmp_path)
    monkeypatch.setattr(data_access, "load_config", lambda: cfg)

    with Database(cfg.database_path()) as db:
        record_milestone(db.conn, label="baseline", self_usage=_zero_db_usage())

    overview = data_access.fetch_performance_overview_now()
    assert _db_growth_warnings(overview.warnings), [w.kind for w in overview.warnings]


def test_fetch_performance_overview_now_has_no_growth_warning_with_no_milestone(tmp_path, monkeypatch):
    import secure_gui.data_access as data_access

    cfg = _config_for(tmp_path)
    monkeypatch.setattr(data_access, "load_config", lambda: cfg)

    with Database(cfg.database_path()):
        pass

    overview = data_access.fetch_performance_overview_now()
    assert not _db_growth_warnings(overview.warnings)
