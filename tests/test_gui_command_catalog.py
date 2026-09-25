"""
Tests for the GUI command catalog (secure_gui/view_models.py) and the

The catalog is the argv contract between the GUI and the CLI. Every entry
must still parse with the real parser and reach the handler it claims, so
a CLI rename cannot silently turn a button into an argparse error. Each
entry also carries its exit-code contract and a timeout, because the GUI
kills a job when its timeout expires.

secure_gui.py (the entry script) shares its name with the secure_gui
package, so it cannot be imported here (docs/DESIGN_SYSTEM.md, "A note on
the package name"). Its wiring is checked by parsing its source.

Run with:  pytest tests/test_gui_command_catalog.py
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from secure.cli import build_parser
from secure.cli import ai as a
from secure.cli import correlate as c
from secure.cli import detect as d
from secure.cli import dfir as f
from secure.cli import diagnostics as g
from secure.cli import threatintel as t
from secure.cli import validate as v
from secure.cli import integrations as i
from secure.cli import investigate as inv
from secure.cli.downloads import cmd_downloads
from secure.cli.loghunt import cmd_loghunt
from secure_gui.view_models import (
    COMMAND_CATALOG,
    DEFAULT_TIMEOUT_SECONDS,
    PRUNE_CONFIRM_BODY,
    PRUNE_CONFIRM_TITLE,
    confirmed_args,
)

_SCRIPT = Path(__file__).resolve().parent.parent / "secure_gui.py"

_DL = "Downloads & Logs"
_IN = "Integrations"
_CH = "Correlation Chains"
_VD = "Validation & Detection"
_TD = "Threat Intel & DFIR"
_AP = "AI & Performance"

# Integration scans exit 0 clean / 1 findings / 2 unavailable or error
# (docs/INTEGRATIONS.md "Exit codes"), so 1 is a finding. Zeek never exits 1.
# Their runtimes are unmeasured on the target Mac: osquery is not installed,
# Suricata/Zeek are unconfigured, and a temp-app-dir run of sigma/yarax has no
# data, so it says nothing about a real pass. 300 s is the conservative value;
# revisit once an engine is configured. status/rules/rulesets/alerts only read
# (exit 1 = unavailable or a rule failed to load, a failure, never a finding).

# label -> (category, argv after `secure`, handler, nonzero_is_finding, timeout)
_EXPECTED = {
    "Download Provenance (last 30 days)": (_DL, ("downloads",), cmd_downloads, False, 60),
    "Flagged Downloads Only": (_DL, ("downloads", "--flagged"), cmd_downloads, False, 60),
    # A default 24 h hunt measured 51.35 s real on the target Mac
    # (2026-09-22), 9 s under the old fixed 60 s kill, and it scales with
    # --hours. 300 s leaves real headroom; the Stop button still works.
    "Log Hunt (last 24 hours)": (_DL, ("loghunt",), cmd_loghunt, False, 300),
    "osquery Status": (_IN, ("integrations", "osquery", "status"), i.cmd_integrations_osquery_status, False, 60),
    "osquery Cross-Check Scan": (_IN, ("integrations", "osquery", "scan"), i.cmd_integrations_osquery_scan, True, 300),
    "osquery Alerts": (_IN, ("integrations", "osquery", "alerts"), i.cmd_integrations_osquery_alerts, False, 60),
    "YARA-X Status": (_IN, ("integrations", "yarax", "status"), i.cmd_integrations_yarax_status, False, 60),
    "YARA-X Rulesets": (_IN, ("integrations", "yarax", "rulesets"), i.cmd_integrations_yarax_rulesets, False, 60),
    "YARA-X Scan File Integrity Alerts": (_IN, ("integrations", "yarax", "scan-fim-alerts"), i.cmd_integrations_yarax_scan_fim_alerts, True, 300),
    "YARA-X Scan Suspicious Persistence": (_IN, ("integrations", "yarax", "scan-suspicious"), i.cmd_integrations_yarax_scan_suspicious, True, 300),
    "YARA-X Alerts": (_IN, ("integrations", "yarax", "alerts"), i.cmd_integrations_yarax_alerts, False, 60),
    "Sigma Status": (_IN, ("integrations", "sigma", "status"), i.cmd_integrations_sigma_status, False, 60),
    "Sigma Rules": (_IN, ("integrations", "sigma", "rules"), i.cmd_integrations_sigma_rules, False, 60),
    "Sigma Scan": (_IN, ("integrations", "sigma", "scan"), i.cmd_integrations_sigma_scan, True, 300),
    "Sigma Alerts": (_IN, ("integrations", "sigma", "alerts"), i.cmd_integrations_sigma_alerts, False, 60),
    "Suricata Status": (_IN, ("integrations", "suricata", "status"), i.cmd_integrations_suricata_status, False, 60),
    "Suricata Scan": (_IN, ("integrations", "suricata", "scan"), i.cmd_integrations_suricata_scan, True, 300),
    "Suricata Alerts": (_IN, ("integrations", "suricata", "alerts"), i.cmd_integrations_suricata_alerts, False, 60),
    "Zeek Status": (_IN, ("integrations", "zeek", "status"), i.cmd_integrations_zeek_status, False, 60),
    "Zeek Scan": (_IN, ("integrations", "zeek", "scan"), i.cmd_integrations_zeek_scan, False, 300),
    # `correlate chains run` returns 1 exactly when it records new chain
    # alerts (secure/cli/correlate.py, `1 if result.new_alerts else 0`); a
    # crash exits 2 (secure.cli.main). It writes chain alerts, so it was not
    # measured against the real database: conservative 300 s. `chains list`
    # always returns 0.
    "Find Correlation Chains": (_CH, ("correlate", "chains", "run"), c.cmd_correlate_chains_run, True, 300),
    "List Correlation Chains": (_CH, ("correlate", "chains", "list"), c.cmd_correlate_chains_list, False, 60),
    # G4. `validate run` returns 1 exactly when a scenario is a MISS
    # (`0 if summary.count("MISS") == 0 else 1`, no other 1 branch; crashes
    # exit 2), so 1 is a detection gap to review. It records a run; its 21
    # synthetic scenarios took 1.2 s in a temp app dir, so the default 60 s.
    # Every other G4 command returns only 0. `detect sync` is left out on
    # threatintel providers/history make no network call (Q2).
    "Run Validation Suite": (_VD, ("validate", "run"), v.cmd_validate_run, True, 60),
    "List Validation Runs": (_VD, ("validate", "list"), v.cmd_validate_list, False, 60),
    "List Detection Rules": (_VD, ("detect", "list"), d.cmd_detect_list, False, 60),
    "Threat Intel Providers": (_TD, ("threatintel", "providers"), t.cmd_threatintel_providers, False, 60),
    "Threat Intel Lookup History": (_TD, ("threatintel", "history"), t.cmd_threatintel_history, False, 60),
    "DFIR Tool Status": (_TD, ("dfir", "status"), f.cmd_dfir_status, False, 60),
    "List Forensic Collections": (_TD, ("dfir", "list"), f.cmd_dfir_list, False, 60),
    "AI Provider Status": (_AP, ("ai", "status"), a.cmd_ai_status, False, 60),
    "AI Role Assignments": (_AP, ("ai", "roles"), a.cmd_ai_roles, False, 60),
    "AI Query History": (_AP, ("ai", "history"), a.cmd_ai_history, False, 60),
    "Performance Milestones": (_AP, ("diagnostics", "history"), g.cmd_diagnostics_history, False, 60),
    # G5. `investigate types` only reads and returns 0.
    "Investigation Entity Types": ("Investigate", ("investigate", "types"), inv.cmd_investigate_types, False, 60),
}


def test_the_catalog_never_writes_the_rule_registry_or_leaves_the_machine():
    # detect sync writes the rule registry; threatintel lookup makes an
    # outbound request (Q2). Neither is a GUI button.
    commands = {entry.args[:2] for entry in COMMAND_CATALOG}
    assert ("detect", "sync") not in commands
    assert ("threatintel", "lookup") not in commands


def _by_label():
    return {entry.label: entry for entry in COMMAND_CATALOG}


def test_the_catalog_holds_exactly_the_expected_commands_in_their_categories():
    assert set(_by_label()) == set(_EXPECTED)
    for label, entry in _by_label().items():
        assert entry.category == _EXPECTED[label][0], label


def test_no_catalog_command_marks_an_alert():
    # Marking known removes an alert from review. Integration mark-alert
    # looks the alert up by id alone, so it stays out of the catalog until
    assert not any("mark" in part for entry in COMMAND_CATALOG for part in entry.args)


@pytest.mark.parametrize("label", sorted(_EXPECTED))
def test_each_entry_parses_and_reaches_its_handler(label):
    entry = _by_label()[label]
    _, argv, handler, _, _ = _EXPECTED[label]
    assert entry.args == argv
    try:
        ns = build_parser().parse_args(list(entry.args))
    except SystemExit as exc:  # argparse reports errors by exiting
        pytest.fail(f"{label}: argv {entry.args} no longer parses (exit {exc.code})")
    assert ns.func is handler


@pytest.mark.parametrize("label", sorted(_EXPECTED))
def test_each_entry_pins_its_exit_contract_and_timeout(label):
    # downloads returns 1 when it cannot read the quarantine history and
    # loghunt returns 1/2 when a hunt fails: a nonzero exit is a failure,
    # never "found something" (SECURITY_INVARIANTS 5, no silent clean pass).
    entry = _by_label()[label]
    _, _, _, nonzero_is_finding, timeout = _EXPECTED[label]
    assert entry.nonzero_is_finding is nonzero_is_finding
    assert entry.timeout_seconds == timeout


def test_default_timeout_is_unchanged_for_every_other_command():
    assert DEFAULT_TIMEOUT_SECONDS == 60


# ---------- confirmed_args (Prune Junk Entries) ----------


def test_a_declined_confirmation_runs_nothing():
    asked = []
    result = confirmed_args(lambda title, body: asked.append((title, body)) or False,
                            PRUNE_CONFIRM_TITLE, PRUNE_CONFIRM_BODY, ["secure", "inventory", "prune"])
    assert result is None
    assert asked == [(PRUNE_CONFIRM_TITLE, PRUNE_CONFIRM_BODY)]


def test_an_accepted_confirmation_runs_the_exact_argv():
    argv = ["python", "-m", "secure", "inventory", "prune"]
    assert confirmed_args(lambda title, body: True, "t", "b", argv) == argv


def test_the_prune_prompt_says_it_deletes():
    assert "delete" in PRUNE_CONFIRM_BODY.lower()


# ---------- secure_gui.py wiring (source checks) ----------


def _script_tree():
    return ast.parse(_SCRIPT.read_text())


def _function(tree, name):
    found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(found) == 1, f"expected one {name}(), found {len(found)}"
    return found[0]


def test_execute_uses_the_jobs_timeout_not_a_literal():
    execute = _function(_script_tree(), "_execute")
    timeouts = [
        kw.value for n in ast.walk(execute) if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and n.func.attr == "communicate"
        for kw in n.keywords if kw.arg == "timeout"
    ]
    assert timeouts, "_execute must pass a timeout to communicate()"
    assert not any(isinstance(v, ast.Constant) for v in timeouts)
    literal_texts = [n.value for n in ast.walk(execute) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not any("after 60s" in t for t in literal_texts), "timeout message must print the real timeout"


def test_the_pytest_button_is_gone():
    source = _SCRIPT.read_text()
    assert "Run Test Suite (pytest)" not in source
    assert '"-m", "pytest"' not in source


def test_the_catalog_buttons_are_built_from_the_catalog():
    assert "COMMAND_CATALOG" in _SCRIPT.read_text()


def test_prune_asks_before_it_runs():
    prune = _function(_script_tree(), "inventory_prune")
    called = {n.func.id for n in ast.walk(prune) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "confirmed_args" in called
