"""
Tests for the GUI command catalog (secure_gui/view_models.py) and the
parts of secure_gui.py that consume it (docs/GUI_ROADMAP.md, step G1).

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

# label -> (expected argv after `secure`, handler, nonzero_is_finding, timeout)
_EXPECTED = {
    "Download Provenance (last 30 days)": (("downloads",), cmd_downloads, False, 60),
    "Flagged Downloads Only": (("downloads", "--flagged"), cmd_downloads, False, 60),
    # A default 24 h hunt measured 51.35 s real on the target Mac
    # (2026-09-22), 9 s under the old fixed 60 s kill, and it scales with
    # --hours. 300 s leaves real headroom; the Stop button still works.
    "Log Hunt (last 24 hours)": (("loghunt",), cmd_loghunt, False, 300),
}


def _by_label():
    return {entry.label: entry for entry in COMMAND_CATALOG}


def test_the_catalog_holds_exactly_the_g1_commands():
    assert set(_by_label()) == set(_EXPECTED)


@pytest.mark.parametrize("label", sorted(_EXPECTED))
def test_each_entry_parses_and_reaches_its_handler(label):
    entry = _by_label()[label]
    argv, handler, _, _ = _EXPECTED[label]
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
    _, _, nonzero_is_finding, timeout = _EXPECTED[label]
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
