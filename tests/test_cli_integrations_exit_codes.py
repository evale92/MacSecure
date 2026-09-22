"""
Exit-code contract for every `secure integrations <engine> scan*` command:

    0  ran, nothing to review
    1  ran, found something to review
    2  engine unavailable or errored this pass

Before this, the unavailable/error branch also returned 1, so exit 1
meant either "found something" or "did not run". On the target Mac,
osquery is not installed and Suricata/Zeek are unconfigured, so a GUI
button treating 1 as findings would have reported findings on every
click. `status`, `rules`, `rulesets` and `alerts` are unchanged.

Each case drives the real CLI handler through the real parser against a
temporary app dir, with the engine's scan function replaced by a result
of the needed shape.

Run with:  pytest tests/test_cli_integrations_exit_codes.py
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from secure import cli
from secure.cli import build_parser
from secure.cli import integrations as integrations_cli
from secure.config import load_config

UNAVAILABLE, FINDINGS, CLEAN = 2, 1, 0


def _result(outcome: str) -> MagicMock:
    r = MagicMock()
    r.available = outcome != "unavailable"
    found = outcome == "findings"
    r.findings = [MagicMock()] if found else []
    r.discrepancies = [MagicMock()] if found else []
    r.outcomes = [MagicMock(matched=True)] if found else []
    r.failed_queries = []
    # Counts reach the database through the scan's performance record, so
    # they must be real numbers, not mocks.
    r.evaluable_count = r.not_evaluable_count = 0
    r.rules_loaded = r.rule_load_errors = r.new_alert_observations = []
    r.matched_count = len(r.outcomes)
    return r


# (argv, scan function patched in secure.cli.integrations, returns (targets, result)?, outcomes)
_SCANS = [
    (["integrations", "osquery", "scan"], "scan_osquery", False, ("unavailable", "findings", "clean")),
    (["integrations", "sigma", "scan"], "scan_sigma", False, ("unavailable", "findings", "clean")),
    (["integrations", "suricata", "scan"], "scan_suricata", False, ("unavailable", "findings", "clean")),
    # zeek never signals findings through its exit code.
    (["integrations", "zeek", "scan"], "scan_zeek", False, ("unavailable", "clean")),
    (["integrations", "yarax", "scan-file", "/tmp/nothing"], "scan_paths", False, ("unavailable", "findings", "clean")),
    (["integrations", "yarax", "scan-fim-alerts"], "scan_fim_alerts", True, ("unavailable", "findings", "clean")),
    (["integrations", "yarax", "scan-suspicious"], "scan_suspicious", True, ("unavailable", "findings", "clean")),
]
_EXPECTED = {"unavailable": UNAVAILABLE, "findings": FINDINGS, "clean": CLEAN}

_CASES = [
    pytest.param(argv, fn, tupled, outcome, id=f"{' '.join(argv[1:3])}-{outcome}")
    for argv, fn, tupled, outcomes in _SCANS
    for outcome in outcomes
]


@pytest.mark.parametrize("argv, scan_fn, tupled, outcome", _CASES)
def test_scan_exit_code_follows_the_contract(tmp_path: Path, monkeypatch, argv, scan_fn, tupled, outcome):
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    result = _result(outcome)
    fake = (lambda *a, **k: ([MagicMock()], result)) if tupled else (lambda *a, **k: result)
    monkeypatch.setattr(integrations_cli, scan_fn, fake)

    ns = build_parser().parse_args(argv)
    with contextlib.redirect_stdout(io.StringIO()):
        rc = ns.func(ns)

    assert rc == _EXPECTED[outcome]


def test_yarax_scans_with_nothing_to_scan_are_clean(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    monkeypatch.setattr(integrations_cli, "scan_fim_alerts", lambda *a, **k: ([], _result("clean")))
    ns = build_parser().parse_args(["integrations", "yarax", "scan-fim-alerts"])
    with contextlib.redirect_stdout(io.StringIO()):
        assert ns.func(ns) == CLEAN
