"""
Tests for secure/diagnostics/integrations_health.py — Phase 30's
INTEGRATIONS roster.

The module holds no health logic of its own: its one job is to name
every external integration and hand back that integration's own
`check_availability()` result. Completeness is therefore the only
property it can get wrong, and it is the one nothing pinned. An
integration absent from the roster produces no row under "External
integrations:" in `secure diagnostics tools` (secure/cli/
diagnostics.py), no row in the GUI diagnostics view (secure_gui/
data_access.py), and no MaintenanceSituation at all in
secure/agent/toolchain.py's `survey_integrations()`, which iterates
only over what the roster returned — so an omitted integration reads
exactly like a healthy one. That is the omission SECURITY_INVARIANTS.md
invariant 5 forbids.

So the roster is checked structurally against what is actually on disk
(TESTING_POLICY rule 8) rather than against the module docstring's
count of six (rule 12): adding a seventh integration package fails this
file instead of quietly never appearing in any health view.

Every `check_availability` is patched at its own module seam (rule 7),
so nothing here runs a real tool, a subprocess, or the network.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import secure.dfir.velociraptor.availability as velociraptor_availability
from secure.config import default_config
from secure.diagnostics.integrations_health import collect_integration_health
from secure.integrations.base import STATUS_OK, STATUS_UNAVAILABLE, IntegrationHealth

INTEGRATIONS_DIR = Path(__file__).resolve().parent.parent / "secure" / "integrations"

# Velociraptor is the one roster entry that does not live under
# secure/integrations/ — it is layer 9's secure/dfir/velociraptor/,
# reusing the same IntegrationHealth shape (Phase 24). Disk discovery
# below cannot see it, so it is named here on purpose.
VELOCIRAPTOR = "velociraptor"


def _integration_packages() -> "list[str]":
    """Every package under secure/integrations/ exporting a
    `check_availability()` — i.e. every integration the roster is
    supposed to cover. Read from disk, never listed in this file."""
    names: "list[str]" = []
    for init in sorted(INTEGRATIONS_DIR.glob("*/__init__.py")):
        package = init.parent.name
        if package.startswith("_"):
            continue
        module = importlib.import_module(f"secure.integrations.{package}")
        if hasattr(module, "check_availability"):
            names.append(package)
    return names


def _health(detail: str, status: str = STATUS_OK) -> IntegrationHealth:
    return IntegrationHealth(
        status=status, detail=detail, collected_at="2026-01-01T00:00:00+00:00"
    )


def _patch_every_check(monkeypatch, make_health) -> None:
    """Replace each integration's real `check_availability` with a stub
    that reports which integration it stands for, so a roster entry
    carrying the wrong integration's health is visible rather than
    plausible."""
    for package in _integration_packages():
        module = importlib.import_module(f"secure.integrations.{package}")
        monkeypatch.setattr(
            module,
            "check_availability",
            lambda *a, _package=package, **k: make_health(_package),
        )
    monkeypatch.setattr(
        velociraptor_availability,
        "check_availability",
        lambda *a, **k: make_health(VELOCIRAPTOR),
    )


def _sandbox_config(tmp_path):
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    return cfg


def test_integration_packages_are_actually_discovered(tmp_path):
    """Guards the discovery helper itself: if the glob ever matched
    nothing, every completeness assertion below would pass vacuously."""
    packages = _integration_packages()
    assert packages, f"no integration packages discovered under {INTEGRATIONS_DIR}"
    assert "osquery" in packages


def test_collect_integration_health_covers_every_integration_package(tmp_path, monkeypatch):
    _patch_every_check(monkeypatch, lambda name: _health(f"stub for {name}"))

    roster = collect_integration_health(_sandbox_config(tmp_path))
    names = [name for name, _ in roster]

    missing = [p for p in _integration_packages() if p not in names]
    assert missing == [], (
        f"integration package(s) exporting check_availability but absent from the "
        f"health roster: {missing} — they would show as no row at all in "
        f"`secure diagnostics tools` and as no situation in survey_integrations()"
    )


def test_collect_integration_health_includes_velociraptor(tmp_path, monkeypatch):
    _patch_every_check(monkeypatch, lambda name: _health(f"stub for {name}"))

    roster = collect_integration_health(_sandbox_config(tmp_path))

    assert VELOCIRAPTOR in [name for name, _ in roster]


def test_collect_integration_health_names_no_integration_that_does_not_exist(tmp_path, monkeypatch):
    """The roster's names are the only identity a caller gets — a stale
    or misspelled one labels a health row after something that is not
    there."""
    _patch_every_check(monkeypatch, lambda name: _health(f"stub for {name}"))

    roster = collect_integration_health(_sandbox_config(tmp_path))
    names = [name for name, _ in roster]

    known = set(_integration_packages()) | {VELOCIRAPTOR}
    assert [n for n in names if n not in known] == []
    assert len(names) == len(set(names)), f"duplicate roster entries: {names}"


def test_collect_integration_health_pairs_each_name_with_its_own_health(tmp_path, monkeypatch):
    """Labelling is the module's whole job, so a row carrying another
    integration's result is a real defect and not a cosmetic one."""
    _patch_every_check(monkeypatch, lambda name: _health(f"stub for {name}"))

    roster = collect_integration_health(_sandbox_config(tmp_path))

    for name, health in roster:
        assert health.detail == f"stub for {name}"


def test_collect_integration_health_keeps_an_unavailable_integration_in_the_roster(tmp_path, monkeypatch):
    """Honest absence (TESTING_POLICY rule 9): an integration that is
    not installed still gets a row reporting UNAVAILABLE. Dropping it
    would leave the caller unable to tell "not installed" from "not
    checked"."""
    _patch_every_check(
        monkeypatch, lambda name: _health(f"{name} is not installed", status=STATUS_UNAVAILABLE)
    )

    roster = collect_integration_health(_sandbox_config(tmp_path))
    names = [name for name, _ in roster]

    for package in _integration_packages():
        assert package in names
    assert VELOCIRAPTOR in names
    assert all(health.status == STATUS_UNAVAILABLE for _, health in roster)
