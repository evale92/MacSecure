"""
Tests for secure/validate/attck.py — the ATT&CK reference table the
validation scenarios cite.

attck.py is pure data, so there is no behavior to exercise. What can
be checked, and what nothing checked before this file, is the
relationship between the table and the scenarios that cite it:

  - REGISTRY agrees with the Technique objects it is built from;
  - no scenario writes an ATT&CK id as a bare string literal, so the
    ids reaching a validation report always came from this table;
  - the table declares no technique the scenario catalog does not
    actually model, apart from one recorded exception.

The scenario-facing checks parse the source rather than running the
scenarios (TESTING_POLICY.md rule 8, and secure/agent/supervisor's own
AST checks set the precedent). That keeps them fast and free of the
sandbox, and it catches the hardcoded-literal case that a runtime
check cannot see — a literal that happens to be spelled correctly
today still defeats the table tomorrow.

Run with:  pytest
"""

from __future__ import annotations

import ast
from pathlib import Path

from secure.validate import attck
from secure.validate.attck import REGISTRY, Technique

_SCENARIOS_DIR = Path(attck.__file__).resolve().parent / "scenarios"

# T1562.001 is in the table but no scenario cites it. It was written
# for the tool-unavailable case (its reference_note says so), and that
# scenario — detections_yarax_engine_unavailable — deliberately reports
# technique_id=None instead: it validates Secure's own honest
# degradation, not an adversary impairing defenses, and mapping it to
# an ATT&CK id would claim a detection the run never made. Recorded
# here as the one known-unmodeled entry so that a seventh technique
# added without a scenario behind it fails instead of passing quietly.
_KNOWN_UNMODELED = {"T1562.001"}


def _declared_techniques():
    return {
        name: value
        for name, value in vars(attck).items()
        if isinstance(value, Technique)
    }


def _scenario_modules():
    paths = sorted(p for p in _SCENARIOS_DIR.glob("*.py") if p.name != "__init__.py")
    assert paths, f"no scenario modules found under {_SCENARIOS_DIR}"
    return paths


def _parse(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _names_imported_from_attck(tree):
    """Names bound in this module by `from secure.validate.attck import ...`."""
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "secure.validate.attck":
            for alias in node.names:
                imported.add(alias.asname or alias.name)
    return imported


def _technique_id_keywords(tree):
    """Every `technique_id=<value>` keyword argument in the module."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "technique_id":
                    yield kw.value


def test_registry_is_keyed_by_technique_id():
    for key, technique in REGISTRY.items():
        assert key == technique.technique_id, (
            f"REGISTRY key {key!r} does not match its value's technique_id "
            f"{technique.technique_id!r}"
        )


def test_registry_contains_every_declared_technique():
    declared = _declared_techniques()
    assert declared, "attck.py declares no Technique objects"
    missing = {
        name: t.technique_id
        for name, t in declared.items()
        if REGISTRY.get(t.technique_id) is not t
    }
    assert not missing, (
        f"Technique(s) declared in attck.py but absent from REGISTRY: {missing}. "
        "Add them to the tuple REGISTRY is built from."
    )


def test_every_declared_technique_is_fully_populated():
    for name, technique in _declared_techniques().items():
        for field in ("technique_id", "name", "tactic", "reference_note"):
            value = getattr(technique, field)
            assert isinstance(value, str) and value.strip(), (
                f"attck.{name}.{field} is empty; the table exists to be cited, "
                "and a blank field reaches a validation report as one"
            )
        assert technique.technique_id.startswith("T"), (
            f"attck.{name}.technique_id={technique.technique_id!r} is not an "
            "ATT&CK-shaped id"
        )


def test_scenarios_never_hardcode_an_attck_id():
    """A scenario must cite the table, not retype an id.

    report.py renders technique_id next to the scenario's own
    technique_name, so a mistyped literal prints a wrong id beside a
    right-looking name and nothing else notices.
    """
    offenders = []
    for path in _scenario_modules():
        tree = _parse(path)
        imported = _names_imported_from_attck(tree)
        for value in _technique_id_keywords(tree):
            if isinstance(value, ast.Constant) and value.value is None:
                continue
            cited = (
                isinstance(value, ast.Attribute)
                and value.attr == "technique_id"
                and isinstance(value.value, ast.Name)
                and value.value.id in imported
            )
            if not cited:
                offenders.append(f"{path.name}:{value.lineno}")
    assert not offenders, (
        "scenario(s) set technique_id to something other than None or "
        f"<Technique imported from attck>.technique_id: {offenders}"
    )


def test_table_declares_no_technique_the_catalog_does_not_model():
    declared = _declared_techniques()
    cited_names = set()
    for path in _scenario_modules():
        cited_names |= _names_imported_from_attck(_parse(path))

    unmodeled = {
        t.technique_id
        for name, t in declared.items()
        if name not in cited_names
    }
    assert unmodeled == _KNOWN_UNMODELED, (
        f"techniques declared in attck.py but cited by no scenario: {unmodeled}; "
        f"expected exactly {_KNOWN_UNMODELED}. Either give the technique a "
        "scenario, or drop it from the table and update this test's "
        "_KNOWN_UNMODELED with the reason."
    )
