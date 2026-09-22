"""
Pins every CLI command the GUI runs from a hard-coded argv (secure_gui.py
and secure_gui/*.py), and checks each still resolves to a real `secure`
subcommand. A CLI rename or removal then fails here instead of turning a
button into an argparse error the operator only sees after clicking.

Commands built from secure_gui/view_models.py COMMAND_CATALOG are left out:
tests/test_gui_command_catalog.py parses each of those with the real parser.

The snapshot is the reviewed list. Adding or removing a GUI command means
updating it on purpose.

Run with:  pytest tests/test_gui_argv_leaves.py
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

from secure.cli import build_parser

_ROOT_DIR = Path(__file__).resolve().parent.parent
_SOURCES = [_ROOT_DIR / "secure_gui.py", *sorted((_ROOT_DIR / "secure_gui").glob("*.py"))]

# 68 leaves as of 2026-09-22 (G3 added correlate chains mark-alert; G5 investigate show).
_PINNED = {
    "add-note",
    "agent approve",
    "agent center check",
    "agent center show",
    "agent discover",
    "agent remove-worktree",
    "agent resume",
    "agent run",
    "ai changes approve",
    "ai changes reject",
    "anomalies mark",
    "arpwatch list",
    "arpwatch mark",
    "arpwatch scan",
    "bluetooth alerts",
    "bluetooth ble alerts",
    "bluetooth ble list",
    "bluetooth ble mark",
    "bluetooth ble mark-alert",
    "bluetooth ble scan",
    "bluetooth list",
    "bluetooth mark",
    "bluetooth mark-alert",
    "bluetooth scan",
    "bluetooth state",
    "check",
    "connections endpoints",
    "connections mark",
    "connections scan",
    "correlate list",
    "correlate chains mark-alert",  # G3: Alerts window marks chain alerts
    "correlate mark-alert",
    "correlate run",
    "diagnostics milestone record",
    "fileintegrity alerts",
    "fileintegrity events",
    "fileintegrity files",
    "fileintegrity mark-alert",
    "fileintegrity mark-file",
    "fileintegrity scan",
    "fileintegrity watch-add",
    "fileintegrity watch-list",
    "init",
    "inventory list",
    "inventory mark",
    "inventory name",
    "inventory prune",
    "investigate show",  # G5: built per click by investigate_show_request
    "inventory scan",
    "listening list",
    "listening mark",
    "listening scan",
    "persistence alerts",
    "persistence items",
    "persistence mark-alert",
    "persistence mark-item",
    "persistence mark-process",
    "persistence processes",
    "persistence scan",
    "run-all",
    "self mark-update-context",
    "snapshot",
    "status",
    "wifi alerts",
    "wifi list",
    "wifi mark",
    "wifi mark-alert",
    "wifi scan",
}


_NOT_ARGV = {"COMMAND_CATALOG", "INVESTIGATE_ENTITY_TYPES"}


def _subparsers(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def _leaf(parser, words):
    node, path = parser, []
    for word in words:
        kids = _subparsers(node)
        if not kids or word not in kids:
            break
        node = kids[word]
        path.append(word)
    return " ".join(path) if path and not _subparsers(node) else None


def _argv_literals(path: Path, top_level):
    tree = ast.parse(path.read_text())
    skip = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            # COMMAND_CATALOG has its own parse test. INVESTIGATE_ENTITY_TYPES
            # is data, not argv, though it starts with "inventory".
            if any(isinstance(t, ast.Name) and t.id in _NOT_ARGV for t in targets):
                skip |= {id(x) for x in ast.walk(node)}
    for node in ast.walk(tree):
        if id(node) in skip or not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
            continue
        words = [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None for e in node.elts]
        if "-m" in words and "secure" in words and words.index("secure") == words.index("-m") + 1:
            words = words[words.index("secure") + 1:]
        elif not (words[0] and words[0] in top_level):
            continue
        if words and words[0] is not None:
            yield words, f"{path.name}:{node.lineno}"


def _scan():
    parser = build_parser()
    top_level = _subparsers(parser)
    found, broken = set(), []
    for source in _SOURCES:
        for words, where in _argv_literals(source, top_level):
            leading = []
            for word in words:
                if word is None:
                    break
                leading.append(word)
            leaf = _leaf(parser, leading)
            if leaf:
                found.add(leaf)
            elif None not in words:  # fully literal, yet not a real command
                broken.append((where, words))
    return found, broken


def test_every_hard_coded_gui_command_is_a_real_cli_command():
    _, broken = _scan()
    assert broken == []


def test_the_gui_runs_exactly_the_pinned_commands():
    found, _ = _scan()
    assert sorted(found - _PINNED) == [], "new GUI command: add it to _PINNED on purpose"
    assert sorted(_PINNED - found) == [], "a GUI command disappeared: remove it from _PINNED on purpose"
