"""
The GUI's "Investigate Entity…" command (docs/GUI_ROADMAP.md G5):
view_models.investigate_show_request() turns the operator's type and key
into `secure investigate show` argv, or a refusal.

It is the enforcement point: the type must be one the CLI accepts (pinned
to the parser's own choices so the two cannot drift), and the key is
stripped, must not be empty, and must not start with "-", which argparse
would read as an option (for example `--max-hops`) instead of the key.

Run with:  pytest tests/test_gui_investigate.py
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

import pytest

from secure.cli import build_parser
from secure.cli.investigate import cmd_investigate_show
from secure_gui.view_models import INVESTIGATE_ENTITY_TYPES, investigate_show_request

_SCRIPT = Path(__file__).resolve().parent.parent / "secure_gui.py"


def _show_parser():
    root = build_parser()
    subs = next(a for a in root._actions if isinstance(a, argparse._SubParsersAction)).choices
    inv = next(a for a in subs["investigate"]._actions if isinstance(a, argparse._SubParsersAction)).choices
    return inv["show"]


def test_the_allowed_types_are_exactly_the_clis():
    choices = next(a.choices for a in _show_parser()._actions if a.dest == "entity_type")
    assert INVESTIGATE_ENTITY_TYPES == tuple(choices)


@pytest.mark.parametrize("entity_type", INVESTIGATE_ENTITY_TYPES)
def test_a_valid_request_parses_to_exactly_that_entity(entity_type):
    args, refusal = investigate_show_request(entity_type, "  some key with spaces  ")
    assert refusal is None
    ns = build_parser().parse_args(list(args))
    assert ns.func is cmd_investigate_show
    assert ns.entity_type == entity_type
    assert ns.entity_key == "some key with spaces"  # stripped; spaces are fine in an argv list
    assert ns.max_hops == 6  # the key did not leak into an option


@pytest.mark.parametrize("entity_type", ["nope", "", "process; rm -rf /", " process"])
def test_an_unknown_type_is_refused_with_the_allowed_list(entity_type):
    args, refusal = investigate_show_request(entity_type, "key")
    assert args is None
    assert "process" in refusal and "indicator" in refusal


@pytest.mark.parametrize("key", ["", "   ", None])
def test_an_empty_key_is_refused(key):
    args, refusal = investigate_show_request("process", key)
    assert args is None and refusal


@pytest.mark.parametrize("key", ["--max-hops", "-x", "  -h"])
def test_a_key_that_argparse_would_read_as_an_option_is_refused(key):
    args, refusal = investigate_show_request("process", key)
    assert args is None
    assert "-" in refusal


def test_the_gui_builds_the_show_command_through_the_request_builder():
    tree = ast.parse(_SCRIPT.read_text())
    fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "investigate_show"]
    assert len(fns) == 1
    called = {n.func.id for n in ast.walk(fns[0]) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "investigate_show_request" in called
