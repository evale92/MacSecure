"""
Structural + behavioral guard for invariant 5 ("No silent clean pass")
at the CLI's exit-code seam.

`secure/cli/__init__.py`'s `main()` ends in `sys.exit(exit_code)`, where
`exit_code` is whatever the selected subcommand handler returned. Python
treats `sys.exit(None)` as exit status 0 (measured, not assumed — see
test_sys_exit_none_is_status_zero below). So a handler that falls off the
end of its body, or returns bare, turns a failure into a process that
reports success. That is the same defect shape
tests/test_failure_modes.py was written for ("never a silent 'clean'
result") and the one SECURITY_INVARIANTS.md invariant 5 forbids.

SECURITY_INVARIANTS.md lists structural tests behind invariants 3, 8 and
12, and says an invariant with neither a structural nor a behavioral test
"is worth a test ... in its own change". This is that change for the CLI
facet of invariant 5. TESTING_POLICY.md rule 8 ("prefer a structural test
over a comment") is why it parses the source rather than documenting the
rule in a comment.

Named `test_cli_exit_codes.py` so `targeted_test_files()` in
secure/agent/tiers.py picks it up: every file under `secure/cli/` maps to
`tests/test_cli*.py`.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

import pytest

from secure import cli

CLI_PACKAGE = Path(cli.__file__).resolve().parent


def _cli_source_files() -> list[Path]:
    return [p for p in sorted(CLI_PACKAGE.rglob("*.py")) if "__pycache__" not in p.parts]


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _registered_handlers() -> tuple[set[str], list[str]]:
    """Every name registered as `parser.set_defaults(func=...)` anywhere in
    the CLI package, plus the source locations of any `func=` value this
    parser cannot resolve to a name. An unresolvable entry is reported, not
    skipped — silently ignoring one would be the very thing invariant 5
    forbids."""
    names: set[str] = set()
    unresolvable: list[str] = []
    for path in _cli_source_files():
        for node in ast.walk(_parse(path)):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "set_defaults":
                continue
            for keyword in node.keywords:
                if keyword.arg != "func":
                    continue
                if isinstance(keyword.value, ast.Name):
                    names.add(keyword.value.id)
                elif isinstance(keyword.value, ast.Attribute):
                    names.add(keyword.value.attr)
                else:
                    unresolvable.append(f"{path.name}:{keyword.value.lineno}")
    return names, unresolvable


def _handler_defs(names: set[str]) -> dict[str, list[tuple[Path, ast.FunctionDef]]]:
    found: dict[str, list[tuple[Path, ast.FunctionDef]]] = {}
    for path in _cli_source_files():
        for node in ast.walk(_parse(path)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
                found.setdefault(node.name, []).append((path, node))
    return found


def _terminates(body: list[ast.stmt]) -> bool:
    """True when control cannot reach the end of `body` — every path
    returns or raises. Conservative: anything it does not model counts as
    falling through, so a new statement shape fails loudly rather than
    passing silently."""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return _terminates(last.body) and _terminates(last.orelse)
    if isinstance(last, (ast.With, ast.AsyncWith)):
        return _terminates(last.body)
    if isinstance(last, ast.Try):
        if last.finalbody and _terminates(last.finalbody):
            return True
        main_path = _terminates(last.orelse) if last.orelse else _terminates(last.body)
        return main_path and all(_terminates(h.body) for h in last.handlers)
    if isinstance(last, ast.Match):
        return bool(last.cases) and all(_terminates(c.body) for c in last.cases)
    if isinstance(last, ast.While):
        # `while True:` with no break never falls through.
        is_always = isinstance(last.test, ast.Constant) and bool(last.test.value)
        has_break = any(isinstance(n, ast.Break) for n in ast.walk(last))
        return is_always and not has_break
    return False


def _none_returns(fn: ast.FunctionDef) -> list[int]:
    """Line numbers of `return` and `return None` inside `fn`, excluding
    nested function definitions, which have their own contract."""
    nested = {n for outer in ast.walk(fn) if outer is not fn
              for n in ast.walk(outer)
              if isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))}
    lines = []
    for node in ast.walk(fn):
        if node in nested or not isinstance(node, ast.Return):
            continue
        if node.value is None or (isinstance(node.value, ast.Constant) and node.value.value is None):
            lines.append(node.lineno)
    return sorted(lines)


# =====================================================================
# The premise: sys.exit(None) is a success status
# =====================================================================


def test_sys_exit_none_is_status_zero():
    """Measured rather than assumed, because every other test in this file
    rests on it. If a future interpreter changed this, the structural
    guard below would be protecting against nothing and should be
    re-justified rather than quietly kept."""
    completed = subprocess.run([sys.executable, "-c", "import sys; sys.exit(None)"])
    assert completed.returncode == 0

    failing = subprocess.run([sys.executable, "-c", "import sys; sys.exit(2)"])
    assert failing.returncode == 2


# =====================================================================
# Structural: no registered handler can return None
# =====================================================================


def test_every_registered_cli_handler_resolves_to_a_definition():
    """Honest absence (invariant 5): if a `func=` target cannot be found,
    this test says so instead of quietly checking a smaller set than it
    claims to. The exit-code guard below is only as good as this list."""
    names, unresolvable = _registered_handlers()
    assert unresolvable == []
    assert names, "no set_defaults(func=...) handlers found — the collector is broken, not the CLI"

    defs = _handler_defs(names)
    assert sorted(names - set(defs)) == []


def test_no_registered_cli_handler_can_return_none_instead_of_an_exit_code():
    """Every subcommand handler must return an exit code on every path.
    `main()` passes the return value straight to `sys.exit()`, so a handler
    that falls off the end or returns bare makes a failed command exit 0 —
    a failure reporting success, which no caller can distinguish from the
    work having been done."""
    names, _ = _registered_handlers()
    defs = _handler_defs(names)

    offending: list[str] = []
    for name in sorted(defs):
        for path, fn in defs[name]:
            if not _terminates(fn.body):
                offending.append(f"{path.name}:{fn.lineno} {name}() can reach the end of its body")
            for lineno in _none_returns(fn):
                offending.append(f"{path.name}:{lineno} {name}() returns None")
    assert offending == []


def test_the_structural_check_detects_a_handler_that_returns_none():
    """Positive control for the two checks above. A structural test that
    cannot fail is indistinguishable from one that passes, so prove the
    detector fires on each shape it is meant to catch."""
    module = ast.parse(
        "def falls_off_end(args):\n"
        "    if args.x:\n"
        "        return 1\n"
        "    print('no return')\n"
        "\n"
        "def returns_bare(args):\n"
        "    if args.x:\n"
        "        return\n"
        "    return 0\n"
        "\n"
        "def always_returns(args):\n"
        "    try:\n"
        "        return 0\n"
        "    except OSError:\n"
        "        return 1\n"
        "\n"
        "def raises_instead(args):\n"
        "    raise SystemExit(2)\n"
    )
    fns = {n.name: n for n in module.body if isinstance(n, ast.FunctionDef)}

    assert not _terminates(fns["falls_off_end"].body)
    assert _none_returns(fns["returns_bare"]) == [8]
    assert _terminates(fns["always_returns"].body)
    assert _none_returns(fns["always_returns"]) == []
    assert _terminates(fns["raises_instead"].body)


# =====================================================================
# Behavioral: main() actually propagates what a handler returned
# =====================================================================


def _parser_returning(value):
    parser = argparse.ArgumentParser(prog="secure-test")
    parser.set_defaults(func=lambda args: value)
    return parser


def test_main_exits_with_the_code_the_handler_returned(monkeypatch):
    """The other half of the contract: the structural guard is only
    worth having if `main()` really hands the handler's return value to
    `sys.exit()`."""
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_returning(3))
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 3

    monkeypatch.setattr(cli, "build_parser", lambda: _parser_returning(0))
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 0


def test_main_exits_zero_when_a_handler_returns_none(monkeypatch):
    """Documents the failure mode the structural guard prevents, rather
    than asserting it is impossible. This is current, correct-for-Python
    behavior of `sys.exit(None)`; it is exactly why no handler may return
    None, and why that is checked by parsing the source instead of hoped
    for."""
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_returning(None))
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code is None


# =====================================================================
# Behavioral: an unexpected crash exits 2, not Python's default 1
# =====================================================================


def _parser_raising(exc):
    def handler(args):
        raise exc

    parser = argparse.ArgumentParser(prog="secure-test")
    parser.set_defaults(func=handler)
    return parser


def test_an_unexpected_exception_exits_2_with_its_traceback(monkeypatch, capsys):
    """Exit 1 is how scans say "found something", so a crash that fell
    through to Python's default handler (exit 1) read as a finding in the
    GUI and the supervisor. Anything unmapped now exits 2, the error code,
    and still prints the traceback."""
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_raising(RuntimeError("boom")))
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "RuntimeError: boom" in err
    assert "Traceback" in err


def test_a_handler_that_exits_on_purpose_keeps_its_code(monkeypatch):
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_raising(SystemExit(5)))
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 5


def test_ctrl_c_still_propagates(monkeypatch):
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_raising(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        cli.main([])


def test_a_broken_logger_cannot_turn_the_crash_exit_back_into_a_crash(monkeypatch, capsys):
    class ExplodingLogger:
        def __getattr__(self, name):
            def fail(*a, **k):
                raise OSError("log file unwritable")
            return fail

    monkeypatch.setattr(cli, "logger", ExplodingLogger())
    monkeypatch.setattr(cli, "build_parser", lambda: _parser_raising(RuntimeError("boom")))
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 2
