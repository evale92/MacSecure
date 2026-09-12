"""tests/test_agent_approval_boundary.py — AGENTS.md rule 4, checked
the way that rule states it.

Rule 4 says "Nothing under `secure/agent/` or `secure/ai/` may call
`approve_change()` or `reject_change()`", and that this "is checked
structurally by a test that parses the source". Three tests do parse
source for it — test_agent_verified.py, test_agent_maintenance.py and
test_agent_notify.py — but each guards its own single module, and each
matches a banned call only as `ast.Name`:

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) ...

Python reaches a function two ways. `import secure.storage.models as m`
followed by `m.set_ai_change_request_status(...)` is an `ast.Attribute`
call, so it is invisible to all three, while the bare-name form is
caught — measured on all three modules, both halves. This file closes
that gap and widens the scan from 3 modules to every module in both
packages, which is the set rule 4 actually names.

The exemption for `secure/ai/changes/workflow.py`, which *defines*
`approve_change` and `reject_change`, is by shape rather than by a path
allowlist: a `def` is not a call, so the definition site needs no
special case and a later file that defines a same-named wrapper gets no
free pass from this test.

`test_the_scan_catches_both_call_forms` is not decoration. A structural
test whose matcher has quietly stopped matching is indistinguishable
from a codebase that is clean, so the matcher is exercised against
source that must fail before the repo-wide assertion is trusted.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# The two packages AGENTS.md rule 4 names.
GUARDED_PACKAGES = ("agent", "ai")

# The two functions rule 4 names. Approval is a human CLI action; the
# only callers in this repository are under secure/cli/.
BANNED_APPROVAL_CALLS = {"approve_change", "reject_change"}


def _guarded_modules() -> "list[Path]":
    modules: "list[Path]" = []
    for package in GUARDED_PACKAGES:
        modules.extend(sorted((REPO_ROOT / "secure" / package).rglob("*.py")))
    return modules


def _approval_calls(source: str, filename: str = "<test>") -> "list[str]":
    """Every call of a banned approval function, in either call form.

    A bare `approve_change(...)` is an `ast.Name` func; a qualified
    `workflow.approve_change(...)` is an `ast.Attribute` func. Both are
    calls and both are reported. A `def approve_change` is neither.
    """
    violations: "list[str]" = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in BANNED_APPROVAL_CALLS:
            violations.append(f"line {node.lineno}: {func.id}()")
        elif isinstance(func, ast.Attribute) and func.attr in BANNED_APPROVAL_CALLS:
            violations.append(f"line {node.lineno}: .{func.attr}()")
    return violations


def test_the_scan_catches_both_call_forms():
    """Positive control. Without this the repo-wide assertion below
    cannot tell "nothing calls these" from "the matcher stopped
    matching" — the failure mode that let the attribute form through
    the three existing per-module checks."""
    bare = "def f(conn):\n    return approve_change(conn, 'CR-1')\n"
    attribute = "import secure.ai.changes.workflow as w\n\ndef f(conn):\n    return w.reject_change(conn, 'CR-1')\n"
    aliased = "from secure.ai.changes import workflow\n\ndef f(conn):\n    return workflow.approve_change(conn, 'CR-1')\n"

    assert _approval_calls(bare) == ["line 2: approve_change()"]
    assert _approval_calls(attribute) == ["line 4: .reject_change()"]
    assert _approval_calls(aliased) == ["line 4: .approve_change()"]


def test_a_definition_is_not_mistaken_for_a_call():
    """The exemption is structural. `secure/ai/changes/workflow.py` is
    inside a guarded package and defines both banned names, and must
    still come back clean."""
    workflow = REPO_ROOT / "secure" / "ai" / "changes" / "workflow.py"
    source = workflow.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(workflow))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in BANNED_APPROVAL_CALLS
    }
    assert defined == BANNED_APPROVAL_CALLS, f"workflow.py no longer defines both: {sorted(defined)}"
    assert _approval_calls(source, str(workflow)) == []


def test_the_scan_actually_reaches_both_packages():
    """A repo-wide walk that finds no files asserts nothing at all. Pin
    that both package roots resolved and that the module count is the
    real one, so a moved directory fails here rather than turning the
    test below into a vacuous pass."""
    modules = _guarded_modules()
    relative = {str(p.relative_to(REPO_ROOT)) for p in modules}

    assert "secure/ai/changes/workflow.py" in relative
    assert "secure/agent/promote.py" in relative
    assert any(p.startswith("secure/agent/") for p in relative)
    assert any(p.startswith("secure/ai/") for p in relative)
    assert len(modules) >= 40, f"only {len(modules)} modules found under {GUARDED_PACKAGES}"


def test_no_module_in_the_agent_or_ai_packages_calls_an_approval_function():
    """AGENTS.md rule 4, over the whole set it names rather than the
    three modules that had their own copy of this check."""
    offending: "list[str]" = []
    for module in _guarded_modules():
        violations = _approval_calls(module.read_text(encoding="utf-8"), str(module))
        offending += [f"{module.relative_to(REPO_ROOT)} {v}" for v in violations]

    assert offending == [], "approval call inside a guarded package: " + "; ".join(offending)
