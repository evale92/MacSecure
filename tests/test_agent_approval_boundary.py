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


# approve_change() and reject_change() are wrappers. The write they
# guard is this storage primitive, whose own docstring says it "does
# not itself enforce WHO may call it", so banning only the wrappers
# leaves `m.set_ai_change_request_status(conn, cr_id=..., status="approved")`
# open to any automated module: measured, appending exactly that to
# secure/agent/verified.py left all 252 tests in the agent tier's
# structural files green (J-0258).
STATUS_WRITER = "set_ai_change_request_status"

# Every place the two guarded packages may reference the writer, keyed
# by enclosing function ("<module>" for a top-level import). The two
# secure/agent/ callers are deterministic bookkeeping, not approval.
STATUS_WRITER_ROSTER = {
    ("secure/ai/changes/workflow.py", "<module>"),
    ("secure/ai/changes/workflow.py", "approve_change"),
    ("secure/ai/changes/workflow.py", "reject_change"),
    ("secure/agent/changes.py", "<module>"),
    ("secure/agent/changes.py", "supersede_change_request"),
    ("secure/agent/promote.py", "_resolve_change_request"),
}

# The only statuses automated code may write through it.
AUTOMATED_STATUS_NAMES = {"STATUS_SUPERSEDED", "STATUS_PROMOTED_AUTOMATICALLY"}


def _status_writer_references(source: str, filename: str = "<test>") -> "list[tuple[str, ast.AST]]":
    """Every reference to the status writer, with its enclosing function.

    A reference, not only a call: `from ... import set_ai_change_request_status as s`,
    `f = m.set_ai_change_request_status` and `getattr(m, "set_ai_change_request_status")`
    each reach the writer without a call node that names it. A string
    only matches when it IS the name, so docstring prose never does.
    """
    found: "list[tuple[str, ast.AST]]" = []

    def visit(node: ast.AST, enclosing: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            enclosing = node.name
        if (
            (isinstance(node, ast.ImportFrom) and any(a.name == STATUS_WRITER for a in node.names))
            or (isinstance(node, ast.Name) and node.id == STATUS_WRITER)
            or (isinstance(node, ast.Attribute) and node.attr == STATUS_WRITER)
            or (isinstance(node, ast.Constant) and node.value == STATUS_WRITER)
        ):
            found.append((enclosing, node))
        for child in ast.iter_child_nodes(node):
            visit(child, enclosing)

    visit(ast.parse(source, filename=filename), "<module>")
    return found


def test_the_status_writer_scan_catches_every_reference_form():
    """Positive control for the roster test below."""
    source = (
        "import secure.storage.models as m\n"
        "from secure.storage.models import set_ai_change_request_status as s\n"
        "def attribute(conn):\n    m.set_ai_change_request_status(conn, cr_id='CR-1', status='approved')\n"
        "def bound(conn):\n    f = m.set_ai_change_request_status\n"
        "def by_string(conn):\n    getattr(m, 'set_ai_change_request_status')\n"
        "def prose():\n    '''calls set_ai_change_request_status() somewhere'''\n"
    )
    found = sorted((enclosing, node.lineno) for enclosing, node in _status_writer_references(source))
    assert found == [("<module>", 2), ("attribute", 4), ("bound", 6), ("by_string", 8)]


def test_only_the_rostered_functions_reach_the_status_writer():
    """AGENTS.md rule 4 names the wrappers; invariant 2 is about the
    write. A new reference anywhere in secure/agent/ or secure/ai/ fails
    here until a human adds it to the roster above."""
    seen: "set[tuple[str, str]]" = set()
    for module in _guarded_modules():
        relative = str(module.relative_to(REPO_ROOT))
        source = module.read_text(encoding="utf-8")
        seen |= {(relative, enclosing) for enclosing, _ in _status_writer_references(source, relative)}

    assert seen == STATUS_WRITER_ROSTER, (
        f"unrostered: {sorted(seen - STATUS_WRITER_ROSTER)}; gone: {sorted(STATUS_WRITER_ROSTER - seen)}"
    )


def test_automated_callers_never_write_approved_through_the_status_writer():
    """The two secure/agent/ call sites pass `status=` as a named
    constant, and neither constant is the approved status."""
    from secure.agent.changes import STATUS_SUPERSEDED
    from secure.agent.promote import STATUS_PROMOTED_AUTOMATICALLY
    from secure.ai.changes.workflow import STATUS_APPROVED

    assert STATUS_APPROVED not in {STATUS_SUPERSEDED, STATUS_PROMOTED_AUTOMATICALLY}

    statuses: "list[str]" = []
    for relative in ("secure/agent/changes.py", "secure/agent/promote.py"):
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source, filename=relative)):
            if isinstance(node, ast.Call) and _status_writer_references(ast.unparse(node.func)):
                status = next((k.value for k in node.keywords if k.arg == "status"), None)
                statuses.append(status.id if isinstance(status, ast.Name) else ast.unparse(status or ast.Constant(None)))

    assert sorted(statuses) == sorted(AUTOMATED_STATUS_NAMES), statuses
