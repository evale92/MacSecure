"""
Tests for the `CheckResult` contract declared in secure/checks/models.py.

Every posture check returns the same four-field record, and the
module's own docstring states one rule about the fourth field:
`remediation` is "the plain-English 'what to do about it' — left as an
empty string when status is PASS (there's nothing to do)."

That is prose. TESTING_POLICY rule 12 says prose is not a test and rule
8 says an invariant checkable by parsing the source should be, so a
future edit fails loudly. This file parses the source.

It enforces both halves, because only one of them was ever written
down and the other is the one that matters to an operator:

  · PASS      => remediation is empty       (the documented half)
  · non-PASS  => remediation is NOT empty   (the load-bearing half)

A WARNING or FAIL row with no remediation is a security tool telling
someone their machine is wrong and giving them nothing to do about it.
Both halves hold across every construction site as of 2026-09-12; the
gap this file closes is that nothing failed if they stopped holding.

Scope, stated rather than left to be found: this is a static check over
`secure/checks/*.py`, which is where all 29 `CheckResult(...)`
constructions in non-test code live (`git grep 'CheckResult('` over
secure/ and secure_gui/ finds none elsewhere). A result assembled
through a variable or a helper would be invisible to it — so an
argument this file cannot resolve to a literal is reported as a
violation, never skipped. Invariant 7: inconclusive is not a pass.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Field order of the CheckResult dataclass, for resolving positional
# arguments. Pinned here rather than read from the dataclass because
# this check must fail — not silently re-index — if the order changes.
_FIELDS = ("name", "status", "message", "remediation")

# The check modules that construct a CheckResult, measured 2026-09-12 at
# 0343233. Pinned so that a NEW posture check module cannot join the
# package without someone reading this contract: the failure message
# below says exactly that.
_EXPECTED_MODULES = {
    "filevault.py",
    "firewall.py",
    "gatekeeper.py",
    "os_version.py",
    "runner.py",
    "sharing.py",
    "sip.py",
    "software_update.py",
    "xprotect.py",
    "backup.py",
    "boot_security.py",
}

# Total construction sites at the same revision. A whole-package walk
# over a clean tree passes identically whether the analysis works or
# quietly matches nothing, so the count is asserted too.
_MEASURED_SITE_COUNT = 29


def _project_root() -> Path:
    # tests/ is one level under the project root.
    return Path(__file__).resolve().parents[1]


def _argument(node: ast.Call, field: str) -> "ast.expr | None":
    """The expression passed for `field`, positionally or by keyword.

    Returns None only when the argument is genuinely absent, which for
    `remediation` means the dataclass default of "".
    """
    for keyword in node.keywords:
        if keyword.arg == field:
            return keyword.value
    index = _FIELDS.index(field)
    if len(node.args) > index:
        return node.args[index]
    return None


def _status_name(node: "ast.expr | None") -> "str | None":
    """"PASS"/"WARNING"/"FAIL" for a literal CheckStatus.X, else None."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id == "CheckStatus":
            return node.attr
    return None


def _is_nonempty_text(node: "ast.expr | None") -> "bool | None":
    """True/False for text this can resolve, None when it cannot.

    Adjacent string literals are already merged into one Constant by
    the parser, so plain multi-line remediation strings resolve. An
    f-string resolves only when it carries a non-empty literal segment
    of its own — `f"{x}"` alone could be empty at runtime and is
    reported unresolved rather than assumed.
    """
    if node is None:
        return False  # dataclass default: remediation = ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value != ""
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if part.value != "":
                    return True
        return None
    return None


def _contract_violations(source: str, filename: str) -> "tuple[list[str], int]":
    """(violations, number of CheckResult construction sites seen)."""
    violations: list[str] = []
    sites = 0

    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "CheckResult":
            continue

        sites += 1
        where = f"{filename}:{node.lineno}"

        status = _status_name(_argument(node, "status"))
        if status is None:
            violations.append(f"{where}: status is not a literal CheckStatus.X, so the contract cannot be checked here")
            continue

        has_remediation = _is_nonempty_text(_argument(node, "remediation"))
        if has_remediation is None:
            violations.append(f"{where}: remediation is not a resolvable literal, so the contract cannot be checked here")
        elif status == "PASS" and has_remediation:
            violations.append(f"{where}: PASS carries a remediation; models.py says PASS leaves it empty")
        elif status != "PASS" and not has_remediation:
            violations.append(f"{where}: {status} has an empty remediation — a finding with nothing to do about it")

    return violations, sites


def test_every_check_result_honors_the_remediation_contract():
    checks_dir = _project_root() / "secure" / "checks"
    violations: list[str] = []
    total_sites = 0
    contributing: set[str] = set()

    for path in sorted(checks_dir.glob("*.py")):
        found, sites = _contract_violations(path.read_text(encoding="utf-8"), path.name)
        violations.extend(found)
        total_sites += sites
        if sites:
            contributing.add(path.name)

    assert violations == []

    # Coverage guards: a clean result above means nothing unless the
    # walk actually looked at the constructions it claims to cover.
    assert contributing == _EXPECTED_MODULES, (
        "the set of check modules constructing a CheckResult changed; a new posture "
        "check must honor the remediation contract in secure/checks/models.py, and a "
        "removed one should be dropped from _EXPECTED_MODULES here"
    )
    assert total_sites >= _MEASURED_SITE_COUNT, (
        f"only {total_sites} CheckResult constructions found, fewer than the "
        f"{_MEASURED_SITE_COUNT} measured at 0343233 — the analysis, not the code, "
        "is probably what changed"
    )


_CLEAN_CONTROL = '''
from secure.checks.models import CheckResult, CheckStatus

def a():
    return CheckResult("n", CheckStatus.PASS, "all good")

def b():
    return CheckResult("n", CheckStatus.FAIL, "bad", "Turn it on.")

def c():
    return CheckResult("n", CheckStatus.WARNING, "hmm", remediation=f"Run `{TOOL}` yourself.")
'''

_DIRTY_CONTROL = '''
from secure.checks.models import CheckResult, CheckStatus

def a():
    return CheckResult("n", CheckStatus.PASS, "all good", "Nothing to do, but here is advice.")

def b():
    return CheckResult("n", CheckStatus.FAIL, "your disk is not encrypted")

def c():
    return CheckResult("n", CheckStatus.WARNING, "hmm", remediation=_ADVICE)

def d():
    return CheckResult("n", status_for(x), "hmm", "Do the thing.")
'''


def test_the_contract_check_actually_bites():
    """Positive control, in both directions.

    A whole-package static check over a tree that already complies
    passes exactly the same way whether it works or is a no-op, so the
    real assertion above cannot establish that the analysis functions.
    This pins it against source the test builds itself.
    """
    clean, clean_sites = _contract_violations(_CLEAN_CONTROL, "clean.py")
    assert clean == []
    assert clean_sites == 3

    dirty, dirty_sites = _contract_violations(_DIRTY_CONTROL, "dirty.py")
    assert dirty_sites == 4
    assert len(dirty) == 4, dirty

    joined = "\n".join(dirty)
    assert "PASS carries a remediation" in joined
    assert "FAIL has an empty remediation" in joined
    assert "remediation is not a resolvable literal" in joined
    assert "status is not a literal CheckStatus.X" in joined
