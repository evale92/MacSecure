"""
Truth-table sweep over every tri-state posture evaluator in secure/checks.

An evaluator whose inputs are `bool | None` has True/False for a value
it read and None for one it could not. Named test cases for such a
function tend to be the pure rows — all on, all off, all unknown — and
those read like complete coverage. The mixed rows are where a silent
clean pass hides: `_evaluate_automatic_updates(None, True)` once
returned PASS with a message asserting *both* settings were on, while
the strictly less informed `(None, None)` correctly warned (J-0232,
found by printing the cross product; J-0238 asked for it as a check).

So this file does not trust names. It discovers every function in
`secure/checks/*` whose parameters are all annotated `bool | None` and
which returns `CheckResult`, runs the full product of (True, False,
None) through it, and holds two rules on each row containing a None:

  1. it is never PASS — PASS asserts something about a value nobody
     read (invariant 5: no silent clean pass);
  2. it is never cleaner than the worst row it could have been had the
     unread values been read — not knowing may not look better than the
     bad answer it might be hiding.

Scope, stated rather than left to be found: discovery is by annotation.
An evaluator whose tri-state parameters are unannotated, or spelled
some way `_TRISTATE_SPELLINGS` does not list, is invisible here, which
is why the known evaluator is pinned below — if the matcher goes blind,
that assertion fails rather than the sweep passing over nothing.
"""

from __future__ import annotations

import importlib
import inspect
import itertools
import pkgutil

import secure.checks
from secure.checks.models import CheckResult, CheckStatus

_VALUES = (True, False, None)

# Annotation spellings that mean "a bool we may have failed to read",
# compared with whitespace removed. String forms because the check
# modules use `from __future__ import annotations` or quote them.
_TRISTATE_SPELLINGS = {"bool|None", "None|bool", "Optional[bool]", "typing.Optional[bool]"}

_SEVERITY = {CheckStatus.PASS: 0, CheckStatus.WARNING: 1, CheckStatus.FAIL: 2}

# Measured 2026-09-15 at f73557d: the only tri-state evaluator in the
# package. Asserted as a subset, not an exact set — a new one is swept
# automatically and needs no edit here.
_KNOWN_EVALUATORS = {"secure.checks.software_update._evaluate_automatic_updates"}


def _annotation_text(annotation) -> str:
    # A quoted annotation under `from __future__ import annotations` is
    # stored with its quotes: `"bool | None"` arrives as "'bool | None'".
    text = annotation if isinstance(annotation, str) else getattr(annotation, "__name__", repr(annotation))
    return "".join(text.split()).strip("'\"")


def _is_tristate(annotation) -> bool:
    return _annotation_text(annotation) in _TRISTATE_SPELLINGS


def _returns_check_result(annotation) -> bool:
    return annotation is CheckResult or _annotation_text(annotation) == "CheckResult"


def _tristate_evaluators() -> "dict[str, object]":
    """Qualified name -> function, for every tri-state evaluator in the package."""
    found: dict[str, object] = {}
    for info in pkgutil.iter_modules(secure.checks.__path__, prefix="secure.checks."):
        module = importlib.import_module(info.name)
        for name, fn in inspect.getmembers(module, inspect.isfunction):
            if fn.__module__ != module.__name__:
                continue
            signature = inspect.signature(fn)
            params = list(signature.parameters.values())
            if not params or not _returns_check_result(signature.return_annotation):
                continue
            if all(_is_tristate(p.annotation) for p in params):
                found[f"{module.__name__}.{name}"] = fn
    return found


def _unread_row_violations(fn, name: str = "evaluator") -> "list[str]":
    """Every row of `fn`'s truth table that breaks rule 1 or rule 2."""
    arity = len(inspect.signature(fn).parameters)
    table = {row: fn(*row).status for row in itertools.product(_VALUES, repeat=arity)}
    violations: list[str] = []

    for row, status in table.items():
        unread = [i for i, value in enumerate(row) if value is None]
        if not unread:
            continue
        if status == CheckStatus.PASS:
            violations.append(f"{name}{row}: PASS with an unread input")
            continue
        fillings = []
        for filled in itertools.product((True, False), repeat=len(unread)):
            candidate = list(row)
            for index, value in zip(unread, filled):
                candidate[index] = value
            fillings.append(table[tuple(candidate)])
        worst = max(fillings, key=_SEVERITY.__getitem__)
        if _SEVERITY[status] < _SEVERITY[worst]:
            violations.append(
                f"{name}{row}: {status.value} is cleaner than {worst.value}, "
                "which reading the unread input could have given"
            )
    return violations


def test_no_tristate_evaluator_is_cleaner_for_not_having_read_something():
    evaluators = _tristate_evaluators()

    assert _KNOWN_EVALUATORS <= set(evaluators), (
        f"discovery found {sorted(evaluators)}; a known tri-state evaluator is missing, "
        "so the annotation matcher, not the code, is probably what changed"
    )

    violations: list[str] = []
    for name, fn in sorted(evaluators.items()):
        violations.extend(_unread_row_violations(fn, name))
    assert violations == []


# ---------- positive controls ----------
#
# The sweep above passes identically over a package that complies and a
# sweep that checks nothing, so these pin both rules against evaluators
# the test builds itself.


def _result(status: CheckStatus) -> CheckResult:
    return CheckResult("control", status, "control", "" if status == CheckStatus.PASS else "do something")


def _control_both_must_be_on(a: "bool | None", b: "bool | None") -> CheckResult:
    if a is False or b is False:
        return _result(CheckStatus.WARNING)
    if a is None or b is None:
        return _result(CheckStatus.WARNING)
    return _result(CheckStatus.PASS)


def _control_pass_on_one_unread(a: "bool | None", b: "bool | None") -> CheckResult:
    # The pre-J-0232 shape: `and` where `or` belongs.
    if a is False or b is False:
        return _result(CheckStatus.WARNING)
    if a is None and b is None:
        return _result(CheckStatus.WARNING)
    return _result(CheckStatus.PASS)


def _control_unknown_softer_than_off(a: "Optional[bool]") -> CheckResult:
    if a is False:
        return _result(CheckStatus.FAIL)
    if a is None:
        return _result(CheckStatus.WARNING)
    return _result(CheckStatus.PASS)


def test_the_sweep_actually_bites():
    assert _unread_row_violations(_control_both_must_be_on) == []

    pass_rows = _unread_row_violations(_control_pass_on_one_unread)
    assert pass_rows == [
        "evaluator(True, None): PASS with an unread input",
        "evaluator(None, True): PASS with an unread input",
    ]

    softer = _unread_row_violations(_control_unknown_softer_than_off)
    assert softer == [
        "evaluator(None,): WARNING is cleaner than FAIL, which reading the unread input could have given"
    ]


def test_the_matcher_recognises_what_it_claims_to():
    for spelling in ("bool | None", "None | bool", "Optional[bool]", "bool|None", "'bool | None'"):
        assert _is_tristate(spelling), spelling
    for spelling in ("bool", "str | None", "int", inspect.Parameter.empty):
        assert not _is_tristate(spelling), spelling

    assert _returns_check_result("CheckResult")
    assert _returns_check_result("'CheckResult'")
    assert _returns_check_result(CheckResult)
    assert not _returns_check_result("list[CheckResult]")
