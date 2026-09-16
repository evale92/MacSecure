"""Structural enforcement of ARCHITECTURE_RULES.md rule 6.

Rule 6: "Every subprocess call goes through a seam. A module's
`_shell.py` (or the equivalent single function), always fixed-argv,
always `shell=False`, always timeout-bound, so tests can mock the one
call site."

That rule closes with its own admission: "Rule 6's `shell=False`
discipline is currently held by convention and code review rather than
by a structural test. That is a known gap, not a statement that the
rule is optional." SECURITY_INVARIANTS.md says the same thing about
any invariant held by design alone — "that is worth a test, not a
shrug — but adding one belongs in its own change". This file is that
change, and TESTING_POLICY.md rule 8 names its shape: "banned calls,
banned argv shapes" should be checked by parsing the source.

Why this one is worth parsing for rather than reviewing for. A single
`shell=True` turns a fixed argv into a string the system shell
re-parses, so any attacker-influenced value in it — a device name from
`arp`, a process path from `ps`, a filename from a launch plist, all
things this app reads off an untrusted machine by design — becomes
command injection. Every one of this codebase's sensors feeds exactly
that kind of value into its seam. The property is cheap to hold and
catastrophic to lose quietly, which is the profile of a thing that
should fail loudly at test time instead of at review time.

What this file does NOT establish, stated so a pass is not read for
more than it earns:

- It is a *syntactic* check. `shell=SOME_FLAG` is rejected because the
  value is not a literal `False`, but a runner reached through an
  indirection this file cannot see (`fn = subprocess.run; fn(...)`) is
  invisible to it. It catches the shape an edit actually introduces.
- It has no TARGETED tier role. `targeted_test_files()` maps
  `secure/<package>/*.py` to `tests/test_<package>*.py`, so no single
  filename can be targeted by a change to all fifteen seam modules.
  Like the other repo-wide static checks in
  `tests/test_clean_install.py`, this one runs in the full suite only.
  Named for the property rather than for a module because there is no
  one module it belongs to.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Runners that accept a `timeout=` deadline and an explicit `shell=`.
# Rule 6's three properties are checked against each of these.
_TIMEOUT_CAPABLE_RUNNERS = frozenset(
    {"run", "call", "check_call", "check_output"}
)

# `Popen` is a runner whose deadline lives on a later `.wait()` /
# `.communicate()` call rather than on the construction site, so rule
# 6's "always timeout-bound" cannot be read off it here. There are
# none in the tree today; one added later should fail loudly and be
# decided by a human rather than pass silently.
_UNBOUNDED_RUNNERS = frozenset({"Popen"})

# Helpers that hand the string to a shell by construction. No keyword
# makes these fixed-argv, so they are banned outright rather than
# checked.
_SHELL_INVOKING = {
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("os", "system"),
    ("os", "popen"),
}


def _string_shaped(node: ast.AST) -> bool:
    """True if `node` is an argv that a shell would have to re-parse.

    A list, a tuple, or a name is fine — those are fixed argv. A bare
    string, an f-string, a `+` concatenation, a `%` format, or a
    `.format()` call is the injection shape rule 6 exists to forbid,
    even with `shell=False`, where it silently means "run the single
    file at this exact path" instead.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):  # f"..."
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("format", "join"):
            return True
    return False


def subprocess_violations(source: str, filename: str) -> "list[str]":
    """Every rule-6 violation in `source`, as readable strings.

    Returns a list rather than a bool so a failure names the file, the
    line, and which of the three properties was lost — and so the
    positive control below can assert on *which* violation was found,
    not merely that the count was non-zero.

    Resolves runners through both import shapes, because a ban list is
    only as strong as the call syntax it matches: `import subprocess`
    plus `subprocess.run(...)`, `import subprocess as sp` plus
    `sp.run(...)`, and `from subprocess import run` plus `run(...)` all
    have to resolve to the same runner or the check has a hole an
    ordinary edit walks straight through.
    """
    tree = ast.parse(source, filename=filename)

    # alias -> real module name, for `import subprocess as sp`
    module_aliases: "dict[str, str]" = {}
    # local name -> (module, attr), for `from subprocess import run`
    imported_runners: "dict[str, tuple[str, str]]" = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("subprocess", "os"):
                    module_aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module in ("subprocess", "os"):
                for alias in node.names:
                    imported_runners[alias.asname or alias.name] = (
                        node.module,
                        alias.name,
                    )

    violations: "list[str]" = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        resolved: "tuple[str, str] | None" = None
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = module_aliases.get(func.value.id)
            if module is not None:
                resolved = (module, func.attr)
        elif isinstance(func, ast.Name):
            resolved = imported_runners.get(func.id)

        if resolved is None:
            continue
        module, attr = resolved
        where = f"{filename}:{node.lineno}"

        if (module, attr) in _SHELL_INVOKING:
            violations.append(f"{where}: {module}.{attr} runs a shell by construction")
            continue

        if module != "subprocess":
            continue

        if attr in _UNBOUNDED_RUNNERS:
            violations.append(
                f"{where}: subprocess.{attr} has no timeout at the call site"
            )
            continue

        if attr not in _TIMEOUT_CAPABLE_RUNNERS:
            continue

        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        shell = keywords.get("shell")
        if shell is not None and not (
            isinstance(shell, ast.Constant) and shell.value is False
        ):
            violations.append(
                f"{where}: shell={ast.unparse(shell)} is not a literal False"
            )

        if "timeout" not in keywords:
            violations.append(f"{where}: subprocess.{attr} call is not timeout-bound")

        argv = node.args[0] if node.args else keywords.get("args")
        if argv is not None and _string_shaped(argv):
            violations.append(
                f"{where}: argv {ast.unparse(argv)!r} is a string, not a fixed argv list"
            )

    return violations


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _source_files() -> "list[Path]":
    """Every source file the rule applies to.

    Deliberately no exclusions. The write-path check in
    `test_clean_install.py` has to exempt `secure/validate/` for its
    tempfile-sandboxed fixtures; rule 6 has no such carve-out, and a
    check with an empty exclusion list cannot be widened by adding a
    directory to one.
    """
    return [
        path
        for path in sorted((_project_root() / "secure").rglob("*.py"))
        if "__pycache__" not in path.parts
    ]


def test_every_subprocess_call_is_fixed_argv_shell_false_and_timeout_bound():
    """The rule-6 check itself, over every file under `secure/`.

    Measured when this was written: 28 call sites across 15 modules,
    all of them clean — the 14 `_shell.py`-style seams omit `shell`
    entirely (defaulting to False) and pass `timeout`; the 14 sites in
    the agent and AI layers pass `shell=False` explicitly and pass
    `timeout`. The rule was already held. This makes losing it fail.
    """
    offending: "list[str]" = []
    for path in _source_files():
        offending.extend(
            subprocess_violations(
                path.read_text(encoding="utf-8", errors="ignore"),
                str(path.relative_to(_project_root())),
            )
        )

    assert offending == []


def test_the_subprocess_seam_check_detects_each_real_violation():
    """Positive control for the test above.

    The scanned tree is clean, so `offending == []` there passes
    identically whether the analysis works or is a no-op that returns
    an empty list for everything. This pins both directions against
    source it constructs itself: each violation shape is caught exactly
    once, and the clean shapes the codebase actually uses are not
    flagged.
    """
    caught = {
        "shell=True": "import subprocess\nsubprocess.run(argv, shell=True, timeout=5)",
        "shell via variable": (
            "import subprocess\nsubprocess.run(argv, shell=FLAG, timeout=5)"
        ),
        "no timeout": "import subprocess\nsubprocess.run(argv, shell=False)",
        "f-string argv": (
            'import subprocess\nsubprocess.run(f"ps -p {pid}", shell=False, timeout=5)'
        ),
        "concatenated argv": (
            'import subprocess\nsubprocess.run("ps -p " + pid, shell=False, timeout=5)'
        ),
        "os.system": 'import os\nos.system("ps aux")',
        "os.popen": 'import os\nos.popen("ps aux").read()',
        "getoutput": 'import subprocess\nsubprocess.getoutput("ps aux")',
        "Popen": "import subprocess\nsubprocess.Popen(argv)",
        # The import-shape holes a ban list normally has: an aliased
        # module and a from-import both have to resolve to the runner.
        "aliased module": (
            "import subprocess as sp\nsp.run(argv, shell=True, timeout=5)"
        ),
        "from-import": "from subprocess import run\nrun(argv, shell=True, timeout=5)",
        "from-import os.system": 'from os import system\nsystem("ps aux")',
    }
    for label, source in caught.items():
        found = subprocess_violations(source, "probe.py")
        assert len(found) == 1, f"{label}: expected exactly one violation, got {found}"

    clean = (
        "import subprocess\n"
        # the seam modules' shape: shell omitted, timeout bound, argv a name
        "subprocess.run(args, capture_output=True, text=True, timeout=timeout)\n"
        # the agent layer's shape: shell=False explicit
        "subprocess.run(argv, capture_output=True, shell=False, timeout=30)\n"
        # a list literal argv with an interpolated *element* is fixed argv:
        # the f-string is one argument, not a command line
        "subprocess.run(['git', 'log', f'-{n}'], shell=False, timeout=5)\n"
        # argv passed by keyword rather than positionally
        "subprocess.run(args=argv, shell=False, timeout=5)\n"
        # unrelated calls that merely share a name with a runner
        "logger.run(x)\n"
        "os.path.join(a, b)\n"
    )
    assert subprocess_violations(clean, "probe.py") == []


def test_the_seam_check_actually_walks_a_populated_source_tree():
    """Guards the walk, which the positive control above cannot reach.

    `subprocess_violations` can be perfect and this suite still prove
    nothing if `_source_files()` silently returns an empty list — a
    typo in the directory name, a `rglob` pattern that matches no file,
    or a future exclusion that swallows the tree all look exactly like
    a clean repository. Pinning a floor and a known member makes the
    empty-walk failure mode distinguishable from a pass.
    """
    files = _source_files()
    names = {path.name for path in files}

    assert len(files) > 100, f"walk collapsed to {len(files)} files"
    assert "_shell.py" in names, "the seam modules themselves are not being scanned"
    assert not any("__pycache__" in path.parts for path in files)
