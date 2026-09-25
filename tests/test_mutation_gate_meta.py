"""Meta-test for mutation gate suite integrity.

Checks A–D from GATE-REMEDIATION-WORKORDER.md.
These are static AST/grep checks (sub-second). They must fail on the current
broken tree and pass after all 12 items are fixed.

Rule 3 compliant: module-level test_* functions only, no classes.
"""

import ast
import subprocess
import sys
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_FILES = [
    REPO_ROOT / "tests/integration/test_mutation_gates.py",
    REPO_ROOT / "tests/integration/test_dashboard_mutation_gates.py",
    REPO_ROOT / "tests/integration/test_automation_mutation_gates.py",
]

GATE_PATTERN = re.compile(r"def (test_gate\w+)\(")
SENTINEL_PATTERN = re.compile(r"GATE\w+")
STUB_READ_PATTERN = re.compile(r'os\.environ\.get\("(SECURE_STUB_\w+)"\)')
STUB_SET_PATTERN = re.compile(r'env\["(SECURE_STUB_\w+)"\]\s*=')
ABSOLUTE_PATH_PATTERN = re.compile(r'cwd\s*=\s*"[/a-zA-Z]')


def _read_all_gate_files():
    """Read all gate files as single text blocks."""
    return {str(f): f.read_text() for f in GATE_FILES if f.exists()}


def _read_all_product_files():
    """Read product code that might read stubs."""
    product_root = REPO_ROOT / "secure"
    files = {}
    for py_file in product_root.rglob("*.py"):
        files[str(py_file)] = py_file.read_text()
    return files


def _read_all_test_files():
    """Read all test files (checking for in-test stubs and sentinels)."""
    test_root = REPO_ROOT / "tests"
    files = {}
    for py_file in test_root.rglob("*.py"):
        files[str(py_file)] = py_file.read_text()
    return files


def test_check_a_every_gate_has_assertion():
    """CHECK A: Every gate function must contain an assert or raise.

    Catches empty gate functions (item 1).
    """
    gate_files = _read_all_gate_files()
    failures = []

    for filepath, content in gate_files.items():
        # Find all gate functions
        gate_names = GATE_PATTERN.findall(content)

        for gate_name in gate_names:
            # Extract the function body
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == gate_name:
                    # Check for assert or raise statements
                    has_assertion = False
                    for child in ast.walk(node):
                        if isinstance(child, (ast.Assert, ast.Raise)):
                            has_assertion = True
                            break

                    if not has_assertion:
                        failures.append(f"{filepath}::{gate_name}")

    assert not failures, (
        f"CHECK A FAILED: Gate functions with no assertion:\n" +
        "\n".join(f"  FAIL {f}" for f in failures)
    )


def test_check_b_all_stubs_read_in_product():
    """CHECK B: Every SECURE_STUB_* set by a gate must be read in product code.

    Catches unread stubs (item 3), fixture stubs (item 11), and in-test stubs (item 4).
    Product-only ruling: fixtures are NOT an acceptable location.
    """
    gate_files = _read_all_gate_files()
    product_files = _read_all_product_files()
    test_files = _read_all_test_files()

    # Collect all stubs set by gates
    stubs_set_by_gates = set()
    for content in gate_files.values():
        matches = STUB_SET_PATTERN.findall(content)
        stubs_set_by_gates.update(matches)

    # Collect stubs read in product (not fixtures, not tests)
    product_reads = {}
    for filepath, content in product_files.items():
        if "tests/" not in filepath and "fixtures" not in filepath:
            matches = STUB_READ_PATTERN.findall(content)
            for stub in matches:
                product_reads[stub] = filepath

    # Collect all reads (for violation report)
    fixture_reads = {}
    test_reads = {}
    for filepath, content in test_files.items():
        if "fixtures" in filepath:
            matches = STUB_READ_PATTERN.findall(content)
            for stub in matches:
                fixture_reads[stub] = filepath
        elif "test_" in filepath and "integration" not in filepath:
            matches = STUB_READ_PATTERN.findall(content)
            for stub in matches:
                test_reads[stub] = filepath

    failures = []
    for stub in sorted(stubs_set_by_gates):
        if stub in product_reads:
            # OK — read in product
            pass
        elif stub in fixture_reads:
            # VIOLATION — fixture is not product
            failures.append(f"{stub}: VIOLATION (fixture: {fixture_reads[stub]})")
        elif stub in test_reads:
            # VIOLATION — read in test under gate
            failures.append(f"{stub}: VIOLATION (read in test: {test_reads[stub]})")
        else:
            # VIOLATION — not read anywhere
            failures.append(f"{stub}: VIOLATION (no reader anywhere)")

    assert not failures, (
        f"CHECK B FAILED: Stub violations:\n" +
        "\n".join(f"  {f}" for f in failures)
    )


def test_check_c_no_dead_sentinels():
    """CHECK C: No dead GATE* sentinels.

    Any GATE* string used as the left operand of 'in' (i.e., searched for in
    subprocess output) must be emitted somewhere outside the gate file.
    """
    gate_files = _read_all_gate_files()
    test_files = _read_all_test_files()

    # Collect sentinels searched for in each gate file
    searched_sentinels = {}
    for filepath, content in gate_files.items():
        # Find strings that are searched for: `if "GATE..." in result.stdout`
        for match in re.finditer(r'"(GATE\w+)"\s+in\s', content):
            sentinel = match.group(1)
            if sentinel not in searched_sentinels:
                searched_sentinels[sentinel] = []
            searched_sentinels[sentinel].append(filepath)

    # Collect sentinels emitted in test files OR product files
    emitted_sentinels = set()
    product_files = _read_all_product_files()

    # Check test files
    for filepath, content in test_files.items():
        # Find strings that look like GATE sentinels
        for match in re.finditer(r'\b(GATE\w+)\b', content):
            sentinel = match.group(1)
            # Only count if it's in an assert message or print (not in the assert checking for it)
            if "GATE" in sentinel and "gate" not in filepath.lower():
                emitted_sentinels.add(sentinel)

    # Check product files (sentinels in error messages)
    for filepath, content in product_files.items():
        for match in re.finditer(r'\b(GATE_\w+)\b', content):
            sentinel = match.group(1)
            emitted_sentinels.add(sentinel)

    failures = []
    for sentinel, searched_in in searched_sentinels.items():
        if sentinel not in emitted_sentinels:
            failures.append(f"searches {sentinel:<30} DEAD (nothing emits it)")

    assert not failures, (
        f"CHECK C FAILED: Dead sentinels:\n" +
        "\n".join(f"  {f}" for f in failures)
    )


def test_check_d_no_absolute_hardcoded_paths():
    """CHECK D: No absolute hardcoded cwd paths.

    Catches hardcoded `/Users/erickvale/...` paths (item 7).
    """
    gate_files = _read_all_gate_files()
    failures = []

    for filepath, content in gate_files.items():
        for i, line in enumerate(content.splitlines(), 1):
            if ABSOLUTE_PATH_PATTERN.search(line):
                failures.append(f"{filepath}:{i}")

    assert not failures, (
        f"CHECK D FAILED: Absolute paths found:\n" +
        "\n".join(f"  {f}" for f in failures)
    )


def test_structural_rule_returncode_check():
    """Structural rule: Every gate must check returncode (== 0 or != 0).

    Catches gates that don't verify test exit status.
    """
    gate_files = _read_all_gate_files()
    failures = []

    for filepath, content in gate_files.items():
        gate_names = GATE_PATTERN.findall(content)

        for gate_name in gate_names:
            # Find returncode checks in the gate
            if f"def {gate_name}" in content:
                # Extract function body using regex
                func_match = re.search(
                    rf"def {gate_name}\(.*?\):(.*?)(?=\n    def |\nclass |\Z)",
                    content,
                    re.DOTALL
                )

                if func_match:
                    func_body = func_match.group(1)
                    # Check for returncode assertion
                    has_check = re.search(r"returncode\s*[!=]=\s*0", func_body) is not None

                    if not has_check:
                        failures.append(f"{filepath}::{gate_name}")

    assert not failures, (
        f"STRUCTURAL RULE FAILED: Gates without returncode check:\n" +
        "\n".join(f"  {f}" for f in failures)
    )


def test_check_e_gates_persist_in_git_history():
    """CHECK E: Gate functions mentioned in git history still exist.

    Prevents accidental deletion of gates to hide failing tests.
    A gate may never be deleted to make the suite pass.
    """
    import subprocess

    gate_files = _read_all_gate_files()
    current_gates = set()

    for filepath, content in gate_files.items():
        gate_names = GATE_PATTERN.findall(content)
        for gate_name in gate_names:
            current_gates.add(gate_name)

    # Check git log for gate function names
    result = subprocess.run(
        ["git", "log", "--pretty=%B", "-S", "test_gate", "--", "tests/integration/"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )

    if result.returncode != 0:
        # If git fails, skip this check gracefully
        return

    git_log = result.stdout
    # Find all test_gate* references in commit messages
    mentioned_gates = set(re.findall(r"(test_gate\w+)", git_log))

    # Also check for gates added/removed in patches
    result = subprocess.run(
        ["git", "log", "-p", "--", "tests/integration/test_*_mutation_gates.py"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )

    if result.returncode == 0:
        # Find removed gate functions (lines starting with -)
        for match in re.finditer(r"-\s*def (test_gate\w+)\(", result.stdout):
            mentioned_gates.add(match.group(1))

    deleted_gates = mentioned_gates - current_gates

    assert not deleted_gates, (
        f"CHECK E FAILED: Gates deleted after being in git history:\n" +
        "\n".join(f"  {g}" for g in sorted(deleted_gates))
    )
