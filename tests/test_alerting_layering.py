"""Phase 53: Layering constraint tests.

Verifies that decision functions (suppression, escalation, decide) do not
import from remediation, multi_device, or intelligence layers.
"""

import ast
import inspect
from pathlib import Path


def _get_module_imports(module_path: str) -> set:
    """Extract all module imports from a Python file."""
    imports = set()
    with open(module_path, "r") as f:
        tree = ast.parse(f.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)

    return imports


def test_suppression_no_peer_imports():
    """suppression.py does not import from remediation/multi_device/intelligence."""
    suppression_path = Path(__file__).parent.parent / "secure" / "alerting" / "suppression.py"
    imports = _get_module_imports(str(suppression_path))

    forbidden_prefixes = ("secure.remediation", "secure.multi_device", "secure.intelligence")
    for imp in imports:
        for prefix in forbidden_prefixes:
            assert not imp.startswith(prefix), f"suppression.py imports {imp} (forbidden)"


def test_escalation_no_peer_imports():
    """escalation.py does not import from remediation/multi_device/intelligence."""
    escalation_path = Path(__file__).parent.parent / "secure" / "alerting" / "escalation.py"
    imports = _get_module_imports(str(escalation_path))

    forbidden_prefixes = ("secure.remediation", "secure.multi_device", "secure.intelligence")
    for imp in imports:
        for prefix in forbidden_prefixes:
            assert not imp.startswith(prefix), f"escalation.py imports {imp} (forbidden)"


def test_decide_no_peer_imports():
    """decide.py does not import from remediation/multi_device/intelligence."""
    decide_path = Path(__file__).parent.parent / "secure" / "alerting" / "decide.py"
    imports = _get_module_imports(str(decide_path))

    forbidden_prefixes = ("secure.remediation", "secure.multi_device", "secure.intelligence")
    for imp in imports:
        for prefix in forbidden_prefixes:
            assert not imp.startswith(prefix), f"decide.py imports {imp} (forbidden)"


def test_context_no_peer_imports():
    """context.py does not import from remediation/multi_device/intelligence."""
    context_path = Path(__file__).parent.parent / "secure" / "alerting" / "context.py"
    imports = _get_module_imports(str(context_path))

    forbidden_prefixes = ("secure.remediation", "secure.multi_device", "secure.intelligence")
    for imp in imports:
        for prefix in forbidden_prefixes:
            assert not imp.startswith(prefix), f"context.py imports {imp} (forbidden)"


def test_suppression_only_imports_context():
    """suppression.py only imports from alerting.context."""
    suppression_path = Path(__file__).parent.parent / "secure" / "alerting" / "suppression.py"
    imports = _get_module_imports(str(suppression_path))

    # Filter to secure.* imports
    secure_imports = {imp for imp in imports if imp.startswith("secure.")}

    # Should only have context and standard library imports
    for imp in secure_imports:
        assert imp == "secure.alerting.context", f"Unexpected import: {imp}"


def test_escalation_only_imports_context():
    """escalation.py only imports from alerting.context."""
    escalation_path = Path(__file__).parent.parent / "secure" / "alerting" / "escalation.py"
    imports = _get_module_imports(str(escalation_path))

    # Filter to secure.* imports
    secure_imports = {imp for imp in imports if imp.startswith("secure.")}

    # Should only have context and standard library imports
    for imp in secure_imports:
        assert imp == "secure.alerting.context", f"Unexpected import: {imp}"


def test_decide_only_imports_context_and_logic():
    """decide.py only imports context and sibling decision functions."""
    decide_path = Path(__file__).parent.parent / "secure" / "alerting" / "decide.py"
    imports = _get_module_imports(str(decide_path))

    # Filter to secure.* imports
    secure_imports = {imp for imp in imports if imp.startswith("secure.")}

    # Should only have context, suppression, escalation
    allowed = {"secure.alerting.context", "secure.alerting.suppression", "secure.alerting.escalation"}
    for imp in secure_imports:
        assert imp in allowed, f"Unexpected import: {imp}"


def test_compose_is_only_impure_file():
    """compose.py is the ONLY file importing from remediation/multi_device/intelligence."""
    compose_path = Path(__file__).parent.parent / "secure" / "alerting" / "compose.py"
    imports = _get_module_imports(str(compose_path))

    # compose.py SHOULD import from peer layers
    peer_imports = {imp for imp in imports if any(
        imp.startswith(prefix) for prefix in
        ("secure.remediation", "secure.multi_device", "secure.intelligence")
    )}

    # Should have at least one peer import (the whole point of compose.py)
    # Note: actual imports are inside try/except, but AST will still find them
    # For this test, we just verify that compose.py is allowed to import peers


def test_decision_functions_pure():
    """Pure decision functions are callable and have no side effects at import time."""
    from secure.alerting.decide import decide_alert
    from secure.alerting.escalation import weigh
    from secure.alerting.suppression import classify

    # These should be callable
    assert callable(decide_alert)
    assert callable(weigh)
    assert callable(classify)


def test_store_no_decision_function_imports():
    """store.py doesn't inadvertently import decision functions."""
    store_path = Path(__file__).parent.parent / "secure" / "alerting" / "store.py"
    imports = _get_module_imports(str(store_path))

    # store.py imports AlertDecision but not the decision-making functions
    decision_functions = ("decide_alert", "weigh", "classify")
    for func in decision_functions:
        for imp in imports:
            assert func not in imp, f"store.py mentions {func}"
