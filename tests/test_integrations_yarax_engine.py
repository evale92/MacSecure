"""
Tests for secure/integrations/yarax/_engine.py's scan timeout.

yara_x's Scanner.set_timeout() takes whole seconds and raises TypeError
for a float. scan_bytes() passed its float timeout straight through, so
every scan, and the availability self-check (timeout 5.0), failed with
"'float' object cannot be interpreted as an integer" on the target Mac
(yara-x 1.20.0). The rest of this integration's tests patch this seam,
which is how that went unnoticed; the last test here makes one real call.

Run with:  pytest tests/test_integrations_yarax_engine.py
"""

from __future__ import annotations

import sys
import types

import pytest

from secure.integrations.yarax import _engine


def _fake_yara_x(monkeypatch):
    seen = []

    class Scanner:
        def __init__(self, rules):
            self.rules = rules

        def set_timeout(self, seconds):
            if not isinstance(seconds, int):
                raise TypeError(f"'{type(seconds).__name__}' object cannot be interpreted as an integer")
            seen.append(seconds)

        def scan(self, data):
            return "scanned"

    monkeypatch.setitem(sys.modules, "yara_x", types.SimpleNamespace(Scanner=Scanner))
    return seen


def test_a_float_timeout_reaches_yara_x_as_whole_seconds(monkeypatch):
    seen = _fake_yara_x(monkeypatch)
    assert _engine.scan_bytes(object(), b"", timeout_seconds=5.0) == "scanned"
    assert seen == [5]


@pytest.mark.parametrize("given, expected", [(10.0, 10), (2.5, 3), (0.2, 1), (0, 1)])
def test_the_timeout_rounds_up_and_never_reaches_zero(monkeypatch, given, expected):
    # Rounding down could shorten the guard, and 0 may mean "no limit".
    seen = _fake_yara_x(monkeypatch)
    _engine.scan_bytes(object(), b"", timeout_seconds=given)
    assert seen == [expected]


def test_a_real_scan_with_a_float_timeout_returns():
    pytest.importorskip("yara_x")
    rules = _engine.compile_ruleset("rule never { condition: false }")
    assert _engine.scan_bytes(rules, b"", timeout_seconds=5.0) is not None
