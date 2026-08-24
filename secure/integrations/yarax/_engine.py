"""
integrations/yarax/_engine.py — the ONLY place this integration touches
the actual `yara_x` library (mirrors every other package's own
subprocess-isolation convention — e.g. secure/listening/_shell.py — just
for an in-process library call instead of a subprocess, the same
"lazy import behind one seam function" pattern secure/bluetooth/ble/
scanner.py already uses for `bleak`).

`yara_x` is imported lazily INSIDE each function here, never at module
load time, so this module (and everything that imports it) can still be
imported and unit-tested on a machine/sandbox without yara_x installed
— tests patch these seam functions directly rather than needing the
real library, the exact same reasoning ble/scanner.py's own docstring
gives for lazily importing `bleak` inside `_discover()`.

Every function here either returns a plain value or raises — callers
(availability.py, scanner.py) are responsible for catching exceptions
and turning them into IntegrationHealth/observation-level unavailable/
error states. Nothing here decides severity, confidence, or whether a
match means anything — this file only runs the engine.
"""

from __future__ import annotations


def engine_version() -> "str | None":
    """The installed yara_x library's own version string, or None if it
    can't be determined (the attribute is missing) — never fabricated.
    Raises ImportError if yara_x isn't installed at all; callers decide
    how to classify that.
    """
    import yara_x  # noqa: PLC0415 - deliberately lazy, see module docstring

    return getattr(yara_x, "__version__", None)


def compile_ruleset(source: str, origin: "str | None" = None):
    """Compile one ruleset's YARA-X source text into a scannable Rules
    object. Raises on a genuine syntax/compile error — callers report
    that as this ruleset's own error, never silently skip it.
    """
    import yara_x  # noqa: PLC0415 - deliberately lazy, see module docstring

    compiler = yara_x.Compiler()
    if origin is not None:
        compiler.add_source(source, origin=origin)
    else:
        compiler.add_source(source)
    return compiler.build()


def scan_bytes(rules, data: bytes, timeout_seconds: float):
    """Scan `data` against an already-compiled Rules object, returning
    yara_x's own ScanResults (duck-typed by parser.py — see that
    module for the exact shape expected). A bounded timeout is applied
    when the installed yara_x build supports it (`Scanner.set_timeout`)
    — pattern-matching against attacker-crafted or pathological input is
    exactly the kind of thing that can run away, and Phase 16's
    instruction is explicit about safe timeout handling. If the
    installed version doesn't expose `set_timeout`, the scan still runs
    (no silent skip), just without that extra guard — the caller-side
    per-file wall-clock budget in scanner.py is the backstop either way.
    """
    import yara_x  # noqa: PLC0415 - deliberately lazy, see module docstring

    scanner = yara_x.Scanner(rules)
    set_timeout = getattr(scanner, "set_timeout", None)
    if callable(set_timeout):
        set_timeout(timeout_seconds)
    return scanner.scan(data)
