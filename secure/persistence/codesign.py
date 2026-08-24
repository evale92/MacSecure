"""
persistence/codesign.py — best-effort code-signing identification via
`codesign -dv --verbose=2 <path>`, Apple's own standard, read-only,
no-sudo tool for checking a binary's signature. "Where practical" per
this phase's own spec: this only ever inspects a bounded, small number
of executables per scan (new processes, plus every persistence entry's
program) — never the full process table — see scanner.py for why.

**Important note on exit codes, since it trips up a naive
implementation:** `codesign` returns a NONZERO exit code for an
unsigned binary — that's not a failure, it's the actual, useful answer
("this isn't signed"). This module deliberately does NOT treat a
nonzero return code as "codesign failed to run" (unlike this package's
own `_shell.run()`, whose generic `ok` field means exactly that, for
every OTHER caller in this app). Instead, `classify_signing()` always
inspects the actual output text, and only reports "unknown" when
`returncode is None` — the one signal `ShellResult` already gives us
for "the command genuinely never ran" (not found, or timed out) —
never for "ran and returned nonzero."

`codesign -dv` writes its human-readable summary to STDERR, not
stdout (a long-standing codesign quirk) — this module checks both
streams so it isn't caught out if that ever differs.
"""

from __future__ import annotations

from secure.persistence._shell import run

SIGNED_APPLE = "signed_apple"
SIGNED_DEVELOPER = "signed_developer"
SIGNED_ADHOC = "signed_adhoc"
UNSIGNED = "unsigned"
UNKNOWN = "unknown"


def classify_signing(stdout: str, stderr: str, returncode: "int | None") -> str:
    """Classify a `codesign -dv --verbose=2` result into one of:

        signed_apple      - signed directly by Apple (system binaries)
        signed_developer   - signed with a Developer ID (normal
                             notarized third-party software)
        signed_adhoc       - technically "signed" but with no chain of
                             trust at all (ad-hoc signature) — common
                             for locally-built tools and scripts, but
                             also trivial for anything (including
                             malware) to produce, so treated as
                             alert-worthy just like unsigned
        unsigned           - confirmed not signed at all
        unknown            - codesign itself never ran (not found,
                             timed out) — NOT the same as "unsigned";
                             never treated as a confirmed negative
    """
    if returncode is None:
        return UNKNOWN

    combined = f"{stdout}\n{stderr}"

    if "code object is not signed" in combined or "not signed at all" in combined:
        return UNSIGNED

    if "Authority=" in combined:
        if "Developer ID Application" in combined:
            return SIGNED_DEVELOPER
        if "Apple Root CA" in combined or "Software Signing" in combined:
            return SIGNED_APPLE
        # Signed, with an authority chain, but not one of the two
        # patterns above (e.g. an enterprise/internal distribution
        # certificate) — genuinely signed with a real chain of trust,
        # closer in spirit to a developer-signed binary than to
        # unsigned/ad-hoc, so classified the same way.
        return SIGNED_DEVELOPER

    if "Signature=adhoc" in combined:
        return SIGNED_ADHOC

    return UNKNOWN


def check_code_signing(path: str) -> str:
    """Run `codesign -dv --verbose=2` on one executable path and
    return its classification. Never raises; an executable that no
    longer exists, isn't a Mach-O binary, or any other codesign error
    still gets a best-effort classification from whatever output
    codesign produced (typically UNSIGNED for "not signed" errors) —
    only a genuine inability to run codesign at all comes back UNKNOWN.
    """
    result = run(["codesign", "-dv", "--verbose=2", path], timeout=5.0)
    return classify_signing(result.stdout, result.stderr, result.returncode)
