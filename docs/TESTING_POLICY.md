# TESTING_POLICY.md

How tests are written, named, and trusted in this repository.

The numbered **Rules** below are complete and sized to fit inside the
per-file excerpt budget `secure/agent/context.py` applies when feeding
this file into a repair prompt. Everything after them is elaboration
and may be truncated, so no rule lives down there.

## Rules

1. **Never weaken a test to make it pass.** No deleting or loosening
   an assertion, no `skip`, no `xfail`, no widening a tolerance. If the
   test is right, fix the code. If you believe the test is wrong, say
   so and change nothing.
2. **One test file per module, named for it.** `tests/test_<module>.py`
   — the agent layer's targeted-test selection maps a changed file to
   `tests/test_<module>*.py`, so a misnamed file silently stops being
   targeted.
3. **Module-level `def test_*` functions only.** No test classes, no
   `conftest.py`. The only fixtures in use are `tmp_path`,
   `monkeypatch`, and `capsys`.
4. **Never touch real state.** Every test runs against `tmp_path` or a
   throwaway sandbox config — never the operator's real `~/.secure`,
   never real system locations, never the live database.
5. **No network.** A test that would make a live request must mock the
   seam instead. The suite has to pass on a machine with no
   connectivity and no optional tools installed.
6. **Deterministic and order-independent.** No dependence on wall-clock
   timing, ambient environment, or another test having run first. Undo
   every `monkeypatch` (the fixture does this) and leave no files
   behind.
7. **Mock at the established seam.** Patch the module's `_shell.py`
   (or its single subprocess function), not `subprocess.run` globally.
8. **Prefer a structural test over a comment.** Invariants that can be
   checked by parsing the source — import rules, banned calls, banned
   argv shapes — should be, so a future edit fails loudly.
9. **Test honest absence, not just the happy path.** For anything
   optional, assert that a missing tool yields
   `UNAVAILABLE`/`DEGRADED`/`ERROR` rather than a clean pass.
10. **Do not optimize tests to make Secure look good.** Record missed
    detections and known limitations as real outcomes. A scenario the
    project only partially handles stays in the catalog reporting a
    `MISS`.
11. **Every phase adds tests, and the full suite must be green.** A
    phase is marked VERIFIED only when its stated acceptance criteria
    actually pass and the whole suite reports 0 failed, 0 errors.
12. **Assert on behavior, not on prose.** Do not assert against a
    docstring or a log message that merely claims a property holds.

---

## Why rule 1 is the load-bearing one

The autonomous repair loop's only deterministic signal is "the tests
pass." If a coding agent — or a human in a hurry — can make a failure
disappear by editing the test, verification stops meaning anything and
every downstream guarantee built on it collapses. This is why it is
also rule 3 in `AGENTS.md` and why it appears in the repair prompt
itself.

## The naming rule has teeth

`targeted_test_files()` in `secure/agent/tiers.py` maps
`secure/<package>/anything.py` to `tests/test_<package>*.py`, a leaf
`secure/<module>.py` to `tests/test_<module>*.py`, and anything under
`secure_gui/` to `tests/test_gui*.py`. A test file that does not follow
the convention still runs in the full suite, but will never be picked
by the TARGETED tier — it quietly loses its fast-feedback role.

## Running the suite

`python3 -m pytest` from the project root is the normal path. Some
development sandboxes used for this project have no real pytest and no
package-install access; in those, a minimal harness supporting exactly
the feature surface above (module-level test functions, `tmp_path`,
`monkeypatch`, `capsys`, `pytest.raises`) is used instead, and the pass
count is reported the same way. That harness is scratch tooling and is
deliberately not committed to this repository — rule 3 above is what
keeps the suite runnable by both.
