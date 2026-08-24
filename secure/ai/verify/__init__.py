"""
secure/ai/verify/ — Phase 28 Stage 6: the constrained verification mode
the governing instruction requires:

    "Also add a constrained verification mode that can safely: inspect
    project files, inspect tests, run pytest, run existing validation
    suites, run synthetic scanner fixtures, compare expected versus
    observed results, inspect coverage and sensor health. Do not give
    the models unrestricted shell access."

    "The deterministic test framework decides PASS or FAIL. The LLM
    only explains the result."

This package is the ONLY way anything in secure/ai/ (a model, a change
request, a human via the CLI) is allowed to touch project files or run
project tests. It enforces four hard rules:

1.  FIXED OPERATION ENUM ONLY. There is no "run this shell command"
    operation, and there never will be — see `operations.VALID_OPERATIONS`.
    A caller (including an LLM, whose output is never trusted as
    executable) can only ever request one of these named, structured
    operations. Anything else is rejected before it runs, not after.

2.  NO SHELL, NO ARBITRARY ARGV. The one operation that spawns a
    subprocess (`run_pytest`) always calls `subprocess.run([...])` with
    a fixed, code-constructed argv list — never `shell=True`, never a
    caller-supplied command string. Every subprocess call has a hard
    timeout and a `cwd` pinned to the project root.

3.  FILE ACCESS IS READ-ONLY AND SANDBOXED TO THE PROJECT ROOT.
    `read_file` resolves every path against the actual project root,
    rejects `..`/absolute escapes (including via symlinks — the
    resolved path is re-checked after resolution), rejects a small
    denylist of sensitive extensions (databases, keys, certs, env
    files), and caps how many bytes it will ever return. Nothing in
    this package ever opens a file for writing.

4.  MECHANISM STATUS IS NOT THE SAME THING AS A VERDICT. Every
    operation reports its own `status` — ok / unavailable / timeout /
    error — describing whether the operation itself ran cleanly. The
    actual deterministic PASS/FAIL verdict (a validation scenario's
    outcome, whether pytest's tests passed) lives inside that
    operation's `output` dict. This split matters: a verification run
    where every test failed is still a successful, informative
    verification run (status="ok", the AI has real information to
    report), not a broken one. Nothing in this package, and nothing
    upstream of it, is allowed to blur that line by making a failing
    test result look like an operational error or vice versa.

Nothing in this package ever modifies real host state, kills a
process, writes a file, creates persistence, or touches anything
outside a throwaway `secure.validate.sandbox.sandbox()` /
subprocess sandbox of its own. It is exactly as safe to run
unattended as `secure validate run` already is (Phase 27) — because
for validation-suite and scenario operations, it just calls that same
code.
"""
