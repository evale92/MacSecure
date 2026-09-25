# CLAUDE.md

Navigation. **The rules are not in this file and must not be copied into it.**

Four documents are normative here, and each is deliberately sized to fit inside
the per-file excerpt budget that `secure/agent/context.py` applies when feeding
it into a repair prompt. Restating a rule here would put a second copy outside
that budget, where it can drift without anyone noticing which copy an agent
actually read.

- **[AGENTS.md](AGENTS.md)** — rules for automated coding agents. Read this
  first if you are one.
- **[SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md)** — properties held since
  the phase that introduced each. Weakening one is a `SECURITY_SEMANTIC_CHANGE`
  and needs explicit human approval *before* any code is written.
- **[ARCHITECTURE_RULES.md](docs/ARCHITECTURE_RULES.md)** — the normative subset of
  the structure. `docs/ARCHITECTURE.md` is the descriptive map.
- **[TESTING_POLICY.md](docs/TESTING_POLICY.md)** — how tests are written, named and
  trusted.

`CLAUDE.md` is **not** in `_POLICY_FILENAMES`, so nothing here reaches a repair
prompt. That is why this file can afford prose and those four cannot.

## Who governs a session here (directive 012)

AGENTS.md addresses Secure's **in-product** repair agent: the external
coding agent Secure itself runs in a worktree, whose patch becomes a
`PENDING` change bound to a diff hash. Its rules 2 and 10 (one failure,
do not commit) are the workflow of that loop, and the product enforces
them there.

A session dispatched by Agent's supervisor is governed on **workflow** —
task state, authorized scope, acceptance, retries, reviewer, whether a
turn commits — by `Agent/harness/AUTHORITY.md`. Nothing in this repository
redefines those. Closing a job is acceptance, so a session's own
measurement records evidence for the reviewer; it does not close the job.

What precedence does **not** move: every execution safeguard still binds
every session — AGENTS.md rules 1 and 3–9, all of SECURITY_INVARIANTS.md,
and the dispatch's own limits (no host-state change, no push, no touching
authorization code). Harness ownership is never a reason to weaken one.
The dated records below are kept as history, including where they cite
AGENTS.md as binding on a dispatched session.

## What this is

A **defensive** macOS security application, built in phases: configuration and
storage, then a point-in-time posture check (FileVault, firewall, Gatekeeper,
SIP, updates, sharing), then continuity snapshots, then local device inventory.
See `docs/OVERVIEW.md` for scope and phase coverage.

Everything it does is something you *request*. It is not a background watcher,
and the distinction is load-bearing rather than a caveat — no daemon, no sudo,
no autonomous changes.

## The two properties everything else is arranged around

Stated here because they explain why the code refuses things that look
harmless, not as a substitute for reading them in SECURITY_INVARIANTS.md:

1. **The deterministic engine is authoritative.** No model output is a
   detection authority. An LLM may explain, summarise or propose — never decide
   severity, never write a finding.
2. **No autonomous change, ever.** Automated code can only create a `PENDING`
   change request bound to an exact content hash. Approval is a human CLI
   action, and a model may *raise* a change's required approval level but never
   lower it.

## Working here

Agents work in an **isolated git worktree** and may not read or write any
absolute path outside it — not `~/.secure`, not the operator's real home.

The suite is large (104 test files) and slow. There is no virtualenv in this
repository; the run below used the interpreter from the Agent repository next
door.

**One invocation, recorded as an invocation rather than as a general fact**,
because a duration and an outcome only mean anything attached to what produced
them:

| | |
|---|---|
| revision | `2f8a18d` |
| command | `python -m pytest tests -q` from the repository root |
| interpreter | `~/Desktop/Agent/.venv/bin/python` (3.14.7) |
| date | 2026-09-10 |
| outcome | **5 failed, 2074 passed, 1 error** in 778.08s |

A separate earlier invocation is on record at 796.12s with the same failure
shape. Both stand; neither replaces the other. During this run I also read a
`pytest` process as still going past twenty minutes and said so — that was a
different process, and the number above is the one that came from this run's
own output.

**Superseded 2026-09-14 by a later invocation, recorded the same way:**

| | |
|---|---|
| revision | `ca5a54c` |
| command | `python -m pytest tests -q -p no:cacheprovider` from the repository root |
| interpreter | `~/Desktop/Agent/.venv/bin/python` (3.14.7) |
| date | 2026-09-14 |
| outcome | **2291 passed, 0 failed** in 802.66s |

The four failures that stood between (the yarax stub, the hardware seam, the
feature-maturity clock, reproduction's `.pytest_cache`) were repaired in
`feffc23`..`ca5a54c`. Each repair was then checked by a mutant that undoes the
behaviour it pins: each kills its own test and none of the other three, with
all four passing before and after. What follows is the 2026-09-10 picture,
kept because it is what the dispatcher still quotes.

**The suite was not green at `2f8a18d`.** That same run: `5 failed, 2074 passed, 1 error`.
Two were reproduced individually in under five seconds, so they are cheap to
look at and are not flakes:

- `test_failure_modes.py::test_main_reports_permission_denied_app_dir_cleanly`
  — expects `SystemExit(2)`, gets `SystemExit(0)`. **A permission-denied app
  directory currently exits zero.** In a security tool that is the worst shape
  of defect: a failure reporting success, which no caller can distinguish from
  the work having been done.
- `test_integrations_yarax.py::test_scan_paths_one_bad_ruleset_does_not_abort_others`
  — one bad ruleset produces two `ruleset_load_error` entries, not one. **This
  one is the test's own stub, not the scanner** (measured 2026-09-11, below).
- `test_agent_center.py::tests_report` errors during collection.

Recorded rather than repaired: AGENTS.md requires one reported failure at a
time in an isolated worktree, and that is a separate change from writing this
file. Anyone starting here should know the baseline is red before attributing
a failure to their own work — judging a candidate against a baseline nobody
measured is how a pre-existing failure gets charged to whoever touched the
code next.

## What the two cheap candidates turned out to be

Measured 2026-09-11 in the **live checkout** at `04f58a3`, same interpreter as
above. Both candidates were run alone first, which is the whole point of
running them alone:

**The permission-denied one now passes** — and not because anyone repaired it
under review. `secure/config.py` carries an *uncommitted* fix in the live
checkout: `load_config()` swapping `path.exists()` for `path.stat()` under
`except FileNotFoundError`, because `exists()` also returns `False` on
`PermissionError`, so an unreadable app dir looked absent and `save_config()`
wrote a default over it and exited 0. The diagnosis is right and the test goes
green with it. **It is committed in neither the live checkout nor the
`fix-permission-denied-app-dir-exit` worktree**, and a repair sitting in the
live checkout is what invariant 8 exists to prevent. Left in place, unstaged
and unclaimed, for a human: invariant 2 makes passing tests explicitly not
approval, so no agent gets to land it.

**The yarax one is a defect in the test, not in the scanner.** Its stub is
`if "bad" in origin: raise SyntaxError`, and `rulesets.py:108` passes
`origin=str(path)` — the full absolute path, which is correct, since yarax uses
origin to point error messages at a file. pytest hands the test a `tmp_path`
named `test_scan_paths_one_bad_rulese0`, which contains `bad`, so *every*
ruleset under it matches. The two rejected rulesets are `bad` and
`secure_test_ruleset` — the second is the good one, thrown out for its parent
directory's name. Re-run with only the directory renamed and nothing else
touched: `load_errors=1, loaded=1, findings=1, degraded` — all four assertions
hold. So the assertion is right, the scanner is right, and the stub
over-matches. Unrepaired on purpose: AGENTS.md rule 3 says that if the test
itself is wrong you say so and change nothing, and a test whose stub matches
its own scratch directory is a test that has never once exercised the scenario
it is named for.

## Both candidates re-measured at `310e338`, and what that cost

A supervisor started another unattended session on 2026-09-11 and offered the
same two candidates as work, quoting the 2026-09-10 baseline — the one the two
commits above already superseded at the very revision it dispatched against.
Run alone at `310e338`, same interpreter:

| candidate | result |
|---|---|
| `test_main_reports_permission_denied_app_dir_cleanly` | **1 passed in 0.42s** |
| `test_scan_paths_one_bad_ruleset_does_not_abort_others` | **1 failed in 0.20s**, rejected rulesets `['bad', 'secure_test_ruleset']` |

Unchanged, both of them, and neither is a repair to make: the first passes only
on the uncommitted `secure/config.py` edit described above, which is still
unstaged and still nobody's to land, and the second is the test defect.

One piece of evidence got stronger. The claim that pytest names the directory
`test_scan_paths_one_bad_rulese0` was previously read off pytest's naming rule;
running with `--basetemp` into a scratch directory and listing it puts the name
on disk, next to `test_scan_paths_one_bad_rulesecurrent`. A counterfactual
changing *only* that name reproduced both halves: `2 errors / 0 loaded / 0
findings` with `bad` in the directory name, `1 / 1 / 1` without it.

The measurement is cheap; re-deriving it for the third time is the expense.
What is missing is not a written record — this file is the written record, it
is correct, and it is committed — but anything that reads it before a failure
is handed out as work again.

## A fifth dispatch, and the first Study Mode finding

2026-09-11, `d90c68e`, same interpreter. The supervisor dispatched the same two
candidates a fifth time, again against the 2026-09-10 baseline. Run alone:
candidate 1 **passed in 0.42s**, candidate 2 **failed in 0.54s** with rejected
rulesets `['bad', 'secure_test_ruleset']`. Both unchanged; neither repaired,
for the reasons already written above. Nothing new was learned by re-running
them, which is the fifth time that sentence has been true.

The session's actual output is a Study Mode finding in
`secure_gui/baseline_view.py`, registered as job J-0162:

**`_mark()` ends in a no-op where the pattern it copies ends in a message.**
Line 388 is `overview_var.set(overview_var.get())` — a `StringVar` written back
to its own value. No `trace` is registered on it anywhere in the module; its
only other writers are `_reload` (327, 333) and its only reader the header
`Label` (162). So after the operator confirms "Mark Known", `secure anomalies
mark <id> known` is dispatched and the screen changes in no way: the row still
reads "— unreviewed", the button still reads "Mark Known", and nothing says the
view is now stale. `alerts_view.py:395` is the same line in the same position
and sets a real one: *"Sent — check Console in the main window for the result,
then Refresh."* The module docstring claims it "reuses the exact DataTable +
EvidencePanel pattern `secure_gui/alerts_view.py` already established".

The divergence is structural rather than a slip: `alerts_view` has a dedicated
`status_var` Label in its header (151-152); `baseline_view` has only
`overview_var`, carrying the multi-line overview, so there is no widget a
per-action status could go in. That is also why it was **left unfixed**. The
fix needs a new header widget, and no test here can execute it — this
project's interpreter has no `_tkinter`, so `baseline_view.py` cannot even be
imported, and invariant 7 says inconclusive is not a pass. Writing
user-visible behaviour that nothing in the environment can run is the shape of
change this repository is arranged to refuse.

**The score was also wrong about the file** (J-0163). "untested = no test names
it" can never be satisfied under `secure_gui/`: `docs/TESTING_POLICY.md` and
`targeted_test_files()` map every `secure_gui/*` path to `tests/test_gui*.py`,
never `tests/test_<module>.py`, and `tests/test_agent_tiers.py:139` asserts
exactly that. A `tests/test_baseline_view.py` would satisfy the score and
silently lose its TARGETED role. The file is not uncovered either:
`tests/test_agent_supervisor.py:332` rglobs `secure_gui/*.py` and `ast.parse`s
each for banned authorization imports, so it is syntax-checked and
invariant-3-checked on every run. The real gap is narrower than the score's
and the score does not name it — `_format_overview_text` and
`_format_evidence_panel_text` are pure, Tkinter-free, ~70 lines, and sit in a
module no test can import, which the module's own docstring forbids ("Keep
genuinely testable logic in `secure_gui/data_access.py` instead").

## Known boundary, stated by the project itself

`docs/SECURITY_INVARIANTS.md` records that there is **no OS-level sandbox** here.
That is written down as a limit rather than left for someone to discover, which
is the same discipline the rest of the project runs on: a gap that is named is
a decision, and a gap that is merely absent is an accident waiting to be found
by someone else.
