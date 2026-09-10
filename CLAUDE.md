# CLAUDE.md

Navigation. **The rules are not in this file and must not be copied into it.**

Four documents are normative here, and each is deliberately sized to fit inside
the per-file excerpt budget that `secure/agent/context.py` applies when feeding
it into a repair prompt. Restating a rule here would put a second copy outside
that budget, where it can drift without anyone noticing which copy an agent
actually read.

- **[AGENTS.md](AGENTS.md)** — rules for automated coding agents. Read this
  first if you are one.
- **[SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md)** — properties held since
  the phase that introduced each. Weakening one is a `SECURITY_SEMANTIC_CHANGE`
  and needs explicit human approval *before* any code is written.
- **[ARCHITECTURE_RULES.md](ARCHITECTURE_RULES.md)** — the normative subset of
  the structure. `docs/ARCHITECTURE.md` is the descriptive map.
- **[TESTING_POLICY.md](TESTING_POLICY.md)** — how tests are written, named and
  trusted.

`CLAUDE.md` is **not** in `_POLICY_FILENAMES`, so nothing here reaches a repair
prompt. That is why this file can afford prose and those four cannot.

## What this is

A **defensive** macOS security application, built in phases: configuration and
storage, then a point-in-time posture check (FileVault, firewall, Gatekeeper,
SIP, updates, sharing), then continuity snapshots, then local device inventory.
[PROJECT_NOTES.md](PROJECT_NOTES.md) has the phase-by-phase detail.

Everything it does is something you *request*. It is not a background watcher,
and the distinction is load-bearing rather than a caveat — see "What's
deliberately NOT here yet" in PROJECT_NOTES.

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

**The suite is not green.** That same run: `5 failed, 2074 passed, 1 error`.
Two were reproduced individually in under five seconds, so they are cheap to
look at and are not flakes:

- `test_failure_modes.py::test_main_reports_permission_denied_app_dir_cleanly`
  — expects `SystemExit(2)`, gets `SystemExit(0)`. **A permission-denied app
  directory currently exits zero.** In a security tool that is the worst shape
  of defect: a failure reporting success, which no caller can distinguish from
  the work having been done.
- `test_integrations_yarax.py::test_scan_paths_one_bad_ruleset_does_not_abort_others`
  — one bad ruleset produces two `ruleset_load_error` entries, not one. The
  count is what a caller would use to decide how degraded a scan was.
- `test_agent_center.py::tests_report` errors during collection.

Recorded rather than repaired: AGENTS.md requires one reported failure at a
time in an isolated worktree, and that is a separate change from writing this
file. Anyone starting here should know the baseline is red before attributing
a failure to their own work — judging a candidate against a baseline nobody
measured is how a pre-existing failure gets charged to whoever touched the
code next.

## Known boundary, stated by the project itself

`SECURITY_INVARIANTS.md` records that there is **no OS-level sandbox** here.
That is written down as a limit rather than left for someone to discover, which
is the same discipline the rest of the project runs on: a gap that is named is
a decision, and a gap that is merely absent is an accident waiting to be found
by someone else.
