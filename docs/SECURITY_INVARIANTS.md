# SECURITY_INVARIANTS.md

Properties this codebase has held since the phase that introduced each.
They are not preferences. Weakening one is a SECURITY_SEMANTIC_CHANGE
and requires explicit human approval before any code is written.

The numbered **Invariants** below are complete and sized to fit inside
the per-file excerpt budget `secure/agent/context.py` applies when
feeding this file into a repair prompt. Everything after them is
elaboration and may be truncated, so no invariant lives down there.

## Invariants

1. **The deterministic engine is authoritative.** No model output is a
   detection authority. An LLM may explain, summarize, or propose —
   never decide severity, never write a finding.
2. **No autonomous change, ever.** Automated code can only create a
   `PENDING` change request bound to an exact content hash. Only one
   explicit human CLI action approves it, revalidated against that
   hash. Model agreement, passing tests, and notification delivery are
   each explicitly **not** approval.
3. **Automated code never authorizes itself.** Nothing under
   `secure/agent/` or `secure/ai/` imports or calls `approve_change()`
   or `reject_change()`.
4. **Observation is read-only.** Sensors observe and persist; they
   never mutate system state. `secure/dfir/` is the sole exception:
   human-triggered and allowlist-gated.
5. **No silent clean pass.** A missing or broken tool reports
   `OK`/`DEGRADED`/`UNAVAILABLE`/`ERROR`. A validation scenario reports
   its real outcome, and no code path can omit a `MISS`,
   `NOT_EVALUABLE`, or `SENSOR_UNAVAILABLE` row from a report.
6. **Every model claim is tagged and checked.** Claims are
   `STORED_FACT`/`SECURE_INTERPRETATION` (must cite a real Secure
   evidence id, verified against the exact context manifest) or
   `AI_ASSESSMENT`/`UNVERIFIED_HYPOTHESIS`. An invalid citation is
   flagged, never silently dropped or accepted.
7. **Verification is deterministic and external.** pytest and `secure
   validate` decide pass/fail, run from outside the tool's process.
   Inconclusive is never treated as a pass.
8. **Repairs are isolated.** An automated repair runs in a throwaway
   git worktree with `HOME` pinned to a disposable agent-owned
   directory. It never writes the live checkout, the real `~/.secure`,
   production config, or operator files. A failed repair is entirely
   discardable.
9. **A tool's self-reported patch is never trusted.** Secure computes
   the real `git diff` itself and hashes it.
10. **Every subprocess the agent layer runs is audited** — argv, cwd,
    target, mutating flag, timing, exit code — redacted and truncated,
    persisted with the run.
11. **Local-only and opt-in.** Provider hosts default to `""` and are
    checked before any I/O, so the app is inert on a fresh install.
12. **`rm -rf ~/.secure` fully uninstalls.** No writes outside the app
    directory, and Secure never registers itself with `launchctl`.

---

## What "weakening" means

Not just deleting an invariant. Adding a bypass, adding a flag that
skips it, broadening an allowlist, treating an inconclusive result as
success, or making a check advisory instead of enforced — all of these
are weakenings, and all of them require approval first.

## Invariants with structural tests behind them

Invariant 3 is enforced by a test that parses the AST of every file
under `secure/agent/`. Invariant 12 is enforced by two static source
checks (no write path outside `cfg.app_dir_path()`, no `launchctl`
invocation shape). Invariant 8 is enforced by adversarial isolation
tests that prove `HOME` override is honored by a real subprocess and
that a removed worktree leaves no residue in git's own registry.

The rest are held by design plus targeted behavioral tests. If you
find an invariant that has neither, that is worth a test, not a
shrug — but adding one belongs in its own change, not smuggled into an
unrelated repair.

## Known boundary, stated honestly

There is no OS-level sandbox: no container, no chroot, no network
namespace. Worktree and `HOME` isolation prevent accidental collisions,
not a determined write to an absolute path that running code already
knows. This is a documented limitation, not an oversight — see
`docs/KNOWN_LIMITATIONS.md`.
