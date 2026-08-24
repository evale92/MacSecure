# AGENTS.md — rules for automated coding agents in this repository

You are an automated coding agent working on Secure. You were given one
specific failure to fix. Read these rules before editing anything.

The numbered **Rules** below are complete and deliberately sized to fit
inside the per-file excerpt budget `secure/agent/context.py` applies
when it feeds this file into a repair prompt. Everything after the
Rules is elaboration for humans and may be truncated in a prompt — so
no rule ever lives down there.

## Rules

1. **Stay inside your working directory.** It is an isolated git
   worktree. Never read or write an absolute path outside it, never
   touch `~/.secure`, and never assume the operator's real home
   directory is reachable.
2. **Fix the reported failure, nothing else.** Smallest change that
   makes the stated failure pass. No refactors, no reformatting, no
   drive-by cleanups, no renaming.
3. **Never weaken a test to make it pass.** Do not delete, skip,
   loosen, or `xfail` an assertion. If the test is right and the code
   is wrong, fix the code. If you believe the test itself is wrong,
   say so in your response and change nothing.
4. **Never touch authorization code.** Nothing under `secure/agent/`
   or `secure/ai/` may call `approve_change()` or `reject_change()`.
   Approval is a human CLI action. This is checked structurally by a
   test that parses the source.
5. **Never change host state.** No `sudo`, no package install or
   upgrade, no `launchctl`, no firewall/network/Wi-Fi/Bluetooth
   config, no Keychain, no macOS security settings, no deleting user
   data. If a fix appears to require one of these, stop and report it.
6. **Never add a dependency.** Standard library and what is already
   imported. Do not add to `requirements.txt`.
7. **Report honest absence, never a fabricated pass.** If a tool,
   file, or signal is missing, the code must say so
   (`UNAVAILABLE`/`DEGRADED`/`ERROR`) rather than return a clean
   result. A silent clean pass is a bug in this codebase.
8. **Respect the layer rule.** A lower layer never imports from a
   higher one. See `ARCHITECTURE_RULES.md`.
9. **Do not weaken a security invariant.** See
   `SECURITY_INVARIANTS.md`. If your fix would change one, stop and
   report instead of editing.
10. **Your patch is a proposal, not a change.** It will be diffed,
    hashed, verified, and reviewed by a human before it lands. Write
    it to be read. Do not commit, do not push, do not tag.

---

## Why these rules exist

Secure runs an autonomous repair loop that is deliberately narrow:
deterministic policy picks a failure, an isolated worktree is created,
an external coding agent (mini-SWE-agent) edits files inside it,
Secure independently computes the real `git diff`, runs tiered
verification with an isolated `HOME`, and files a pending change
request bound to the diff's SHA-256. A human approves it against that
exact hash, or it never lands.

Every rule above protects one link in that chain. Rule 1 protects
isolation. Rules 2 and 10 keep the diff small enough for a human to
actually review. Rule 3 protects the only deterministic signal in the
loop — if tests can be edited to pass, verification means nothing.
Rules 4, 5, and 9 are the trust boundary itself. Rule 7 is the oldest
convention in the project: this is security software, and a false
clean is worse than an honest gap.

## What Secure owns, and what you own

You own reading the failing code, deciding what to change, and
producing the edits. Secure owns everything else: which failures are
eligible, what context you get, what the diff actually is (it is
recomputed independently — your own account of what you changed is
never trusted), whether verification passed, and whether a human
approved. Do not try to do Secure's half of the job.

## If you cannot fix it

Say so plainly and change nothing. An honest "I could not fix this,
here is what I found" is a useful result. A speculative patch that
makes the failure disappear without addressing its cause is not.
