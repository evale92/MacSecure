# Phase 47.5 — Close the Verified Safe-Code Loop (verbatim governing text)

Saved to disk before any work began, so this never has to be re-pasted
and any future session can pick it up cold. **This file is the verbatim
governing instruction as issued by the user.** Do not paraphrase or
reinterpret it here — this phase's acceptance criteria are whatever
this file says they are. Results and decisions live in
`PROJECT_NOTES.md`.

Context: Part 2 (Phases 32–47) was completed and VERIFIED. Phase 47
deliberately stopped at *reporting* promotion eligibility rather than
performing promotion, because nothing in the Part 2 roadmap authorized
writing to the live checkout. The user reviewed that call, agreed with
it, and is now authorizing automatic promotion narrowly.

Three operational notes accompanied the spec and are binding alongside
it:

1. **Do not run `git init` on the live checkout.** Promotion
   requirements 1, 2, 6 and 7 presuppose the live checkout is a git
   repository, and it is not (see `docs/KNOWN_LIMITATIONS.md`).
   Inspect and report first; the one-time init is the user's call to
   make knowingly.
2. **This is the first phase that authorizes writing to the live
   checkout.** Every boundary since Phase 31 existed to prevent
   exactly that write, so the safety burden is higher than anything
   built so far. **Prefer refusing to promote over promoting wrongly,
   in every ambiguous case.**
3. **Present implementation and test results BEFORE declaring
   VERIFIED.** Stop and report rather than self-certifying, and do not
   continue past 47.5.

---

PHASE 47.5 — CLOSE THE VERIFIED SAFE-CODE LOOP

Part 2 is complete, but two intentional conservative gaps remain.

Do not change anything until you inspect the existing Phase 36, Phase 39,
Phase 44, and Phase 47 implementations and propose the smallest solution.

GOAL:

Permit automatic promotion ONLY for fully VERIFIED SAFE_PROJECT_CODE repairs.

First fix the current happy-path gap:

Phase 47 must invoke or obtain the authoritative Phase 36 verification tiers
required by Phase 44. Do not manufacture PASS results and do not translate
UNKNOWN into PASS.

A candidate may proceed only when Phase 44 can deterministically establish
every applicable criterion as satisfied.

Then implement the following narrowly:

SAFE_PROJECT_CODE may be automatically promoted only when:

- original failure was reproduced
- repair occurred in the isolated worktree
- actual diff is known and hash-bound
- FAST verification passes
- TARGETED verification passes
- FULL regression passes when required
- Phase 27 validation passes when applicable
- performance checks pass when applicable
- independent reviewer has no blocker
- engineering/security policies pass
- classification is exactly SAFE_PROJECT_CODE
- current diff still matches the verified hash
- no approval request is pending
- no criterion is UNKNOWN

Promotion must:

1. verify the live checkout is still at the expected base revision
2. refuse if the live checkout has unrelated/uncommitted changes that could
   be overwritten
3. apply only the exact verified patch
4. record every filesystem/Git action through the Phase 31.5 audit boundary
5. immediately perform post-promotion verification
6. retain enough information for deterministic rollback
7. automatically rollback the promoted patch if post-promotion verification
   fails, but only when rollback can be proven safe and limited to that exact
   promoted change
8. otherwise stop and escalate

NEVER auto-promote:

- DEPENDENCY_CHANGE
- SECURITY_SEMANTIC_CHANGE
- SYSTEM_CHANGE
- PRIVILEGED_CHANGE
- destructive/data migrations
- ambiguous classifications
- reviewer disagreements
- anything with UNKNOWN verification criteria

Those remain AWAITING_APPROVAL.

Do not weaken `secure agent approve`; it remains the manual promotion path.

Also replace remaining brittle forbidden-command substring tests with
structural/argv/AST-based checks where practical. A documentation sentence
mentioning a forbidden command must not trigger a safety failure, while an
actual executable command shape still must.

Add adversarial tests proving:

- fully verified SAFE_PROJECT_CODE can auto-promote
- UNKNOWN blocks promotion
- failed tests block promotion
- stale diff blocks promotion
- changed live base blocks promotion
- dirty live checkout blocks unsafe promotion
- reviewer blocker blocks promotion
- consequential classifications never auto-promote
- actual forbidden commands are detected
- prose merely mentioning forbidden commands is not detected
- failed post-promotion verification safely rolls back when possible

Run the complete regression and Phase 27 validation.

Present the implementation and test results before declaring Phase 47.5
VERIFIED.
