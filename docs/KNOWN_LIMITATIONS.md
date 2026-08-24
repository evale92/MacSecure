# Known Limitations (Phase 29)

This document describes what Phase 29's nine audit/validation stages
actually proved and, just as importantly, what they didn't — every
item below is either a deliberate design boundary (see
`docs/THREAT_MODEL.md`'s non-goals) or a gap this phase found real
evidence for, not a guess. Nothing here is claimed to be fixed unless
a stage's own regression test or live-host run backs the claim.

## Sensing gaps (things Secure genuinely cannot see)

- **Background Items / `SMAppService`-registered persistence has no
  read API.** `secure/persistence/` covers LaunchAgents/LaunchDaemons
  and classic login items; modern Background Items (macOS 13+) have no
  public enumeration API Apple exposes, so this is a permanent,
  documented `NOT_EVALUABLE` gap — confirmed by
  `secure/validate/scenarios/persistence.py`'s own scenario, not a
  silent hole.
- **`lsof`-based sensors (connections, listening ports) may not see
  every system-owned socket** without elevated privileges. Secure
  reports what it can see and never claims total visibility — this is
  stated in the sensor's own capability row, not just here.
- **Detection coverage depends entirely on what's installed.** osquery,
  YARA-X, Sigma, Suricata, Zeek, and Velociraptor are all optional; a
  Mac with none of them installed gets native-sensor coverage only.
  This phase's job was making that limitation *visible*
  (`SENSOR_UNAVAILABLE`/`UNAVAILABLE`), not making the coverage gap
  itself disappear — it can't.
- **A local root-level attacker defeats any userland monitor,
  including this one, by definition** (`docs/THREAT_MODEL.md`
  non-goals). Secure is a detection and investigation aid, not a
  preventive control, and was never designed to survive a fully
  compromised kernel.

## What Stage 9 validated, and its own boundary

Stage 9 ran the full 1573-test suite and a live `secure validate run`
for real — see `docs/VALIDATION_REPORT.md` for the specific commands
and output. Two things that run could not do, stated there and
repeated here so this document doesn't oversell it:

- **The development/audit sandbox has no real `pytest` and no network
  access to install it**, and is Linux, not macOS. Stage 9's 1573/1573
  pass count comes from a narrowly-scoped, honesty-checked compatible
  runner built for this session, cross-referenced against a full grep
  of the suite's own fixture usage (confirmed to use only `tmp_path`,
  `monkeypatch`, `capsys`, and `pytest.raises` — nothing outside that
  surface). It has not been cross-checked against an actual `pytest`
  invocation on the user's own machine.
- **Sensors that need real macOS binaries (`spctl`, `csrutil`,
  `fdesetup`, `launchctl`, `osascript`, `arp`) were only provable in
  their "honestly reports unavailable" direction in this sandbox**,
  because those binaries are genuinely absent here — this is real
  evidence for the *absence* half of "no missing sensor may look
  clean," proved live in Stage 9's own subprocess run. The *presence*
  half — that these sensors correctly detect real findings when the
  underlying tool exists — can only be proven on a real Mac.

## AI analyst (Phase 28, re-affirmed, not re-tested, this phase)

Carried over from `docs/AI_ANALYST.md`'s own limitations section,
since Phase 29's scope didn't re-verify AI-analyst-specific claims
beyond confirming its tests still pass in Stage 9:

- Never smoke-tested against a real Ollama/LM Studio server (same
  sandbox network constraint as above) — verified instead against
  fake local HTTP servers matching each backend's real response shape.
- `run_pytest` (one of the AI analyst's own tools) can only report
  `status="unavailable"` in this sandbox for the same reason Stage 9
  couldn't run real pytest — its subprocess mechanics are tested with
  a stub, not exercised against this repo's real suite.
- `inspect_test_presence` is a structural text cross-reference, not
  real statement/branch coverage — labeled honestly in its own output,
  never presented as a coverage percentage.
- Every AI-generated claim is citation-checked against real evidence
  before being shown, and the AI can never itself execute a change —
  but a wrong or generic-but-technically-cited answer is still
  possible; `secure ai changes show` before approving is expected to
  always be read by a human.

## Permission-hardening scope (Stage 4)

`chmod 600`/`700` on `config.json`/`secure.db`/`secure.log` and their
parent directory protects against a different local *account* reading
these files. It does not protect against another process running
*under the same account* (the same boundary essentially all local
config-file tooling on a single-user Mac operates within) — stated
plainly in `docs/THREAT_MODEL.md`'s own compromise-blast-radius table,
not a new gap introduced here.

## Live checkout is not a git repository (found Phase 32/33 session, Part 2)

`secure/agent/policy.py`'s `evaluate_policy()` refuses to start any
repair attempt unless `is_git_repository(repo_root)` is true, and
`secure/agent/worktree.py`'s isolation depends entirely on `git
worktree add` against that same repo. This is correct and was never
loosened — but it means the self-healing/repair workflow (Phase 31
onward) can only ever run against a checkout that is actually a git
repository with commit history.

As of this note, the user's real, live `Secure/` project directory on
disk is **not** a git repository (`git status` inside it fails; no
`.git` directory exists). This was discovered while setting up an
external hourly-mirrored backup folder (`secure_backup/`, a plain
filesystem copy with no version history of its own) as an interim
safety net at the user's explicit request, in place of turning
`Secure/` into a git repo — the user was offered that option directly
and chose to keep the plain-mirror backup only, for now. This is a
recorded, deliberate choice, not an oversight.

Practical effect: `secure agent run`/`attempt_repair()` invoked
against the real `Secure/` checkout today will report the trigger
ineligible with reason "the Secure checkout is not a git repository" —
never a crash, never a silent skip, an honest `PolicyDecision(allowed=False,
...)`. Every automated test in `tests/test_agent.py`/`tests/test_agent_context.py`
still passes because each test spins up its own disposable, real git
repository in a `tmp_path` fixture (`_init_repo()`) — the *code* has
always been fully exercised against a real git repository; only the
*user's actual daily checkout* currently lacks one.

**Workaround, to enable self-healing later without re-litigating this
decision:** at any point the user wants to actually exercise
`secure agent` against the real project (this becomes load-bearing
starting around Phase 43, "Automated Failure Diagnosis"), run, once,
from inside `Secure/`:

    git init
    git add -A
    git commit -m "baseline for agent self-healing"

This is a local-only, non-consequential, fully reversible action (no
network call, no package install, no privilege change, nothing that
meets this roadmap's own SYSTEM_CHANGE/PRIVILEGED_CHANGE/
DEPENDENCY_CHANGE/SECURITY_SEMANTIC_CHANGE bar) — it does not require
the approval workflow described in Phase 39/40. It can be done at any
later time with zero code changes on Secure's side; nothing in Phases
32-33 (or planned for 34+) assumes today's answer is permanent. Until
that happens, the plain hourly `secure_backup/` mirror remains the
only backup, and offers no rollback to a prior good state — only a
copy of whatever is currently on disk, good or broken.

## What this phase deliberately did not do

Per the phase's own governing instruction, Phase 29 audited and
hardened the existing platform — it did not add a new security
capability. So none of the sensing gaps above were closed this phase;
they were made *visible* (correct `SENSOR_UNAVAILABLE`/`NOT_EVALUABLE`
reporting, backed by real tests and, where possible, real live-host
runs) rather than fixed, except for the one gap Stage 5 did fix
outright (the ARP-availability false-clean bug — a genuine defect, not
a documented boundary, and squarely in scope for a hardening phase).
