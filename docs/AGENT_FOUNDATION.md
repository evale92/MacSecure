# Agent Foundation (Phase 31)

Supervised, human-approved autonomous repair — "Part 2" of the
project's own long-running plan (Secure Project MB). Answers "when a
deterministic test or validation scenario fails, can Secure isolate
the failure, hand it to an external coding agent in a sandbox, verify
the result the same way it verifies everything else, and put a
reviewable, exactly-bound change request in front of a human" — never
"can Secure fix and apply things on its own." It cannot: nothing in
this phase applies a diff to the live repository automatically, and
nothing in this phase can approve its own output.

## The governing instruction, condensed

Do not build a custom agent framework; use mature open-source tools.
Secure owns health signals, policy, isolation, evidence, verification,
approval, and auditability. mini-SWE-agent (external, invoked as a
subprocess) owns the coding-agent loop: reading files, deciding what
to change, running commands, producing a patch. The external agent may
modify only an isolated `git worktree`, never the live Secure
repository. Model confidence never equals success — tests and
`secure validate` decide whether a repair technically passes, and
passing verification still does not authorize application. No Aider,
no OpenHands, no autonomous sudo/system/network/package changes, a
path denylist over the security-relevant core, bounded retries, and an
approved repair does not auto-apply — a future, explicitly-controlled
`secure agent apply` is left for a later phase.

## Architecture placement and reuse

`secure/agent/` sits alongside `secure/ai/` and `secure/validate/` in
the layer model (`docs/ARCHITECTURE.md`) — callable only from the
interfaces layer, never imported by any sensor/integration/evidence/
baseline/correlation/explanation module. Nothing here rebuilds
infrastructure that already existed:

- **Approval workflow** — `secure/agent/changes.py` calls
  `secure.ai.changes.workflow.propose_change()` (Phase 28) literally
  unmodified. `secure/agent/` never calls `approve_change()` or
  `reject_change()` anywhere — enforced structurally, not just by
  convention, by `tests/test_agent.py`'s
  `test_agent_package_never_calls_approve_or_reject`, which parses
  every file under `secure/agent/` with `ast` and fails the build if
  either name is ever imported or called there.
- **Verification** — `secure/agent/verify.py` runs the project's own
  `pytest`/`secure validate run` inside the worktree; it invents no
  new pass/fail model. `VerificationOutcome.overall_passed` follows
  Phase 28's own status-vs-verdict split: `None` (not `False`) when a
  mechanism didn't run cleanly, so an inconclusive result is never
  silently reported as a pass.
- **Local-model configuration** — reuses `AppConfig.ollama_host`/
  `ollama_model` (Phase 28) unchanged; mini-SWE-agent's model backend
  is litellm, selected with model name `ollama/<model>` plus
  `api_base` in `model_kwargs` — zero new provider code.
- **Schema shape** — `agent_repair_runs` uses the same
  `run_id`/`created_at`/`completed_at`/status-lifecycle shape every
  other `*_runs` table in this schema already uses.

## The loop

```
deterministic failure (pytest / secure validate / a detection rule's own test)
  -> secure/agent/policy.py: deterministic eligibility (trigger kind
     allowed, is a git repo, under agent_max_attempts, not already
     verified)
  -> secure/agent/worktree.py: git worktree add --detach <isolated dir>
  -> secure/agent/runner.py: invoke mini-SWE-agent once, non-interactively,
     HOME pinned to a throwaway directory, hard wall-clock timeout
  -> secure/agent/worktree.py: Secure computes the diff ITSELF
     (git diff in the worktree) — the tool's own self-reported
     "submission" text is stored as supplementary context only, never
     trusted
  -> secure/agent/changes.py: path denylist check against the
     independently-computed changed-files list; any violation stops
     here, before verification, before any change request exists
  -> secure/agent/verify.py: pytest + secure validate, run inside the
     worktree with HOME pinned to the same isolated directory
  -> secure/agent/changes.py: only on verification.overall_passed is
     True, propose_repair_change_request() embeds the diff's SHA-256
     as literal text in the change request, so Phase 28's existing
     exact-revision-hash-match requirement transitively pins the exact
     diff content too
  -> a PENDING change request exists; a human reviews and, via
     `secure agent approve <run_id>`, triggers one more independent
     check (see Guardrail 2 below) before Phase 28's own
     approve_change() ever runs
  -> approval records authorization; applying the diff to the live
     repository remains a manual, separate step in this phase
```

## Isolation

`git worktree add --detach` — a full separate working directory backed
by the same repository's object store. Detached (no branch), since a
repair attempt has no business creating a ref in the live repository's
namespace before a human has approved anything. Every subprocess this
package spawns — mini-SWE-agent itself, and the post-run
pytest/`secure validate` verification calls — gets `HOME` pinned to a
throwaway per-run `agent_home_path` directory, so nothing can ever
write to the operator's real `~/.secure/secure.db` or mini's own
global config directory.
`tests/test_agent.py`'s `test_worktree_changes_never_touch_the_live_repo`
and `test_run_mini_swe_agent_home_is_isolated_not_real_home` prove both
boundaries concretely, not just by code inspection.

**Known limitation, stated plainly:** this phase implements no
OS-level network isolation — no container, no network namespace (that
is exactly what Docker/OpenHands would add, and the governing
instruction explicitly excluded both for Phase 31). Pointing the model
backend at a local-only Ollama instance means model *inference* makes
no external network call, but a shell command the agent itself chooses
to run inside the worktree could still reach the network if the host
running Secure permits it. True network sandboxing is deferred to a
later phase.

## Two approval guardrails (both added per explicit user instruction, after the initial build)

**1. Reproducibility.** Every `agent_repair_runs` row records the exact
argv mini-SWE-agent was invoked with, the exact generated config YAML
handed to `mini -c`, the tool's own version and the model name, the
git base revision the worktree was created from, and a sha256 of the
raw transcript file bytes actually read back — so a completed run's
inputs can be inspected or reasoned about later without guessing, and
a transcript altered on disk after the fact is detectable by
re-hashing it. `resume_repair_run()` reconstructs the same argv via a
pure function of `(cfg, worktree, candidate)` and reads the config
YAML back from the same file mini-SWE-agent wrote originally, rather
than inventing new values.

**2. Pre-approval diff revalidation.** Phase 28's `approve_change()`
already refuses unless the caller's `revision_hash` matches the hash
of the change request's own *text* — that catches someone approving
against a stale copy of the title/reason/risks. It says nothing about
whether the worktree's actual `git diff` still matches what that text
describes. `secure agent approve <run_id>` closes that gap: before
calling the real `approve_change()`, it re-runs Secure's own diff
computation against the worktree *right now*
(`secure/agent/changes.py`'s `revalidate_worktree_diff()`) and compares
its hash to the one embedded in the change request at proposal time.
If it still matches, approval proceeds exactly as before. If the
worktree has drifted — a human edited it, a second tool pass ran,
anything — the stale change request is marked `superseded` (a third
terminal state, distinct from Phase 28's human-only
`pending`/`approved`/`rejected`, set via the same raw storage
primitive `set_ai_change_request_status()` that `approve_change()`/
`reject_change()` already wrap, never via `reject_change()` itself —
this is an automatic integrity finding, not a disguised human
rejection decision) and can never be approved again (`approve_change()`
already requires `status == 'pending'`). If re-verification of the
*current* worktree state still passes, a fresh change request is
proposed from what's actually there now, for a human to separately
review and approve. Nothing in this path approves anything
automatically — a human still has to run the command, and a second,
independent replacement CR still starts life `pending`.
`tests/test_agent.py`'s
`test_revalidate_before_approval_deliberately_broken_diff_supersedes_and_regenerates`
proves this end to end: it drives a repair to a normal verified state
with a real pending change request, deliberately corrupts the worktree
*after* the CR was proposed, and confirms the stale CR can never be
approved (including a direct attempt against the raw `approve_change()`
call, bypassing the CLI entirely), that it becomes `superseded`, that a
replacement CR is generated with its own distinct diff hash, and that
the replacement approves normally.

## Storage

One table, `agent_repair_runs` — deliberately flat, not split by
concern the way Phase 28's `ai_*` tables are, since every column here
describes one run's own lifecycle (trigger -> sandbox -> tool ->
verification -> optional change request). A row is created with
`status='running'` *before* the external tool is ever invoked, so a
crash mid-run always leaves a findable, resumable record. Approval
state is never duplicated onto this table — a run's `change_request_id`
is a foreign reference into `ai_change_requests`, always read by join,
so the two can never disagree about whether something was approved.

## Resumability

`resume_repair_run()` never re-invokes mini-SWE-agent — there is no
safe way to reattach to a possibly-still-running or half-finished LLM
session. It only works if a transcript file already exists on disk: it
re-reads it, reconstructs the reproducibility fields from what's still
on disk, and re-runs the diff/denylist/verification/proposal tail. If
no transcript was ever written, the tool invocation itself never
completed, and this reports a clear `error` status rather than
guessing.

## Path denylist

Prefix-matched against `AppConfig.agent_path_denylist` against
Secure's own independently-computed changed-files list — never against
anything the tool claims to have touched. Includes `secure/validate/`,
`secure/ai/verify/`, `secure/ai/changes/`, `secure/agent/` itself,
`config.py`, and the schema — so a repair can never rewrite the
referee that grades it. A single violation anywhere in the diff means
no change request is ever created; the run stops as
`rejected_by_denylist`.

## CLI

```
secure agent status                  tool/Ollama/git-worktree preconditions
secure agent discover                current deterministic failures + eligibility
secure agent run [--trigger-kind K --trigger-ref R] [--limit N]
secure agent list [--status S] [--limit N]
secure agent show <run_id>
secure agent resume <run_id>
secure agent approve <run_id>        revalidate, then approve if unchanged
secure agent remove-worktree <run_id>
```

## GUI

A normal "Agent — Repairs" category in `secure_gui.py`
(`secure_gui/agent_view.py`), following the same DISPLAY/ACTIONS split
every other screen in this package uses: a read-only list and detail
view sourced from `secure_gui.data_access.fetch_agent_repairs_overview_now()`
(a direct, read-only database query — no policy decision made in
Python), and every action (Discover, Run, Resume, Remove Worktree,
Approve, Reject) shells out to the real CLI subprocess, narrating into
the same console transcript as every other button. The Approve button
calls `secure agent approve <run_id>` — never `secure ai changes
approve` directly — so every agent-originated approval goes through
the diff-revalidation gate.

## Known limitations

- **No OS-level network isolation** (see above) — the single largest
  gap relative to what Docker/OpenHands would add; explicitly deferred.
- **`secure agent apply` does not exist yet.** An approved change
  request still requires a human to apply the diff by hand. The
  architecture (exact diff, exact hash, exact worktree/commit identity
  all persisted) is designed so a future, explicitly-controlled apply
  step could be added without changing anything above it.
- **Resume cannot reattach to a running tool process** — only to one
  that already finished and left a transcript.
- **No adversarial second-model review of a repair's own diff.** Phase
  31's only automated check is deterministic (pytest + `secure
  validate`); `risks`/`model_b_opinion` on an agent-originated change
  request say so explicitly, so a human reviewer doesn't mistake the
  absence of a second opinion for one having been given.
- **Aider and OpenHands are intentionally not integrated** in this
  phase, per the governing instruction — mini-SWE-agent is the only
  coding-agent framework used.

## Phase 31.5 — Agent Action Audit

A pure observability/auditing checkpoint, added after the user reported
that running the app "randomly opened a bunch of stuff" (traced to an
unrelated macOS Finder/resource-fork artifact on the user's own launcher
script — see PROJECT_NOTES.md's change log — but the concern itself was
legitimate and is what motivated this phase). Governing instruction:
"Before adding more autonomous capability, make every externally
visible action performed by Secure or secure/agent auditable." **No new
autonomous behavior was added in this checkpoint** — every change below
is either a new read-only record of something the code already did, or
a new read-only surface for viewing those records.

### What is audited

Every subprocess, external-tool invocation, filesystem-changing
operation, Git operation, and proposed system change in `secure/agent/`
records: timestamp, `run_id`, component, exact argv/action, working
directory, target files/resources, whether it was read-only or
mutating, whether human approval was required, exit code/result, and
duration — in a new `agent_actions` table (`secure/storage/models/agent.py`).

### The audit boundary mechanism

`secure/agent/audit.py`'s `record_action()` is the one place every
audited entry is constructed and redacted. Every subprocess-invoking
function in `secure/agent/worktree.py`, `runner.py`, and `verify.py`
accepts an **optional** `audit_trail: Optional[list] = None` parameter.
When it is `None` — the default, and what every call site written
before this phase still passes — recording is a no-op and behavior is
byte-for-byte identical to before Phase 31.5. Only
`secure/agent/orchestrator.py` (which owns a real database connection
and a `run_id`) creates a real list, threads it through one
attempt/resume/revalidate call, and persists the whole batch in one
place via `persist_audit_trail()`, right before that call returns —
`secure/agent/changes.py`'s `propose_repair_change_request()`/
`supersede_change_request()` (which already own a live `conn`) instead
call `record_and_persist_one()` to log immediately. This design was
chosen specifically to avoid threading a `sqlite3.Connection` into
low-level pure git/subprocess wrapper modules, and to guarantee zero
behavior change for any pre-existing caller or test — including tests
that monkeypatch `module.subprocess.run` directly, since the audit
boundary still calls that same module-local `subprocess.run` reference,
never a copy.

`tests/test_agent.py`'s
`test_agent_subprocess_call_sites_all_accept_audit_trail_parameter`
proves this structurally (every function in those three files that
directly calls `subprocess.run`/`Popen` accepts `audit_trail`), and
`test_attempt_repair_persists_worktree_and_runner_audit_rows_with_redaction`
proves it functionally (a real `attempt_repair()` call actually lands
correctly-shaped rows in `agent_actions`).

### Redaction

Environment variables are never part of an audited action at all — the
only place `HOME` overrides are constructed is directly in the
subprocess `env=` kwarg, never logged. Every argv token is redacted:
one matching a secret-shaped pattern (`api_key`/`secret`/`password`/
`token`/`bearer`/`authorization`, case-insensitive) is replaced outright
with `[REDACTED]`; any token longer than 200 characters (this is what
protects mini-SWE-agent's own `-t "<task text>"` argument — effectively
the model prompt — from ever being logged verbatim) is truncated to a
short prefix plus a length note. `result_summary` is always a short,
call-site-computed string (`"exit 0"`, never raw subprocess
stdout/stderr, which could otherwise carry file contents).

### CLI and GUI

```
secure agent actions [--run-id ID] [--limit N]
```

prints every audited action, optionally filtered to one run. The same
rows are shown in the "Agent — Repairs" GUI window's new Audited
Actions panel (`secure_gui/agent_view.py`): selecting a run in the runs
list populates it via a new read-only fetch,
`secure_gui.data_access.fetch_agent_actions_now()`.

### The startup-safety invariant

**Ordinary `secure_gui.py` startup — `SecureGUI.__init__` reaching the
point where `mainloop()` would be called — cannot invoke any
subprocess at all**, and therefore cannot invoke mini-SWE-agent, Aider,
a package manager, `open`/`osascript`, `sudo`, a system configuration
tool, or agent repair execution. This is a structural property of the
GUI's own construction, not a runtime check: every button (including
"Agent — Repairs", and everything inside that window) is wired via
Tkinter's `command=`/`target=` keyword arguments, which hold a bare
callable *reference* — never an immediate call — so nothing behind
them executes until a real user click or a scheduled `.after()`/thread
job fires, strictly after `__init__` has already returned.

Proven in `tests/test_agent.py` via AST reachability analysis (tkinter
itself is unavailable in this sandbox, and `secure_gui.py` has always
been verified only by `ast.parse`, never live-instantiated — see
`tests/test_gui_components.py`'s own docstring for that pre-existing
project constraint):

- `test_secure_gui_startup_reaches_no_subprocess_call` — the transitive
  closure of methods reachable from `SecureGUI.__init__` via *immediate*
  `self.method(...)` calls (as opposed to deferred `command=`/`target=`
  references) contains zero calls to `subprocess.run`/`Popen`,
  `os.system`, or `os.exec*` — a strictly stronger invariant than
  merely banning specific tool names, since it proves no subprocess can
  be invoked at all during construction.
- `test_secure_gui_startup_never_reaches_named_dangerous_methods` — the
  same reachable set is checked by name against `_execute` (the single
  choke point where `secure_gui.py` spawns any `secure ...` subprocess,
  including `agent run`/`agent approve`), `_worker_loop`,
  `_open_agent_window`, `_update_and_restart`, and `_do_relaunch`.
- `test_secure_gui_agent_window_only_reachable_via_deferred_command` —
  confirms the "Agent — Repairs" button really is bound via
  `command=self._open_agent_window` (a bare reference), the concrete
  mechanism the two tests above depend on.

### What Phase 31.5 deliberately did not do

No new autonomous behavior, no new trigger, no new CLI action that
changes system state, no change to the approval model. `secure agent
actions` is read-only. The Audited Actions GUI panel is read-only. The
only production-code changes are: a new table, a new optional
parameter threaded through existing subprocess call sites, and the
redaction/persistence logic that fills that table when the parameter is
supplied.

## Phase 32 — Local Model Routing (Part 2, Supervised Agentic Development)

Phase 32 opens "Part 2" of the agent roadmap (Phases 32–47), aimed at
supervised self-healing built on top of the Phase 31/31.5 foundation
above. Its own scope was narrow: give the eventual repair/review
workflow (Phases 33+) a way to ask "which provider plays which
engineering-maintenance role, and is it actually usable right now,"
without building any new inference code to do it.

### Reuse, not a new framework

Phase 28 (`secure/ai/`) already built everything a role-based local
model routing layer needs: `secure/ai/base.py`'s duck-typed provider
boundary (`.identity`, `.configured`, `.complete(system_prompt,
user_prompt, *, timeout) -> ProviderCompletionResult`), two real
provider implementations (`secure/ai/providers/ollama.py`,
`secure/ai/providers/openai_compatible.py`), and — critically —
`secure/ai/roles.py`'s `resolve_role_providers(providers)`, which was
already written generically: given `{"ollama": ..., "openai_compatible":
...}` it prefers two *different* configured backends, falls back to one
provider playing both roles when only one is configured, and returns
`(None, None)` honestly when neither is configured. Nothing about that
function is specific to the Analyst/Verifier roles it was built for in
Phase 28, so Phase 32 reuses it completely unchanged for an entirely
different pair of roles.

The only new file is `secure/ai/model_roles.py`, a thin naming/recording
layer:

- `ROLE_PRIMARY_CODER` / `ROLE_INDEPENDENT_REVIEWER` — the two role
  names this phase's instruction specified.
- `RoleBinding(role, provider_name, model, configured, timeout_seconds)`
  — a frozen dataclass capturing everything worth recording about a
  role assignment *before* any completion is attempted: provider,
  model, availability, and effective timeout. When no provider could be
  assigned, `provider_name`/`model` are `""` and `configured` is
  `False` — never a fabricated identity.
- `resolve_maintenance_roles(providers) -> dict[str, RoleBinding]` —
  calls `resolve_role_providers()` once, then wraps each side into a
  `RoleBinding`. Always returns both roles, even when nothing is
  configured.
- `RoleInvocationResult(role, completion)` / `invoke_role(role,
  provider, system_prompt, user_prompt, *, timeout=None)` — a direct,
  unmodified call to the provider's own `.complete()`, with the role
  name stamped alongside the result. Each call is independent, with no
  shared mutable state between roles, so PRIMARY_CODER and
  INDEPENDENT_REVIEWER invocations never interfere with each other.

`OllamaProvider` and `OpenAICompatibleProvider` each gained one small
addition: a `.timeout` property exposing the timeout they were already
storing internally, so `_binding()` can record it without reaching into
private state. No other change to either provider.

### No new config fields, no new shell authority

Phase 32 needed zero new `AppConfig` fields — `ollama_host`,
`ollama_model`, `local_llm_host`, `local_llm_model`,
`local_llm_api_key`, and the two providers' existing timeout
constructor arguments (already wired from Phase 28's `build_providers()`
in `secure/ai/registry.py`) are exactly what a maintenance-role provider
needs too. Neither role gains any shell/subprocess authority here —
`invoke_role()` only ever calls a provider's `.complete()`, which itself
only ever makes one HTTP request to a already-configured local host.
Nothing in this phase runs an external command.

### CLI

`secure ai roles` (`secure/cli/ai.py::cmd_ai_roles`) is read-only: it
builds providers, resolves both maintenance-role bindings, and for each
configured role calls the provider's existing `check_reachable()` (the
same liveness probe `secure ai status` already uses — a `GET` that
never invokes the model) to report REACHABLE vs. "configured but
unreachable" alongside the recorded model/timeout. When both roles
resolve to the same provider (only one backend configured), it prints a
note that review isn't currently independent of the coder model. This
command touches no state — it doesn't even open the database.

### Acceptance criteria, and how each is met

- **Both roles can be invoked independently.** `invoke_role()` takes
  one `(role, provider)` pair per call, with no shared state — proven
  by `test_invoke_role_both_roles_invokable_independently` in
  `tests/test_ai_model_roles.py`.
- **Unavailable models fail honestly.** An unconfigured provider's
  `.complete()` already returns `STATUS_UNAVAILABLE` with a
  non-`None` `.error` and a `None` `.text` (Phase 28's own
  `ProviderCompletionResult` invariant, unchanged) — never a crash,
  never a fabricated success. `resolve_maintenance_roles()` reports
  `configured=False` honestly for a role with no provider at all.
- **Model identity is recorded.** `RoleBinding` captures
  provider/model/timeout at resolution time, independent of whether the
  role is ever invoked — this is what makes "provider, model, role,
  availability, timeout... recorded" true even for a role that's never
  actually called.
- **Deterministic Secure logic remains authoritative.** Role
  resolution and binding construction never call `.complete()` —
  proven by `test_resolve_maintenance_roles_binding_is_pure_no_network_call`.
  This phase adds no autonomous decision-making of its own; it only
  answers "who would handle this role, and can I reach them right
  now."

### What Phase 32 deliberately did not do

No repair/review workflow yet (that's Phase 33's "mini-SWE-agent Repair
Integration" and Phase 38's "Independent Reviewer" — this phase only
builds the routing they'll need). No GUI surface (the acceptance
criteria didn't call for one; `secure ai roles` covers the stated
diagnostic need). No new provider backends, no new HTTP client, no new
inference framework — every actual model call still goes through the
exact same `ProviderCompletionResult` shape Phase 28 established.

## Phase 33 — mini-SWE-agent Repair Integration (Part 2)

Phase 31 already gave mini-SWE-agent a task prompt (`kind`/`reference`/
`detail` — see `secure/agent/runner.py::_build_task_text()`) and already
computed the diff of record independently rather than trusting the
tool's own textual `submission` field. What Phase 33 adds is the
*bounded* extra context the governing instruction asked for — relevant
files, recent history for them, and (once Phase 37 exists) engineering
policy — without ever dumping the whole repository into the prompt, and
without changing anything about how isolation, diffing, verification,
or approval work.

### The new module: secure/agent/context.py

One new file, `secure/agent/context.py`, owns exactly this: given a
`RepairCandidate` (Phase 31's own struct — trigger kind/ref/detail,
unchanged), it deterministically derives a `RepairContext`:

- **`affected_files`** — for a pytest-failure trigger, the failing
  test's own file (from its node id) plus any file paths mentioned in
  the `--tb=short` traceback text already present in `trigger_detail`,
  each checked against the live checkout and included only if it
  actually exists. Capped at 5 files. A trigger kind with no reliable
  file-path signal (e.g. a Sigma/YARA-X detection-rule-test failure)
  simply gets an empty tuple — never a guessed path.
- **`recent_changes`** — up to 5 one-line `git log` entries per
  affected file, read-only, run against the live checkout (safe because
  the isolated worktree is a checkout of that exact same history).
- **`policy_excerpts`** — reads `AGENTS.md`/`ARCHITECTURE_RULES.md`/
  `docs/SECURITY_INVARIANTS.md`/`docs/TESTING_POLICY.md` from the repo root when
  they exist, truncated per-file. None of them exist yet (that's
  Phase 37's job) so this is `{}` today — the moment Phase 37 adds any
  of them, every future repair task automatically includes them with
  zero code change here.
- **`workspace_note`** — a fixed sentence reminding the model its
  writable scope is the current working directory only.

`render_context_block()` turns a `RepairContext` into the text block
appended to the task prompt, omitting each section entirely (not with
an empty/placeholder heading) when there's nothing real to show.

### Wiring: additive, default-None, byte-identical when omitted

`_build_task_text()`, `build_mini_argv()`, and `run_mini_swe_agent()`
(all in `secure/agent/runner.py`) each gained one new keyword-only
parameter, `context: Optional[RepairContext] = None`. When omitted —
every call site before this phase, and every test written before this
phase — the rendered task text is byte-for-byte identical to before
Phase 33 (proven by
`test_build_mini_argv_context_none_is_byte_identical_to_before_phase_33`).
`secure/agent/orchestrator.py`'s `attempt_repair()` now calls
`build_repair_context(candidate, root=repo_root)` once, right before
invoking the tool, and passes it through; `resume_repair_run()` rebuilds
context fresh from the live checkout for the same reason
`build_mini_argv()`'s own docstring already accepts `cfg` may have
drifted since the original run — an honest approximation, not a
persisted second copy of the prompt.

No new database column, no new persisted field: the rendered context
becomes part of the same `-t "<task text>"` argument Phase 31 already
stores in `agent_repair_runs.tool_argv` (full, for reproducibility) and
already redacts/truncates in the Phase 31.5 audit trail — the exact
same reproducibility and redaction machinery, unmodified, now covers a
larger prompt.

### What Secure still owns (unchanged from Phase 31)

mini-SWE-agent's own reasoning loop is untouched — Phase 33 only
changes what's *in* the prompt handed to it, never how it reasons, what
tools it calls, or how it edits files. Secure still computes the actual
diff independently (`diff_and_changed_files()`), still never trusts
`MiniRunResult.submission` as the diff of record, still enforces the
path denylist, still requires deterministic pytest/validate verification
to pass, and still requires human approval before any change lands.
None of that changed.

### Acceptance criterion

"A deliberately broken test can be diagnosed and repaired in isolation
without modifying the live checkout" was already Phase 31's own proven
property (its adversarial worktree-isolation tests are unchanged by
this phase) and remains true — Phase 33 only enriches the prompt inside
that same isolated boundary.
`test_attempt_repair_builds_and_passes_context_to_run_mini_swe_agent`
in `tests/test_agent_context.py` additionally proves the orchestrator
actually builds and threads a real context (derived from the real
candidate and real checkout) through to the tool-invocation call.

### What Phase 33 deliberately did not do

No Aider integration (Phase 34). No new trigger kinds, no loosening of
Phase 31's pytest/validate/detect-rule-only trigger restriction. No
change to the approval or verification model. No fabricated
architecture-policy content — `policy_excerpts` stays honestly empty
until Phase 37 actually creates those files.

## Phase 34 — Aider Integration (Part 2): concluded not warranted

The user's own governing instruction for this phase was explicit:
"first determine whether Aider adds a concrete capability that
mini-SWE-agent + Git + the existing Secure infrastructure does not
already provide. If it does not, document that conclusion and keep
Phase 34 intentionally minimal rather than adding unnecessary
complexity." This section is that determination.

The roadmap's own list of Aider's potential uses was checked one by
one against what Phases 31/33 already built:

- **Repository-aware editing.** Already mini-SWE-agent's entire job —
  it reads/edits files via bash commands inside the isolated worktree
  (`secure/agent/runner.py`). Adding Aider as a second editor working
  the same worktree would be two autonomous tools with edit authority
  over the same files at once — exactly the "competing autonomous
  decision system" the roadmap's own Phase 34 text says not to create.
- **Clean diffs.** Irrelevant to what Secure actually uses. Secure
  never trusts any tool's self-reported patch —
  `secure/agent/worktree.py::diff_and_changed_files()` always computes
  `git diff` itself, directly against the worktree, regardless of which
  tool (or human) produced the changes. A tool that produces a
  cleaner-looking diff internally provides zero marginal benefit to a
  caller that ignores the tool's own diff output on principle.
- **Lint/test loops.** Already `secure/agent/verify.py`'s job — pytest
  and `secure validate` run once, deterministically, from outside the
  tool's own process, after it exits. This is a cleaner boundary than
  a tool-internal test loop: Secure's own verification step is what's
  authoritative for "did this actually fix the failure," never the
  tool's self-assessment, and that's already true today independent of
  which editing tool ran.
- **Git-aware change management / rollback-friendly commits.** Directly
  at odds with how `secure/agent/changes.py` already works: a repair
  never becomes a commit — it becomes a *diff*, hashed and bound into a
  PENDING change request that a human must separately approve
  (`propose_repair_change_request()`). Aider's own auto-commit-per-edit
  behavior would need to be worked around, not used, since Secure needs
  an inspectable, hashable diff in an otherwise-discardable worktree,
  not a tool-managed commit history.
- **Controlled patch refinement.** The one area where a second,
  differently-designed editing tool could theoretically add precision
  mini-SWE-agent's bash-loop approach lacks. But introducing it here
  means two autonomous editors with independent judgment about the same
  files — the same "competing decision system" problem as the first
  bullet, for a benefit that hasn't been shown to be needed: nothing in
  Phase 31/33's testing (including deliberately-broken-test repair
  scenarios) has hit a case mini-SWE-agent's own editing loop couldn't
  handle.

**Conclusion: Aider adds no concrete capability over mini-SWE-agent +
Git + the existing Secure infrastructure for the bounded-repair
workflow this roadmap has built so far.** Every value-add area listed
in the roadmap's own Phase 34 text is either already owned by Secure
(diff computation, verification, provenance, approval — all
deliberately tool-agnostic by design) or would duplicate mini-SWE-agent's
existing editing responsibility. Per the user's own instruction, no
Aider integration was built: no new module, no new provider, no new
config field, no dependency added or requested. If a future phase
surfaces a concrete gap Aider would genuinely close (not just "the
roadmap mentions it"), that would be a new, separately-justified
decision — this conclusion is not permanent, only currently accurate.

Phase 34 is VERIFIED under the user's own redefined acceptance for this
phase (a documented, reasoned conclusion in place of an integration) —
no code changed, so no new tests were needed and the existing full
regression (1687/1687) remains the relevant proof that nothing broke.

## Phase 35 — Sandboxed Repair Workflow (Part 2): hardening, not rebuilding

Phase 35's own required flow — LIVE SECURE → ISOLATED WORKTREE → AGENT
REPAIR → ACTUAL GIT DIFF → TARGETED VERIFICATION → BROADER VERIFICATION
→ REVIEW → PROMOTION OR CHANGE REQUEST — already exists structurally,
built across Phase 31/31.5/33 and unchanged by this phase:

    LIVE SECURE               secure/agent/worktree.py::project_root()
    ISOLATED WORKTREE          create_repair_worktree() (git worktree add --detach)
    AGENT REPAIR                run_mini_swe_agent()
    ACTUAL GIT DIFF              diff_and_changed_files() (never the tool's own submission text)
    TARGETED VERIFICATION         run_pytest_in_worktree()
    BROADER VERIFICATION           run_validate_in_worktree() (secure validate run — Phase 27 security scenarios)
    REVIEW                          (manual today — Phase 38 adds the second model's independent review)
    CHANGE REQUEST                   propose_repair_change_request() (PENDING; a human decides "promotion" from here)

So this phase's job, per its own text ("harden... use standard
Git/worktree/temp-directory mechanisms rather than building a custom
filesystem snapshot framework"), was closing verification gaps in how
thoroughly the existing isolation is *proven* — not building new
isolation machinery.

### What was already proven (Phase 31, unchanged)

- Worktree edits never reach the live checkout
  (`test_worktree_changes_never_touch_the_live_repo`).
- The mini-SWE-agent subprocess's HOME is the throwaway agent-home
  directory, never the real one
  (`test_run_mini_swe_agent_home_is_isolated_not_real_home`).
- The pytest verification subprocess's HOME is likewise isolated
  (`test_run_pytest_in_worktree_uses_isolated_home`).

### What Phase 35 added (`tests/test_agent_isolation.py`)

- **Verification-subprocess symmetry.**
  `test_run_validate_in_worktree_uses_isolated_home` closes an
  asymmetry: only the pytest half of `verify_worktree()` had a
  dedicated HOME-isolation proof; `secure validate run` uses the exact
  same `_isolated_env()` helper but wasn't separately proven. It now
  is.
- **Discard completeness, adversarially.**
  `test_removed_worktree_leaves_no_git_worktree_list_residue` plants a
  messy failed-repair-shaped worktree (extra files, a fake cache dir, a
  fake database under the throwaway home) and proves `git worktree
  list` in the LIVE repo no longer references the path after removal —
  not just that the directory is gone, but that git's own registry is
  clean too, which a bare `shutil.rmtree` alone would not guarantee.
  `test_removed_worktree_permits_a_fresh_worktree_at_the_same_run_id`
  is a stronger behavioral version of the same claim: git itself
  refuses to reuse a path with leftover registration, so successfully
  creating a second worktree at the identical path is direct evidence
  the first left nothing behind.
- **The underlying OS/Python mechanism, proven directly.**
  `test_home_env_override_mechanism_is_honored_by_python_path_home` is
  a real (unmocked) subprocess test proving that overriding
  `env["HOME"]` on `subprocess.run()` genuinely changes what
  `Path.home()` resolves to inside that subprocess — this is the exact
  mechanism `AppConfig.DEFAULT_APP_DIR` (`Path.home() / ".secure"`,
  `secure/config.py`) depends on to land under the throwaway directory
  rather than the operator's real `~/.secure` when `secure validate
  run` executes inside a repair worktree. This closes the config/
  database-isolation claim that was previously only implied by
  `verify.py`'s own docstring, not independently proven.
- **A test-environment lesson worth recording.** An earlier version of
  `test_agent_home_path_is_never_the_real_operator_home_or_a_subpath_of_it`
  asserted the throwaway home is never nested under the real HOME
  directory — this failed in this project's own sandbox, where `HOME`
  is set to a broad umbrella directory that `tmp_path` fixtures also
  live under. That's a sandbox-layout artifact, not a real isolation
  gap (on an actual Mac, `HOME=/Users/<name>` and temp directories live
  under `/tmp`, genuinely disjoint). The test was corrected to assert
  what actually matters — the throwaway directory is never literally
  the same directory as real HOME, and starts genuinely empty — kept
  here as a reminder not to write isolation tests that accidentally
  encode a specific machine's directory layout as a security property.

### What Phase 35 deliberately did not (and could not) close

Repeating Phase 31's own documented limitation, on purpose, so
"hardening" is never mistaken for "fixed": there is still no OS-level
sandbox here (no container, no chroot, no network namespace). Git
worktree isolation and HOME-overriding a subprocess prevent
*accidental* collisions — cwd-relative operations, HOME-relative
config/database resolution — but they do not stop code running inside
the worktree from opening an absolute path to the live repository or
the operator's real `~/.secure` if it already knows that path and
chooses to. Building a real filesystem-level sandbox would be exactly
the "custom filesystem snapshot framework" this phase's own text says
not to build unless a mature framework (OpenHands was named as the one
candidate, evaluated only for a concrete capability gap, not adopted
here) provides it outright — that evaluation has not changed since
Phase 31 and remains a live open question for a future phase, not
something Phase 35 silently resolved.

Phase 35 is VERIFIED: 5 new adversarial tests added, all passing; full
regression **1692 passed, 0 failed, 0 errors** (1687 carried over from
Phase 34 plus 5 new Phase 35 tests). No production code changed — this
phase closed proof gaps, not implementation gaps, so no code needed to
change, only tests. No consequential action was taken and nothing is
pending approval.

## Phase 36 — Tiered Test Orchestration (Part 2)

New module `secure/agent/tiers.py` defines four escalating verification
tiers and a policy for choosing among them, reusing existing
infrastructure for two of the four:

- **FAST** — `python -m compileall` (syntax check) plus `python -c
  "import secure"` (import check), both pytest-free so this tier never
  depends on pytest being installed. New in this phase.
- **TARGETED** — pytest scoped to whatever `tests/test_<module>*.py`
  files map to the changed files' modules, via `targeted_test_files()`
  (reuses the exact "map a changed file to its module" idea Phase 33's
  `secure/agent/context.py` established for a different purpose). New
  in this phase.
- **FULL** — `secure/agent/verify.py`'s existing
  `run_pytest_in_worktree()`, called unchanged.
- **SECURITY VALIDATION** — `secure/agent/verify.py`'s existing
  `run_validate_in_worktree()` (Phase 27's own suite), called
  unchanged.

`choose_and_run_verification()` is the escalation policy: FAST always
runs first and stops everything on a definite failure; otherwise
TARGETED runs against the mapped tests; FULL escalates when TARGETED
found nothing to target, didn't pass cleanly, was forced, or the
caller passed no changed-file list at all (unknown scope, treated
conservatively); SECURITY VALIDATION runs whenever a changed file
touches one of a small, deliberately conservative set of
security-sensitive path prefixes (`SECURITY_SENSITIVE_PREFIXES` —
explicitly documented as separate from `agent_path_denylist`, which
blocks edits outright; this list only affects verification depth), or
scope is unknown. `EscalationOutcome` records exactly which tiers ran,
each one's exact command(s)/duration/status, the base commit
(`revision`), the changed-file list, and an optional caller-supplied
`diff_hash` — "store exact commands, results, duration, and relevant
revision/diff identity," the phase's own words.

**This phase deliberately does not rewire
`secure/agent/orchestrator.py`.** `_finish_repair_run()` still always
runs FULL + SECURITY VALIDATION unconditionally after every repair
attempt — a conservative, already-tested default. Phase 44 ("Verified
Self-Healing") explicitly lists "FAST verification passes, TARGETED
tests pass, FULL regression passes when required, Phase 27 validation
passes when security behavior is affected" as part of its own VERIFIED
criteria, using the exact vocabulary this module defines — so
`tiers.py` is groundwork for that phase to consume, not a replacement
for Phase 31's existing, safer-by-default verification call today.
Changing the live repair flow's verification depth is exactly the kind
of "unreviewed behavior change" this roadmap's own discipline says to
avoid making silently.

Tests: `tests/test_agent_tiers.py` (16 tests) — FAST tier tested with
real, unmocked subprocesses (compileall/import checks need no pytest,
so they run for real in every environment including this project's own
sandbox); `targeted_test_files()` tested as a pure function including
the leaf-module-vs-subpackage distinction (`secure/widget.py` → module
segment `"widget"`; `secure/agent/context.py` → module segment
`"agent"` — a real bug in the first draft of `_module_segment()`
conflated these, caught by
`test_targeted_test_files_maps_changed_module_to_matching_test_files`
failing for real, fixed before this phase was marked VERIFIED); the
escalation policy tested with mocked subprocesses (this sandbox has no
real pytest, matching every other verification test in this project)
covering: stop-at-FAST on a syntax error, unknown-scope forcing both
FULL and SECURITY, a clean TARGETED pass skipping both FULL and
SECURITY for a non-sensitive change, a security-sensitive change still
running SECURITY even when TARGETED passes cleanly, a TARGETED failure
escalating to FULL, `force_full=True` always running FULL, and
`EscalationOutcome` correctly carrying `revision`/`diff_hash`/
`changed_files`.

Phase 36 is VERIFIED: the acceptance criterion ("the orchestrator
chooses bounded appropriate verification and can escalate to the
complete regression suite") is met and proven by the tests above; full
regression **1708 passed, 0 failed, 0 errors** (1692 carried over from
Phase 35 plus 16 new Phase 36 tests). No consequential action was taken
and nothing is pending approval.

## Phase 37 — Engineering Policy (Part 2): the four files, and why they are shaped the way they are

Phase 33 built `secure/agent/context.py`'s `policy_excerpts` hook and
left it deliberately dormant: it reads `AGENTS.md`,
`ARCHITECTURE_RULES.md`, `docs/SECURITY_INVARIANTS.md`, and
`docs/TESTING_POLICY.md` from the repository root, and returned `{}` because
none of them existed. Phase 37 creates them. No code changed — the hook
was written to need nothing when the files arrived, and it needed
nothing.

### The front-loading convention

`_load_policy_excerpts()` truncates each file at
`_MAX_POLICY_CHARS_PER_FILE` (3000). For ordinary documentation that is
harmless. For a numbered rule list it is not: a 12-rule file longer
than the cap would reach a coding agent as rules 1-7 plus a truncation
notice, with no error anywhere, and the agent would have no way to know
it was reading a partial policy.

The fix is structural, not code. Every policy file puts its **complete**
numbered normative section first, ahead of a `---` marker, sized to fit
the budget; everything below the marker is rationale for human readers
and may be truncated with no loss of meaning. Each file states this in
its own opening paragraph. Current sizes of the normative sections:
`AGENTS.md` 2487, `ARCHITECTURE_RULES.md` 2626,
`docs/SECURITY_INVARIANTS.md` 2941, `docs/TESTING_POLICY.md` 2647 characters.

The alternative — raising `_MAX_POLICY_CHARS_PER_FILE` — was rejected.
That constant is a deliberate prompt bound, part of Phase 33's own
"do not dump the entire repository into model context" instruction;
loosening a safety limit to accommodate documentation length would be
a production change made for a documentation reason.

### What is in each file

- **`AGENTS.md`** — rules for an automated coding agent working inside
  an isolated worktree: scope, minimality, never weaken a test, never
  touch authorization code or host state, never add a dependency,
  honest absence, the layer rule, never weaken an invariant, and "your
  patch is a proposal, not a change."
- **`ARCHITECTURE_RULES.md`** — the normative subset of
  `docs/ARCHITECTURE.md`: the layer order, interface-only peers, thin
  interfaces, SQL confined to `storage/models/`, additive-only schema,
  the `_shell.py` subprocess seam, empty-string-default gating,
  new capability in a new package, no upward imports, and no
  reimplementation of what an adopted framework already provides.
- **`docs/SECURITY_INVARIANTS.md`** — the twelve properties that may not be
  weakened without explicit human approval, each traceable to
  `secure/ai/__init__.py`'s Phase 28 hard rules,
  `secure/validate/__init__.py`'s Phase 27 hard rules, or a Phase
  31/31.5/35 trust boundary. It also names, honestly, the boundary that
  is not closed: there is no OS-level sandbox.
- **`docs/TESTING_POLICY.md`** — never weaken a test (first, because the
  repair loop's only deterministic signal depends on it), the
  `tests/test_<module>.py` naming rule that Phase 36's
  `targeted_test_files()` actually depends on, the fixture surface in
  use, no real state, no network, determinism, seam mocking, structural
  tests over comments, testing honest absence, not optimizing tests to
  flatter Secure, and asserting on behavior rather than prose.

### Tests (`tests/test_agent_engineering_policy.py`, 9 tests)

Named to fall inside Phase 36's own `tests/test_agent*.py` targeting
glob, so a future change under `secure/agent/` still selects it.

The load-bearing test is
`test_no_numbered_rule_is_lost_to_truncation_in_a_real_repair_context`:
rather than asserting the arithmetic (section length ≤ cap), it builds
a real `RepairContext` against the live checkout and compares the
number of numbered rules in each excerpt **as a coding agent would
actually receive it** against the number in the file on disk. If a
future edit pushes a rule past the cap, that test fails on the real
path, not on a proxy for it.

The rest: the four files exist at `project_root()`; `_POLICY_FILENAMES`
and the files on disk cannot drift apart; every file has the `---`
marker with rules numbered contiguously from 1; each normative section
fits the cap; the live-root context carries all four non-empty
excerpts; `render_context_block()` emits the policy section and each
file header; the rendered block specifically carries "Never weaken a
test to make it pass"; and Phase 33's honest-absence behavior is
unchanged for an unrelated root — the loader reads the root it is
given and never falls back to this repository's own files.

### An accuracy correction worth recording

A first draft of `ARCHITECTURE_RULES.md` asserted that the
`shell=False` rule is enforced by a structural source-parsing test.
It is not. The structural tests that actually exist are
no-write-outside-`cfg.app_dir_path()`, no-`launchctl`-invocation, and
the AST-based no-self-approval check under `secure/agent/`. The file
now says so and names `shell=False` as a known convention-only gap.
A policy file that overstates its own enforcement is the documentation
equivalent of a silent clean pass — the exact failure mode this
project's own invariant 5 exists to prevent.

Phase 37 is VERIFIED: the files exist, the dormant hook demonstrably
lights up against the live checkout, every rule provably survives into
a real repair prompt, and full regression is **1717 passed, 0 failed,
0 errors** (1708 from Phase 36 plus 9 new). No production code changed
and nothing is pending approval.

## Phase 38 — Independent Reviewer (Part 2): the second model, and the one direction it can push

Phase 32 created `ROLE_INDEPENDENT_REVIEWER` and left it without a
caller. Phase 28 created `ai_change_requests.model_b_opinion` and Phase
31 could only fill it with a placeholder saying no second model had
looked at the change. Phase 38 connects those two. `secure/agent/review.py`
is the new module; no new provider, no new inference path, no new
approval mechanism.

### The trust rule, stated precisely

The reviewer can turn a PASS into a STOP. It can never turn a FAIL, an
inconclusive result, or an unavailable verification into a pass.

Two things enforce that, neither of them a comment:

1. `review_repair()` is called from exactly one place — the
   `verification.overall_passed is True` branch of
   `_finish_repair_run()`. The failed and inconclusive branches do not
   reference the reviewer at all.
2. `review_gate()`'s return vocabulary is exactly `{proceed, escalate}`.
   There is no value in that type that means "verification succeeded,"
   so there is nothing for a reviewer to return that could be mistaken
   for one.

`test_the_reviewer_is_never_even_consulted_when_verification_did_not_pass`
asserts the provider's call list is empty on a failing run, and — so
the test cannot pass for the wrong reason — also asserts that run
produced a real diff and real changed files. The reviewer was excluded
by the branch, not by there being nothing to review.

### Absent reviewer vs. broken reviewer

| Situation | Status | Blocks? |
|---|---|---|
| No local model configured | `unavailable` | No — Phase 31 behavior preserved |
| Change is trivial | `not_required` | No |
| Provider raised or returned a non-OK completion | `error` | **Yes** |
| Output could not be parsed into answers | `unparseable` | **Yes** |
| Reviewed, no blocking findings | `ok` | No |
| Reviewed, blocking findings | `ok` | **Yes** |

The asymmetry is deliberate. An operator who has configured no local
model has made a choice, and the change request has always said in
plain words that no second model reviewed it. A reviewer that ran and
produced something unusable has not made a choice — it has malfunctioned,
and a malfunction must not be read as assurance.

### "Unknown" blocks

An `unknown` answer on a blocking question blocks. This is the same
rule `VerificationOutcome.overall_passed` already applies to
deterministic verification: inconclusive is never a pass. The gate
exists to obtain an assurance; a reviewer that cannot give one has not
given one.

### Blocking is computed, never self-reported

`compute_blocking()` derives the blocking set from the parsed answers.
A model that emits `"blocking": []` and `"verdict": "approve"` next to
a `tests_weakened: yes` answer does not clear itself — there is a test
that feeds exactly that response.

Two of the nine questions are recorded but deliberately non-blocking.
"Unnecessarily broad" is a quality judgment rather than a disagreement
about correctness, and escalating on breadth alone would make the gate
noisy enough that a human would learn to wave it through. "Requires
human approval" is already true of every repair this system produces,
so treating it as blocking would escalate unconditionally and therefore
mean nothing; Phase 39 gives that question teeth by replacing the
model's opinion with a deterministic classification.

### What counts as non-trivial

More than one changed file, more than 20 changed diff lines, any
security-sensitive path (Phase 36's own prefix list, reused), or any
file under `tests/`. Unknown scope counts as non-trivial — uncertainty
escalates toward review, not away from it.

The `tests/` clause carries more weight than its size suggests.
Deleting a single assertion is a one-line, one-file change that every
size-based heuristic would call trivial, and it is precisely what
AGENTS.md rule 3 and TESTING_POLICY.md rule 1 exist to prevent. A
change to a test is never trivial here.

### Material disagreement

Coder asserted success (tool completed, produced a diff, and that diff
then passed deterministic verification) AND reviewer raised at least
one blocking finding. That sets run status `escalated_for_review`,
records `review_disagreement=1`, and creates **no** change request.
The worktree and diff persist; a human picks it up.

### Persistence

Nine additive columns on `agent_repair_runs`, in both `CREATE TABLE`
and `_COLUMN_MIGRATIONS`, so an existing database heals itself and a
pre-Phase-38 run honestly reads back as "no review was performed."
`complete_agent_repair_run()` writes them via a separate all-optional
statement, so a caller that says nothing about the review leaves the
existing values untouched rather than blanking them.

`model_b_opinion` on the resulting change request now carries the real
reviewer identity, the computed blocking list, the summary, and all
nine answers with rationales. The accompanying risk sentence says
explicitly that a second model agreeing is a second opinion and **not**
an approval.

### A gap in this phase's own first draft

`coder_assessment` was computed and threaded into the gate but never
persisted — a direct miss against "record both assessments." It
survived the first green test run because the test meant to catch it
had been written as `record.coder_assessment == "" or "widget" in
record.coder_assessment`, an assertion with an always-true arm. Both
were fixed. Worth remembering: a disjunction with a trivially-satisfied
branch is not a test, and it will report success forever.

## Phases 38-47 (Part 2 complete) — the supervised maintenance loop

Phases 38-47 were built in one continuous session after the Phase 37
handoff. The verbatim governing roadmap is saved at
`docs/ROADMAP_PART2_PHASES_38_47.md`; per-phase results are in
`PROJECT_NOTES.md`. This section is the map.

### What each phase added

| Phase | Module | What it owns |
|---|---|---|
| 38 | `secure/agent/review.py` | Independent reviewer: nine questions, computed blocking set, escalation on material disagreement |
| 39 | `secure/agent/classify.py` | Deterministic change classification into five classes; a model may raise, never lower |
| 40 | `secure/agent/center.py` | Change Request Center: full review surface, and post-approval content integrity |
| 41 | `secure/agent/notify.py` | Sanitized consequential-change email; no secrets, no authorization path |
| 42 | `secure/agent/supervisor.py` | Bounded observe-only background jobs + launchd plist generation (no install code) |
| 43 | `secure/agent/diagnose.py` | The REPRODUCE gate in front of every repair |
| 44 | `secure/agent/verified.py` | The authoritative eleven-criterion VERIFIED definition |
| 45 | `secure/agent/memory.py` | Structured, searchable repair history; evidence, never authority |
| 46 | `secure/agent/toolchain.py` | Dependency/tool maintenance situations → approval-gated proposals (no update code) |
| 47 | `secure/agent/maintenance.py` | The sequencer that runs all of it as one bounded loop |

### The four recurring design rules

Every one of these appeared in more than one phase, and each is
enforced by a test rather than by a comment.

1. **Inconclusive is never a pass.** Phase 31's verification, Phase
   36's escalation, Phase 38's review gate, Phase 43's reproduction
   gate, and Phase 44's criteria all answer True/False/None, and None
   blocks exactly as False does. The single most repeated line in
   Part 2.
2. **Models may restrict, never permit.** Phase 38's reviewer can turn
   a pass into a stop and can never turn a failure into a pass. Phase
   39's classifier accepts a model's suggestion only when it RAISES the
   required approval level. Phase 44 reads no free-text model field at
   all.
3. **Enforced by absence.** Where a capability would be dangerous, the
   code for it does not exist rather than existing behind a flag: no
   launchd install path (42), no package-update path (46), no patch
   replay path (45), no patch-apply path (47). An install path that
   exists is an install path a bug can reach.
4. **Measured now, not remembered.** Phase 40 re-hashes change-request
   content on demand; Phase 44 re-runs the original failure and
   re-hashes the diff at evaluation time. A recorded result is a claim
   about the past, and the attacks these phases guard against all
   happen after the recording.

### A note on structural tests and substring matching

Five times in this session, a structural test written as a substring
check produced a false positive on legitimate prose or on an unrelated
identifier: `launchctl` inside a lookup table and then inside the
comment explaining that table (39), `approve_change` inside a docstring
describing Phase 28 (40), `install` inside the sentence "does not
install, update, or remove anything" (46), and a bare attribute named
`run` matching `diagnosis.run` (47). In every case the test was wrong,
not the code, and the fix was to make the check precise — argv shape,
parsed AST with docstrings excluded, command phrase, or import name.

Phase 31's own no-self-approval test got this right first, and its
comment says why: it parses the source "since the module docstrings
legitimately discuss these functions by name." That lesson generalizes.
A structural invariant worth testing is worth testing precisely; a
blunt check that fires on documentation will eventually be silenced,
and a silenced check protects nothing.
