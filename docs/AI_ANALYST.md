# Local AI Security Analyst (Phase 28)

## Governing instruction, condensed

The full governing instruction (both the original scope message and the
much more detailed follow-up specification) is preserved verbatim in this
repo's own session history; the load-bearing rules it establishes are:

> The deterministic Secure engine remains authoritative. The AI may
> analyze, explain, test, challenge, and propose changes, but it must
> never become the detection authority or make autonomous destructive
> changes.

> Use two local-model backends: Ollama, and a generic OpenAI-compatible
> endpoint (LM Studio / llama.cpp server / MLX / vLLM).

> Use two AI roles: Model A (Analyst) explains findings, identifies
> important evidence, suggests benign explanations, proposes
> simplifications. Model B (Verifier) challenges Model A, looks for
> contradictory evidence and unsupported assumptions, and must
> independently analyze the issue BEFORE reviewing Model A's conclusion.

> Require AI responses to distinguish stored facts, deterministic Secure
> interpretations, AI assessments, and unverified hypotheses. Require
> Secure evidence IDs in AI answers. Validate every cited evidence ID
> against the context actually supplied to the model. Invalid citations
> must be visibly flagged.

> Add a constrained verification mode that can safely inspect project
> files, inspect tests, run pytest, run the validation suite, run
> synthetic scanner fixtures, and inspect sensor health — without
> unrestricted shell access. The deterministic test framework decides
> PASS or FAIL. The LLM only explains the result.

> Any system change proposed by either LLM must be approved by a human
> before execution. Neither LLM may approve the other. Agreement between
> both models does not equal approval. Passing tests does not equal
> approval. Silence does not equal approval. Every AI-generated
> system-change request creates a PENDING change request and sends an
> email notification. Approval applies only to the exact change revision
> approved.

## The five hard rules

Documented in full in `secure/ai/__init__.py`'s own docstring; summarized:

1. **Read-only by construction.** Every fact a model sees comes from an
   existing read-only call (`investigate()`, cached threat-intel lookups,
   `check_availability()`). `secure/ai/context.py` computes nothing new.
2. **Every claim traceable.** A four-way vocabulary
   (`secure/ai/vocab.py`) — `stored_fact`, `secure_interpretation`,
   `ai_assessment`, `unverified_hypothesis` — and citation validation
   against the exact context manifest the model was actually shown
   (`secure/ai/response.py`). An invalid citation is flagged, never
   silently dropped.
3. **Verification mode is read-only-plus-deterministic-tests only.** A
   fixed, seven-operation allowlist (`secure/ai/verify/operations.py`) —
   no raw command strings ever reach a shell (`subprocess.run([...])`,
   never `shell=True`).
4. **No autonomous change, ever.** Every change request is born
   `pending`. Only one explicit human CLI action can approve it, bound
   to the exact revision hash it was created with.
5. **Local-only, opt-in.** `ollama_host`/`local_llm_host` default to
   `""` (disabled), checked before any network call — exactly like
   `virustotal_api_key`.

## Architecture

```
secure/ai/
    __init__.py         the five hard rules (docstring)
    base.py              ProviderIdentity / ProviderCompletionResult
    vocab.py              the four-way claim vocabulary
    response.py            StructuredAnswer, parse_answer(), validate_citations()
    prompt.py               builds the analyst / verifier-independent / verifier-review prompts
    context.py                read-only context builder (entity-scoped + free-form)
    roles.py                    resolve_role_providers(), run_analyst(), run_verifier()
    analyst.py                   ask() — the top-level entry point, persists ai_analyst_queries
    registry.py                   builds {"ollama": ..., "openai_compatible": ...}
    providers/
        _http.py                    shared urllib GET/POST-JSON helper
        ollama.py                    Ollama backend (/api/chat, /api/tags)
        openai_compatible.py          LM Studio/llama.cpp/MLX/vLLM backend (/chat/completions, /models)
    verify/
        __init__.py                    the constrained-verification hard rules
        operations.py                    the fixed 7-operation allowlist + implementations
        runner.py                         execute_operation(), run_operations(), the default bundle
    changes/
        __init__.py                        the change-request hard rules
        model.py                             ProposedChangeContent + compute_revision_hash()
        notify.py                              SMTP email (gated, non-blocking)
        workflow.py                             propose_change/approve_change/reject_change/propose_simplification

secure/cli/ai.py        secure ai status/ask/history/show/verify.../changes...
secure/storage/models/ai.py   ai_analyst_queries / ai_verification_runs / ai_change_requests
```

## The two-role, two-pass workflow

Model A (Analyst) answers a question once. Model B (Verifier) answers
**twice**:

1. An **independent pass** — the exact same context and question, no
   knowledge of what Model A concluded.
2. A **review pass** — now shown both its own independent answer and
   Model A's answer, explicitly instructed to look for contradictions,
   unsupported assumptions, and citation errors rather than simply agree.

This is enforced structurally, not just by prompt wording:
`run_verifier()` makes two separate `.complete()` calls with two
different prompts (`build_verifier_independent_prompt()` /
`build_verifier_review_prompt()`), and the independent prompt's user
message never contains Model A's answer text at all — verified directly
in `tests/test_ai_roles_analyst.py`.

When only one backend is configured, that single provider plays both
roles (still two genuinely independent completion calls). When neither
is configured, `ask()` returns `status="unavailable"` and creates no
half-finished record pretending otherwise.

## Citation discipline

`AnalystContext.evidence_manifest()` (`secure/ai/context.py`) derives the
citation whitelist directly from what's actually in the context — never
hand-maintained, so it can never drift out of sync with what a model was
actually shown. `validate_citations()` (`secure/ai/response.py`) checks
every `stored_fact`/`secure_interpretation` claim's `"table#id"` citation
against that manifest and mutates `citation_valid` in place. An invalid
or missing citation stays in the answer, visibly flagged
(`citation_valid=False`) — never silently dropped, and a fact/
interpretation claim with no citation at all is itself invalid by
definition.

## The constrained verification mode

Seven allowlisted operations, and nothing else can ever run:

| Operation | What it does |
|---|---|
| `list_tests` | Discovers `tests/test_*.py` files and their `test_*` function names (AST only, never imports). |
| `read_file` | Reads one file, path confined to the project root, `..`/absolute escapes rejected, sensitive extensions (`.db`, `.key`, `.pem`, `.env`, ...) denied, size-capped. |
| `run_pytest` | `subprocess.run([sys.executable, "-m", "pytest", target, "-q"], shell=False)` with a hard timeout; `target` is either the whole `tests/` dir or one file already returned by `list_tests`. |
| `run_validation_suite` | Runs Phase 27's `secure/validate/runner.py` unchanged. |
| `run_scenario` | Runs one named Phase 27 scenario and reports its outcome. |
| `check_tool_health` | Every integration's own `check_availability()`. |
| `inspect_test_presence` | Structural test-file cross-reference per module — explicitly labeled "not statement/branch coverage," never a fabricated percentage. |

Every operation reports its own mechanism `status`
(`ok`/`unavailable`/`timeout`/`error`) separately from any deterministic
verdict inside its `output` (e.g. `tests_passed: false` is still a clean
`status="ok"` run — the tests ran fine mechanically, they just failed).
**The LLM only explains that verdict; it never computes it.**

## The change-request workflow

```
Model A proposes a change  (run_analyst(), same machinery as ask())
        |
Model B attacks the proposal  (run_verifier() — independent pass first)
        |
Deterministic tests run  (run_default_verification_suite(), Stage 6 unchanged)
        |
PENDING change request created  (propose_change() — status is ALWAYS 'pending')
        |
Email notification sent  (best-effort, non-blocking, notification only)
        |
Human approval required  (secure ai changes approve CR-N <revision-hash>)
```

`propose_simplification()` (`secure/ai/changes/workflow.py`) composes
this pipeline entirely from already-built machinery: Stage 5's
`run_analyst`/`run_verifier` for the Model A/Model B exchange, Stage 6's
`run_default_verification_suite()` for "deterministic tests run," and a
new `propose_change()` that creates the row and attempts notification.

**Approval is bound to an exact revision hash.** `compute_revision_hash()`
(`secure/ai/changes/model.py`) hashes exactly the fields a human is
approving (title, proposed change, reason, affected component, risks).
`approve_change()` requires the caller to pass that same hash back and
raises `RevisionMismatchError` on any mismatch — approval can never
silently apply to content someone hasn't actually seen.

**Nothing here can approve itself.** `propose_change()` never calls
`approve_change()`. Model output is never treated as authorization, no
matter how both models "agree" — `tests/test_ai_changes.py`'s own
`test_propose_simplification_never_auto_approves` asserts this directly:
even when both stub models return `agreement="agrees"`, the resulting
change request is still `status="pending"`.

**Email is notification only.** `secure/ai/changes/notify.py` sends an
email containing all eight fields the governing instruction requires
(change request ID, proposed change, reason, affected component, risks,
verification results, Model A opinion, Model B opinion) when
`cfg.smtp_host` is configured; it is entirely skipped (never blocking)
when it isn't, and a send failure never prevents the change request
itself from being created — `mark_ai_change_request_notified()` records
the outcome, nothing more.

## CLI reference

```
secure ai status                                    show configured providers + reachability
secure ai ask "<question>" [--entity-type T --entity-key K]
secure ai history [--limit N]
secure ai show <query-id>

secure ai verify list-ops
secure ai verify run <op> [--path P] [--scenario-id S] [--test-path F] [--timeout N]
secure ai verify suite
secure ai verify history [--limit N]
secure ai verify show <run-id>

secure ai changes propose --title T --topic Q --affected-component C [--entity-type T --entity-key K]
secure ai changes list [--status pending|approved|rejected] [--limit N]
secure ai changes show <cr-id>
secure ai changes approve <cr-id> <revision-hash> [--approved-by NAME]
secure ai changes reject <cr-id> [--approved-by NAME]
```

`secure ai changes approve` refuses a change request that an agent repair
run proposed, and names the command to use instead:
`secure agent approve <run-id>`, which first re-checks that the repair
worktree's diff still matches what was proposed.

## Configuration

All new `AppConfig` fields default to disabled/empty — the AI analyst is
entirely opt-in:

```
ollama_host = ""                 # e.g. "http://127.0.0.1:11434"
ollama_model = "llama3.1"
ollama_timeout_seconds = 60.0

local_llm_host = ""              # e.g. "http://127.0.0.1:1234/v1" (LM Studio/llama.cpp/MLX/vLLM)
local_llm_model = ""
local_llm_api_key = ""
local_llm_timeout_seconds = 60.0

ai_notify_email = "evale92@gmail.com"
smtp_host = ""                   # notification skipped, non-blocking, until set
smtp_port = 587
smtp_username = ""
smtp_password = ""
smtp_use_tls = true
smtp_from_addr = ""
```

## Known limitations

- **Not smoke-tested against a real Ollama/LM Studio server.** This
  development sandbox has no outbound network access and cannot install
  or run either backend. Every provider, orchestration, verification,
  and change-request code path was verified end-to-end using fake local
  HTTP servers (mimicking Ollama's and the OpenAI-compatible API's exact
  response shapes) and, for the automated test suite, monkeypatched
  `http_get_json`/`http_post_json`/`subprocess.run`/`smtplib.SMTP` calls
  — never real network I/O. The wire protocols implemented match each
  project's own published API shape as of this session, but have not
  been confirmed against a live server.
- **`run_pytest` requires a real `pytest` installation on the operator's
  machine.** This sandbox has none (no network/pip access), so
  `run_pytest` here always reports `status="unavailable"` — correctly
  and honestly, but never exercised in its `status="ok"` path against
  this repo's real test suite. Its subprocess mechanics (success,
  failure, timeout, path-safety rejection) are fully covered using a
  stub `pytest` module and monkeypatched `subprocess.run`.
  `run_validation_suite` and `run_scenario`, which need no external
  dependency, ARE exercised for real against this repo's actual
  `secure/validate/` suite.
- **`inspect_test_presence` is a structural cross-reference, not
  statement/branch coverage.** The `coverage` package isn't available in
  every environment Secure runs in; this operation checks whether a
  module's dotted path or filename stem appears in some test file's
  source text, which is a real but weak signal — a module can be
  "referenced" without being meaningfully exercised. Labeled honestly in
  its own output (`"note"` field), never presented as a percentage.
- **`propose_simplification()`'s CR field mapping is deliberately
  simple.** `proposed_change` is Model A's own summary verbatim,
  `reason` is Model A's own claim text joined, `risks` is drawn from
  Model B's `contradictions_found`/`unsupported_assumptions`. This
  avoids any NLG-style guessing about what a human-authored "reason" or
  "risk" field should say, at the cost of the resulting text being
  exactly as good (or as generic) as the underlying model's own answer
  — a `secure ai changes show` before approving is expected to always be
  read by a human, not rubber-stamped.
- **No GUI surface yet.** Every Phase 28 capability is CLI-only; a
  `secure_gui.py` category (mirroring `secure validate`'s own eventual
  GUI treatment) was out of scope for this phase.
- **Entity-scoped verification/change proposals reuse `build_entity_context`
  as-is**, so anything Stage 3 doesn't yet expose (e.g. an entity type
  with no registered explainer) is invisible to the AI in exactly the
  same way it's invisible to `secure investigate show` — a deliberate
  consistency, not a Phase 28-specific gap.
