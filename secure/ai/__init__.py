"""
secure/ai/ — Phase 28 Local AI Security Analyst: an OPTIONAL local-LLM
investigation assistant. Governing instruction's own words, and the
hard rules they imply:

    "The AI is NOT a detection authority... The deterministic security
    engine remains authoritative... Do not allow autonomous destructive
    response... any system change proposed by either LLM must be
    approved by me before execution."

Five hard rules every module in this package is built to enforce
structurally, not just by convention:

1. **Read-only by construction.** The context a model sees
   (`secure/ai/context.py`) is assembled entirely from existing
   read-only calls (`secure.investigate.view.investigate()`,
   `explain_observation()`, cached threat-intel lookups, integration
   `check_availability()`) — nothing in this package writes to a
   finding, an alert, a baseline, or any detection-relevant table. The
   ONLY tables this package ever writes to are its own three
   (`ai_analyst_queries`, `ai_verification_runs`,
   `ai_change_requests`).
2. **Every claim must be traceable, or explicitly not.** A model's
   answer is parsed into individually-tagged claims — `STORED_FACT` /
   `SECURE_INTERPRETATION` (from data Secure itself already computed)
   vs. `AI_ASSESSMENT` / `UNVERIFIED_HYPOTHESIS` (the model's own new
   reasoning) — see `secure/ai/vocab.py`. The first two categories
   require a cited Secure evidence id; every cited id is checked after
   the fact against the exact context manifest the model was given
   (`secure/ai/response.py`) — an invalid citation is flagged, never
   silently dropped or silently accepted.
3. **Verification mode is read-only-plus-deterministic-tests, never a
   modification of real host state.** `secure/ai/verify/` runs only a
   fixed, hardcoded enum of operations (never a raw command string
   supplied by a model), via `subprocess.run([...])` argument lists
   (never `shell=True`), always timeout-bound. The deterministic test
   framework (pytest, `secure/validate/`) decides PASS/FAIL; the model
   only explains the result afterward.
4. **No autonomous change, ever.** `secure/ai/changes/` can only ever
   create a `PENDING` change request — a two-model Propose/Attack
   pipeline plus deterministic test results, bound to an exact content
   hash. Nothing in this codebase transitions a change request to
   `approved` except one explicit human CLI action
   (`secure ai changes approve CR-xxx`) checked against that exact
   hash. Agreement between the two models, passing tests, and email
   delivery are each explicitly NOT approval — see
   `secure/ai/changes/workflow.py`'s own docstring.
5. **Local-only, opt-in, gated before any I/O.** Both providers
   (`secure/ai/providers/`) follow the exact same
   empty-value-means-unconfigured discipline
   `secure.threatintel.providers.virustotal` already established —
   `AppConfig.ollama_host`/`local_llm_host` default to `""`, checked
   before any request is made, so this entire package is inert on a
   fresh install.
"""

from __future__ import annotations
