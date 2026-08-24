# Threat Model (Phase 29)

Secure Project MB is a single-user, single-machine, local-first macOS
security monitoring and investigation tool. This document makes explicit
the trust boundaries and design invariants that have held, largely
implicitly, across all 28 prior phases — Phase 29 formalizes them, does
not introduce new ones.

## What Secure protects against

Secure is a **detection and investigation aid**, not a preventive
control. It helps an operator notice and understand:

- New or modified persistence mechanisms (LaunchAgents/LaunchDaemons,
  login items, unsigned/unusual processes).
- Unexpected file changes in monitored locations.
- New or changed network behavior (outbound connections, listening
  services, ARP/neighbor-table anomalies, Wi-Fi/Bluetooth exposure).
- Signature/rule-based detections from integrated tools it can find
  installed (osquery, YARA-X, Sigma, Suricata, Zeek).
- Deviations from the operator's own established behavioral baseline.
- Cross-sensor correlation that a single sensor alone wouldn't surface.

It does this by observing, recording, and explaining — never by
blocking, quarantining, or remediating.

## What Secure explicitly does NOT do (by design, not by omission)

These are architectural invariants, verified during this phase's audit
(Stage 5) by searching the entire `secure/` tree, not just documented in
prose:

1. **No `sudo`, ever.** Every module that shells out to a system tool
   states this in its own docstring, and a repo-wide search for `sudo`
   found zero invocations — only comments and check descriptions
   *about* things that would require it (which Secure reports on, never
   executes). A check that genuinely cannot get a definitive answer
   without elevated privileges reports that honestly instead of
   escalating.
2. **No `shell=True`, ever.** Every subprocess call in the codebase
   passes a fixed argv list. A repo-wide search for `shell=True` found
   zero real usages — the only two matches are comments explicitly
   documenting its absence (`secure/ai/__init__.py`, `secure/ai/verify/
   __init__.py`).
3. **No destructive filesystem operations in production code paths.** A
   repo-wide search for `os.remove`/`shutil.rmtree`/`.unlink(` outside
   `tests/` and `secure/validate/`'s own throwaway sandboxes returned
   nothing. Secure cannot delete a file anywhere on the host.
4. **No autonomous remediation, ever.** Nothing in this codebase kills a
   process, disables a service, changes a permission, modifies a
   security control, or alters detection logic/thresholds/baselines
   without an explicit, synchronous, human-triggered action. Phase 26
   (guarded automated response) was researched and deliberately
   deferred rather than built. Phase 28's AI change-request workflow
   goes further: even a human-adjacent *proposal* to change something
   is born `pending` and requires a separate, explicit approval command
   bound to an exact content hash.
5. **No self-updating, no silent network fetch of code.** Secure never
   downloads or executes remote code. The "update" mechanism is
   entirely manual: pull/sync source (optionally via Syncthing, itself
   outside this app) and relaunch — `secure/self_update.py` only marks
   *that a relaunch is in progress* so in-flight scans aren't
   misinterpreted as gaps, it never fetches anything.
6. **A minimal, fully enumerated outbound-network surface.** Exactly
   three files in the whole `secure/` tree ever open a network
   connection: `secure/threatintel/providers/_http.py` (VirusTotal
   lookups, opt-in via `virustotal_api_key`, only for indicators already
   in Secure's own database), `secure/ai/providers/_http.py` (talks only
   to a *local* model server the operator configured — `ollama_host`/
   `local_llm_host`, both default empty), and `secure/ai/changes/
   notify.py` (one outbound SMTP email per AI-proposed change request,
   opt-in via `smtp_host`, default empty). Every one of these is
   opt-in, empty-string-gated before any I/O, and never triggered by a
   passive scan.
7. **One explicitly elevated, explicitly gated exception:**
   `secure dfir collect` (Phase 24) can invoke a real Velociraptor
   binary to gather forensic artifacts. This is the single capability
   in the system with more reach than "read a file / run a read-only
   system command" — and it is scoped hard: never called automatically
   by a scan or `run-all`, only by an explicit CLI invocation naming one
   artifact from `cfg.dfir_artifact_allowlist` (empty by default — must
   be configured before first use).

## Trust boundaries

```
Operator (you)                     <- the only trusted principal
    |  runs CLI/GUI directly, owns ~/.secure/*
    v
Secure (this codebase)             <- trusted, but see rules above
    |  reads: system state via read-only commands/log files
    |  writes: ONLY to its own ~/.secure/secure.db and config.json/logs
    v
External tools Secure OBSERVES     <- untrusted input, never trusted output
(osquery, YARA-X, Sigma, Suricata,
 Zeek, Velociraptor binaries)
    |
    v
The network                        <- untrusted, opt-in only (see #6 above)
(VirusTotal, a local LLM server, an SMTP relay)
```

Everything crossing the outer boundary (system commands' stdout,
external tool output, log file contents, network responses) is treated
as **untrusted data**, not instructions:

- Detection-rule content (Sigma YAML, YARA-X rules) is parsed with
  `yaml.safe_load` — never `yaml.load` — and never executed.
- An AI model's own output (Phase 28) is *always* re-validated: every
  citation is checked against the exact context manifest the model was
  actually given, an invalid citation is flagged not trusted, and the
  model's text can never itself trigger a state change — only a
  separate, human-typed approval command can.
- Integration/tool output is parsed defensively; a malformed or
  unexpected shape produces an honest `ERROR`/`DEGRADED` status, never
  a crash and never a silently-accepted result.

## What a compromise of each component would mean

| Component | Blast radius if compromised/malicious |
|---|---|
| A detection rule file (Sigma/YARA-X) on disk | Could cause false positives/negatives in that one rule's own findings; cannot execute code (rules are data, parsed defensively) or reach other subsystems. |
| An external tool binary (osquery/suricata/zeek/velociraptor) | Whatever that binary's own compromise implies at the OS level — outside Secure's control surface entirely; Secure treats its output as untrusted and never runs it with elevated privileges itself. |
| The local LLM server (Ollama/LM Studio/etc.) | Can return arbitrary text; every claim is citation-checked and the LLM can never itself execute a change — worst case is a bad or invalid-cited answer, or a rejected/no-op change-request proposal. |
| `~/.secure/config.json` | Contains any configured API keys/SMTP credentials in plaintext and every feature toggle. Phase 29 Stage 4 restricts this file and its parent directory to owner-read/write-only (`chmod 600`/`700`, applied on every `save_config()` call — see `secure/permissions.py`), the same baseline `~/.ssh` already gets; an attacker with local read access to *this account* could still see the secrets or redirect where Secure sends threat-intel lookups/notification email, but a different local account on the same Mac no longer can. Requires this account's own compromise — the same threshold at which most local tooling's config is readable anyway. |
| `~/.secure/secure.db` | Contains every finding/observation Secure has ever recorded — sensitive from a privacy standpoint (a full activity history) but not a code-execution vector; nothing in the codebase executes data read back out of it. Same owner-only permission hardening as config.json (Stage 4), applied on every `connect()` call. |

## Non-goals (explicitly out of scope, by design)

- Multi-user / multi-tenant access control — Secure assumes one
  operator, one Mac, one `~/.secure` directory.
- Defending against a fully compromised kernel/root attacker on the
  same machine — a local root-level adversary can defeat any userland
  monitoring tool, including this one, by definition.
- Real-time blocking or prevention of any kind.
- Managing or hardening the external tools it integrates with
  (osquery/Suricata/Zeek/etc.'s own security is each tool's own
  responsibility).
