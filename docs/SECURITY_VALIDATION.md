# Security Validation (Phase 27)

## Governing instruction, verbatim

> PHASE 27 — SECURITY VALIDATION
> Build a controlled validation framework for Secure Project MB.
> Use safe, established defensive testing resources such as applicable
> Atomic Red Team techniques and purpose-built local fixtures.
> Test representative behaviors including: persistence creation, suspicious
> file changes, unusual process execution, new listeners, unusual outbound
> connections, supported YARA/Sigma/Suricata detections.
> Measure: whether Secure observed it, which sensor/tool observed it,
> detection latency, correlation result, explanation quality, false
> positives, sensor failures, deduplication correctness.
> Do not optimize tests to make Secure look good. Record missed detections
> and limitations.
> Produce a repeatable validation report suitable for portfolio
> demonstration.

## The two hard rules

1. **Sandbox-only, always.** Every scenario runs against a throwaway,
   temp-file SQLite database and an isolated `AppConfig`
   (`secure/validate/sandbox.py`) — never the operator's real `~/.secure`
   database, never real system locations like `~/Library/LaunchAgents`.
   MITRE ATT&CK / Atomic Red Team supply CONTENT here — real technique
   IDs, realistic artifact shapes (`secure/validate/attck.py`) — not an
   EXECUTION MECHANISM. This framework never creates a real LaunchAgent,
   opens a real listening socket, or touches a real file outside its own
   sandbox. This is deliberately narrower than literal Atomic Red Team
   usage (which normally acts on the real host), approved this way by the
   user specifically because Phase 26 (real, confirmed enforcement actions
   on the live Mac) is still deferred — see the Phase 26 roadmap entry.
2. **Never filter a failure out of the report.** A scenario's outcome is
   always exactly one of `PASS`, `PARTIAL`, `MISS`, `NOT_EVALUABLE`,
   `SENSOR_UNAVAILABLE`, decided by comparing what actually happened to the
   scenario's own `expected_result`. `list_validation_scenario_results()`
   never accepts an outcome filter — nothing in `secure/validate/` or
   `secure/validate/report.py` is able to omit a MISS/NOT_EVALUABLE/
   SENSOR_UNAVAILABLE row. The scenario catalog deliberately includes cases
   Secure is known, going in, to only partially handle.

## Architecture

```
secure/validate/
    __init__.py       outcome + category constants, the two hard rules
    attck.py           six real MITRE ATT&CK technique references (content only)
    sandbox.py         throwaway temp-dir AppConfig + Database per scenario
    rubric.py           deterministic explanation-quality checklist
    scenario.py         ScenarioResult shape + timed() wall-clock helper
    scenarios/
        persistence.py      persistence creation + unusual process execution
        fileintegrity.py    suspicious file changes
        connections.py      unusual outbound connections
        listening.py        new listeners
        detections.py       Sigma/YARA-X/Suricata (reuses Phase 25 fixtures)
        crosssensor.py       correlation result + deduplication correctness
    runner.py            orchestration: collect all SCENARIOS, run, persist
    report.py            Markdown + JSON report generation
secure/cli/validate.py   `secure validate run/list/show/report`
```

Every scenario function reuses Secure's own real scanner/correlate/explain
code paths unchanged — this package adds zero new detection logic of its
own, only synthetic input data and measurement. Fixture injection reuses
the exact same `unittest.mock.patch` boundaries the existing test suite
already proves safe (`secure.persistence.scanner.list_processes`/
`.get_login_items`/`.check_code_signing`,
`secure.persistence.launch_items._LAUNCH_ITEM_DIRECTORIES`,
`secure.connections.scanner.run`, `secure.listening.scanner.run`), applied
via `unittest.mock.patch.object` context managers rather than pytest's
`monkeypatch` fixture, since this code runs at CLI-invocation time, not
under pytest.

## Two databases are deliberately in play at once

- Each scenario's **fixture injection** happens against its own fresh
  `sandbox()` database/AppConfig — created per scenario so no scenario can
  see another scenario's synthetic data.
- The **result** of running that scenario (a `ScenarioResult`) is recorded
  into the operator's real `~/.secure` database via
  `add_validation_scenario_result()`, the same way any other Secure
  module's findings are recorded — so a validation run's own history
  survives across invocations and `secure validate list`/`show` behave
  like every other Secure subsystem's CLI.

## Scenario catalog (21 scenarios across 6 categories)

| Category | Scenario | Expected outcome |
|---|---|---|
| persistence_creation | new unsigned LaunchDaemon | PASS |
| persistence_creation | new signed/benign LaunchDaemon (false-positive check) | PASS |
| unusual_process_execution | unusual unsigned process | PASS |
| unusual_process_execution | `ps` sensor unavailable | SENSOR_UNAVAILABLE |
| persistence_creation | modern "Background Item" (SMAppService) | NOT_EVALUABLE |
| suspicious_file_change | executable content modified | PASS |
| suspicious_file_change | unchanged file, no false alert | PASS |
| unusual_outbound_connection | new outbound endpoint | PASS |
| unusual_outbound_connection | known endpoint not re-flagged | PASS |
| unusual_outbound_connection | `lsof` sensor unavailable | SENSOR_UNAVAILABLE |
| new_listener | new listener on a non-standard port | PASS |
| new_listener | known listener not re-flagged | PASS |
| new_listener | `lsof` sensor unavailable | SENSOR_UNAVAILABLE |
| detection_rule | Sigma rule fixtures pass | PASS |
| detection_rule | Sigma rule requiring Windows telemetry | NOT_EVALUABLE |
| detection_rule | YARA-X ruleset compiles and fires | PASS |
| detection_rule | YARA-X engine unavailable | SENSOR_UNAVAILABLE |
| detection_rule | Suricata EVE parser fixtures pass | PASS |
| correlation | persistence + file-integrity cluster into one alert | PASS |
| correlation | single-module signal does NOT cluster (false-positive check) | PASS |
| deduplication | persistence entry + its backing process link as one event | PASS |

Every `NOT_EVALUABLE`/`SENSOR_UNAVAILABLE` row here is a genuine,
already-documented capability boundary elsewhere in the codebase — for
example, `persistence_background_items_not_evaluable` reuses the exact gap
`secure/persistence/login_items.py`'s own docstring already documents
(modern macOS Background Items require `sfltool dumpbtm`, which this
project has never implemented without a real Mac to verify the
undocumented, version-dependent output format against). No scenario in this
catalog was invented to look bad or good — each one is either a real,
representative attack shape or a real, already-known limitation.

## Explanation-quality rubric

`secure/validate/rubric.py` scores a real `Explanation` object (from
`secure/explain/dispatch.explain()`) against a deterministic checklist —
never a fuzzy score:

- `has_severity`
- `has_evidence`
- `evidence_provenance_valid`
- `summary_non_generic`
- `not_degraded`

Scenarios whose finding has no dedicated explainer (connections, listening
— see `secure/storage/database.py`, which has no `*_alerts` table for
either) honestly report an empty `{}` checklist rather than forcing a
fabricated score through a code path that has nothing registered for that
table.

## Honesty note on "detection latency"

`secure/validate/scenario.py`'s `timed()` helper measures **in-process
framework overhead** — fixture injection, the real scan pass, and any
`explain()` call — timed with `time.monotonic()`. This is **not** a
measurement of real-world attacker dwell time or detection latency against
a live adversary. Every report generated by `secure/validate/report.py`
states this explicitly next to every latency figure it prints.

## The report

`secure validate report` writes `docs/generated/VALIDATION_REPORT.md`
(always) and `docs/generated/validation_report.json` (unless `--no-json`).
Both formats include: Secure version, run timestamp, total scenario count,
counts by outcome (all five buckets, always, even at zero), a "Failures and
Gaps" section that surfaces every MISS/PARTIAL up front, a full
per-scenario table/detail (ATT&CK ID/name, description, expected result,
sensors observed, findings, correlation result, explanation checklist,
dedup result, latency, final outcome, notes), and a "Scope and Honesty
Notes" section restating the sandbox-only and latency caveats above.

**No function anywhere in `secure/validate/report.py` computes a single
aggregate "security score" or percentage.** The only aggregate numbers
ever printed are the five outcome counts — a percentage would obscure
exactly which capability gaps and misses exist, which is the opposite of
this framework's purpose.

## CLI

```
secure validate run                 # runs all 21 scenarios, persists results
secure validate list                # past runs
secure validate show <run_id>       # full per-scenario detail for one run
secure validate report [run_id]     # writes docs/generated/VALIDATION_REPORT.md (+ .json)
    [--output-dir PATH] [--no-json]
```

`secure validate run` exits `1` only if at least one scenario returned a
genuine `MISS` this run (`PARTIAL`, `NOT_EVALUABLE`, and
`SENSOR_UNAVAILABLE` do not affect the exit code — they are expected,
documented outcomes, not failures of this run).

## What this framework is not

- Not a penetration test. It does not simulate a real adversary end to
  end, does not test privilege escalation, lateral movement, or exfil
  paths beyond the outbound-connection scenario above.
- Not a measurement of Secure's real-world detection latency — see the
  honesty note above.
- Not a substitute for `tests/test_validate_*.py` and
  `tests/test_cli_validate.py`, which test this framework's own
  correctness (determinism, unfiltered persistence, honest report
  generation) rather than Secure's detection behavior.
- Not exhaustive: 21 scenarios across 6 categories is a representative
  sample per the governing instruction's own list, not full coverage of
  every technique Secure's sensors could ever observe. Extending the
  catalog means adding a new `scenario_*` function to the relevant
  `secure/validate/scenarios/*.py` module and adding its expected outcome
  to `tests/test_validate_scenarios.py`'s own `_EXPECTED_OUTCOMES` table
  — nothing else needs to change.
