# Performance & Diagnostics (Phase 30)

Answers "what hardware is this, how loaded is it, how much is Secure
itself using, which modules are expensive, and is anything worth a
plain factual warning" — ordinary, always-on diagnostics, not a
security-detection engine and not a gated "Developer Mode." An earlier
draft of this phase had an enable/disable toggle; the approved design
removed it: performance observability is normal Secure behavior, the
same way `secure status` always shows the database's own state.

## The one rule this entire phase is built around

**A slow scan is not a security alert.** Nothing in `secure/diagnostics/`
writes to `severity`, `anomaly_score`, `correlation_alerts`, or
anything `secure/explain/` reads. Every warning this package produces
is a plain factual sentence about measured behavior against a
configured number ("Secure's RSS was 612MB, above the configured
500MB budget") — never routed through the detection/scoring/
explanation pipeline. This is enforced structurally, not just by
convention: `secure/diagnostics/` sits where `secure/validate/` and
`secure/ai/` do in the layer model (`docs/ARCHITECTURE.md`) — callable
only from the interfaces layer (CLI/GUI), never imported by any
sensor, integration, evidence, baseline, correlation, or explanation
module. A scanner has no way to know it's being timed.

## Architecture placement and reuse

Per this phase's own governing instruction, nothing here duplicates
infrastructure that already existed:

- **Integration health** — `secure/diagnostics/integrations_health.py`
  calls the same six `check_availability()` functions
  (`secure/integrations/{osquery,yarax,sigma,suricata,zeek}/`,
  `secure/dfir/velociraptor/`) every other integration diagnostic
  already uses, returning the same `IntegrationHealth`
  (`STATUS_OK`/`DEGRADED`/`UNAVAILABLE`/`ERROR`) Phase 15 established.
  No second health model was built.
- **Reporting** — `secure/diagnostics/report.py` follows
  `secure/validate/report.py`'s own Markdown-plus-optional-JSON
  pattern exactly: pure formatting, no DB writes, no interpretation
  logic.
- **Run/group identity and timing** — `perf_module_runs` uses the same
  `run_id`/`started_at`/`completed_at` shape every other `*_runs`
  table in this schema already uses (`validation_runs`,
  `baseline_runs`, `integration_runs`).
- **Subprocess boundary** — `secure/diagnostics/_shell.py` is the same
  isolated, mockable, read-only `subprocess.run(...)` seam every other
  package's own `_shell.py` already is.

## What's measured, and how

### System (never persisted — computed fresh every call)

- **Hardware** (`secure/diagnostics/hardware.py`): Mac model, CPU
  brand, logical/physical core count, total RAM (`sysctl`), macOS
  version (`platform.mac_ver()`), architecture (`platform.machine()`),
  Python version, Secure version. Advertised CPU clock speed is
  deliberately never surfaced as a performance number — `cpu_brand` is
  a label, not a benchmark, per this phase's own instruction not to
  treat it as universally meaningful (especially on Apple Silicon).
- **Live system health** (`secure/diagnostics/system.py`): load average
  (`os.getloadavg()`), memory free (`vm_stat`, parsed), swap
  (`sysctl vm.swapusage`, parsed), disk free (`shutil.disk_usage()`,
  stdlib), battery/AC state and thermal pressure (`pmset -g batt`/
  `-g therm`, parsed). Every parser (`_parse_vm_stat`,
  `_parse_swapusage`, `_parse_battery`, `_parse_thermal`) is a pure
  function of captured command text, unit-tested against real macOS
  output shapes independent of a live Mac.

Every field on both dataclasses is `Optional`; a metric this platform
genuinely can't expose is `None`, with its name listed in
`unavailable` — never a fabricated number, and a battery-less desktop
Mac is reported as "no battery" rather than an error.

### Secure itself (`secure/diagnostics/self_usage.py`)

Secure is not a daemon — every invocation is a short-lived process, so
"Secure's resource usage" means this invocation's own usage-so-far,
measured from inside itself via `resource.getrusage(RUSAGE_SELF)`
(in-process, stdlib, no subprocess — the monitoring system does not
materially distort what it's measuring). `ru_maxrss` is already a
lifetime-of-process peak, so no separate sampling loop is needed for
"peak memory." Also reports database/log file size, total events, and
total findings across every known finding table
(`secure/storage/models/perf.py`'s `count_total_findings()`, a fixed
allowlist of tables — the same "never build a dynamic query against an
arbitrary table name" discipline `secure/storage/integrity.py`
established in Phase 29).

### Per-module timing (`secure/diagnostics/instrument.py`)

`instrument_module()` is a context manager wrapped **around** a
scan/integration call at the CLI call site — `cmd_run_all`'s nine
native scans, and the four integrations with a single canonical `scan`
command (osquery, sigma, suricata, zeek) — never inside the scanner
function itself. On success it records duration, CPU-time delta,
end-of-run RSS, and best-effort observation/finding counts read off
whatever attributes the scan's own result object happens to expose. On
an exception, it records the error message and then **re-raises the
original exception unchanged** — it never swallows, converts, or
delays a failure, so every existing error-handling path behaves
identically whether or not instrumentation is active. This is what
makes the "performance measurement does not alter security results"
claim true by construction rather than by promise (see
`tests/test_diagnostics.py`'s own adversarial test proving an
instrumented scan's return value is byte-for-byte identical to an
uninstrumented one).

### Threshold warnings (`secure/diagnostics/budgets.py`)

Four configurable thresholds in `AppConfig`
(`perf_budget_secure_max_rss_mb`, `perf_budget_scan_max_seconds`,
`perf_budget_min_free_disk_gb`, `perf_budget_db_growth_warn_mb_per_run`),
each compared by a pure function against already-collected
measurements. `PerfWarning` has exactly two fields — `kind` and
`message` — no severity, no score, nothing an alert-consuming code
path could accidentally treat as a security finding.

### Development-tool process aggregate (`secure/diagnostics/tools.py`)

Driven entirely by `AppConfig.dev_tool_process_patterns` (default
`"Claude"`), a comma-separated list of substrings matched against
`ps -axo pid,rss,pcpu,comm`'s command-name column. Deliberately
generic — the code never mentions "Claude" — and deliberately narrow:
only process count, aggregate CPU%, and aggregate RSS are read, never
a full command line, open files, network activity, or environment
variables.

## Storage — deliberately minimal

Two tables, both additive, neither high-frequency:

- **`perf_module_runs`** — one row per instrumented scan/integration
  operation, written only when that operation actually runs.
- **`perf_milestones`** — one row per explicit
  `secure diagnostics milestone record "<label>"` call, never written
  automatically. This is the "Phase 15: run-all = Xs, peak RAM = Y —
  Phase 30: ..." history requirement.

No system-health snapshot table exists at all — hardware/live-health
reads are always computed fresh, never stored, since there's nothing
about them worth a history (a Mac's core count doesn't change between
runs; live load does, but at a granularity this app has no reason to
retain).

## CLI

```
secure diagnostics performance        concise summary: system + Secure + warnings
secure diagnostics system             full hardware/live-health detail
secure diagnostics modules [--sort-by-duration] [--module NAME]
secure diagnostics tools              integration health + dev-tool aggregate
secure diagnostics history            recorded milestones
secure diagnostics milestone record "<label>" [--notes "..."]
secure diagnostics report [--output-dir PATH] [--no-json]
```

## GUI

A normal "Diagnostics — Performance" category in `secure_gui.py`
(`secure_gui/performance_view.py`), reusing the DataTable-adjacent
pattern `secure_gui/baseline_view.py` established: a header, a Refresh
button, four labeled sections (SYSTEM, SECURE, MODULES,
INTEGRATIONS / TOOLS), and a "Record Milestone…" action that runs the
same `secure diagnostics milestone record` CLI command a terminal
would, narrating into the same console transcript as every other
button. No enable/disable toggle — it's always in the category list.

## Reporting

`secure diagnostics report` reuses `secure/validate/report.py`'s own
dual Markdown+JSON pattern. Sanitization is an explicit allowlist
(`_SAFE_CONFIG_FIELDS` in `secure/diagnostics/report.py`) rather than a
denylist — only fields explicitly named there ever reach the report, so
a new secret field added to `AppConfig` later is excluded by default,
never accidentally included. `tests/test_diagnostics.py` proves this
with a configured SMTP password and VirusTotal API key that never
appear anywhere in the generated report text.

## Known limitations

- **CPU% is not a continuously-sampled live percentage.** Secure's own
  CPU figure is cumulative process CPU-time, not an instantaneous
  utilization percentage (which would require sampling twice over an
  interval); this is stated as CPU-time throughout, never mislabeled.
- **Observation/finding counts in `perf_module_runs` are best-effort**,
  read off whichever common attribute name (`entries`, `devices`,
  `alerts`, `files_visited`, ...) a scan result object happens to
  expose — `None` when a result type has none of those, never a
  fabricated 0.
- **Memory pressure (`mem_pressure`) is deliberately left unavailable.**
  macOS's `memory_pressure -Q` output format varies across versions and
  the command itself samples slowly; rather than add a slow, flaky
  subprocess call for one field, it's honestly reported as
  unavailable.
- **Thread count is Python-level only** (`threading.active_count()`),
  not a full OS-level thread count — macOS has no simple portable `ps`
  column for that the way Linux's `nlwp` is. Labeled as "Python-level"
  everywhere it's shown.
