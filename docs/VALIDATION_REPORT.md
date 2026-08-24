# Validation Report — Phase 29 Stage 9

Date: 2026-08-22
Scope: full automated test suite + fresh `secure validate run`, per the user's Stage 9 instruction to keep "mocked tests and real sensor truth" distinct.

## Environment this report was produced in

This report was produced in a Linux sandbox, not the macOS host Secure targets. Two consequences, stated up front rather than glossed over:

Real pytest is not installed here and could not be installed — every `pip install pytest` attempt this session failed identically with a 403 from the sandbox's outbound proxy (`ProxyError('Cannot connect to proxy.', OSError('Tunnel connection failed: 403 Forbidden'))`), confirmed again immediately before this stage began. To still get a genuine pass/fail signal rather than none, a minimal pytest-compatible runner was hand-built for this session only (not added to the repo — it lives outside the project and is not a Secure deliverable). A grep across all 1573 test functions in `tests/` first confirmed the fixture surface was narrow enough for this to be trustworthy: zero `@pytest.fixture`, zero `parametrize`, zero test classes, zero skip/importorskip markers, and only three fixtures in use anywhere (`tmp_path`, `monkeypatch`, `capsys`), with `pytest.raises` used in exactly one file. The shim implements exactly those primitives — nothing more — so a test needing anything outside that surface fails loudly as an ERROR rather than silently reporting a false PASS.

Several native macOS commands the app depends on for full functionality genuinely do not exist here: `spctl`, `csrutil`, `fdesetup`, `system_profiler`, `launchctl`, `osascript`, and `arp`. This is not a workaround-needed problem — it is the correct real-world condition for proving the sensor-honesty invariant this whole phase is about, and is used as such below rather than being hidden.

## What was run, and what it proved

### 1. Full test suite (1573 tests, 85 files)

Run with the hand-built shim described above, against the real `secure/` package, no test skipped or mocked out of the shim itself.

```
COLLECTED: 1573 test functions across 85 files
PASS: 1573  FAIL: 0  ERROR: 0
```

Zero failures, zero harness errors. This includes every test written across Stages 4–8 this session (`tests/test_permissions.py`, `tests/test_storage_integrity.py`, `tests/test_failure_modes.py`, `tests/test_clean_install.py`) plus the full pre-existing suite spanning all 28 prior phases.

This is real evidence, not a rubber stamp: it is the same codebase, the same test files, executed with real fixture semantics (fresh `tmp_path` per test, `monkeypatch` with restore-on-teardown, `capsys` redirect/readouterr) — the shim's only difference from real pytest is that it lacks parametrize/custom-fixture/marker support, none of which this suite uses.

**What this does not prove:** since real pytest was never available in this environment, this session's own test runs cannot be cross-checked against an actual `pytest -q` invocation. That check still needs to happen on the user's Mac (command below).

### 2. Full static compile sweep

```
python3 -m compileall -q secure tests
```

Clean — no syntax errors anywhere in the package or test tree.

### 3. Real subprocess CLI runs against a genuinely fresh, genuinely arp/launchctl/spctl-less environment

Not mocked — real `python3 -m secure ...` invocations against a throwaway `$HOME`.

`secure init` → creates config/db/log, all present, all correctly permissioned (verified separately in `tests/test_clean_install.py`, see Stage 8).

`secure status` → clean run, 0 events, no crash.

`secure run-all` → all 9 scanners complete, exit 0, no traceback.

`secure inventory scan`, run directly against this sandbox where `arp` is genuinely absent (not simulated):

```
Could not run `arp` (not installed, or it didn't finish in time).
No device inventory data was recorded this scan.
[WARNING] secure.cli: Inventory scan could not run arp
EXIT:1
```

This is the Stage 5 ARP-availability fix (`read_arp_table_with_availability`) firing for real, on a real absent binary, not a mocked `returncode=None` — the exact condition it was built for.

`secure validate run`, against this same arp/launchctl/spctl-less environment:

```
21 scenario(s) evaluated:
  PASS                15
  PARTIAL             0
  MISS                0
  NOT_EVALUABLE       2
  SENSOR_UNAVAILABLE  4
```

`secure validate show <run-id>` detail on the 6 non-PASS scenarios:

```
SENSOR_UNAVAILABLE  persistence_process_sensor_unavailable
NOT_EVALUABLE       persistence_background_items_not_evaluable
SENSOR_UNAVAILABLE  connections_lsof_sensor_unavailable
SENSOR_UNAVAILABLE  listening_lsof_sensor_unavailable
NOT_EVALUABLE       detections_sigma_rule_not_evaluable
SENSOR_UNAVAILABLE  detections_yarax_engine_unavailable
```

This is direct, live proof of the phase's own completion criterion — "no sensor may convert 'could not observe' into 'observed nothing'" — holding on a real machine where the underlying tools are genuinely missing. Nothing here reports a false PASS; every gap is labeled SENSOR_UNAVAILABLE or NOT_EVALUABLE, matching exactly what a user would need to see to trust the result.

## What still needs to happen on the user's actual Mac

Per the user's own Stage 9 wording ("run the complete suite on the actual Mac, then run the live-host verification layer separately"), two things this sandbox cannot do:

1. **Real pytest**, to cross-check the 1573/1573 result above against the actual tool, and to pick up the small number of fixture/behavior edge cases a hand-rolled shim can't fully replicate:

   ```
   cd <project root>
   pip install -r requirements.txt
   pytest -q
   ```

   Expected: all tests pass, count at or above 1573 (this session added 4 new files; the pre-existing suite from before Phase 29 was already at 1500+).

2. **`secure validate run` on real macOS**, where `spctl`, `csrutil`, `fdesetup`, `launchctl`, `arp`, and `osascript` genuinely exist, to confirm the scenarios that reported SENSOR_UNAVAILABLE/NOT_EVALUABLE here (persistence process sensor, lsof-based connections/listening, YARA-X engine — this sandbox also lacks `bleak`/`yara_x`/`pyobjc` as real absent packages, confirmed via direct import in Stage 8) instead report PASS or a real, non-fabricated finding:

   ```
   secure init
   secure run-all
   secure validate run
   secure validate show <run-id>
   ```

   This is the step that proves the opposite half of the invariant: not just "absence is reported honestly" (proved here) but "presence is detected correctly" (only provable where the sensors' real dependencies exist).

## Bottom line

Everything provable without a real Mac and without real pytest was run for real in this session, not merely asserted: 1573/1573 tests passing under a narrowly-scoped, honesty-checked shim; a clean compile sweep; and — most importantly for this phase's actual goal — live, non-mocked proof that both the ARP-availability fix and the broader `secure validate run` machinery correctly report DEGRADED/UNAVAILABLE/NOT_EVALUABLE rather than a false clean result when real sensors are genuinely absent. The two items above are the honest remainder: they require the user's own Mac and cannot be faked or approximated here.
