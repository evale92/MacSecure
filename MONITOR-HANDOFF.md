# Handoff — Baseline Monitoring (Phase 54 follow-on)

**Written:** 2026-09-23 ~10:40 EDT, after verifying the claims in `HANDOFF.md`
against the machine.
**Status:** Phase 54 code is done and tested. Baseline collection is **not
running** and has collected **nothing**. Three things must change before it can.

Read this before you act on the "Baseline Collection" section of `HANDOFF.md` —
that section is wrong and has been corrected to point here.

---

## 1. What is actually true right now

| Claim you may have been told | Reality | How it was checked |
|---|---|---|
| "Core alerting tests: 7/7 passing" | True but understated — **61/61 pass** | `.venv-tk/bin/python3 -m pytest tests/test_alerting_*.py -q` |
| "Latest commit a2393a5 (baseline collection automated)" | Commit is real; it is **19 added lines of `HANDOFF.md` and nothing else** | `git show --stat a2393a5` |
| "Monitor: Scheduled, next scan ~1:59 PM EDT" | **Nothing is scheduled.** No such time will fire | see below |
| "Awaiting baseline data" | The wait never ends as configured | `Total entities: 0` in every log |

Nothing is scheduled — all three mechanisms are empty:

```bash
launchctl list | grep secure.monitor                     # → no output
ls ~/Library/LaunchAgents/com.secure.monitor.plist       # → No such file
crontab -l                                               # → no crontab for erickvale
```

`com.secure.monitor.plist` exists **only in the repo**. It was never installed.
The six files in `.monitoring/` are timestamped 08:05, 08:06, 08:06, 08:58,
09:42, 09:59 — a cluster of manual runs, not a 4-hour cadence. Nothing since
09:59.

---

## 2. Three defects to fix (all required — fixing one alone changes nothing)

### A. The plist was never installed or loaded
It sits at `./com.secure.monitor.plist` in the repo. `launchctl` only reads
`~/Library/LaunchAgents/`.

### B. `--log-only` skips every collector
`HANDOFF.md` documented the automation as running `secure_monitor.sh --log-only`.
In `secure_monitor.sh`, all five scanners are inside:

```bash
if [ "$LOG_ONLY" = false ]; then
    run_scanner "persistence" ...
    run_scanner "listening"   ...
    run_scanner "connections" ...
    run_scanner "wifi"        ...
    run_scanner "bluetooth"   ...
fi
```

So `--log-only` runs *only* the detection pipeline, over data that nothing
gathered. **This is why the baseline is empty**, not a storage bug — the last
log shows `Total entities: 0` across all eleven entity types after six runs.
Do not go debugging `anomaly_events` or the Phase 14 storage layer; they were
never given anything to store.

### C. The plist's PATH cannot find the interpreter
```xml
<string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
```
No `/opt/homebrew/bin`. The script calls bare `python3`. The only interpreter
with both `pytest` and the `secure` module's dependencies is
`/Users/erickvale/Desktop/secure-resource/.venv-tk/bin/python3` — confirmed:

```
.venv-tk/bin/python3 -c "import pytest, secure"   → OK
/opt/homebrew/opt/python@3.14/bin/python3.14      → No module named pytest
```

---

## 3. The decision that is NOT yours to make

**Do not install the LaunchAgent on your own.** Two reasons:

1. The plist's own header says it is unloaded deliberately:
   `NOT LOADED BY DEFAULT (Invariant 12: full uninstall reversibility)`.
2. `MONITORING_SETUP.md` describes this project as
   *"Threat detection pipeline monitoring on macOS (manual/on-demand)"* and
   lists cron as merely "optional, if desired".

So the repo's own documents say unscheduled is the intended state, and
`HANDOFF.md` said otherwise. Whether a persistent background job is allowed
under Invariant 12 is a design question. **Ask the user; if they want it
settled properly, escalate to `deep`.** Per `CLAUDE.md` this fires two triggers:
a design decision, and something persistent that is awkward to undo.

---

## 4. If the user says go — the exact sequence

```bash
cd /Users/erickvale/Desktop/secure-resource

# C: point the script at the venv interpreter (edit secure_monitor.sh),
#    or add /opt/homebrew/bin to the plist PATH. Prefer the venv — explicit.

# B: drop --log-only from whatever invokes it so the scanners actually run.

# A: install and load
cp com.secure.monitor.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.secure.monitor.plist

# verify it is really there (this is the step that was skipped last time)
launchctl list | grep secure.monitor
```

Note the plist sets `RunAtLoad=false`, so loading it fires nothing for 4 hours.
To confirm the fix works, run it once by hand first and check the log:

```bash
./secure_monitor.sh
tail -30 "$(ls -t .monitoring/monitor_*.log | head -1)"
```

**Acceptance:** `Total entities:` is greater than 0. If it still reads 0 after a
run *without* `--log-only`, that is a real collector bug and worth investigating.

Also: `StandardOutPath` is `/var/log/secure_monitor.log`. A user LaunchAgent
usually cannot write to `/var/log`. Expect to redirect into `.monitoring/`
instead.

---

## 5. Constraints that apply to this machine

- **8 GB RAM, and swap was at 5.5/7.2 GB while this was written.** Never run the
  full suite. One test file at a time: `.venv-tk/bin/python3 -m pytest tests/test_alerting_decide.py -q`
- **Never wait in the foreground** — no `until ... done`, no sleep loops. That
  deadlocked the bot on 2026-09-23 and took it offline for ~40 minutes. If a job
  is long, hand the user the command instead.
- **Do not commit, push, or advance a phase without asking.**
- `timeout` is not installed on this machine. Don't reach for it.

---

## 6. Other traps in `HANDOFF.md`

- Its Quick Start says `git log` "should show b29fc71 at top". Head is now
  `a2393a5`. Treat commit hashes in that file as stale.
- It claims "275 tests passing" as a headline. That number was not verified in
  this session; only the 61 alerting tests were, and all 61 pass.

---

## 7. Open, unrelated to the monitor

Four items carried from earlier reviews, none started:
- osquery partial-pass exits 0 (should be a finding)
- integration alerts share one table — crowd-out risk
- AI hosts not forced to loopback
- stale docstrings in `secure/cli.py`

Plus two approval-path follow-ups: re-hash `diff.patch` before approval, and a
backstop for orphaned CR-run links.
