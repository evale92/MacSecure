# secure-resource — State Handoff

**Written:** 2026-09-24 ~06:40 EDT, from direct inspection of the machine.
**Stage:** Phase 61 committed and working. Phases 62–63 exist only as
**uncommitted** work in the tree. The platform is now genuinely *operating*,
not just built — that is the main change from 24 hours ago.

---

## 1. Where the code is (read this first)

| Path | What it is | Trust |
|---|---|---|
| `~/Desktop/secure-resource` | **The live working tree.** Use this. | authoritative |
| `~/secure-backup/secure.git` | Bare repo, `origin` for the above | backup |
| `~/secure-backup/secure-working` | Second checkout, clean, same HEAD | stale — do not edit |
| `~/.secure` | App data only: `config.json`, `secure.db`, `secure.log` | runtime |
| `github.com/evale92/secure` | **A different, older lineage** (119 commits) | not this project |

```
HEAD      188aad5  Phase 61: GUI Dashboard — timeline view + sensor status panel
commits   177        tracked files  611        tests  181 files
```

**The `secure` repo on GitHub is NOT this project.** It is an earlier line that
diverged; its last commit is 2026-09-22. None of this project's commits were
ever pushed anywhere. Do not "restore from GitHub" — you would lose Phases
48–61.

### Why paths moved (the thing that caused a false alarm)

`DEPLOYMENT.md` in this repo instructs, as step 1 of install:

```bash
mv ~/Desktop/secure-resource ~/.secure    # "Option A (recommended)"
```

That `mv` was executed on 2026-09-23. It is why the Desktop directory
disappeared and why it looked deleted — **nothing was ever destroyed.** It was
later moved back. If a directory vanishes again, look for a `mv` before
concluding data loss.

---

## 2. Verified state

### Operational — the platform is collecting real data

```
baseline entities   493  (all maturity: learning)
baseline runs        14  (latest 2026-09-24T02:33Z, status success)
anomaly_events       99
alert_decisions     100
```

This is the material change. As of 2026-09-23 morning these were all zero.
Phases 57–61 closed that gap: monitor health checks, a sensor coverage audit,
adding fileintegrity + checks to the monitor, end-to-end validation, and the
GUI dashboard.

### Tests — partially verified, honestly stated

| Scope | Result |
|---|---|
| Alerting + detection pipeline (7 files) | **75 passed** |
| First 60 test files | **1005 passed, 14 failed** |
| Remaining 121 files | **NOT RUN** — see below |

The 14 known failures include
`test_clean_install.py::test_status_works_immediately_after_fresh_init` and
`test_run_all_completes_even_with_optional_dependencies_missing`. The other 12
were not individually captured; re-run `tests/test_clean_install.py` and
neighbours to enumerate them.

**Do not run the full suite in one process.** Attempting the remaining files
drove swap from 6 GB to 15.99 GB of 16 GB on this 8 GB machine and had to be
killed. This is the documented memory-exhaustion failure mode. Run at most
~20 files at a time:

```bash
/usr/bin/python3 -m pytest tests/test_alerting_*.py -q -p no:cacheprovider
```

**Use `/usr/bin/python3`** — it is the only interpreter on this machine with
`pytest` (8.4.2). `pytest-timeout` is not installed, so `--timeout` will error.

---

## 3. Uncommitted work — the actual current stage

```
 M secure_monitor.sh
?? secure/notifications/          (email.py, 296 LOC with the senders)
?? send_email_report.py
?? send_email_report_mail.py
?? SETUP_EMAIL.md
?? DEPLOYMENT.md
?? email.json.example
?? tests/test_email_notifications.py     ← 5 passed
?? .monitoring/*.log  (6 files)
```

This is the "Phase 62–63" a prior session referred to. **It is not committed.**
Its test passes. Decide with the operator whether to commit it as a phase or
drop it; until then it is at risk, because nothing outside this working tree
has a copy of it.

The `secure_monitor.sh` modification is an improvement worth keeping: `REPO` is
now derived from the script's own location instead of a hardcoded Desktop path,
and the `--quick` flags were dropped from the scanners.

---

## 4. Open items

1. **No off-machine copy of anything.** `secure.git` is a bare repo on the same
   disk as both checkouts. A disk failure loses Phases 48–61 entirely. Pushing
   to a remote is the single highest-value action available. Needs operator
   approval (it publishes a private security tool).
2. **Baseline collection is still not automated.** `com.secure.monitor.plist`
   is in the repo but not in `~/Library/LaunchAgents/` and not loaded
   (`launchctl list | grep secure.monitor` → nothing). The 493 entities came
   from manual runs. The plist's own header says staying unloaded is deliberate
   under Invariant 12 — that is an operator decision, not an agent's.
3. **`--log-only` still skips every collector.** In `secure_monitor.sh` all five
   scanners sit inside `if [ "$LOG_ONLY" = false ]`. Any automation that uses
   that flag will collect nothing.
4. **Phases 55–61 have no design docs.** `docs/` stops at `PHASE_53.md`.
5. **14 test failures** above, uncharacterised.

---

## 5. Working rules on this machine

- **8 GB RAM.** Never run the full suite. Never run a build over ~1 minute.
- **Never wait in the foreground** — no `until ... done`, no sleep loops. That
  deadlocked the Telegram bot on 2026-09-23 and took it offline ~40 minutes.
- **Do not commit, push, advance a phase, or move directories without asking.**
  Moving directories is what started the last incident.
- `timeout` is not installed. `pytest-timeout` is not installed.
- The Telegram bot's workspace is pinned to `~/Desktop/claude-resource`, a
  *different* project. Tell it explicitly to work in `~/Desktop/secure-resource`
  or it will report this repo as "Phase 6, skill scanning".

---

## 6. Suggested next action

Commit or discard the email-notification work, then get a remote copy in place.
Everything else can wait; those two are the only items where delay costs
something irreversible.
