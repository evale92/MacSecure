# Start here — secure-resource

**The project moved on 2026-09-24.** It is no longer on the Desktop.

```bash
cd /Users/erickvale/Projects/secure-resource
```

`~/Desktop/secure-resource` no longer exists. If any handoff, doc, plist or
note still points there, that reference is stale — fix it, don't recreate the
directory. The move was deliberate: macOS blocks background/scheduled jobs from
reading `~/Desktop`, which silently broke every automated backup and baseline
run for days.

---

## Verify you are in the right place

```bash
cd /Users/erickvale/Projects/secure-resource
git log -1 --oneline     # 83b2e25 Docs: Phase 61 completion handoff for deep review
git log --oneline | wc -l # 180
```

If the count is 119, you are in the wrong repo — that is `evale92/secure`, an
older separate lineage. Do not work there and do not "restore" from it.

---

## Running things

**Use `/usr/bin/python3`.** It is the only interpreter on this machine with
`pytest` installed (8.4.2). There is no `.venv` any more.

```bash
/usr/bin/python3 -m secure --help
/usr/bin/python3 -m pytest tests/test_alerting_*.py -q -p no:cacheprovider
```

**Never run the full test suite.** This is an 8 GB machine. Running all 181
test files drove swap to 15.99 GB of 16 GB and had to be killed. Run at most
~20 files per invocation.

`timeout` is not installed. `pytest-timeout` is not installed — `--timeout`
will error.

---

## Never do this

- **Never wait in the foreground.** No `until ... done`, no sleep loops. That
  deadlocked this bot on 2026-09-23 and took it offline ~40 minutes.
- **Never move or rename the project directory.** A `mv ~/Desktop/secure-resource
  ~/.secure` on 2026-09-23 — taken from a DEPLOYMENT.md instruction — looked
  exactly like catastrophic data loss and cost hours to unwind. If a doc tells
  you to move it, stop and ask.
- **Never commit, push, or advance a phase without asking.**
- Do not edit anything under `~/ProjectVault/`. Those copies are locked with the
  macOS immutable flag on purpose.

---

## Current state (2026-09-24)

- **Phase 61 complete.** HEAD `83b2e25`, 180 commits, 611 tracked files.
- GitHub remote: `github.com/evale92/secure-resource` (private). It is **3
  commits behind** local — `83b2e25`, `14cfc3e`, `c5d5e14` are unpushed.
- Live data in `~/.secure/secure.db`: 493 baseline entities, 99 anomaly events,
  100 alert decisions, 14 baseline runs.
- Known: 14 test failures in the first 60 test files, including
  `test_clean_install.py::test_status_works_immediately_after_fresh_init`.
  Not yet characterised.
- `docs/` has no design docs for phases 55–61.

## Scheduled jobs (all verified exit 0 after the move)

| Job | Does |
|---|---|
| `com.evale.projectvault` | locked copies + hourly snapshots, every 5 min |
| `com.secure.backup` | daily 03:00 git bundle to `~/Backups/secure-resource/` |
| `com.secure.baseline` | `secure_monitor.sh` every 4 h |

Check any of them with `launchctl list | grep <label>` — second column is the
last exit status. `126` or `78` means it cannot reach the repo; re-read the
path in its plist before changing anything else.
