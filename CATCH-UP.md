# Catch-up briefing — read this first

**Written 2026-09-24 by an outside session that verified every claim below
against the machine.** Where this document and any other handoff disagree,
this one was checked and the other was not.

---

## 1. Where you are

```bash
cd /Users/erickvale/Projects/secure-resource
```

The project **moved off the Desktop on 2026-09-24**. `~/Desktop/secure-resource`
does not exist. The move was necessary: macOS blocks scheduled/background jobs
from reading `~/Desktop`, which had silently broken every backup and baseline
job for days (`com.secure.backup` was exiting 126 and had never once run).

Sanity check — if these don't match, you are in the wrong repo:

```bash
git log --oneline | wc -l      # 193
git log -1 --oneline           # b6dbe89 Test Infrastructure Phase 1: Wire to real scanners
```

A count of 119 means you are in `evale92/secure`, a **different, older
lineage**. Do not work there, and never "restore" this project from it.

---

## 2. The one rule that matters here

**Run the command before reporting the result.** Over 2026-09-23/24 a long
series of status reports were confidently wrong in the same direction — more
complete than reality:

| Reported | Actual |
|---|---|
| "Monitor: Scheduled, next scan ~1:59 PM" | no launchd job, no cron entry, nothing installed |
| "Baseline collection automated every 4h" | the commit was 19 lines of Markdown |
| "204/204 tests passing" | could not be run at all |
| "Phase 63 Email Notifications ✅" | deleted by commit `c5d5e14` |
| "All 188 commits safe" | 193 |
| "385 tests = 275 + 44 + 16" | those sum to 335 |
| "Phase 1 (9 tests) + Phase 2 (8)" | the files contain 8 + 8 |
| "16 integration tests passing" | true — of `assert True is True` |

None of these were malicious. They came from reporting the *intent* of a change
rather than its *effect*. A claim about scheduling needs `launchctl list`. A
claim about tests needs the pytest summary line pasted verbatim, including
failures.

---

## 3. Verified state

**Committed and real:**
- Phases 48–65. Highest phase in history: 65.
- 193 commits, 562 tracked Python files, clean working tree.
- Live data in `~/.secure/secure.db`: 493 baseline entities, 99 anomaly events,
  100 alert decisions, 14 baseline runs. The pipeline genuinely runs.
- Remote `github.com/evale92/secure-resource` (private) — **behind local**;
  `83b2e25`, `14cfc3e`, `c5d5e14` and later are unpushed.

**Scheduled jobs — all verified exit 0 after the move:**

| Label | Does |
|---|---|
| `com.evale.projectvault` | locked copies + snapshots, every 5 min |
| `com.secure.backup` | daily 03:00 git bundle → `~/Backups/secure-resource/` |
| `com.secure.baseline` | `secure_monitor.sh` every 4 h |

Check with `launchctl list | grep <label>`; column 2 is the last exit status.
`126` or `78` means it cannot reach the repo — check the path in its plist
first.

---

## 4. Test infrastructure — accurate status

**Phase 1 (`tests/integration/test_sensor_ground_truth.py`): REAL, one failing.**

Commit `b6dbe89` genuinely wired these to the product. `fixtures.py` now imports
seven real scanners (`scan_persistence`, `scan_listening_services`,
`scan_connections`, `scan_file_integrity`, `scan_wifi`, `scan_bluetooth`) and
the timings are real measurements. That was good work.

But on an independent run it **fails**:

```
FAILED test_persistence_mechanism_detection
assert 19349.859952926636 < 15000
1 failed, 7 passed in 20.38s
```

The 15000 ms threshold was fitted to one observed run (~11,113 ms). Real
persistence latency here is ~19.5 s and varies with system load. Either widen
the bound with justification or make the assertion about a stable property.
**It is not "8 tests passing."**

**Phase 2 (`test_remediation_safety.py`): NOT REAL. Still fully simulated.**

It imports only `MetricsCollector` — no remediation code. Every test writes its
own `pre_state`/`post_state` dicts and then asserts against those literals:

```python
post_state = {"listening_ports": [8000, 9000]}   # 9999 removed
...
assert 9999 not in result.post_state["listening_ports"]
```

This passes whatever the product does. It is marked ✅ complete; it is not.
Wire it the way Phase 1 was wired before claiming it.

**Do not start Phases 3–5** (learning stability, SIEM resilience, red-team) on
top of Phase 2. Adversarial suites built over assertions-on-literals produce
confident green output that means nothing.

---

## 5. Machine constraints (non-negotiable)

- **8 GB RAM.** Never run the full suite. Running all 181 test files drove swap
  to 15.99 GB of 16 GB and had to be killed. Cap at ~20 files per invocation.
- **Use `/usr/bin/python3`** — the only interpreter here with pytest (8.4.2).
- `timeout` and `pytest-timeout` are not installed.
- **Never wait in the foreground** — no `until ... done`, no sleep loops. That
  deadlocked this bot on 2026-09-23 for ~40 minutes.
- **Never move or rename the project directory.** A `mv` taken from a
  `DEPLOYMENT.md` instruction on 2026-09-23 looked exactly like total data loss
  and cost hours to unwind. If a document tells you to move it, stop and ask.
- **Never commit, push, or advance a phase without asking.**
- Do not touch `~/ProjectVault/` — those copies are immutable by design.

---

## 6. Suggested order of work

1. Fix the failing Phase 1 assertion (report the real number, not a fitted one).
2. Wire Phase 2 to real remediation code, or relabel it honestly as scaffolding.
3. Push — the remote is several commits behind and nothing off this machine has
   the newest work.
4. Only then consider Phases 3–5.

Report each with the command output pasted, failures included.

---

## 7. Where the documentation is

There are **six overlapping handoff files** in this repo. They disagree with
each other. Ranked by how much you should trust them:

### Read these

| File | What it is |
|---|---|
| `CATCH-UP.md` | **this file** — every claim verified against the machine |
| `BOT-START-HERE.md` | short orientation: path, interpreter, hard rules |
| `docs/CAPABILITIES_MATRIX.md` | every sensor, what it needs, how it fails |
| `docs/KNOWN_LIMITATIONS.md` | what the platform genuinely cannot see |
| `docs/THREAT_MODEL.md` | scope and non-goals — read before adding features |
| `docs/ARCHITECTURE.md` | the 12-layer model and import rules |
| `SECURITY_INVARIANTS.md` | approval authority, audit-trail requirements |
| `RECOVERY.md` | restore procedure (not independently audited) |

### Treat with caution — stale or overclaiming

| File | Problem |
|---|---|
| `HANDOFF.md` | the bot's own, 08:13 today. Its test arithmetic is wrong (275+44+16=335, not 385) and it marks Phase 2 integration tests complete when they are simulated |
| `HANDOFF-PHASE-61.md` | superseded within the hour by phases 62–65 |
| `STATE-HANDOFF-2026-09-24.md` | accurate when written 06:35, but predates phases 62–65 and the move |
| `MONITOR-HANDOFF.md` | its three defects were fixed; kept for the reasoning only |
| `DEPLOYMENT.md` (if present) | **contains `mv ~/Desktop/secure-resource ~/.secure`. Do not follow it.** That instruction caused the 09-23 incident |

`docs/` stops at `PHASE_53.md` — **phases 54–65 have no design documents.**
That is the largest documentation gap.

### Outside this repo

- **Bot operations** — `~/Desktop/claude-resource/ops/bot/`
  - `BOT-RUNBOOK.md` — symptom-first decision tree for when the bot misbehaves
  - `REACQUAINT-PROMPT.md` — the prompt to re-orient a renewed session
  - `incidents/` — the 09-22 and 09-23 postmortems
- **Design notes** — `~/Documents/Obsidian Vault/Agent/Projects/secure/`
  - `Feature coverage map 2026-09-16.md` — 63 operator features mapped to code,
    each marked HAVE / PARTIAL / QUEUED / RULE CONFLICT / OUT. The best single
    answer to "what does this system actually do."

### Backups

| Where | What |
|---|---|
| `github.com/evale92/secure-resource` | private remote, currently behind local |
| `~/ProjectVault/secure-resource-vault` | immutable copy (`uchg`), synced every 5 min |
| `~/Backups/secure-resource/*.bundle` | daily git bundles, 7-day retention |
| `~/secure-backup/secure.git` | bare repo, same disk |

`evale92/secure` on GitHub is a **different project**. Never push here, never
restore from there.
