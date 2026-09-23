# Handoff Rules & Requirements

**Purpose:** Every handoff document (HANDOFF.md) must enable any bot/agent to pick up work without ramp-up time.

**Audience:** Bots resuming work, external collaborators, future maintainers.

---

## Handoff Must Include

### 0. Project Location & Access (FIRST THING)

**What to include:**
- Absolute path to project directory
- Commands to verify bot is in correct location
- Commands to verify project health (git, pytest, imports)

**Example:**
```
## Project Location & Access

**Save this for the bot:**
cd /Users/erickvale/Desktop/secure-resource
pwd  # Should output: /Users/erickvale/Desktop/secure-resource
ls HANDOFF.md  # Should exist
```

**Why:** Bot may not know where project is. Always include absolute path. Provide copy-paste ready commands.

---

### 1. Executive Summary (Top of File)

**What to include:**
- Last update timestamp (ISO 8601 format, timezone)
- Current phase and status (COMPLETE ✅, IN PROGRESS 🏗️, BLOCKED ⏸️)
- Total progress metrics (tests passing, LOC, commits)
- Working directory (absolute path)

**Example:**
```
**Last Updated:** 2026-09-23 07:31 EDT  
**Current Phase:** Phase 53 COMPLETE ✅  
**Total Progress:** 265 tests passing, 5316+ LOC, 16 commits  
**Working Directory:** `/Users/erickvale/Desktop/secure-resource`
```

**Why:** Bot needs to know project state at a glance. All metrics must be current.

---

### 2. Quick Start Instructions for Bot

**What to include:**
- Exact command to verify project is healthy (`git log`, `pytest`, import test)
- Files/sections to read in priority order
- Working directory setup command

**Example:**
```bash
# Read in order:
1. HANDOFF.md (this file)
2. HANDOFF_RULES.md (what handoffs must contain)
3. docs/PHASE_X.md (current phase specification)
4. ARCHITECTURE_RULES.md (layering/constraints)

# Verify health:
cd /Users/erickvale/Desktop/secure-resource
git log --oneline -5
python3 -m pytest tests/test_alerting_*.py -q  # Should show: 61 passed
```

**Why:** Bot should not have to search for where to start. Be explicit about reading order.

---

### 3. Project Overview (Vision & Scope)

**What to include:**
- One-sentence project vision
- High-level feature list (what the system does)
- Major architectural layers
- Key constraints (no external ML, audit trail required, etc.)

**Example:**
```
**Vision:** Zero-trust threat detection and automated response for macOS.

**Architecture Layers:**
1. Phase 48: Remediation orchestration
2. Phase 49: Multi-device coordination
3. Phase 50: Threat intelligence
4. Phase 51: Playbook library
5. Phase 52: GUI & CLI interfaces
6. Phase 53: Alerting layer

**Key Constraints:**
- No external ML dependencies (stdlib only)
- Audit trail preserved for every action
- Frozen dataclasses for immutability
```

**Why:** Context needed to make sensible decisions about what to build next.

---

### 4. Phase Completion Table

**What to include:**
- Status of each major phase (✅ done, 🏗️ in progress, ⏸️ blocked)
- Commits per phase
- Test count per phase
- LOC per phase

**Format:**
```markdown
| Phase | Component | Status | Commits | Tests | LOC |
|-------|-----------|--------|---------|-------|-----|
| 48 | Automated Remediation | ✅ | 11 | 173+ | 2000+ |
| 49 | Multi-Device | ✅ | 2 | 28 | 1300+ |
| 50 | Threat Intelligence | ✅ | 1 | 45 | 655 |
| 51 | Extended Playbooks | ✅ | 1 | 26 | 500+ |
| 52 | GUI & CLI | ✅ | 3 | 0* | 1280 |
| 53 | Detection Intelligence | ✅ | 2 | 61 | 1120 |
| **Total** | | **✅** | **16** | **265** | **5316+** |
```

**Why:** Bot needs to see full project state at once, plus metrics to validate health.

---

### 5. This Session's Work Summary

**What to include:**
- Date range of session
- Which phases were completed
- Major commits with short descriptions
- Architecture decisions made this session
- Bugs fixed this session

**Example:**
```
**Session:** 2026-09-23 06:18–07:31 EDT

**Completed:**
- Phase 52: GUI Panel & CLI Wiring (1280 LOC, 3 commits)
- Phase 53: Detection Intelligence (1120 LOC, 61 tests, 2 commits)

**Key Commits:**
- 4cee6f0 Phase 53: CLI, explainer, comprehensive tests
- c4ae767 Phase 52: GUI panel (part 2)

**Architecture Decisions:**
- Pure decision functions in Phase 53 (no I/O, no upward imports)
- compose.py as single impure boundary
- Frozen dataclasses for context passing
```

**Why:** New bot needs to know what happened this session to understand current state.

---

### 6. Directory Structure (with Purpose)

**What to include:**
- Tree of major directories
- One-line purpose for each
- Highlight files created this session

**Example:**
```
secure/
├── remediation/         # Phase 48 — Actions, playbooks, approval
│   ├── models.py
│   ├── catalog.py
│   └── cli.py
│
├── alerting/            # Phase 53 — Detection intelligence
│   ├── context.py       # Frozen dataclasses for safe value passing ✨ NEW
│   ├── suppression.py   # Pure classify() function ✨ NEW
│   ├── escalation.py    # Pure weigh() function ✨ NEW
│   └── compose.py       # Impure context assembly ✨ NEW
```

**Why:** Bot needs to find files and understand what each directory contains.

---

### 7. Key Architecture Decisions & Constraints

**What to include:**
- Non-obvious design choices (why not HTTP API? why frozen dataclasses?)
- Layering rules (what imports what)
- Import restrictions (if any)
- Immutability/audit trail requirements

**Example:**
```
**Layering Rules (Phase 53):**
- Decision functions can ONLY import from alerting/context.py
- compose.py is the SINGLE file allowed to import from remediation/multi_device/intelligence
- All new code must preserve this pattern

**Why:** Ensures pure decision logic stays testable and independent.

**Audit Trail Requirements:**
- Every alert decision must store reasoning with decision
- Every remediation approval must log approval authority
- No silent failures or untracked decisions
```

**Why:** Next developer needs to know constraints *before* writing code.

---

### 8. Test Coverage Summary

**What to include:**
- Total test count and pass rate
- Tests per module/phase
- Run commands for different test subsets
- Any known failing/skipped tests

**Example:**
```
**Total: 265 tests, all passing**

| Module | Tests | Status |
|--------|-------|--------|
| Remediation | 173 | ✅ |
| Multi-device | 28 | ✅ |
| Intelligence | 45 | ✅ |
| Alerting | 61 | ✅ |

**Run tests:**
python3 -m pytest tests/ -q          # All tests
python3 -m pytest tests/test_alerting_*.py -q  # Phase 53 only
```

**Why:** Bot must verify project health before making changes.

---

### 9. Files to Read (Priority Order)

**What to include:**
- List of documentation files in reading order
- One-line purpose for each
- Highlight security/architectural docs

**Example:**
```
**Read in this order (required for next bot):**

1. **HANDOFF.md** (this file) — project state, recent work
2. **HANDOFF_RULES.md** — what every handoff must contain (you're reading it)
3. **docs/PHASE_53.md** — Phase 53 detailed specification
4. **ARCHITECTURE_RULES.md** — layering constraints, import rules ⚠️ CRITICAL
5. **SECURITY_INVARIANTS.md** — approval authority, audit trail ⚠️ CRITICAL
6. docs/PHASE_48.md — Phase 48 specification
```

**Why:** New bot should not have to guess what to read. Be explicit.

---

### 10. Critical Rules for Next Session

**What to include:**
- Do's and don'ts for the project
- Tests that MUST pass before committing
- Architecture rules that MUST be preserved
- Never/Always statements

**Example:**
```
**NEVER:**
- Commit with failing tests
- Break layering rules (imports from peer layers into decision functions)
- Skip audit trail logging
- Use external ML dependencies

**ALWAYS:**
- Run full test suite before committing: python3 -m pytest tests/ -q
- Update HANDOFF.md before pushing
- Preserve frozen dataclass pattern for context
- Document architecture decisions in commit messages
```

**Why:** Prevents common mistakes and maintains quality.

---

### 11. Bot Instructions (If this is for a Bot)

**What to include:**
- How bot should behave when resuming
- When to escalate to human/deep agent
- Communication style preferences
- Model selection (Haiku for fast work, Opus for architecture)

**Example:**
```
**When resuming:**
1. Read HANDOFF.md first
2. Run: git log --oneline -5
3. Run: python3 -m pytest tests/test_alerting_*.py -q
4. Identify next work (refer to "Next Phase" section)

**Escalate to deep agent when:**
- Architecture/design decision needed
- 2+ fix attempts have failed
- Security-sensitive changes
- Hard-to-undo operations (force-push, destructive refactors)

**Communication style:**
- Keep responses short (assume phone reading)
- No trailing summaries (user can read diffs)
- Be direct and action-oriented
```

**Why:** Bot needs explicit guidance on behavior.

---

### 12. Next Phase (What Comes After Current Work)

**What to include:**
- Title and brief description of next phase
- Why it's next (priority, dependencies)
- Key components to build
- Estimated LOC and test count

**Example:**
```
### Phase 54: Integration with Detection Pipeline

**Why:** Wire alerting layer into existing baseline anomaly detection.

**Components to build:**
1. Feed baseline/scoring outputs to decide_alert()
2. Integrate Phase 49 correlation with alert decisions
3. Create end-to-end: baseline → anomaly → alert → decision

**Estimate:** 800 LOC, 40+ tests, 2 commits
```

**Why:** Bot needs to know what to work on next.

---

### 13. Known Issues & Workarounds

**What to include:**
- Any bugs or edge cases discovered (but not critical)
- Temporary workarounds
- TODOs with explanation

**Example:**
```
**Known Issues:**
- Test `test_a_genuinely_failing_test_reproduces` fails (pre-existing, not Phase 53)
  Workaround: Run with `--ignore=tests/test_agent_diagnose.py`

**TODOs:**
- Phase 54: Wire threshold_overrides from Phase 50 into scoring.py
- Phase 55: Store user feedback on alert decisions
```

**Why:** Prevents bot from chasing non-blocking issues.

---

### 14. User Preferences & Style

**What to include:**
- Model preferences (Haiku/Opus/Claude 5)
- Communication preferences
- Code style preferences
- Where to get help

**Example:**
```
**Bot preferences:**
- Use Haiku for this work (fast, efficient)
- Escalate to deep (Opus) for architecture decisions
- Keep responses short (assume reading on phone)
- No trailing summaries — just show results

**Code style:**
- No comments unless WHY is non-obvious
- Type hints on all public APIs
- Frozen dataclasses for immutability
- No external dependencies
```

**Why:** Bot works more efficiently with explicit preferences.

---

### 15. Contact & Meta Information

**What to include:**
- User email
- Session dates
- Working directory
- Git remote/branch

**Example:**
```
**Email:** evale92@gmail.com  
**Session started:** 2026-09-22 21:49 EDT  
**Current session:** 2026-09-23 06:18–07:31 EDT  
**Working directory:** `/Users/erickvale/Desktop/secure-resource`  
**Git branch:** main (local development)
```

**Why:** Bot needs to know how to contact user and basic context.

---

## Handoff Structure Template

```markdown
# Secure Project Handoff — Session [DATE]

**Last Updated:** [ISO timestamp, timezone]  
**Current Phase:** [Name] [STATUS: ✅/🏗️/⏸️]  
**Total Progress:** [test count] tests, [LOC] LOC, [commits] commits

## Project Location & Access

cd /Users/erickvale/Desktop/secure-resource
pwd  # Should output: /Users/erickvale/Desktop/secure-resource
ls HANDOFF.md  # Should exist

## Quick Start for Bot
[Read in order / Commands to run]

## Project Overview
[Vision / Layers / Key constraints]

## Phase Completion Status
[Table: Phase | Component | Status | Commits | Tests | LOC]

## This Session's Work
[What was completed, commits, decisions]

## Architecture Decisions
[Non-obvious choices, layering rules, constraints]

## Directory Structure
[Tree with purposes]

## Test Coverage
[Summary + run commands]

## Files to Read (Priority Order)
[Docs in reading order]

## Critical Rules for Next Session
[NEVER / ALWAYS statements]

## Bot Instructions
[How to resume, when to escalate, style]

## Next Phase
[What comes after current work]

## Known Issues & Workarounds
[Bugs, edge cases, TODOs]

## User Preferences & Style
[Model, communication, code style]

## Contact & Meta
[Email, dates, directory, git info]
```

---

## Review Checklist (Before Every Commit)

**Update HANDOFF.md with:**
- [ ] Project Location section (absolute path + verification commands)
- [ ] Last Updated timestamp (current session time)
- [ ] Current Phase and status (✅/🏗️/⏸️)
- [ ] Total test count (run `pytest --co -q | tail -1`)
- [ ] Total LOC (run `find secure/ -name "*.py" | xargs wc -l`)
- [ ] Recent commits (run `git log --oneline -5`)
- [ ] Session work summary (if work completed this session)
- [ ] New architecture decisions (if design changed)
- [ ] Test coverage update (by module/phase)
- [ ] Next phase (updated if phases completed)
- [ ] Known issues (any bugs discovered)

**Before pushing:**
- [ ] All tests pass (`python3 -m pytest tests/ -q`)
- [ ] HANDOFF.md is current
- [ ] Commit message is clear and references phase
- [ ] No trailing print statements or debug code
- [ ] Audit trail preserved (if applicable)

---

## Examples of Good Handoffs

**What makes a handoff excellent:**
1. ✅ Bot can resume in <2 minutes without questions
2. ✅ Phase status is clear (DONE / IN PROGRESS / BLOCKED)
3. ✅ All test counts and LOC are accurate
4. ✅ Critical rules are highlighted (ARCHITECTURE_RULES.md linked)
5. ✅ Next work is obvious (Next Phase section)
6. ✅ Recent commits are listed with descriptions
7. ✅ Directory structure is up to date
8. ✅ Timestamp is current (within hours of work ending)

**What makes a handoff bad:**
1. ❌ Stale timestamp (hours/days old)
2. ❌ Unclear current phase or status
3. ❌ Test count doesn't match actual test suite
4. ❌ Missing ARCHITECTURE_RULES.md reference
5. ❌ No "Next Phase" section
6. ❌ Generic instructions (could apply to any project)
7. ❌ No critical rules highlighted
8. ❌ Directory structure doesn't match actual repo

---

## Obsidian Export Format (Optional)

If saving handoff to Obsidian, use this structure:

**File:** `secure-project/HANDOFF.md`  
**Frontmatter:**
```yaml
---
title: Secure Project Handoff
tags: [project, handoff, secure-resource]
updated: 2026-09-23 07:31 EDT
phase: Phase 53 COMPLETE ✅
tests: 265
loc: 5316
---
```

**Create sibling files:**
- `secure-project/ARCHITECTURE_RULES.md` (link from HANDOFF)
- `secure-project/SECURITY_INVARIANTS.md` (link from HANDOFF)
- `secure-project/phases/PHASE_48.md` — etc.

Link all from HANDOFF using `[[file-name]]` syntax.

---

## When to Update HANDOFF.md

**Update immediately after:**
- ✅ Phase completion (all tests pass)
- 🧪 Major test additions (>10 tests)
- 🏗️ Architecture decision (save to ARCHITECTURE_RULES.md too)
- 🐛 Bug fix or workaround discovered
- 📁 New directory or module added

**Do NOT update for:**
- Single-line comments or docstrings
- Variable renames
- Minor formatting fixes

---

**This document is your contract with future developers (including bots).**  
**Keep it accurate, current, and detailed enough that a stranger can pick up where you left off.**
