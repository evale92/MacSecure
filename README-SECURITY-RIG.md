# secure-resource — Security-focused Claude Code rig

This is a clone of the **secure** project with **claude-resource** configuration applied for security auditing and development.

## What's ready to use

**Skills installed:**
- `/code-review` — Audit code for bugs, security issues, quality
- `/security-review` — Deep security analysis
- `/scan-skill` — Vet dependencies/third-party code
- `/ship` — Verify security checklist before release
- `/tdd` — Test-driven development
- `/grilling` — Stress-test designs and assumptions
- `/prototype` — Prototype features safely

**Guardrails:**
- `verify-before-done.sh` hook — blocks "done" claims without evidence
- Deep subagent routing — complex security decisions route to Opus

## How to use

1. **Open this directory in Claude Code:**
   ```bash
   cd ~/Desktop/secure-resource
   claude
   ```

2. **Run audits on actual code:**
   ```
   /code-review            # Audit uncommitted changes
   /security-review        # Deep security assessment
   /scan-skill scan-skill.md  # Audit a SKILL.md before install
   ```

3. **For features:**
   ```
   /tdd                    # Test-first development
   /grilling               # Stress-test the design
   /prototype              # Build throwaway prototype
   ```

4. **Before shipping:**
   ```
   /ship                   # Release readiness check
   ```

## Configuration files

- `.claude/settings.json` — Routes `/code-review`, `/ship`, etc. to installed skills
- `CLAUDE.md` — Routing rules (when to use Opus vs Haiku, when to escalate)

## What happens when you run these

**`/code-review`:**
- Parses git diff (working tree changes only)
- Looks for correctness bugs, security issues, quality problems
- Returns concrete scenarios (not generic warnings)

**`/security-review`:**
- Opus-level security reasoning
- Threat modeling
- Attack surface analysis

**`/ship`:**
- Runs test suite
- Checks security scan results
- Verifies deployment checklist
- Refuses to clear if tests fail

**verify-before-done hook:**
- Fires when you claim "this is done" or "ready to ship"
- Blocks unless you ran a verification command (test, build, audit)
- Forces evidence instead of assertions

## Example workflow

```
1. Make code changes
2. Run: /code-review
3. Fix findings
4. Run: /tdd (test-first for new features)
5. Say: "this is ready to ship"
6. Hook blocks: "run a verification command first"
7. Run: /ship (verifies tests + checklist)
8. If /ship clears: you can merge
```

## Status (2026-09-21)

**Rig installed:** ✅ hooks, agents, skills in `.claude/`

**Proven working** (tested on secure-resource fixtures):
- ✅ `/code-review` catches real bugs (4/4 bugs found in fixture)
- ✅ `verify-before-done.sh` hook blocks unverified claims
- ✅ `/ship` validates tests (pass/fail verdicts exact)
- ✅ Skills route correctly

**GUI interpreter: resolved 2026-09-21.**
Homebrew's `python3.14` had no `_tkinter`, so `secure_gui/` could not be
imported or tested. Now fixed with a dedicated venv:

```bash
brew install python-tk@3.14            # adds tkinter (Tk 9.0) to python3.14
cd ~/Desktop/secure-resource
python3.14 -m venv .venv-tk            # git-ignored (venv writes its own .gitignore)
source .venv-tk/bin/activate
pip install -r requirements.txt        # not `pip install -e .`: no setup.py/pyproject.toml
pytest tests/ -q                       # 2540 tests, ~3-5 min
```

Baseline on that venv: 2540 passed (commits e057ac3, 9cfc5d7 fixed three
date-dependent tests, two more found by review, and five tests that
re-ran the whole suite recursively). Always activate `.venv-tk` before
GUI work.

Then proceed to audit and extract pure functions from `secure_gui/` closures.

## What to test first

1. **Activate the interpreter:** `source .venv-tk/bin/activate`
2. Open in Claude Code: `cd ~/Desktop/secure-resource && claude`
3. Run: `/code-review` on actual Secure code
4. Confirm: findings surface correctly
5. Then proceed to audit `secure_gui/` and build first sprint

---

**claude-resource** — unified dev tooling from 11 open-source projects, tested and cleared. All phases verified with blind adjudication.
