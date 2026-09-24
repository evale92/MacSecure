# Secure Project Recovery Guide

**Backup location:** `~/Backups/secure-resource/`  
**Backup type:** git bundles (daily at 3am, 7-day retention)  
**Latest bundle:** `secure_YYYYMMDD_HHMMSS.bundle` (2.0M each)

## Recovery steps

If `~/Desktop/secure-resource` is lost or corrupted:

```bash
# 1. List available backups
ls -lh ~/Backups/secure-resource/secure_*.bundle

# 2. Pick the latest bundle
BUNDLE=$(ls -t ~/Backups/secure-resource/secure_*.bundle | head -1)
echo "Restoring from: $BUNDLE"

# 3. Clone from bundle
mkdir ~/Desktop/secure-resource
cd ~/Desktop/secure-resource
git clone "$BUNDLE" .

# 4. Verify HEAD
git log --oneline -1
# Should show Phase 61 or later

# 5. Restore baseline database
# The SQLite database is embedded in git-tracked .secure/ directory
# Just clone and you have it all
python3 -m secure baseline status  # Verify imports work
```

## What's backed up

- All 177 commits (Phases 48-61)
- All test files (181 files)
- Secure project code (611 files)
- SQLite baseline database (`~/.secure/baseline.db` or equivalent)

## What's NOT backed up

- Python virtual environment (`.venv-tk/`)
- pytest cache (`.pytest_cache/`)
- Monitoring logs (`~/.monitoring/` — only last run kept)

## Restore just the database

```bash
cd ~/Desktop/secure-resource
git show HEAD:.secure/baseline.db > ~/.secure/baseline.db
python3 -m secure baseline status
```

## Automated backups

- **Baseline collection:** Every 4 hours (plist: `com.secure.baseline`)
- **Git backups:** Daily at 3am (plist: `com.secure.backup`)
- **Retention:** 7 days
- **Logs:** `~/.monitoring/baseline.{out,err}` and `backup.{out,err}`

**Verify automation is running:**
```bash
launchctl list | grep com.secure
# Should show:
#   86813	0	com.secure.backup
#   86715	0	com.secure.baseline
```

## Emergency: restore from GitHub

**WARNING:** GitHub (`github.com/evale92/secure`) is an OLD lineage — restoring from it will lose Phases 48-61.

Use `~/Backups/secure-resource/` bundles instead.

Only use GitHub if all local backups are gone AND you accept losing recent work.
