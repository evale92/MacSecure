# Secure Project Recovery Guide

**Backup location:** `~/Backups/secure-resource/`  
**Backup types:**
- Git bundles: `secure_YYYYMMDD_HHMMSS.bundle` (daily, 7-day retention, 2.0M each)
- Database backups: `secure_db_YYYYMMDD_HHMMSS.bak` (daily, 7-day retention, 2.2M each)

## Recovery steps

If `~/Projects/secure-resource` is lost or corrupted:

```bash
# 1. List available backups
ls -lh ~/Backups/secure-resource/

# 2. Pick the latest git bundle and database backup
BUNDLE=$(ls -t ~/Backups/secure-resource/secure_*.bundle | head -1)
DB_BAK=$(ls -t ~/Backups/secure-resource/secure_db_*.bak | head -1)
echo "Restoring from: $BUNDLE and $DB_BAK"

# 3. Clone git bundle
mkdir ~/Projects/secure-resource
cd ~/Projects/secure-resource
git clone "$BUNDLE" .

# 4. Restore database
mkdir -p ~/.secure
cp "$DB_BAK" ~/.secure/secure.db

# 5. Verify
git log --oneline -1          # Should show Phase 61 or later
/usr/bin/python3 -m secure baseline status  # Verify imports work
```

## What's backed up

- All 180 commits (Phases 48-61+)
- All test files (181 files)
- Secure project code (611 tracked files)
- **SQLite database:** `~/.secure/secure.db` (backed up via SQLite's `.backup()` command, not a file copy)
  - 2.2M, contains: baseline entities, anomaly events, alert decisions, remediation history

## What's NOT backed up

- Python interpreter (but `/usr/bin/python3` is system-provided)
- pytest cache (`.pytest_cache/`)
- Monitoring logs (`<repo>/.monitoring/` — transient, latest run only)

## Restore just the database (without full repo restore)

```bash
# If git repo is intact but database is corrupted:
DB_BAK=$(ls -t ~/Backups/secure-resource/secure_db_*.bak | head -1)
mkdir -p ~/.secure
cp "$DB_BAK" ~/.secure/secure.db
/usr/bin/python3 -m secure baseline status
```

## Automated backups

- **Baseline collection:** Every 4 hours (plist: `com.secure.baseline`)
  - Runs: persistence, listening, connections, fileintegrity, checks, wifi, bluetooth scans
  - Plus detection pipeline
- **Full backups:** Daily at 3am (plist: `com.secure.backup`)
  - Git bundle of all commits
  - SQLite backup of live database (safe while database is running)
- **Retention:** 7 days (older backups auto-deleted)
- **Logs:** `<repo>/.monitoring/baseline.{out,err}` and `backup.{out,err}`

**Verify automation is running:**
```bash
launchctl list | grep com.secure
# Should show:
#   XXXXX	0	com.secure.backup     (last exit status 0)
#   XXXXX	0	com.secure.baseline   (last exit status 0)

# To manually trigger a backup:
launchctl kickstart user/503/com.secure.backup
# Then check the logs:
tail <repo>/.monitoring/backup.{out,err}
```

## If database backup fails

The `com.secure.backup` plist may fail with "Operation not permitted" if the
backup script cannot read `~/.secure/secure.db`. Causes:
- macOS privacy permission blocking background jobs (System Preferences → Security & Privacy)
- Database locked by another process

Check `<repo>/.monitoring/backup.err`:
```bash
tail /Users/erickvale/Projects/secure-resource/.monitoring/backup.err
```

## Emergency: restore from GitHub

**WARNING:** GitHub (`github.com/evale92/secure-resource`) is behind local by 3 commits.

Use `~/Backups/secure-resource/` bundles (they are current).

Only use GitHub if all local backups are gone AND you accept losing recent work.
