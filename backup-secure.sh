#!/bin/bash
# Secure project backup — git bundle + database backup daily
# Stores off-machine in ~/Backups/secure-resource/
# Keeps last 7 days of snapshots

set -e

REPO="/Users/erickvale/Projects/secure-resource"
BACKUP_DIR="$HOME/Backups/secure-resource"
DB_PATH="$HOME/.secure/secure.db"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$BACKUP_DIR"
cd "$REPO"

# Create fresh git bundle
BUNDLE="$BACKUP_DIR/secure_${TIMESTAMP}.bundle"
git bundle create "$BUNDLE" --all
echo "[$(date)] Git bundle: $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"

# Back up database using SQLite's native backup (safe while live)
if [ -f "$DB_PATH" ]; then
    DB_BACKUP="$BACKUP_DIR/secure_db_${TIMESTAMP}.bak"
    /usr/bin/python3 << EOF
import sqlite3
src = sqlite3.connect("$DB_PATH")
dst = sqlite3.connect("$DB_BACKUP")
with dst:
    src.backup(dst)
src.close()
dst.close()
EOF
    echo "[$(date)] Database backup: $DB_BACKUP ($(du -h "$DB_BACKUP" | cut -f1))"
else
    echo "[$(date)] WARNING: Database not found at $DB_PATH"
fi

# Keep last 7 days of backups
find "$BACKUP_DIR" -name "secure_*.bundle" -mtime +7 -delete
find "$BACKUP_DIR" -name "secure_db_*.bak" -mtime +7 -delete

echo "[$(date)] Cleanup complete. Current backups:"
ls -lh "$BACKUP_DIR"/secure_* | awk '{print $9, $5}'
