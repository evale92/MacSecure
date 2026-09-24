#!/bin/bash
# Secure project backup — full git bundle daily
# Stores off-machine in ~/Backups/secure-resource/
# Keeps last 7 days of snapshots

set -e

REPO="/Users/erickvale/Desktop/secure-resource"
BACKUP_DIR="$HOME/Backups/secure-resource"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$BACKUP_DIR"
cd "$REPO"

# Create fresh bundle
BUNDLE="$BACKUP_DIR/secure_${TIMESTAMP}.bundle"
git bundle create "$BUNDLE" --all

echo "[$(date)] Backup created: $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"

# Keep last 7 days of backups
find "$BACKUP_DIR" -name "secure_*.bundle" -mtime +7 -delete

echo "[$(date)] Cleanup complete. Current backups:"
ls -lh "$BACKUP_DIR"/secure_*.bundle | awk '{print $9, $5}'
