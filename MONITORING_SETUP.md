# Secure Monitoring Setup (Phase 14 + Phase 54)

Threat detection pipeline monitoring on macOS (manual/on-demand).

## Quick Start

### One-shot scan:
```bash
./secure_monitor.sh --log-only
```

### Output only (no LaunchAgent persistence):
Results logged to `.monitoring/monitor_YYYYMMDD_HHMMSS.log` (local file only).

### Optional: Schedule with cron (if desired):
```bash
# Edit crontab
crontab -e

# Add line to run every 4 hours:
0 */4 * * * cd /path/to/secure-resource && ./secure_monitor.sh --log-only >> .monitoring/cron.log 2>&1
```

**Note:** LaunchAgent plist is NOT loaded by default (Invariant 12: full uninstall reversibility).
To load manually: `launchctl load ~/Library/LaunchAgents/com.secure.monitor.plist`
To remove: `launchctl unload ~/Library/LaunchAgents/com.secure.monitor.plist && rm ~/Library/LaunchAgents/com.secure.monitor.plist`

## What It Does

Each run:
1. **Scans system subsystems** (optional, requires root for some):
   - Persistence entries (unsigned binaries, kernel extensions)
   - Listening ports (unexpected network bindings)
   - Connections (unexpected destinations)
   - WiFi networks (lookalike SSIDs)
   - Bluetooth devices (unknown devices)

2. **Runs detection pipeline**:
   - Fetches baseline anomalies (last 60 minutes)
   - Correlates findings across devices (Phase 49)
   - Makes alert decisions using pure logic (Phase 53)
   - Stores reasoning with audit trail

3. **Logs results**:
   - `.monitoring/monitor_YYYYMMDD_HHMMSS.log` — timestamped run results
   - `/var/log/secure_monitor.log` — LaunchAgent stdout
   - `/var/log/secure_monitor_error.log` — LaunchAgent stderr

## Output Format

### Text (default):
```
[timestamp] Detection pipeline results:
  Total processed: N
  Successful: N
  Errors: N
  ✓ /usr/bin/curl: ACTIVE (HIGH)
  ✓ /opt/app/binary: SUPPRESSED_EXPECTED (LOW)
```

### JSON (`--json`):
```json
{
  "total": 5,
  "processed": 4,
  "errors": 1,
  "events": [
    {
      "anomaly_id": 1,
      "entity_type": "process",
      "entity_path": "/usr/bin/curl",
      "anomaly_tier": "high",
      "verdict": "ACTIVE",
      "final_severity": "HIGH",
      "correlation_id": "corr_001",
      "error": null
    }
  ]
}
```

## Architecture

```
Baseline Scanner (Phase 14)
    ↓
Database (SQLite anomaly_events table)
    ↓
Detection Pipeline (Phase 54)
    ├── Fetch recent anomalies
    ├── Correlate across devices (Phase 49)
    ├── Compose alert context (Phase 48/49/50/53)
    ├── Make pure alert decisions (Phase 53)
    └── Store with audit trail
    ↓
Results logged + displayed
```

## Customization

### Change scan interval:
Edit `com.secure.monitor.plist`, change `<key>StartInterval</key>` (seconds, default 14400 = 4 hours)

### Change lookback window:
Edit `secure_monitor.sh`, change `--lookback-minutes 60` to desired value

### Skip subsystem scans:
Edit script, remove or comment out `run_scanner` calls (currently safe but slow)

### Enable JSON output:
Change script to call `./secure_monitor.sh --json` instead of `--log-only`

## Security Notes

- ✅ Pure decision logic (testable, auditable)
- ✅ Audit trail preserved (all reasoning logged)
- ✅ No external dependencies (stdlib only)
- ⚠️ Requires read access to system state files (may need sudo for some scanners)
- ⚠️ Logs contain system anomaly details (protect log files)

## Troubleshooting

**LaunchAgent not running:**
```bash
launchctl list | grep secure.monitor  # Check if loaded
launchctl load ~/Library/LaunchAgents/com.secure.monitor.plist  # Reload
```

**Permission denied on logs:**
```bash
sudo touch /var/log/secure_monitor.log
sudo touch /var/log/secure_monitor_error.log
sudo chmod 644 /var/log/secure_monitor*.log
```

**No anomalies detected:**
- Baseline still in `learning` state (needs 24+ hours of data)
- Run subsystem scanners: `python3 -m secure persistence scan`

## Next Steps

1. **Run for 24-48 hours** to collect baseline data
2. **Review audit logs** for real threats detected
3. **Hand off to security agent** (Opus) for:
   - Threat modeling & decision logic audit
   - Hardening recommendations
   - Vulnerability assessment
