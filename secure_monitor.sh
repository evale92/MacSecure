#!/bin/bash
#
# Secure Monitor — Phase 14 + Phase 54 integration
# Runs baseline scanners and detection pipeline, logs results
#
# Usage: ./secure_monitor.sh [--json] [--log-only]
# Optional: add to crontab for automated runs (e.g., every 4 hours)
#   0 */4 * * * /Users/erickvale/Projects/secure-resource/secure_monitor.sh >> /var/log/secure_monitor.log 2>&1

set -e

REPO="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_DIR="${REPO}/.monitoring"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
TIMESTAMP_FILE=$(date +"%Y%m%d_%H%M%S")
JSON_OUTPUT=false
LOG_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --json) JSON_OUTPUT=true; shift ;;
        --log-only) LOG_ONLY=true; shift ;;
        *) shift ;;
    esac
done

# Create log directory
mkdir -p "$LOG_DIR"

# Log file
LOG_FILE="${LOG_DIR}/monitor_${TIMESTAMP_FILE}.log"

log() {
    echo "[${TIMESTAMP}] $1" | tee -a "$LOG_FILE"
}

log_json() {
    echo "$1" >> "$LOG_FILE"
}

log "=== Secure Monitor Start ==="

# Function to run a scanner safely
run_scanner() {
    local scanner_name=$1
    local cmd=$2

    log "Running $scanner_name..."
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        log "✓ $scanner_name completed"
        return 0
    else
        log "✗ $scanner_name failed (exit code: $?)"
        return 1
    fi
}

# Run scanners (safe, read-only operations)
cd "$REPO"

FAILED=0
if [ "$LOG_ONLY" = false ]; then
    # Persistence scan (unsigned binaries, kernel extensions, etc.)
    run_scanner "persistence" "python3 -m secure persistence scan" || FAILED=$((FAILED + 1))

    # Listening ports (unexpected network bindings)
    run_scanner "listening" "python3 -m secure listening scan" || FAILED=$((FAILED + 1))

    # Connections (unexpected destinations)
    run_scanner "connections" "python3 -m secure connections scan" || FAILED=$((FAILED + 1))

    # File integrity (changes to critical paths)
    run_scanner "fileintegrity" "python3 -m secure fileintegrity scan" || FAILED=$((FAILED + 1))

    # Posture checks (Gatekeeper, SIP, FileVault, firewall, etc.)
    run_scanner "checks" "python3 -m secure check" || FAILED=$((FAILED + 1))

    # WiFi (lookalike SSIDs)
    run_scanner "wifi" "python3 -m secure wifi scan" || FAILED=$((FAILED + 1))

    # Bluetooth (unknown devices)
    run_scanner "bluetooth" "python3 -m secure bluetooth scan" || FAILED=$((FAILED + 1))
fi

# Run detection pipeline on anomalies found
log "Running detection pipeline..."
if python3 -m secure detection-pipeline run --lookback-minutes 60 --json >> "$LOG_FILE" 2>&1; then
    log "✓ Detection pipeline completed"
else
    log "✗ Detection pipeline failed (exit code: $?)"
fi

# Show baseline status
log "Baseline status:"
python3 -m secure baseline status 2>&1 | head -20 >> "$LOG_FILE" || true

log "=== Secure Monitor Complete ==="
log "Results logged to: $LOG_FILE"

# Report failures
if [ "$FAILED" -gt 0 ]; then
    log "WARNING: $FAILED scanner(s) failed"
fi

# Print summary
if [ "$JSON_OUTPUT" = true ]; then
    STATUS="success"
    if [ "$FAILED" -gt 0 ]; then
        STATUS="partial"
    fi
    echo "{\"timestamp\": \"$TIMESTAMP\", \"log_file\": \"$LOG_FILE\", \"status\": \"$STATUS\", \"failed_scanners\": $FAILED}"
fi

exit $FAILED
