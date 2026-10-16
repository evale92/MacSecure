# MacSecure — Local macOS Security Monitoring

A read-only local security monitoring tool for macOS that detects and investigates unusual activity—no daemon, no sudo, nothing blocked.

Collects snapshots of running processes, listening ports, active connections, network devices, Bluetooth/BLE peripherals, Wi-Fi networks, and system persistence mechanisms (LaunchAgents, LaunchDaemons, login items). Flags newly-seen entries and maintains historical inventory for investigation.

## Engineering focus

Python-based local observation, SQLite history, investigation workflows, and failure-path testing. Monitoring observes rather than blocks; the application persists local data, and separately documented forensic or repair actions have their own controls. This is not a claim of production readiness or independently validated detection accuracy.

Formerly named Secure. The Python package and CLI remain `secure`.

## Install

```bash
git clone https://github.com/evale92/MacSecure.git
cd MacSecure
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m secure init  # Set up ~/.secure config and database
```

Requirements: Python 3.9+ and macOS. See [requirements.txt](requirements.txt) for declared Python packages and optional integrations.

## Examples

**Check overall status:**
```
$ python3 -m secure status
Device name:   example-mac.local
Device role:   workstation
App directory: /Users/example/.secure
Database:      /Users/example/.secure/secure.db
Log file:      /Users/example/.secure/secure.log
Log level:     INFO
Total events:  0
```

**Scan running processes and persistence mechanisms:**
```
$ python3 -m secure persistence scan
2026-09-24 23:39:02,556 [INFO] secure.cli: Ran a persistence scan
Scan at 2026-09-25T03:38:57.779663+00:00 (run id: 7cc780abfa2d)
Processes with a resolvable executable path: 335

No new processes detected.

No new persistence entries detected.
```

**Audit listening ports:**
```
$ python3 -m secure listening scan | head -20
2026-09-24 23:39:04,305 [INFO] secure.cli: Ran a listening-service audit
Scan at 2026-09-25T03:39:04.261561+00:00 (run id: 9e35b4d7d26e)
Listening services seen: 36 (25 exposed to your network, 11 localhost-only)

[TCP] *:5000                  network   pid=732     ControlCenter
          Exposed to your local network — review if you don't recognize ControlCenter.
[TCP] ::1:5175                localhost pid=94495   node
          Only reachable from this Mac itself — not exposed to your network.
[TCP] *:7000                  network   pid=732     ControlCenter
          Exposed to your local network — review if you don't recognize ControlCenter.
```

**List active connections:**
```
$ python3 -m secure connections scan
2026-09-24 23:39:06,294 [INFO] secure.cli: Ran a connections scan
Scan at 2026-09-25T03:39:06.221561+00:00 (run id: 9d40c14e-5a8c-4abe1d17)
Active connections: 42 TCP, 3 UDP
```

## Verification scope

Performance depends on the machine, permissions, integrations, and workload. No benchmark or current passing-test total is asserted here. Review the tests and run them in your own environment.

## What It Does

- **Inventory**: Scans persistent and transient aspects of the system (processes, persistence mechanisms, listening ports, connections, devices, network, Bluetooth).
- **Detect**: Flags newly-seen entries and unusual/unsigned processes.
- **Investigate**: Entity-centric pivoting—given a process/file/destination/persistence item, explore everything Secure knows about it.
- **Baselines**: Learns per-Mac normal behavior over time; detects statistically unusual activity.
- **Integration**: Normalizes output from external tools (osquery, YARA-X, Sigma, Suricata, Zeek, Velociraptor).
- **Read-only**: Never modifies, disables, quarantines, or blocks anything.

## Dashboard

A modern web-based dashboard displays your system's security posture at a glance. Launch it with:

```bash
python3 dashboard_server.py --port 8765
# Then open http://127.0.0.1:8765
```

The dashboard shows key metrics (system health, finding counts, scan times), findings by severity (critical/warning/healthy), sensor status with individual module health, and recent scan activity.

See [docs/DASHBOARD.md](docs/DASHBOARD.md) for design principles and future enhancements.

## Full Command Reference

```
secure init                          Set up config, database, log file
secure status                        Show paths and database summary

secure check                         Run macOS security posture check (FileVault, firewall, SIP, etc.)
secure snapshot                      Continuity snapshot: recent file/LaunchAgent/posture changes

secure persistence scan              Inventory running processes and persistence mechanisms
secure persistence list              List every process/persistence entry ever recorded
secure persistence alerts            List all persistence alerts
secure persistence mark-process/mark-item/mark-alert <id> known|unknown

secure listening scan                Audit every listening port
secure listening list                List every service ever recorded
secure listening mark <id> known|unknown

secure connections scan              Show active TCP/UDP connections
secure connections endpoints         List every remote destination ever recorded
secure connections mark <id> known|unknown

secure inventory scan                Network device discovery (ARP + ping sweep)
secure inventory list                List every device ever recorded
secure inventory mark <id> known|unknown

secure arpwatch scan                 Check ARP table for IP-to-MAC spoofing
secure arpwatch list                 List all arpwatch alerts
secure arpwatch mark <id> known|unknown

secure wifi scan                     Current Wi-Fi + flag first-time/lookalike networks
secure wifi list                     List every network ever recorded
secure wifi alerts                   List lookalike-SSID alerts
secure wifi mark <id> known|unknown

secure bluetooth scan                List Bluetooth devices macOS knows about
secure bluetooth list                List every device ever recorded
secure bluetooth mark <id> trusted|untrusted
secure bluetooth ble scan            Live BLE peripherals discovery
secure bluetooth ble list            List every peripheral ever recorded
secure bluetooth ble mark <id> trusted|untrusted

secure integrations osquery scan     Cross-check with osquery
secure integrations osquery status   Show osquery health
secure integrations yarax scan-file <path>
secure integrations sigma scan       Evaluate Sigma rules
secure integrations suricata scan    Ingest Suricata EVE alerts
secure integrations zeek status      Show Zeek availability

secure explain <source> <id>         Show the full explanation for one alert
secure add-note "text"               Insert a test row (diagnostic)
```

## Development

Tests use Python `unittest` and `pytest`, including failure-path and mutation-gate checks. Their presence does not establish a current passing run; no fresh test-suite result is claimed by this documentation update.

```bash
python3 -m pytest tests/ -v
```

## License

No license has been selected for this repository. Public visibility alone does not grant an open-source license.
