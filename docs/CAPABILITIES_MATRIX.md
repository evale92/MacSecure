# Supported-Capabilities Matrix (Phase 29)

Every sensor and integration Secure has, what it needs to work, and how
it reports when it can't. "Reports honestly" below was verified during
this phase (Stage 5), not assumed — see that stage's audit for the
specific check performed on each row.

## Native sensors

All native sensors are read-only, no-sudo (verified repo-wide in
`docs/THREAT_MODEL.md`), and depend only on Apple-supplied command-line
tools already present on any Mac — no third-party dependency, no
network.

| Sensor | Commands used | macOS permission | Failure reporting |
|---|---|---|---|
| Process & persistence (`secure/persistence/`) | `ps -axo ...`, `osascript -e '...System Events...'` (login items), `codesign -dv` | **Login items query may trigger a one-time "Terminal wants to control System Events" Automation prompt** — not previously documented; noted here as a Stage 3 finding. `ps`/`codesign` need no special permission. | `ps` failure -> honest `SENSOR_UNAVAILABLE` outcome (confirmed by `secure/validate/scenarios/persistence.py`'s own scenario). Background Items/SMAppService items are a documented, permanent `NOT_EVALUABLE` capability gap (no read API exists), not a false clean. |
| File integrity (`secure/fileintegrity/`) | Pure Python (`hashlib`, `os.stat`) — no subprocess at all | None | A monitored path that disappears/can't be read is recorded as its own event, never silently skipped. |
| Active connections (`secure/connections/`) | `lsof -i -n -P +c0` | None expected for a plain Terminal-launched process (no sandboxing); some system-owned sockets may be invisible without elevated privileges — Secure reports what it can see, never claims total visibility. | `lsof` failure -> `SENSOR_UNAVAILABLE` (validated in `secure/validate/scenarios/connections.py`). |
| Listening ports (`secure/listening/`) | `lsof -i -n -P +c0` | Same as above | `SENSOR_UNAVAILABLE` on `lsof` failure (validated in `secure/validate/scenarios/listening.py`). |
| Wi-Fi (`secure/wifi/`) | `ipconfig`, `networksetup -getairportnetwork`, `system_profiler SPAirPortDataType`, legacy `airport -I` if present | None expected for CLI-tool invocation (this is distinct from an app calling CoreWLAN's own API directly, which DOES need Location Services — Secure never does that). | Tri-state connected/disconnected/**status_unknown** (Phase 8 bugfix) — never collapses an unknown read into "not connected." |
| Bluetooth (classic, `secure/bluetooth/`) | `system_profiler SPBluetoothDataType` | None (reads system_profiler's own cache, not live CoreBluetooth) | Absence of expected fields degrades gracefully, never fabricates a device. |
| Bluetooth (BLE, `secure/bluetooth/ble/`) | `bleak` + `pyobjc-framework-CoreBluetooth` (live scanning) | **Real macOS Bluetooth permission required** — already explicitly modeled: `STATE_UNAUTHORIZED` is a first-class state (`secure/bluetooth/ble/state.py`), never confused with "no devices found." | Confirmed honest by design; this is the one sensor whose own step-zero diagnostic script (`scripts/ble_stepzero_check.py`) exists specifically because of this permission's flakiness. |
| ARP watch (`secure/arpwatch/`) | `arp -an`, `route -n get default` | None | Command failure surfaces as its own event, not a "no conflicts" false-clean. |
| Device inventory (`secure/inventory/`) | `arp -an`, `ifconfig`, `route`, `ping` | None | Best-effort; a failed hostname/vendor lookup leaves that field blank, never guessed. **Stage 5 fix:** `arp` failing to run entirely used to be indistinguishable from a genuine "zero devices on the network" scan — `ScanResult.arp_available` (mirroring arpwatch's own field) now makes that distinction explicit; a failed read returns exit code 1 and an honest "could not run arp" message instead of a clean "0 devices" report. |
| Security posture (`secure/checks/`) | `spctl --status`, `csrutil status`, `fdesetup status`, `/usr/libexec/ApplicationFirewall/socketfilterfw`, `defaults read`, `softwareupdate -l` | None (all read-only status queries) | A check that can't get a definitive answer without sudo reports that honestly (`secure/checks/models.py`) rather than guessing or escalating. |

## External integrations

All six report through `secure/integrations/base.py`'s shared
`STATUS_OK` / `STATUS_DEGRADED` / `STATUS_UNAVAILABLE` / `STATUS_ERROR`
vocabulary — confirmed by direct code read of every `check_availability()`
implementation during Stage 5, and by `secure/ai/context.py`'s tool-health
collector, which surfaces all six identically regardless of which are
actually installed.

| Integration | Dependency | Requires | Reports |
|---|---|---|---|
| osquery | `osqueryi` binary on PATH | Nothing beyond the binary | `UNAVAILABLE` if not found, `ERROR` on malformed output, `OK`/`DEGRADED` otherwise. |
| YARA-X | `yara-x` Python package (lazy import) | `pip install yara-x` | `UNAVAILABLE` if the import fails — never crashes the rest of a scan. |
| Sigma | `PyYAML` (installed, version-confirmed: 6.0.3) | Rule files present under configured path | `UNAVAILABLE` with zero rules loaded, `DEGRADED` if some rules fail to parse. |
| Suricata | `suricata` binary (optional, version-probe only) + its EVE JSON log file | A running Suricata + readable `eve.json` path in config | `UNAVAILABLE` if the log path is missing/unreadable; log staleness is itself surfaced as a health signal, not silently ignored. |
| Zeek | `zeek` binary (optional, version-probe only) + its own JSON logs | A running Zeek + readable log directory in config | Same staleness-aware honesty as Suricata. |
| Velociraptor | `velociraptor` binary | Configured `dfir_artifact_allowlist` (empty by default) | `UNAVAILABLE` if the binary isn't found; never runs without an explicit `secure dfir collect` invocation. |

## AI analyst backends (optional, Phase 28)

| Backend | Requires | Reports |
|---|---|---|
| Ollama | A running local Ollama server; `ollama_host` configured (default empty = disabled) | `secure ai status` shows REACHABLE/unreachable per backend; `ask()`'s own `status` field is `unavailable`/`error`/`partial`/`ok` — never silently treats a failed call as a real answer. |
| OpenAI-compatible (LM Studio/llama.cpp/MLX/vLLM) | A running local server; `local_llm_host` configured (default empty = disabled) | Same as above. |

## Dependency summary

Everything in this table is what `requirements.txt` already documents,
extensively, with the reasoning for each exception — see `requirements.txt`
itself and `docs/SBOM.md` (Stage 4) for the formal, licensed inventory. In short:
the app is standard-library-only except for `bleak` +
`pyobjc-framework-CoreBluetooth` (live BLE), `yara-x` (content
detection), and `PyYAML` (Sigma rule parsing) — three deliberate,
individually-justified exceptions out of 252 source files.
