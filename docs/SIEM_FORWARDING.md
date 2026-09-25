# Phase 65: SIEM Integration

## Scope

Forward security alerts to external SIEM systems via pluggable transport formats. Supports CEF (Common Event Format), Syslog (RFC 3164), Splunk HEC (HTTP Event Collector), and generic JSON. Endpoint configuration persisted to disk; CLI management interface.

## What Phase 65 Deliberately Does NOT Do

- **Not SIEM selection.** Does not choose which alerts go where. Transport only; routing is upstream.
- **Not compliance logging.** Does not audit access to SIEM endpoints or forwarding history.
- **Not alert enrichment.** Does not add context, threat intel, or asset correlation; forwards raw severity/entity/verdict.
- **Not severity mapping enforcement.** Maps levels within each format, but does not validate that format severity band matches phase 64 risk level.
- **Not transport authentication.** API keys are stored plaintext in ~/.secure/siem_endpoints.json. Assumes endpoint secrets are managed by wrapper (vault, environment, etc).
- **Not multi-tenancy.** No per-user or per-session SIEM endpoints.

## Design

**SIEMForwarder** — Format abstraction. Dispatches to format-specific methods (format_cef, format_syslog, format_splunk_hec, format_json) based on SIEMFormat enum. Each returns a string ready for transmission.

**SIEMEndpoint** — Configuration dataclass. Stores endpoint_id, name, format, URL/host/port (transport-dependent), API key, enabled flag, timeout_seconds. Immutable after creation.

**SIEMConfigManager** — Persistence layer. Loads/saves endpoint configs to ~/.secure/siem_endpoints.json. Used by CLI only; product code reads via SIEMForwarder static reference.

**Transport abstraction** — send_http, send_syslog methods dispatch to urllib/socket based on endpoint type. No retry; single shot with timeout.

**Severity mapping:**

CEF (siem.py:70):
```python
{"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "NONE": 0}
```

Syslog (siem.py:116):
```python
{"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 5, "NONE": 7}
```

Splunk HEC and JSON pass severity string through as-is.

## Modules

- **secure/integrations/siem.py** — SIEMForwarder, SIEMFormat, SIEMEndpoint (355 lines)
- **secure/integrations/config.py** — SIEMConfigManager implementation, config file I/O (167 lines)
- **secure/cli/siem.py** — CLI: `secure siem add|list|remove|test|enable|disable` (186 lines)
- **tests/test_siem_integration.py** — 11 tests: format_cef, format_syslog, format_splunk_hec, format_json, send_http, send_syslog, endpoint config load/save

## Test Coverage

✅ All 4 format functions tested (CEF, Syslog, Splunk HEC, JSON)
✅ HTTP and Syslog transport tested
✅ Endpoint config persistence tested
✅ CLI command shell tested (add/list/remove)

## Known Gaps

1. **No mutation gate.** Unlike Phase 64, no subprocess gate verifies that SIEM forwarding actually succeeds. A test could pass with send_http/send_syslog stubbed to return False without failing the suite. (Phase 64 showed this pattern: dispatcher tests passed even when stub broke SIEM transport, because dispatcher doesn't call SIEMForwarder.)

2. **No integration with Phase 64 dispatcher.** AutomatedAlertDispatcher (Phase 64) does not call SIEMForwarder. Confidence-based approval and SIEM forwarding are independent flows. An approved automation could fail to reach the SIEM without surfacing an error.

3. **Severity mapping untested against mixed alert types.** Tests use one severity per run. Real deployments forward HIGH and CRITICAL together; mapping edge cases (CRITICAL→CEF 10, MEDIUM→CEF 5 in same batch) not verified.

4. **Transport timeout and failure recovery not specified.** A slow or down SIEM endpoint blocks send_http/send_syslog for timeout_seconds. No async, no queue, no fallback. Forwarding failure is logged but not escalated.

5. **API keys stored world-readable.** SIEMConfigManager writes api_key in cleartext to ~/.secure/siem_endpoints.json (config.py:65) using bare open(..., "w") at config.py:72 — no chmod, no mode, no umask. File inherits default permissions (world-readable). ~/.secure/secure.db is 0600; this is not. File does not exist yet, so nothing has leaked.
