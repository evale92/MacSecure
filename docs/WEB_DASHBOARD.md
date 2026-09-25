# Phase 63: Web Dashboard

## Scope

Real-time dashboard for alert monitoring, timeline, and feedback. HTML + JavaScript (no external dependencies, stdlib HTTP server). REST API endpoints for alerts, export (JSON/CSV), and feedback submission. Severity-based coloring, filtering by alert type and verdict.

## What Phase 63 Deliberately Does NOT Do

- **Not external web framework.** Uses Python's http.server.HTTPServer + BaseHTTPRequestHandler. No Flask, Django, or npm tooling. Payload entirely in HTML_TEMPLATE string.
- **Not WebSocket or real-time push.** Polling only. `/api/alerts` endpoint returns snapshot of database at query time.
- **Not authentication or authorization.** No user login, no role-based access, no rate limiting. Assumes dashboard runs on trusted network (localhost or private VPN).
- **Not multi-dashboard coordination.** Each running instance has its own in-memory state. No shared session, no dashboard-to-dashboard messaging.
- **Not alert mutation.** Dashboard is read-only for alerts. Feedback submission (POST /api/feedback) is the only write path, and writes only to alert_feedback table, not alert_decisions.
- **Not schema additions.** Reuses alert_decisions, alert_feedback, and derived views. No new tables.

## Design

**DashboardHandler** — HTTPRequestHandler subclass. Routes GET to serve HTML/API, POST to accept feedback. Handles three endpoints:
- GET / → HTML template (severity-colored alerts, timeline, stat cards)
- GET /api/alerts → JSON {total, critical_count, alerts:[...]} with optional filter params
- GET /api/export → JSON or CSV export of all alerts
- POST /api/feedback → {decision_id, verdict, reason} → writes to alert_feedback

**Alert timeline** — Lists all alert_decisions ordered by created_at DESC. Severity color-coded (CRITICAL red, HIGH orange, MEDIUM yellow, LOW green).

**Stat cards** — Display: total_count, critical_count, active_count (verdict='ACTIVE'), suppressed_count, average_severity.

**Export formats** — JSON: full alert + feedback object per decision. CSV: tabular (decision_id, severity, verdict, entity_type, feedback_count).

**Feedback form** — Inline per alert: dropdown (true_positive / false_positive / unclear) + optional text reason + submit button.

## Modules

- **secure/web/app.py** — DashboardHandler, HTML_TEMPLATE, API endpoints (402 lines)
- **tests/test_web_dashboard.py** — 4 tests: GET /, /api/alerts, /api/export, POST /api/feedback
- No separate dashboard.py; all logic in app.py main()

## Test Coverage

✅ Serve HTML template: GET / returns Content-Type text/html
✅ API alerts endpoint: returns {total, critical_count, alerts:[...]}
✅ API export JSON: structured export, all fields present
✅ API export CSV: tabular format, quoted fields, CRLF lines
✅ Feedback submission: POST /api/feedback inserts into alert_feedback
✅ Severity coloring: CLASS="severity-CRITICAL" etc in rendered HTML

## Known Gaps

1. **No dashboard mutation gate.** Run_server() binds to host:port; if binding fails, it raises RuntimeError. Gate added to catch this (GATE_DASHBOARD_SERVER_BIND_FAILURE), but no payload-level verification that response data is correct. A test could pass with stub alert data.

2. **No filter on active alerts.** /api/alerts returns all, not just ACTIVE verdict. Operators see suppressed and resolved alerts in the timeline, which may be confusing. No alert lifecycle state machine (NEW → ACTIVE → RESOLVED → ARCHIVED).

3. **No pagination or lazy loading.** /api/alerts returns entire result set. Large deployments (10k+ alerts) will have slow API response and bloated JSON.

4. **Feedback form only in timeline.** No bulk feedback (select 5 alerts, apply verdict to all). No dismiss/resolve action (toggle ACTIVE → RESOLVED without feedback loop).

5. **Export does not filter by time range.** No date picker; /api/export always dumps entire alert history. 

6. **No dashboard authentication.** Anyone on the network can view and submit feedback. No audit trail of who submitted what feedback.
