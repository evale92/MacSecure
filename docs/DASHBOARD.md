# Security Dashboard

A modern web-based dashboard for Secure's security monitoring and findings management.

## Overview

The dashboard provides a visual summary of your system's security posture at a glance. It displays:

- **Key metrics**: System health, finding counts, last scan time, sensor coverage
- **Findings by severity**: Critical, warning, and healthy status indicators
- **Sensor status**: Health of each security module with finding counts
- **Recent activity**: Timeline of recent scans and operations
- **Quick actions**: Common operations (full scan, posture check, view findings)

## Design Principles

The dashboard applies modern information design to security monitoring:

1. **Status-first display**: Color + icon + text (never color alone) for accessibility
2. **Progressive disclosure**: Summary metrics first, detailed tables below
3. **Visual hierarchy**: Most important information at the top
4. **Responsive layout**: Single column on mobile, multi-column on desktop
5. **Dark mode support**: Automatically adapts to system preferences

## Running the Dashboard

### Method 1: Python Server

```bash
python3 dashboard_server.py --port 8765
```

Then open http://127.0.0.1:8765 in your browser.

### Method 2: Simple HTTP Server

```bash
cd /path/to/secure-resource
python3 -m http.server 8765 --bind 127.0.0.1
```

Then open http://127.0.0.1:8765/dashboard.html

### Method 3: Manual

Simply open `dashboard.html` directly in your browser (file:/// protocol).

The dashboard currently displays mock/example data. Integration with real Secure commands (secure status, secure check, etc.) is in future development.

## Features

### Key Performance Indicators (KPIs)

- **System Health**: Overall status (Safe/Warning/Critical)
- **Active Findings**: Count by severity level
- **Last Full Scan**: Time since baseline update
- **Sensor Coverage**: Number of active monitoring modules

### Findings Summary

Three-column layout showing findings grouped by severity:
- Critical findings (require immediate review)
- Warning findings (monitor closely)
- Healthy sensors (all checks passing)

### Sensor Status

Bar chart showing each security module's health:
- Individual finding counts per sensor
- Color-coded status (green/yellow/red)
- Clickable rows for drill-down (future enhancement)

### Recent Activity

Table of recent operations showing:
- Operation name (Full scan, File integrity check, etc.)
- Completion status
- Timestamp
- Result summary

### Quick Actions

Cards for common operations:
- Full System Scan
- Security Posture Check
- View All Findings

Click any card to see the command that would be executed (future: direct integration).

## Styling & Customization

The dashboard uses CSS custom properties (variables) for theming. To customize colors or fonts, edit the `:root` variables in the `<style>` section:

```css
:root {
  --accent: #2a78d6;      /* Primary brand color */
  --critical: #d03b3b;    /* Critical alert color */
  --warning: #fab219;     /* Warning color */
  --good: #0ca30c;        /* Success color */
  /* … more variables … */
}
```

Dark mode is automatically detected via `prefers-color-scheme: dark` media query.

## Future Enhancements

Planned features:

1. **Live data integration**: Fetch real data from `secure status`, `secure check`, etc.
2. **Drill-down views**: Click findings to see full details
3. **Historical trends**: Charts showing security posture over time
4. **Customizable dashboard**: User-configurable widget layout
5. **Export/reporting**: Generate PDF security reports
6. **Alerting**: Desktop notifications for critical findings
7. **API backend**: RESTful API for programmatic access

## Technical Details

- **Pure client-side**: Loads as static HTML (no backend required initially)
- **Responsive**: Adapts to window width (1–3 column grid)
- **Accessible**: ARIA labels, keyboard navigation, high contrast support
- **Standards-based**: HTML5, CSS Grid, vanilla JavaScript
- **Dark mode ready**: Uses `prefers-color-scheme` media query

## Reference

This dashboard applies design patterns from the Agent priority-dashboard:

- Information hierarchy with KPIs first
- Status vocabulary: icon + text + color
- Progressive disclosure for details
- Responsive grid layout
- Semantic HTML with ARIA labels

See the Agent dashboard for more context: https://github.com/anthropics/agent

## Files

- `dashboard.html` — Standalone dashboard (open directly or serve via HTTP)
- `dashboard_server.py` — Python server for easy local hosting
- `docs/DASHBOARD.md` — This documentation
