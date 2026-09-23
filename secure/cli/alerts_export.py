"""Phase 56: Export alert decisions for compliance reporting."""

from __future__ import annotations
import json
import csv
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3


def cmd_alerts_export(args):
    """Export alert decisions to JSON or CSV for compliance."""
    from secure.storage.database import Database
    from secure.alerting.store import AlertDecisionStore

    db_path = Path.home() / ".secure" / "secure.db"

    with Database(db_path) as db:
        store = AlertDecisionStore(db.conn)

        # Get decisions from lookback period
        lookback = args.lookback_hours or 24
        decisions = store.get_recent_decisions(limit=1000)

        # Filter by date if needed
        if lookback:
            cutoff = datetime.utcnow() - timedelta(hours=lookback)
            decisions = [
                d for d in decisions
                if datetime.fromisoformat(d.created_at.replace('Z', '+00:00')) >= cutoff
            ]

        # Filter by verdict if specified
        if args.verdict:
            decisions = [d for d in decisions if d.verdict == args.verdict]

        # Export based on format
        if args.format == "json":
            export_json(decisions, args.output)
        elif args.format == "csv":
            export_csv(decisions, args.output)
        else:
            export_text(decisions, args.output)

        if args.output:
            print(f"✓ Exported {len(decisions)} alerts to {args.output}")
        else:
            print(f"✓ Exported {len(decisions)} alerts to stdout")


def export_json(decisions, output=None):
    """Export decisions as JSON."""
    data = {
        "exported_at": datetime.utcnow().isoformat(),
        "total": len(decisions),
        "decisions": [
            {
                "id": d.id,
                "source": d.source_table,
                "entity_type": d.entity_type,
                "entity_path": d.entity_path,
                "base_severity": d.base_severity,
                "final_severity": d.final_severity,
                "verdict": d.verdict,
                "correlation_id": d.correlation_id,
                "device_count": d.device_count,
                "created_at": d.created_at.isoformat(),
            }
            for d in decisions
        ],
    }

    content = json.dumps(data, indent=2)
    if output:
        Path(output).write_text(content)
    else:
        print(content)


def export_csv(decisions, output=None):
    """Export decisions as CSV."""
    fieldnames = [
        "id",
        "source",
        "entity_type",
        "entity_path",
        "base_severity",
        "final_severity",
        "verdict",
        "correlation_id",
        "device_count",
        "created_at",
    ]

    rows = []
    for d in decisions:
        rows.append({
            "id": d.id,
            "source": d.source_table,
            "entity_type": d.entity_type,
            "entity_path": d.entity_path or "",
            "base_severity": d.base_severity,
            "final_severity": d.final_severity,
            "verdict": d.verdict,
            "correlation_id": d.correlation_id or "",
            "device_count": d.device_count,
            "created_at": d.created_at,
        })

    if output:
        with open(output, "w") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    else:
        import sys
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_text(decisions, output=None):
    """Export decisions as human-readable text."""
    lines = []
    lines.append(f"Alert Export — {datetime.utcnow().isoformat()}")
    lines.append(f"Total: {len(decisions)} decisions\n")
    lines.append("=" * 80)

    for d in decisions:
        lines.append(f"Decision #{d.id}")
        lines.append(f"  Source: {d.source_table}:{d.source_id}")
        lines.append(f"  Entity: {d.entity_type} ({d.entity_path})")
        lines.append(f"  Severity: {d.base_severity} → {d.final_severity}")
        lines.append(f"  Verdict: {d.verdict}")
        lines.append(f"  Correlation: {d.correlation_id} ({d.device_count} devices)")
        lines.append(f"  Time: {d.created_at}")
        lines.append("-" * 80)

    content = "\n".join(lines)
    if output:
        Path(output).write_text(content)
    else:
        print(content)
