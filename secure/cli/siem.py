"""SIEM integration CLI commands (Phase 65)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from secure.integrations.siem import SIEMEndpoint, SIEMFormat, SIEMForwarder
from secure.integrations.config import SIEMConfigManager


def cmd_siem_add(args: argparse.Namespace) -> int:
    """Add a SIEM endpoint."""
    fmt = SIEMFormat(args.format)

    endpoint = SIEMEndpoint(
        endpoint_id=args.endpoint_id,
        name=args.name,
        format=fmt,
        url=args.url,
        host=args.host,
        port=args.port,
        api_key=args.api_key,
        enabled=True,
        timeout_seconds=args.timeout or 10,
    )

    SIEMConfigManager.add_endpoint(endpoint)

    if args.json:
        print(
            json.dumps(
                {
                    "status": "ok",
                    "endpoint_id": endpoint.endpoint_id,
                    "message": f"Endpoint {endpoint.name} added",
                }
            )
        )
    else:
        print(f"✓ SIEM endpoint '{endpoint.name}' added ({args.format} format)")

    return 0


def cmd_siem_list(args: argparse.Namespace) -> int:
    """List SIEM endpoints."""
    endpoints = SIEMConfigManager.list_endpoints()

    if not endpoints:
        if args.json:
            print(json.dumps({"endpoints": []}))
        else:
            print("No SIEM endpoints configured")
        return 0

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "endpoint_id": ep.endpoint_id,
                        "name": ep.name,
                        "format": ep.format.value,
                        "url": ep.url,
                        "host": ep.host,
                        "port": ep.port,
                        "enabled": ep.enabled,
                        "timeout_seconds": ep.timeout_seconds,
                    }
                    for ep in endpoints
                ]
            )
        )
    else:
        print("SIEM Endpoints:")
        for ep in endpoints:
            status = "✓" if ep.enabled else "✗"
            dest = ep.url or f"{ep.host}:{ep.port}"
            print(f"  {status} [{ep.endpoint_id}] {ep.name} ({ep.format.value}) → {dest}")

    return 0


def cmd_siem_remove(args: argparse.Namespace) -> int:
    """Remove a SIEM endpoint."""
    if SIEMConfigManager.remove_endpoint(args.endpoint_id):
        if args.json:
            print(json.dumps({"status": "ok", "message": "Endpoint removed"}))
        else:
            print(f"✓ Endpoint '{args.endpoint_id}' removed")
        return 0
    else:
        if args.json:
            print(json.dumps({"error": "Endpoint not found"}))
        else:
            print(f"✗ Endpoint '{args.endpoint_id}' not found", file=sys.stderr)
        return 1


def cmd_siem_test(args: argparse.Namespace) -> int:
    """Test a SIEM endpoint with a sample alert."""
    endpoint = SIEMConfigManager.get_endpoint(args.endpoint_id)
    if not endpoint:
        if args.json:
            print(json.dumps({"error": "Endpoint not found"}))
        else:
            print(f"✗ Endpoint '{args.endpoint_id}' not found", file=sys.stderr)
        return 1

    forwarder = SIEMForwarder()

    # Create sample alert
    sample_timestamp = datetime.utcnow()
    message = forwarder.format_alert(
        format=endpoint.format,
        alert_id=999,
        severity="HIGH",
        entity_type="test_process",
        entity_path="/usr/bin/test",
        verdict="ACTIVE",
        timestamp=sample_timestamp,
    )

    # Try to send
    success = forwarder.send_alert(
        endpoint,
        alert_id=999,
        severity="HIGH",
        entity_type="test_process",
        entity_path="/usr/bin/test",
        verdict="ACTIVE",
        timestamp=sample_timestamp,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "status": "ok" if success else "failed",
                    "endpoint_id": args.endpoint_id,
                    "message": "Test alert sent" if success else "Failed to send test alert",
                }
            )
        )
    else:
        if success:
            print(f"✓ Test alert sent to {args.endpoint_id}")
        else:
            print(f"✗ Failed to send test alert to {args.endpoint_id}", file=sys.stderr)

    return 0 if success else 1


def cmd_siem_enable(args: argparse.Namespace) -> int:
    """Enable a SIEM endpoint."""
    if SIEMConfigManager.enable_endpoint(args.endpoint_id):
        if args.json:
            print(json.dumps({"status": "ok", "message": "Endpoint enabled"}))
        else:
            print(f"✓ Endpoint '{args.endpoint_id}' enabled")
        return 0
    else:
        if args.json:
            print(json.dumps({"error": "Endpoint not found"}))
        else:
            print(f"✗ Endpoint '{args.endpoint_id}' not found", file=sys.stderr)
        return 1


def cmd_siem_disable(args: argparse.Namespace) -> int:
    """Disable a SIEM endpoint."""
    if SIEMConfigManager.disable_endpoint(args.endpoint_id):
        if args.json:
            print(json.dumps({"status": "ok", "message": "Endpoint disabled"}))
        else:
            print(f"✓ Endpoint '{args.endpoint_id}' disabled")
        return 0
    else:
        if args.json:
            print(json.dumps({"error": "Endpoint not found"}))
        else:
            print(f"✗ Endpoint '{args.endpoint_id}' not found", file=sys.stderr)
        return 1
