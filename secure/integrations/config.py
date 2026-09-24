"""SIEM configuration management — Phase 65."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import List, Optional

from secure.integrations.siem import SIEMEndpoint, SIEMFormat


class SIEMConfigManager:
    """Manage SIEM endpoint configurations."""

    CONFIG_FILE = Path.home() / ".secure" / "siem_endpoints.json"

    @classmethod
    def load_config(cls) -> List[SIEMEndpoint]:
        """Load SIEM endpoints from config file.

        Returns:
            List of SIEMEndpoint objects
        """
        if not cls.CONFIG_FILE.exists():
            return []

        try:
            with open(cls.CONFIG_FILE) as f:
                data = json.load(f)
                return [
                    SIEMEndpoint(
                        endpoint_id=ep["endpoint_id"],
                        name=ep["name"],
                        format=SIEMFormat(ep["format"]),
                        url=ep.get("url"),
                        host=ep.get("host"),
                        port=ep.get("port"),
                        api_key=ep.get("api_key"),
                        enabled=ep.get("enabled", True),
                        timeout_seconds=ep.get("timeout_seconds", 10),
                    )
                    for ep in data
                ]
        except (json.JSONDecodeError, KeyError, ValueError):
            return []

    @classmethod
    def save_config(cls, endpoints: List[SIEMEndpoint]) -> None:
        """Save SIEM endpoints to config file.

        Args:
            endpoints: List of SIEMEndpoint objects
        """
        cls.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        data = [
            {
                "endpoint_id": ep.endpoint_id,
                "name": ep.name,
                "format": ep.format.value,
                "url": ep.url,
                "host": ep.host,
                "port": ep.port,
                "api_key": ep.api_key,
                "enabled": ep.enabled,
                "timeout_seconds": ep.timeout_seconds,
            }
            for ep in endpoints
        ]

        with open(cls.CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def add_endpoint(cls, endpoint: SIEMEndpoint) -> None:
        """Add a new SIEM endpoint.

        Args:
            endpoint: SIEMEndpoint to add
        """
        endpoints = cls.load_config()
        # Remove if already exists
        endpoints = [e for e in endpoints if e.endpoint_id != endpoint.endpoint_id]
        endpoints.append(endpoint)
        cls.save_config(endpoints)

    @classmethod
    def remove_endpoint(cls, endpoint_id: str) -> bool:
        """Remove a SIEM endpoint.

        Args:
            endpoint_id: ID of endpoint to remove

        Returns:
            True if endpoint was removed, False if not found
        """
        endpoints = cls.load_config()
        original_count = len(endpoints)
        endpoints = [e for e in endpoints if e.endpoint_id != endpoint_id]

        if len(endpoints) < original_count:
            cls.save_config(endpoints)
            return True

        return False

    @classmethod
    def get_endpoint(cls, endpoint_id: str) -> Optional[SIEMEndpoint]:
        """Get a specific SIEM endpoint.

        Args:
            endpoint_id: ID of endpoint

        Returns:
            SIEMEndpoint or None if not found
        """
        endpoints = cls.load_config()
        for ep in endpoints:
            if ep.endpoint_id == endpoint_id:
                return ep
        return None

    @classmethod
    def list_endpoints(cls) -> List[SIEMEndpoint]:
        """List all SIEM endpoints.

        Returns:
            List of SIEMEndpoint objects
        """
        return cls.load_config()

    @classmethod
    def enable_endpoint(cls, endpoint_id: str) -> bool:
        """Enable a SIEM endpoint.

        Args:
            endpoint_id: ID of endpoint

        Returns:
            True if enabled, False if not found
        """
        endpoints = cls.load_config()
        for ep in endpoints:
            if ep.endpoint_id == endpoint_id:
                ep.enabled = True
                cls.save_config(endpoints)
                return True
        return False

    @classmethod
    def disable_endpoint(cls, endpoint_id: str) -> bool:
        """Disable a SIEM endpoint.

        Args:
            endpoint_id: ID of endpoint

        Returns:
            True if disabled, False if not found
        """
        endpoints = cls.load_config()
        for ep in endpoints:
            if ep.endpoint_id == endpoint_id:
                ep.enabled = False
                cls.save_config(endpoints)
                return True
        return False
