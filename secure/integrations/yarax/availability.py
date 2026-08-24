"""
integrations/yarax/availability.py — determines whether the yara_x
library can actually be used right now, and if so, its own version.
Mirrors secure/integrations/osquery/availability.py's own reasoning:
don't infer "present, so surely fine" from a bare successful import —
actually compile a trivial rule and scan a trivial input, since a
library can import successfully but still fail to do real work (a
broken native extension build, an incompatible ABI, ...).
"""

from __future__ import annotations

from datetime import datetime, timezone

from secure.integrations.base import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)
from secure.integrations.yarax import _engine

# Deliberately named so it can never collide with a real user rule and
# is obviously synthetic in any log/output it might appear in.
_SMOKE_RULE = 'rule _secure_yarax_smoke_test { condition: false }'


def check_availability() -> IntegrationHealth:
    """ok — yara_x imported, and a trivial compile+scan round-trip
    succeeded. unavailable — yara_x is not installed. error — yara_x is
    installed but the compile/scan smoke test itself failed.
    """
    now = datetime.now(timezone.utc).isoformat()

    try:
        version = _engine.engine_version()
    except ImportError as exc:
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail=f"yara_x is not installed ({exc}).",
            collected_at=now,
        )
    except Exception as exc:  # noqa: BLE001 - any other import-time failure is still "unavailable"
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail=f"yara_x could not be imported: {type(exc).__name__}: {exc}",
            collected_at=now,
        )

    try:
        rules = _engine.compile_ruleset(_SMOKE_RULE, origin="_secure_smoke_test")
        _engine.scan_bytes(rules, b"", timeout_seconds=5.0)
    except Exception as exc:  # noqa: BLE001 - a broken install must show as error, never crash the caller
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail=f"yara_x is installed but failed a basic compile/scan check: "
            f"{type(exc).__name__}: {exc}",
            collected_at=now,
            tool_version=version,
        )

    return IntegrationHealth(
        status=STATUS_OK,
        detail="yara_x is available",
        collected_at=now,
        tool_version=version,
    )
