"""
integrations/sigma/availability.py — determines whether PyYAML can
actually be used right now. Mirrors secure/integrations/yarax/
availability.py's own reasoning: a bare successful import isn't
proof enough, so this actually round-trips a trivial YAML document
through _yaml.parse_yaml() rather than just checking `import yaml`
succeeds.

Unlike yara_x (Phase 16, never actually installed in that sandbox),
PyYAML genuinely is available here, so — unlike yarax's — this
integration's STATUS_OK path is exercised for real by this project's
own tests, not just mocked at the seam.
"""

from __future__ import annotations

from datetime import datetime, timezone

from secure.integrations.base import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)
from secure.integrations.sigma._yaml import parse_yaml

# Deliberately synthetic and obviously not a real rule — same "clearly
# a smoke test, not real content" naming discipline as yarax's own
# _SMOKE_RULE.
_SMOKE_DOCUMENT = "secure_smoke_test: true\n"


def check_availability() -> IntegrationHealth:
    """ok — PyYAML imported and a trivial parse round-trip succeeded.
    unavailable — PyYAML is not installed. error — PyYAML is installed
    but the smoke-test parse itself failed unexpectedly.
    """
    now = datetime.now(timezone.utc).isoformat()

    try:
        import yaml  # noqa: PLC0415 - only used here to read __version__ for provenance
    except ImportError as exc:
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail=f"PyYAML is not installed ({exc}).",
            collected_at=now,
        )

    version = getattr(yaml, "__version__", None)

    try:
        result = parse_yaml(_SMOKE_DOCUMENT)
        if not isinstance(result, dict) or result.get("secure_smoke_test") is not True:
            raise ValueError(f"unexpected smoke-test parse result: {result!r}")
    except Exception as exc:  # noqa: BLE001 - a broken install must show as error, never crash the caller
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail=f"PyYAML is installed but failed a basic parse check: "
            f"{type(exc).__name__}: {exc}",
            collected_at=now,
            tool_version=version,
        )

    return IntegrationHealth(
        status=STATUS_OK,
        detail="PyYAML is available",
        collected_at=now,
        tool_version=version,
    )
