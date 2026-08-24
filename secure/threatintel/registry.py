"""
secure/threatintel/registry.py — builds the list of active providers
from AppConfig. The ONLY file that needs to change when a third
provider is added (register its `build_provider()` call here); nothing
else in enrich.py, explain wiring, or the CLI needs to know a new
provider exists — see secure/threatintel/providers/__init__.py's own
docstring.

Both shipped providers are always registered, never conditionally
omitted based on config — each provider's own `.lookup()` already
reports STATUS_UNAVAILABLE honestly when it isn't configured (no local
feed files present; no VirusTotal API key set), the same "always show
up, report your own honest status" convention IntegrationHealth already
established for every integrations/ engine. This means `secure
threatintel providers` can always list every provider Secure KNOWS
about, not just the ones currently configured.
"""

from __future__ import annotations

from typing import List

from secure.config import AppConfig
from secure.threatintel.providers import local_feed, virustotal


def build_providers(cfg: AppConfig) -> List:
    return [
        local_feed.build_provider(cfg.threat_intel_local_feed_dir_path()),
        virustotal.build_provider(cfg.virustotal_api_key),
    ]
