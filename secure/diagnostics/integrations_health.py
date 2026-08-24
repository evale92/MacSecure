"""
diagnostics/integrations_health.py — Phase 30's "INTEGRATIONS" section:
reuses every external integration's own `check_availability()` (layer
3's `secure/integrations/base.py` STATUS_OK/DEGRADED/UNAVAILABLE/ERROR
vocabulary, Phase 15-19; layer 9's `secure/dfir/velociraptor/` uses the
same shape, Phase 24) rather than building a second health model. This
module contains no health logic of its own — it only calls the six
existing functions and returns their results labeled by name.
"""

from __future__ import annotations

from secure.config import AppConfig
from secure.integrations.base import IntegrationHealth


def collect_integration_health(cfg: AppConfig) -> "list[tuple[str, IntegrationHealth]]":
    results: "list[tuple[str, IntegrationHealth]]" = []

    from secure.integrations.osquery import check_availability as osquery_check
    results.append(("osquery", osquery_check()))

    from secure.integrations.yarax import check_availability as yarax_check
    results.append(("yarax", yarax_check()))

    from secure.integrations.sigma import check_availability as sigma_check
    results.append(("sigma", sigma_check()))

    from secure.integrations.suricata import check_availability as suricata_check
    results.append(("suricata", suricata_check(cfg)))

    from secure.integrations.zeek import check_availability as zeek_check
    results.append(("zeek", zeek_check(cfg)))

    from secure.dfir.velociraptor.availability import check_availability as velociraptor_check
    results.append(("velociraptor", velociraptor_check(cfg)))

    return results
