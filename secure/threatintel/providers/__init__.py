"""
secure/threatintel/providers/ — concrete threat-intelligence providers.

    local_feed.py  — reads user-configured local IOC list files
                    (`network=False`: zero outbound calls, so never
                    subject to the private/local indicator skip).
    virustotal.py  — a real network-capable provider (`network=True`),
                    gated behind an optional API key, demonstrating
                    that the base.py interface genuinely supports an
                    external network source without any change to
                    enrich.py, explain wiring, or the CLI.

Adding a THIRD provider (another reputable feed, or MISP) means adding
one more module here that exposes an `identity` (base.ProviderIdentity)
and a `.lookup(indicator_type, indicator_value)` method, then
registering it in secure/threatintel/registry.py — nothing else in this
codebase changes, which is exactly Phase 20's own "design the provider
interface so additional... feeds can be added later without changing
Secure's analysis layers" requirement.
"""
