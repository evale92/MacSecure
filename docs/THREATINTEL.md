# Secure — Threat-Intelligence Enrichment (Phase 20)

This documents `secure/threatintel/`, the provider-neutral
threat-intelligence enrichment layer. Companion reading:
`docs/EXPLAINABILITY.md` (the explanation layer this phase attaches
enrichment to) and `PROJECT_NOTES.md` (phase-by-phase build log,
including this phase's own entry and the "Phase 24 — Threat
Intelligence" roadmap bullet this delivers).

## Why this exists, and the one rule that matters most

**Threat intelligence is enrichment, not ground truth.** An IP,
domain, or file hash appearing on one external feed must never by
itself mean "confirmed malicious," and — just as important, and easy
to get wrong — a provider having **no record** of an indicator must
never be silently treated as "confirmed safe." Nothing in this package
makes a detection decision; it only attaches externally-sourced
reputation context to indicators Secure already has some other reason
to care about (an alert's own message text), for a human to weigh
alongside everything else.

## Why `secure/threatintel/` is not `secure/integrations/`

`secure/integrations/` (Phase 15+) wraps external tools that **collect
telemetry Secure reads passively** (osquery queries, YARA-X scans
files already on disk, Sigma evaluates rules against existing
observations, Suricata/Zeek read log files they wrote on their own).
Threat intelligence is a different shape of external dependency: it is
an **active, on-demand lookup** Secure itself initiates about one
specific indicator, optionally over the network, and the whole point
is to be deliberate and rare about when that happens — not something
a periodic `scan` sweeps automatically. That's different enough from
"read whatever this already-running background tool wrote" to warrant
its own top-level package rather than a sixth `integrations/` entry.

## The provider interface (`secure/threatintel/base.py`)

Duck-typed, not a class hierarchy — the same "smallest generic
boundary, no ABCs, no plugin registry" discipline
`secure/integrations/base.py` established for a different kind of
external source. A provider is anything with:

- **`.identity`** — a `ProviderIdentity(name, network, schema_version)`.
  `network` is the one flag that matters for privacy: `True` means
  this provider can make an outbound network call, and is therefore
  subject to the private/local-indicator skip below; `False` (an
  offline/local-only provider) is exempt, since nothing it does can
  leak information off the Mac.
- **`.lookup(indicator_type, indicator_value) -> ProviderLookupResult`**
  — perform (or attempt) one lookup.

Adding a third provider (another reputable feed, or MISP) means
writing one module implementing this interface and registering it in
`secure/threatintel/registry.py` — the **only** file that changes.
Nothing in `enrich.py`, explain wiring, or the CLI needs to know a new
provider exists; two genuinely different providers (an offline file
feed and a live network API) were built against this exact interface
with zero special-casing anywhere else, as concrete proof.

### `ProviderLookupResult` and the six-state status vocabulary

Every lookup produces exactly one `ProviderLookupResult`, carrying:
indicator type/value, provider name, lookup timestamp (`queried_at`),
`status`, `verdict`, `score`/`score_meaning`, `categories`,
`raw_response`, exact `source_query` (never a secret/API key),
`expires_at` (TTL), and a human-readable `detail`.

`status` is one of six values, each a genuinely different fact:

| Status | Meaning |
|---|---|
| `ok` | Provider reached; has a real answer. |
| `not_found` | Provider reached; **no record** for this indicator. |
| `unavailable` | Provider not configured/reachable right now (e.g. no API key) — routine. |
| `error` | Provider reachable but this attempt failed unexpectedly. |
| `rate_limited` | Provider explicitly rejected the request as over-quota. |
| `skipped_private` | Secure itself declined to send this indicator to a network-capable provider — the provider's own `.lookup()` was never even called. |

**`not_found` is not `clean`.** This is enforced structurally, not
just by convention: `ProviderLookupResult.__post_init__` **raises**
`ValueError` if a `verdict` is ever set on a result whose `status` is
not `ok`. There is no code path — today or added later by a future
provider — that can produce a "not found, but treat as safe" result;
the dataclass itself refuses to construct it.

`verdict`, when present, is Secure's own **translated** three-value
bucket (`clean` / `suspicious` / `malicious`, or `unknown`) — a
translation of the provider's raw response, never a second independent
judgment. `unknown` exists for a provider giving an answer with
literally no meaningful signal (e.g. zero vendor votes either way).

## Privacy: what never leaves this Mac (`indicators.py`)

`is_sendable_to_network_provider(indicator_type, value)` is checked
**before** a `network=True` provider's `.lookup()` is ever called:

- **IPs** — `is_private_or_local_ip()` uses Python's stdlib
  `ipaddress` module: RFC1918 private ranges, loopback, link-local,
  multicast, and other reserved ranges are all withheld. This
  includes the IANA TEST-NET-1/2/3 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) used
  throughout this project's own test fixtures elsewhere — `ipaddress`
  marks those `is_private = True` too, correctly, since they can never
  route anywhere real. (This project's own threat-intel tests
  therefore use a real, well-known public address — `8.8.8.8` — to
  exercise the "genuinely public, would be sent" code path.)
- **Domains** — `is_local_domain()` is a best-effort heuristic: a
  known local-only suffix (`.local`, `.internal`, `.lan`, `.home`,
  `.localdomain`, `.corp`, `.test`) or a bare single-label hostname
  with no dot at all is withheld. Not exhaustive — a corporate domain
  that's internal-only but doesn't use one of these suffixes will not
  be caught; a known limitation, not a silent gap.
- **Hashes** — always sendable. A file hash carries no location/network
  information about this Mac by itself.

When an indicator fails this check, `enrich.py` records a
`skipped_private` result **without calling the provider at all** —
`source_query` says plainly "no request made."

## Storage: `threat_intel_lookups` (append-only)

One new SQLite table, one row per lookup **attempt** — never
overwritten or upserted, matching this codebase's universal
`*_observations`/`*_runs` append-only-history discipline. Columns:
`indicator_type`, `indicator_value`, `provider`, `queried_at`,
`status`, `verdict`, `score`, `score_meaning`, `categories_json`,
`raw_response_json`, `source_query`, `expires_at`, `detail`, plus the
usual `id`/`created_at`. Because every attempt is its own row (not one
row per indicator), conflicting results from different providers about
the same indicator are naturally preserved side by side rather than
one silently overwriting another.

`secure/storage/models/threatintel.py` provides the reads
`enrich.py` needs: `find_fresh_lookup()` (non-expired cache read, used
to decide whether a real provider call happens at all),
`find_latest_lookups_for_indicator()` (latest row per distinct
provider — what explain wiring shows), `find_latest_lookup()` (most
recent row for one provider regardless of freshness — explain wiring
would rather show an honestly-labeled stale result than nothing), and
`list_threat_intel_lookups()` (the read behind `secure threatintel
history`).

## Caching and TTL

`enrich_indicator()` is cache-first **per provider**: a fresh cached
row for a given (indicator, provider) means that provider's
`.lookup()` is not called again until the cache entry expires.
`ok`/`not_found` results get the configured default TTL
(`AppConfig.threat_intel_cache_ttl_hours`, default 24 hours) unless the
provider itself supplied an `expires_at`. `unavailable`/`error`/
`rate_limited` results are **deliberately never cached long-term**
(`expires_at` stays `None`, always treated as already-expired) — a
transient failure should be retried on the next request, not silently
frozen in place for a day.

## Orchestration (`secure/threatintel/enrich.py`)

Two entry points, deliberately serving different callers:

- **`enrich_indicator(conn, cfg, indicator_type, indicator_value)`** —
  performs REAL lookups (cache-first, but will make a genuine provider
  call, including a network request, on a cache miss). This is what
  `secure threatintel lookup` calls — the **only** command in the
  whole app that can make a real external network request for an
  arbitrary indicator.
- **`attach_cached_threat_intel(conn, explanation, text)`** —
  CACHE-ONLY, read-only, makes no provider call and therefore no
  network request, ever. Scans `text` (an alert's own rendered message)
  for candidate indicators via `extract.py`'s best-effort regex
  extraction (each match re-validated through `classify_indicator()`,
  so a regex false-positive is silently dropped, never guessed at;
  bounded to `MAX_INDICATORS_PER_EXPLANATION` = 5 per explanation), and
  for each one either shows what's already cached or states plainly
  that no lookup has been performed yet — never fabricates a result.

`attach_cached_threat_intel()` is applied by call sites as a strictly
separate, additive step **after** `explain()` returns (currently only
`secure/cli/root.py`'s `cmd_explain()`), using `dataclasses.replace()`
to produce a new `Explanation` — `secure/explain/dispatch.py` needed
**zero changes**. This is what guarantees viewing an alert's
explanation can never silently trigger an external disclosure; only an
explicit `secure threatintel lookup` call can.

## "Investigations"

This project has no separate, formal "investigation" feature yet (the
codebase's only pre-existing related concept is the
`INVESTIGATE_NOW` recommended-action constant in `explain/vocab.py`).
"Integrate enrichment into investigations" is interpreted here as the
two places a human analyst actually looks something up by hand: the
ad-hoc `secure explain <source> <alert-id>` command (cache-only, per
above) and the new `secure threatintel lookup` command (the deliberate,
explicit, real-lookup path).

## Shipped providers

### `local_feed` (`secure/threatintel/providers/local_feed.py`)

Offline, `network=False`. Reads three optional flat files under
`AppConfig.threat_intel_local_feed_dir_path()` (default
`<app_dir>/threat_intel_feeds/`): `ip_feed.txt`, `domain_feed.txt`,
`hash_feed.txt`, one `value[,category[,severity]]` entry per line
(`#`-comments and blank lines ignored). A missing file means zero
entries of that type — routine, not an error. A match becomes
`verdict=suspicious` (default) or `verdict=malicious` (only if the
line explicitly says so); a non-match is always `status=not_found`,
**never** "clean" — a local list's silence about an indicator says
nothing about its actual reputation.

### `virustotal` (`secure/threatintel/providers/virustotal.py`)

Real network API, `network=True`, gated behind an optional
`AppConfig.virustotal_api_key` (empty by default → `unavailable`,
never a crash — the same "absence is normal" convention every other
optional integration field in this app uses). Uses VirusTotal's v3 API
(`GET /api/v3/{ip_addresses|domains|files}/{value}`), translating the
aggregate `last_analysis_stats` vote count into Secure's own
verdict/score/score_meaning. Every actual network call goes through
`secure/threatintel/providers/_http.py`'s `http_get_json()` — the one
seam every network-capable provider uses, stdlib `urllib.request`
only, so tests mock exactly one function and never make a real network
call. **This dependency could not be exercised against the real API in
the sandbox this phase was built in** (no network access, no API key)
— confirm against a real API key before relying on this in production.

Both providers are always registered (`registry.py`), never
conditionally omitted — each reports its own honest `unavailable`
status when unconfigured, so `secure threatintel providers` always
lists every provider Secure knows about, not just the ones currently
usable.

## CLI (`secure/cli/threatintel.py`)

```
secure threatintel lookup auto|ip|domain|hash <value>
secure threatintel history [--type T] [--value V] [--provider P] [--limit N]
secure threatintel providers
```

`lookup` is the only command that can make a real external network
request; `history`/`providers` are read-only. `lookup`'s exit code is
non-zero when any provider's verdict came back `malicious` or
`suspicious` — useful for scripting, without turning this into an
automated blocking decision (nothing here disables, blocks, or
quarantines anything).

## Tests

`tests/test_threatintel.py` (79 tests) covers pure indicator
classification/privacy logic, the structural not-found-can't-become-
verdict invariant, message-text extraction, storage persistence and
cache-freshness, both shipped providers (VirusTotal fully mocked via
`providers._http.http_get_json`, so no real network call is ever
made), provider registration, orchestration (caching, the privacy
skip, transient-failure non-caching), explain wiring end-to-end
(including a real `secure explain` run against a synthetic ARP alert),
and the CLI surface. Fixtures live under `tests/fixtures/threatintel/`
(IANA TEST-NET IP ranges, `-secure-test-` marked domains/hashes — never
real-world IOCs, matching this suite's existing fixture convention).
