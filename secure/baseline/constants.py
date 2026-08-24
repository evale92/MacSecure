"""
secure/baseline/constants.py — every tunable number Phase 14's baseline
and anomaly-scoring logic depends on, in one place, named rather than
scattered as magic numbers through maturity.py / eligibility.py /
scoring.py / engine.py (Phase 14 approval: "Keep these thresholds as
named/configurable constants").

Nothing in this file touches the database or the filesystem — it's
pure data, safe to import from anywhere, including tests.
"""

from __future__ import annotations

# ---------- Maturity (see maturity.py) ----------
# An entity may only reach ESTABLISHED once ALL THREE eligible-history
# requirements hold simultaneously (Phase 14 approval item 3). Many
# scans in a short period must never establish a baseline on their
# own — that's why both a count AND a calendar-day-count AND a
# calendar-span requirement exist together.
MIN_ELIGIBLE_OBSERVATIONS = 20.0
MIN_ELIGIBLE_DISTINCT_DAYS = 14
MIN_ELIGIBLE_SPAN_DAYS = 14

# An entity becomes STALE once it hasn't been observed (eligible or
# not) in this many days, regardless of how mature it once was
# (approval item 4). History is preserved through this transition.
STALE_AFTER_DAYS = 30

# ---------- Eligibility weighting (see eligibility.py) ----------
# Approval item 6: an unresolved MEDIUM-severity finding still counts
# toward history, but at half weight rather than full exclusion.
FULL_WEIGHT = 1.0
MEDIUM_ALERT_WEIGHT = 0.5
EXCLUDED_WEIGHT = 0.0

# ---------- Drift / current-normal window (see scoring.py) ----------
# "CURRENT NORMAL" statistics are computed over this trailing window;
# LIFETIME counters (which back maturity and the "previously normal,
# not seen recently" narrative) are never windowed (approval item 10).
ROLLING_WINDOW_DAYS = 90

# ---------- Time-of-day model (see time_buckets.py) ----------
# Four broad buckets, deliberately coarse (approval item 9). Hours are
# local time, half-open interval [start, end).
TIME_BUCKETS = (
    ("night", 0, 6),
    ("morning", 6, 12),
    ("afternoon", 12, 18),
    ("evening", 18, 24),
)

# A time-of-day / weekday-vs-weekend deviation may only be scored once
# this entity's TIME dimension specifically has this much breadth —
# independent of the entity's overall maturity_state (approval item 9;
# "do not score time deviation when historical coverage is
# insufficient").
TIME_MIN_OBSERVATIONS = 20.0
TIME_MIN_DISTINCT_DAYS = 10

# ---------- Entity caps (see engine.py) ----------
# A single flat global cap (originally proposed at 2000) was flagged
# during design review as unrealistic once "process_destination" is
# included as its own entity_type: a single actively-used browser can
# accumulate hundreds to low-thousands of distinct remote destinations
# over a 90-day rolling window (CDNs, ad/analytics domains, per-site
# subdomains), which would exhaust a flat 2000-entity budget on its
# own and starve every other entity_type of baseline tracking.
# Capping PER entity_type instead keeps one noisy entity_type from
# crowding out the others, while keeping naturally-small entity_types
# (Wi-Fi networks, Bluetooth devices) tightly bounded. All values here
# are configurable; an entity_type not listed falls back to
# DEFAULT_ENTITY_CAP. Reaching a cap is never silent — see
# baseline_runs.entities_skipped_cap and `secure baseline status`.
ENTITY_CAPS = {
    "inventory": 500,
    "process": 2000,
    "process_destination": 20000,
    "listening": 500,
    "wifi": 200,
    "bluetooth": 200,
    "ble": 500,
    "persistence": 500,
    "file_watch_path": 500,
    # Phase 19 (Zeek): distinct DNS domains / TLS SNI hostnames a single
    # active Mac can genuinely query/connect to over a 90-day rolling
    # window is large (CDNs, ad/analytics domains, per-service
    # subdomains) but bounded well below process_destination's own
    # 20000 — there's no per-process multiplication here, just one flat
    # namespace of domains/hostnames.
    "dns_query": 5000,
    "tls_sni": 5000,
}
DEFAULT_ENTITY_CAP = 1000

# ---------- Anomaly score tiers (see scoring.py) ----------
# raw_score (0-100, sum of named components) maps to a tier via these
# upper bounds; 80+ is CRITICAL. Every boundary is a plain number, not
# a description — reproducible from stored data, per approval item 8.
SCORE_TIER_NONE_MAX = 14
SCORE_TIER_LOW_MAX = 34
SCORE_TIER_MEDIUM_MAX = 59
SCORE_TIER_HIGH_MAX = 79

ANOMALY_TIER_NONE = "none"
ANOMALY_TIER_LOW = "low"
ANOMALY_TIER_MEDIUM = "medium"
ANOMALY_TIER_HIGH = "high"
ANOMALY_TIER_CRITICAL = "critical"

ANOMALY_TIERS = (
    ANOMALY_TIER_NONE,
    ANOMALY_TIER_LOW,
    ANOMALY_TIER_MEDIUM,
    ANOMALY_TIER_HIGH,
    ANOMALY_TIER_CRITICAL,
)

# A LEARNING or NO_BASELINE entity can never produce a tier above LOW,
# regardless of raw score (approval item 3: "do not issue strong
# anomaly claims while a baseline is still LEARNING"). A STALE
# baseline's score is still computed and shown, but per approval item 4
# it may not itself justify HIGH/CRITICAL until refreshed — this is a
# tier CAP, not a score multiplier (the previously-proposed 0.7
# multiplier was removed during design review as arbitrary).
IMMATURE_TIER_CAP = ANOMALY_TIER_LOW
STALE_TIER_CAP = ANOMALY_TIER_MEDIUM

# ---------- Score components (see scoring.py) ----------
# Every boundary below is a plain number compared against a stored
# statistic — never a subjective judgment call (approval item 8).
#
# RARITY (0-40): how much of this entity's own rolling-window activity
# for this feature belongs to this specific value.
RARITY_NEVER_SEEN = 40  # value_weight == 0 in the rolling window (first time ever, or first time in ROLLING_WINDOW_DAYS)
RARITY_LOW_SHARE = 25
RARITY_LOW_SHARE_THRESHOLD = 0.05  # < 5% of this entity's rolling activity for this feature
RARITY_MODERATE_SHARE = 10
RARITY_MODERATE_SHARE_THRESHOLD = 0.20  # < 20%
# >= 20% share -> 0 points.

# RECENCY (0-15): only applies when value_weight > 0 (mutually
# exclusive with RARITY_NEVER_SEEN — a value that's never been seen
# has no "last seen" gap to measure; see scoring.py).
RECENCY_STALE_POINTS = 15
RECENCY_STALE_GAP_DAYS = 60  # hasn't recurred in over this many days
RECENCY_QUIET_POINTS = 8
RECENCY_QUIET_GAP_DAYS = 30

# BEHAVIOR_CHANGE (0-20): a specific, documented categorical
# transition (see scoring.py's per-feature rule functions) — never a
# generic diff of arbitrary fields.
BEHAVIOR_CHANGE_POINTS = 20

# SECURITY_CONTEXT (0-20 in principle, effectively 0-10 in practice):
# additive flags reusing EXISTING detector output, never re-derived.
# The unsigned/network-bind/weak-wifi flags are domain-specific (only
# one applies per entity_type), so at most two flags (the unreviewed-
# alert flag plus one domain flag) fire for any single observation.
# May fire together with BEHAVIOR_CHANGE for the same observation when
# they represent genuinely different facts (a persistent current
# condition vs. a transition) — see scoring.py's module docstring for
# the worked example of why this is not double-counting.
SECURITY_CONTEXT_UNREVIEWED_ALERT_POINTS = 5
SECURITY_CONTEXT_UNSIGNED_POINTS = 5
SECURITY_CONTEXT_NETWORK_BIND_POINTS = 5
SECURITY_CONTEXT_WEAK_WIFI_POINTS = 5

# TIME_DEVIATION (0-10): only scored once the entity's TIME dimension
# specifically is mature (TIME_MIN_OBSERVATIONS/TIME_MIN_DISTINCT_DAYS
# above) — otherwise always 0, explicitly noted as unscored rather than
# silently absent (approval item 9).
TIME_DEVIATION_NEVER_SEEN = 10
TIME_DEVIATION_LOW_SHARE = 5
TIME_DEVIATION_LOW_SHARE_THRESHOLD = 0.05
