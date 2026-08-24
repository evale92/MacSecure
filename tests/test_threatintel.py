"""
Tests for secure/threatintel/ (Phase 20: provider-neutral threat-
intelligence enrichment).

Covers, in order: pure indicator classification/privacy logic
(indicators.py), the structural "never silently turn 'not found' into
safe" invariant (base.py), best-effort message-text extraction
(extract.py), storage persistence/cache-freshness (storage/models/
threatintel.py), both shipped providers (local_feed.py, offline;
virustotal.py, network-capable and mocked via monkeypatching
providers._http.http_get_json — no real network call is ever made),
provider registration (registry.py), orchestration/caching/privacy-skip
(enrich.py), explain wiring (attach_cached_threat_intel), and the CLI
surface (secure threatintel lookup/history/providers).

Per indicators.py's own documented discovery, Python's `ipaddress`
module marks the IANA TEST-NET-1/2/3 documentation ranges used
everywhere else in this suite's fixtures as `is_private = True` — so
tests that need a genuinely "would be sent to a network provider" IP
use a real, well-known public resolver address (8.8.8.8) instead of a
TEST-NET range. Local-feed fixtures still use TEST-NET ranges (they
have nothing to do with "would this leave the Mac").

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure import cli
from secure.config import AppConfig
from secure.explain.explanation import Explanation
from secure.explain import vocab
from secure.storage.database import Database
from secure.storage.models import add_arp_alert
from secure.threatintel import enrich as enrich_module
from secure.threatintel import extract as extract_module
from secure.threatintel import indicators as indicators_module
from secure.threatintel import registry as registry_module
from secure.threatintel.base import (
    STATUS_ERROR,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_SKIPPED_PRIVATE,
    STATUS_UNAVAILABLE,
    VERDICT_CLEAN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    ProviderIdentity,
    ProviderLookupResult,
)
from secure.threatintel.providers import _http as http_module
from secure.threatintel.providers import local_feed, virustotal

FIXTURES = Path(__file__).parent / "fixtures" / "threatintel"

REAL_PUBLIC_IP = "8.8.8.8"  # a genuinely public address — see module docstring


def _ns(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def _run_capturing_stdout(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


def _cfg_with_local_feed(tmp_path: Path, api_key: str = "") -> AppConfig:
    cfg = AppConfig(app_dir=str(tmp_path))
    cfg.threat_intel_local_feed_dir = "threat_intel_feeds"
    cfg.virustotal_api_key = api_key
    feed_dir = cfg.threat_intel_local_feed_dir_path()
    feed_dir.mkdir(parents=True, exist_ok=True)
    for name in ("ip_feed.txt", "domain_feed.txt", "hash_feed.txt"):
        (feed_dir / name).write_text((FIXTURES / name).read_text())
    return cfg


def _result(
    indicator_type="ip",
    indicator_value="198.51.100.23",
    provider="test_provider",
    status=STATUS_OK,
    verdict=None,
    score=None,
    score_meaning=None,
    categories=(),
    raw_response=None,
    source_query="test://query",
    expires_at=None,
    detail="test detail",
    queried_at=None,
) -> ProviderLookupResult:
    return ProviderLookupResult(
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        provider=provider,
        queried_at=queried_at or datetime.now(timezone.utc).isoformat(),
        status=status,
        verdict=verdict,
        score=score,
        score_meaning=score_meaning,
        categories=categories,
        raw_response=raw_response,
        source_query=source_query,
        expires_at=expires_at,
        detail=detail,
    )


# =========================================================================
# indicators.py
# =========================================================================


def test_classify_indicator_ipv4():
    assert indicators_module.classify_indicator("198.51.100.23") == indicators_module.IP


def test_classify_indicator_ipv6():
    assert indicators_module.classify_indicator("2001:db8::1") == indicators_module.IP


def test_classify_indicator_sha256_hash():
    assert indicators_module.classify_indicator("a" * 64) == indicators_module.HASH


def test_classify_indicator_sha1_hash():
    assert indicators_module.classify_indicator("a" * 40) == indicators_module.HASH


def test_classify_indicator_md5_hash():
    assert indicators_module.classify_indicator("a" * 32) == indicators_module.HASH


def test_classify_indicator_domain():
    assert indicators_module.classify_indicator("bad-secure-test.example") == indicators_module.DOMAIN


def test_classify_indicator_rejects_version_like_string():
    # No alphabetic TLD label -> not domain-shaped; not hex-length -> not
    # a hash; not parseable -> not an IP. Must not guess.
    assert indicators_module.classify_indicator("7.0.3") is None


def test_classify_indicator_rejects_garbage():
    assert indicators_module.classify_indicator("not an indicator!!") is None


def test_classify_indicator_empty_and_none():
    assert indicators_module.classify_indicator("") is None
    assert indicators_module.classify_indicator(None) is None


def test_hash_algorithm_by_length():
    assert indicators_module.hash_algorithm("a" * 32) == "md5"
    assert indicators_module.hash_algorithm("a" * 40) == "sha1"
    assert indicators_module.hash_algorithm("a" * 64) == "sha256"
    assert indicators_module.hash_algorithm("a" * 10) is None


def test_normalize_indicator_ip_uses_compressed_form():
    assert indicators_module.normalize_indicator(indicators_module.IP, "2001:0db8::1") == "2001:db8::1"


def test_normalize_indicator_lowercases_domain_and_hash():
    assert indicators_module.normalize_indicator(indicators_module.DOMAIN, "Bad-Secure-Test.EXAMPLE") == "bad-secure-test.example"
    assert indicators_module.normalize_indicator(indicators_module.HASH, "A" * 32) == "a" * 32


def test_is_private_or_local_ip_true_for_rfc1918():
    assert indicators_module.is_private_or_local_ip("10.0.0.5") is True
    assert indicators_module.is_private_or_local_ip("192.168.1.1") is True


def test_is_private_or_local_ip_true_for_loopback_and_link_local():
    assert indicators_module.is_private_or_local_ip("127.0.0.1") is True
    assert indicators_module.is_private_or_local_ip("169.254.1.1") is True


def test_is_private_or_local_ip_true_for_test_net_documented_behavior():
    # Documented discovery in indicators.py: TEST-NET ranges ARE flagged
    # private by the stdlib ipaddress module — correct, since they can
    # never route anywhere real.
    assert indicators_module.is_private_or_local_ip("198.51.100.23") is True
    assert indicators_module.is_private_or_local_ip("203.0.113.9") is True
    assert indicators_module.is_private_or_local_ip("192.0.2.1") is True


def test_is_private_or_local_ip_false_for_real_public_address():
    assert indicators_module.is_private_or_local_ip(REAL_PUBLIC_IP) is False


def test_is_private_or_local_ip_false_for_unparseable_value():
    assert indicators_module.is_private_or_local_ip("not-an-ip") is False


def test_is_local_domain_true_for_local_suffixes():
    assert indicators_module.is_local_domain("myhost.local") is True
    assert indicators_module.is_local_domain("router.lan") is True
    assert indicators_module.is_local_domain("nas.internal") is True


def test_is_local_domain_true_for_bare_hostname():
    assert indicators_module.is_local_domain("nohostname") is True
    assert indicators_module.is_local_domain("") is True


def test_is_local_domain_false_for_real_domain():
    assert indicators_module.is_local_domain("bad-secure-test.example") is False


def test_is_sendable_to_network_provider_ip():
    assert indicators_module.is_sendable_to_network_provider(indicators_module.IP, "10.0.0.5") is False
    assert indicators_module.is_sendable_to_network_provider(indicators_module.IP, REAL_PUBLIC_IP) is True


def test_is_sendable_to_network_provider_domain():
    assert indicators_module.is_sendable_to_network_provider(indicators_module.DOMAIN, "host.local") is False
    assert indicators_module.is_sendable_to_network_provider(indicators_module.DOMAIN, "bad-secure-test.example") is True


def test_is_sendable_to_network_provider_hash_always_true():
    # A hash carries no location information by itself.
    assert indicators_module.is_sendable_to_network_provider(indicators_module.HASH, "a" * 32) is True


# =========================================================================
# base.py — the structural "never silently turn 'not found' into safe"
# invariant
# =========================================================================


def test_provider_identity_fields():
    identity = ProviderIdentity(name="local_feed", network=False)
    assert identity.name == "local_feed"
    assert identity.network is False
    assert identity.schema_version == 1


def test_provider_lookup_result_valid_ok_with_verdict():
    result = _result(status=STATUS_OK, verdict=VERDICT_MALICIOUS)
    assert result.found is True


def test_provider_lookup_result_valid_not_found_with_no_verdict():
    result = _result(status=STATUS_NOT_FOUND, verdict=None)
    assert result.found is False


def test_provider_lookup_result_rejects_verdict_on_non_ok_status():
    # This is the structural enforcement of "never silently turn 'not
    # found' into safe" — a NOT_FOUND (or any non-OK) result may never
    # carry a verdict at all.
    try:
        _result(status=STATUS_NOT_FOUND, verdict=VERDICT_CLEAN)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "verdict must be None" in str(exc)


def test_provider_lookup_result_rejects_invalid_status():
    try:
        _result(status="not_a_real_status")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "invalid ProviderLookupResult.status" in str(exc)


def test_provider_lookup_result_rejects_invalid_verdict():
    try:
        _result(status=STATUS_OK, verdict="not_a_real_verdict")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "invalid ProviderLookupResult.verdict" in str(exc)


def test_provider_lookup_result_found_false_for_every_non_ok_status():
    for status in (STATUS_NOT_FOUND, STATUS_UNAVAILABLE, STATUS_ERROR, STATUS_RATE_LIMITED, STATUS_SKIPPED_PRIVATE):
        assert _result(status=status).found is False


# =========================================================================
# extract.py
# =========================================================================


def test_extract_indicators_from_text_finds_ip_domain_hash():
    text = (
        "Connection observed to 198.51.100.23 (bad-secure-test.example), "
        "file hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa flagged."
    )
    found = extract_module.extract_indicators_from_text(text)
    kinds = {kind for kind, _ in found}
    values = {value for _, value in found}
    assert indicators_module.IP in kinds
    assert indicators_module.DOMAIN in kinds
    assert indicators_module.HASH in kinds
    assert "198.51.100.23" in values
    assert "bad-secure-test.example" in values


def test_extract_indicators_from_text_deduplicates():
    text = "Seen 198.51.100.23 twice: 198.51.100.23 again."
    found = extract_module.extract_indicators_from_text(text)
    assert found.count((indicators_module.IP, "198.51.100.23")) == 1


def test_extract_indicators_from_text_empty_text_returns_empty():
    assert extract_module.extract_indicators_from_text("") == []
    assert extract_module.extract_indicators_from_text(None) == []


def test_extract_indicators_from_text_no_indicators_present():
    assert extract_module.extract_indicators_from_text("Nothing interesting here at all.") == []


def test_extract_indicators_from_text_version_like_string_not_treated_as_ip():
    # "7.0.3" is not a 4-octet IPv4 shape, so the IP regex won't even
    # match it; confirms no false positive slips through.
    found = extract_module.extract_indicators_from_text("Updated to version 7.0.3 today.")
    assert found == []


# =========================================================================
# storage/models/threatintel.py
# =========================================================================


def test_add_and_find_fresh_lookup_round_trip(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup, find_fresh_lookup

    with Database(tmp_path / "test.db") as db:
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="198.51.100.23", provider="local_feed",
            queried_at=datetime.now(timezone.utc).isoformat(), status=STATUS_OK, verdict=VERDICT_MALICIOUS,
            score=None, score_meaning=None, categories=("c2_server",), raw_response={"x": 1},
            source_query="test", expires_at=future, detail="matched",
        )
        found = find_fresh_lookup(db.conn, "ip", "198.51.100.23", "local_feed")
        assert found is not None
        assert found.verdict == VERDICT_MALICIOUS
        assert found.categories == ("c2_server",)
        assert found.raw_response == {"x": 1}


def test_find_fresh_lookup_returns_none_when_expired(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup, find_fresh_lookup

    with Database(tmp_path / "test.db") as db:
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="198.51.100.23", provider="local_feed",
            queried_at=datetime.now(timezone.utc).isoformat(), status=STATUS_OK, verdict=VERDICT_MALICIOUS,
            score=None, score_meaning=None, categories=(), raw_response=None,
            source_query="test", expires_at=past, detail="matched",
        )
        assert find_fresh_lookup(db.conn, "ip", "198.51.100.23", "local_feed") is None


def test_find_fresh_lookup_returns_none_when_never_cacheable(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup, find_fresh_lookup

    with Database(tmp_path / "test.db") as db:
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="198.51.100.23", provider="virustotal",
            queried_at=datetime.now(timezone.utc).isoformat(), status=STATUS_UNAVAILABLE, verdict=None,
            score=None, score_meaning=None, categories=(), raw_response=None,
            source_query="test", expires_at=None, detail="no api key",
        )
        assert find_fresh_lookup(db.conn, "ip", "198.51.100.23", "virustotal") is None


def test_list_threat_intel_lookups_filters(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup, list_threat_intel_lookups

    with Database(tmp_path / "test.db") as db:
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="1.1.1.1", provider="local_feed",
            queried_at="t", status=STATUS_NOT_FOUND, verdict=None, score=None, score_meaning=None,
            categories=(), raw_response=None, source_query="test", expires_at=None, detail="none",
        )
        add_threat_intel_lookup(
            db.conn, indicator_type="domain", indicator_value="example.com", provider="virustotal",
            queried_at="t", status=STATUS_UNAVAILABLE, verdict=None, score=None, score_meaning=None,
            categories=(), raw_response=None, source_query="test", expires_at=None, detail="none",
        )
        all_rows = list_threat_intel_lookups(db.conn)
        assert len(all_rows) == 2
        ip_only = list_threat_intel_lookups(db.conn, indicator_type="ip")
        assert len(ip_only) == 1 and ip_only[0].indicator_value == "1.1.1.1"
        provider_only = list_threat_intel_lookups(db.conn, provider="virustotal")
        assert len(provider_only) == 1 and provider_only[0].provider == "virustotal"


def test_find_latest_lookups_for_indicator_one_per_provider(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup, find_latest_lookups_for_indicator

    with Database(tmp_path / "test.db") as db:
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="1.1.1.1", provider="local_feed",
            queried_at="t1", status=STATUS_NOT_FOUND, verdict=None, score=None, score_meaning=None,
            categories=(), raw_response=None, source_query="test", expires_at=None, detail="first",
        )
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="1.1.1.1", provider="local_feed",
            queried_at="t2", status=STATUS_NOT_FOUND, verdict=None, score=None, score_meaning=None,
            categories=(), raw_response=None, source_query="test", expires_at=None, detail="second (latest)",
        )
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="1.1.1.1", provider="virustotal",
            queried_at="t3", status=STATUS_UNAVAILABLE, verdict=None, score=None, score_meaning=None,
            categories=(), raw_response=None, source_query="test", expires_at=None, detail="vt",
        )
        latest = find_latest_lookups_for_indicator(db.conn, "ip", "1.1.1.1")
        assert len(latest) == 2  # one per distinct provider
        by_provider = {r.provider: r for r in latest}
        assert by_provider["local_feed"].detail == "second (latest)"


def test_find_latest_lookups_for_indicator_empty_when_never_looked_up(tmp_path: Path):
    from secure.storage.models import find_latest_lookups_for_indicator

    with Database(tmp_path / "test.db") as db:
        assert find_latest_lookups_for_indicator(db.conn, "ip", "9.9.9.9") == []


def test_find_latest_lookup_ignores_freshness(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup, find_latest_lookup

    with Database(tmp_path / "test.db") as db:
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value="1.1.1.1", provider="local_feed",
            queried_at="t", status=STATUS_OK, verdict=VERDICT_SUSPICIOUS, score=None, score_meaning=None,
            categories=(), raw_response=None, source_query="test", expires_at=past, detail="stale but real",
        )
        record = find_latest_lookup(db.conn, "ip", "1.1.1.1", "local_feed")
        assert record is not None
        assert record.detail == "stale but real"


# =========================================================================
# providers/local_feed.py
# =========================================================================


def test_local_feed_provider_matches_ip(tmp_path: Path):
    cfg = _cfg_with_local_feed(tmp_path)
    provider = local_feed.build_provider(cfg.threat_intel_local_feed_dir_path())
    result = provider.lookup(indicators_module.IP, "198.51.100.23")
    assert result.status == STATUS_OK
    assert result.verdict == VERDICT_MALICIOUS
    assert result.categories == ("c2_server",)


def test_local_feed_provider_matches_domain_with_default_severity(tmp_path: Path):
    cfg = _cfg_with_local_feed(tmp_path)
    provider = local_feed.build_provider(cfg.threat_intel_local_feed_dir_path())
    result = provider.lookup(indicators_module.DOMAIN, "suspicious-secure-test.example")
    assert result.status == STATUS_OK
    assert result.verdict == VERDICT_SUSPICIOUS  # default when severity omitted


def test_local_feed_provider_matches_hash(tmp_path: Path):
    cfg = _cfg_with_local_feed(tmp_path)
    provider = local_feed.build_provider(cfg.threat_intel_local_feed_dir_path())
    result = provider.lookup(indicators_module.HASH, "a" * 64)
    assert result.status == STATUS_OK
    assert result.verdict == VERDICT_MALICIOUS


def test_local_feed_provider_not_found_never_becomes_clean(tmp_path: Path):
    cfg = _cfg_with_local_feed(tmp_path)
    provider = local_feed.build_provider(cfg.threat_intel_local_feed_dir_path())
    result = provider.lookup(indicators_module.IP, "1.2.3.4")
    assert result.status == STATUS_NOT_FOUND
    assert result.verdict is None
    assert result.found is False


def test_local_feed_provider_missing_files_are_routine_not_found(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    provider = local_feed.build_provider(cfg.threat_intel_local_feed_dir_path())  # dir doesn't exist at all
    result = provider.lookup(indicators_module.IP, "1.2.3.4")
    assert result.status == STATUS_NOT_FOUND


def test_local_feed_provider_malformed_line_skipped(tmp_path: Path):
    # ip_feed.txt fixture has a deliberately malformed ",bad_entry,malicious" line
    cfg = _cfg_with_local_feed(tmp_path)
    provider = local_feed.build_provider(cfg.threat_intel_local_feed_dir_path())
    result = provider.lookup(indicators_module.IP, "")
    assert result.status == STATUS_NOT_FOUND  # the blank "value" was never actually stored as a key


def test_local_feed_provider_never_makes_network_call():
    assert local_feed.IDENTITY.network is False


# =========================================================================
# providers/virustotal.py (mocked via providers._http.http_get_json)
# =========================================================================


def test_virustotal_provider_identity_is_network():
    assert virustotal.IDENTITY.network is True


def test_virustotal_provider_no_api_key_is_unavailable():
    provider = virustotal.build_provider("")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert result.status == STATUS_UNAVAILABLE
    assert result.verdict is None


def test_virustotal_provider_never_leaks_api_key_in_source_query(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, timeout=10.0):
        captured["headers"] = headers
        return http_module.HttpResult(ok=True, status_code=200, json={"data": {"attributes": {}}}, text="", error=None)

    monkeypatch.setattr(virustotal, "http_get_json", fake_get)
    provider = virustotal.build_provider("super-secret-key-12345")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert "super-secret-key-12345" not in result.source_query
    assert "super-secret-key-12345" not in result.detail
    assert captured["headers"]["x-apikey"] == "super-secret-key-12345"


def test_virustotal_provider_404_is_not_found(monkeypatch):
    monkeypatch.setattr(
        virustotal, "http_get_json",
        lambda url, headers=None, timeout=10.0: http_module.HttpResult(ok=False, status_code=404, json=None, text="", error="HTTP 404"),
    )
    provider = virustotal.build_provider("key")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert result.status == STATUS_NOT_FOUND
    assert result.verdict is None


def test_virustotal_provider_429_is_rate_limited(monkeypatch):
    monkeypatch.setattr(
        virustotal, "http_get_json",
        lambda url, headers=None, timeout=10.0: http_module.HttpResult(ok=False, status_code=429, json=None, text="", error="HTTP 429"),
    )
    provider = virustotal.build_provider("key")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert result.status == STATUS_RATE_LIMITED


def test_virustotal_provider_network_failure_is_error(monkeypatch):
    monkeypatch.setattr(
        virustotal, "http_get_json",
        lambda url, headers=None, timeout=10.0: http_module.HttpResult(ok=False, status_code=None, json=None, text="", error="connection refused"),
    )
    provider = virustotal.build_provider("key")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert result.status == STATUS_ERROR


def test_virustotal_provider_malicious_verdict_translation(monkeypatch):
    payload = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 4}, "tags": ["c2"]}}
    }
    monkeypatch.setattr(
        virustotal, "http_get_json",
        lambda url, headers=None, timeout=10.0: http_module.HttpResult(ok=True, status_code=200, json=payload, text="", error=None),
    )
    provider = virustotal.build_provider("key")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert result.status == STATUS_OK
    assert result.verdict == VERDICT_MALICIOUS
    assert result.score == 5.0
    assert result.categories == ("c2",)


def test_virustotal_provider_clean_verdict_translation(monkeypatch):
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 0}}}}
    monkeypatch.setattr(
        virustotal, "http_get_json",
        lambda url, headers=None, timeout=10.0: http_module.HttpResult(ok=True, status_code=200, json=payload, text="", error=None),
    )
    provider = virustotal.build_provider("key")
    result = provider.lookup(indicators_module.IP, REAL_PUBLIC_IP)
    assert result.status == STATUS_OK
    assert result.verdict == VERDICT_CLEAN


def test_virustotal_provider_unsupported_indicator_type_is_error():
    provider = virustotal.build_provider("key")
    result = provider.lookup("not_a_real_type", "value")
    assert result.status == STATUS_ERROR


# =========================================================================
# registry.py
# =========================================================================


def test_build_providers_returns_local_feed_and_virustotal(tmp_path: Path):
    cfg = _cfg_with_local_feed(tmp_path, api_key="k")
    providers = registry_module.build_providers(cfg)
    names = {p.identity.name for p in providers}
    assert names == {"local_feed", "virustotal"}


# =========================================================================
# enrich.py — orchestration, caching, privacy skip
# =========================================================================


class _FakeProvider:
    def __init__(self, identity, result_fn):
        self.identity = identity
        self._result_fn = result_fn
        self.call_count = 0

    def lookup(self, indicator_type, indicator_value):
        self.call_count += 1
        return self._result_fn(indicator_type, indicator_value)


def test_enrich_indicator_never_turns_not_found_into_clean(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    fake = _FakeProvider(
        ProviderIdentity(name="fake", network=False),
        lambda t, v: _result(indicator_type=t, indicator_value=v, provider="fake", status=STATUS_NOT_FOUND, verdict=None),
    )
    with Database(tmp_path / "test.db") as db:
        result = enrich_module.enrich_indicator(db.conn, cfg, "ip", "1.2.3.4", providers=[fake])
    assert len(result.lookups) == 1
    assert result.lookups[0].result.status == STATUS_NOT_FOUND
    assert result.lookups[0].result.verdict is None
    assert result.any_malicious is False
    assert result.any_suspicious is False


def test_enrich_indicator_second_call_uses_cache(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    fake = _FakeProvider(
        ProviderIdentity(name="fake", network=False),
        lambda t, v: _result(indicator_type=t, indicator_value=v, provider="fake", status=STATUS_OK, verdict=VERDICT_MALICIOUS),
    )
    with Database(tmp_path / "test.db") as db:
        first = enrich_module.enrich_indicator(db.conn, cfg, "ip", "1.2.3.4", providers=[fake])
        second = enrich_module.enrich_indicator(db.conn, cfg, "ip", "1.2.3.4", providers=[fake])
    assert first.lookups[0].from_cache is False
    assert second.lookups[0].from_cache is True
    assert fake.call_count == 1  # the provider's own .lookup() was only really called once


def test_enrich_indicator_skips_private_ip_for_network_provider(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    network_fake = _FakeProvider(
        ProviderIdentity(name="network_fake", network=True),
        lambda t, v: _result(indicator_type=t, indicator_value=v, provider="network_fake", status=STATUS_OK, verdict=VERDICT_MALICIOUS),
    )
    with Database(tmp_path / "test.db") as db:
        result = enrich_module.enrich_indicator(db.conn, cfg, "ip", "10.0.0.5", providers=[network_fake])
    assert result.lookups[0].result.status == STATUS_SKIPPED_PRIVATE
    assert network_fake.call_count == 0  # .lookup() must never even be called


def test_enrich_indicator_local_provider_still_runs_for_private_ip(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    local_fake = _FakeProvider(
        ProviderIdentity(name="local_fake", network=False),
        lambda t, v: _result(indicator_type=t, indicator_value=v, provider="local_fake", status=STATUS_NOT_FOUND, verdict=None),
    )
    with Database(tmp_path / "test.db") as db:
        result = enrich_module.enrich_indicator(db.conn, cfg, "ip", "10.0.0.5", providers=[local_fake])
    assert local_fake.call_count == 1
    assert result.lookups[0].result.status == STATUS_NOT_FOUND


def test_enrich_indicator_transient_failures_are_never_cached_long(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    fake = _FakeProvider(
        ProviderIdentity(name="fake", network=False),
        lambda t, v: _result(indicator_type=t, indicator_value=v, provider="fake", status=STATUS_ERROR, verdict=None),
    )
    with Database(tmp_path / "test.db") as db:
        first = enrich_module.enrich_indicator(db.conn, cfg, "ip", "1.2.3.4", providers=[fake])
        second = enrich_module.enrich_indicator(db.conn, cfg, "ip", "1.2.3.4", providers=[fake])
    assert first.lookups[0].result.expires_at is None
    assert second.lookups[0].from_cache is False  # retried, not treated as a valid cache hit
    assert fake.call_count == 2


def test_enrich_indicator_any_malicious_and_any_suspicious():
    result_malicious = enrich_module.EnrichmentResult(
        indicator_type="ip", indicator_value="1.2.3.4",
        lookups=(enrich_module.EnrichedLookup(result=_result(status=STATUS_OK, verdict=VERDICT_MALICIOUS), from_cache=False),),
    )
    assert result_malicious.any_malicious is True
    assert result_malicious.any_suspicious is False

    result_suspicious = enrich_module.EnrichmentResult(
        indicator_type="ip", indicator_value="1.2.3.4",
        lookups=(enrich_module.EnrichedLookup(result=_result(status=STATUS_OK, verdict=VERDICT_SUSPICIOUS), from_cache=False),),
    )
    assert result_suspicious.any_suspicious is True


# =========================================================================
# enrich.py — attach_cached_threat_intel (explain wiring, cache-only)
# =========================================================================


def _blank_explanation(summary="A finding.") -> Explanation:
    return Explanation(
        summary=summary, severity="medium", confidence=vocab.INSUFFICIENT_EVIDENCE,
        confidence_reason="test", significance="test", recommended_action="classify",
        recommended_action_text="test", evidence=(), correlated_events=(),
        uncertainty_status="insufficient_information", uncertainty=(),
    )


def test_attach_cached_threat_intel_no_candidates_returns_unchanged(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        exp = _blank_explanation(summary="Nothing indicator-shaped here.")
        result = enrich_module.attach_cached_threat_intel(db.conn, exp, "Nothing indicator-shaped here.")
    assert result is exp


def test_attach_cached_threat_intel_honest_not_yet_checked(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        exp = _blank_explanation()
        text = f"Possible beacon to {REAL_PUBLIC_IP}."
        result = enrich_module.attach_cached_threat_intel(db.conn, exp, text)
    assert len(result.evidence) == 1
    assert "No threat-intelligence lookup has been performed yet" in result.evidence[0].text
    assert REAL_PUBLIC_IP in result.evidence[0].text
    assert result.evidence[0].provenance == vocab.DERIVED_FACT


def test_attach_cached_threat_intel_shows_cached_result(tmp_path: Path):
    from secure.storage.models import add_threat_intel_lookup

    with Database(tmp_path / "test.db") as db:
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        add_threat_intel_lookup(
            db.conn, indicator_type="ip", indicator_value=REAL_PUBLIC_IP, provider="local_feed",
            queried_at=datetime.now(timezone.utc).isoformat(), status=STATUS_OK, verdict=VERDICT_MALICIOUS,
            score=None, score_meaning=None, categories=("c2_server",), raw_response=None,
            source_query="test", expires_at=future, detail="matched",
        )
        exp = _blank_explanation()
        result = enrich_module.attach_cached_threat_intel(db.conn, exp, f"Possible beacon to {REAL_PUBLIC_IP}.")
    assert len(result.evidence) == 1
    assert "verdict malicious" in result.evidence[0].text
    assert result.evidence[0].provenance == vocab.DIRECT_OBSERVATION


def test_attach_cached_threat_intel_original_explanation_never_mutated(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        exp = _blank_explanation()
        original_evidence = exp.evidence
        enrich_module.attach_cached_threat_intel(db.conn, exp, f"Beacon to {REAL_PUBLIC_IP}.")
    assert exp.evidence == original_evidence  # the original object is untouched


def test_attach_cached_threat_intel_bounded_to_max_indicators(tmp_path: Path):
    ips = [f"8.8.8.{n}" for n in range(1, 8)]  # 7 candidates, all real-looking public IPs
    text = "Contacted " + ", ".join(ips) + "."
    with Database(tmp_path / "test.db") as db:
        exp = _blank_explanation()
        result = enrich_module.attach_cached_threat_intel(db.conn, exp, text)
    assert len(result.evidence) == enrich_module.MAX_INDICATORS_PER_EXPLANATION


# =========================================================================
# CLI: secure threatintel lookup|history|providers
# =========================================================================


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path, api_key: str = ""):
    cfg = _cfg_with_local_feed(tmp_path, api_key=api_key)
    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    return cfg


def test_cli_threatintel_providers_lists_both(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_providers, _ns())
    assert rc == 0
    assert "local_feed" in stdout
    assert "virustotal" in stdout


def test_cli_threatintel_lookup_explicit_type(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_lookup, _ns(type="ip", value="198.51.100.23"))
    assert rc == 1  # local feed match is malicious -> non-zero
    assert "local_feed" in stdout
    assert "MALICIOUS" in stdout.upper()


def test_cli_threatintel_lookup_auto_detects_type(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_lookup, _ns(type="auto", value="198.51.100.23"))
    assert "Detected indicator type: ip" in stdout


def test_cli_threatintel_lookup_auto_unclassifiable_fails_cleanly(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_lookup, _ns(type="auto", value="not-an-indicator!!"))
    assert rc == 1
    assert "Could not classify" in stdout


def test_cli_threatintel_lookup_clean_indicator_returns_zero(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_lookup, _ns(type="ip", value="9.9.9.9"))
    assert rc == 0  # NOT_FOUND from local feed, UNAVAILABLE from virustotal (no key) -> no malicious/suspicious verdict
    assert "NOT_FOUND" in stdout.upper()


def test_cli_threatintel_history_empty(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_history, _ns(type=None, value=None, provider=None, limit=50))
    assert rc == 0
    assert "No threat-intelligence lookups recorded yet" in stdout


def test_cli_threatintel_history_after_lookup(monkeypatch, tmp_path: Path):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    _run_capturing_stdout(cli.cmd_threatintel_lookup, _ns(type="ip", value="198.51.100.23"))
    rc, stdout = _run_capturing_stdout(cli.cmd_threatintel_history, _ns(type=None, value=None, provider=None, limit=50))
    assert rc == 0
    assert "198.51.100.23" in stdout
    assert "local_feed" in stdout


# =========================================================================
# End-to-end: secure explain wiring (cache-only enrichment attached to a
# real alert's explanation)
# =========================================================================


def test_cmd_explain_attaches_cached_threat_intel(monkeypatch, tmp_path: Path):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        alert_id = add_arp_alert(
            db.conn, run_id="run1", kind="new_mapping", severity="medium", ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff",
            previous_mac=None, message=f"New ARP mapping observed, possible related lookup to {REAL_PUBLIC_IP}",
        )
        db.conn.commit()

    rc, stdout = _run_capturing_stdout(cli.cmd_explain, _ns(source="arpwatch", alert_id=alert_id))
    assert rc == 0
    assert "No threat-intelligence lookup has been performed yet" in stdout
    assert REAL_PUBLIC_IP in stdout


def test_cmd_explain_shows_prior_lookup_result(monkeypatch, tmp_path: Path):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        alert_id = add_arp_alert(
            db.conn, run_id="run1", kind="new_mapping", severity="medium", ip="198.51.100.23", mac="aa:bb:cc:dd:ee:ff",
            previous_mac=None, message="New ARP mapping observed, related lookup to 198.51.100.23",
        )
        db.conn.commit()

    # First, explicitly look the indicator up (the ONLY path that may do so).
    _run_capturing_stdout(cli.cmd_threatintel_lookup, _ns(type="ip", value="198.51.100.23"))

    # Now explain should show the CACHED result without making any new call.
    rc, stdout = _run_capturing_stdout(cli.cmd_explain, _ns(source="arpwatch", alert_id=alert_id))
    assert rc == 0
    assert "verdict malicious" in stdout
    assert "No threat-intelligence lookup has been performed yet" not in stdout
