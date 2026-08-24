"""
Tests for secure/baseline/time_buckets.py. No I/O.

Run with:  pytest
"""

from __future__ import annotations

from secure.baseline import time_buckets


def test_bucket_for_hour_covers_all_24_hours():
    for hour in range(24):
        bucket = time_buckets.bucket_for_hour(hour)
        assert bucket in ("night", "morning", "afternoon", "evening")


def test_bucket_for_hour_boundaries():
    assert time_buckets.bucket_for_hour(0) == "night"
    assert time_buckets.bucket_for_hour(5) == "night"
    assert time_buckets.bucket_for_hour(6) == "morning"
    assert time_buckets.bucket_for_hour(11) == "morning"
    assert time_buckets.bucket_for_hour(12) == "afternoon"
    assert time_buckets.bucket_for_hour(17) == "afternoon"
    assert time_buckets.bucket_for_hour(18) == "evening"
    assert time_buckets.bucket_for_hour(23) == "evening"


def test_is_weekend():
    assert time_buckets.is_weekend(5) is True  # Saturday
    assert time_buckets.is_weekend(6) is True  # Sunday
    assert time_buckets.is_weekend(0) is False  # Monday
    assert time_buckets.is_weekend(4) is False  # Friday


def test_classify_returns_bucket_and_weekend_flag():
    # 2026-08-19 is a Wednesday.
    bucket, weekend = time_buckets.classify("2026-08-19T14:00:00+00:00")
    assert weekend is False
    assert bucket in ("night", "morning", "afternoon", "evening")


def test_classify_handles_naive_timestamp():
    bucket, _ = time_buckets.classify("2026-08-19T14:00:00")
    assert bucket in ("night", "morning", "afternoon", "evening")
