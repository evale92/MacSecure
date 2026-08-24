"""
Tests for secure/investigate/entity.py (Phase 23 Stage 1: the EntityRef
vocabulary). Pure, no I/O.

Run with:  pytest
"""

from __future__ import annotations

from secure.baseline.entities import ENTITY_TYPES as BASELINE_ENTITY_TYPES
from secure.investigate.entity import (
    DESTINATION,
    ENTITY_TYPES,
    FILE,
    INDICATOR,
    INVESTIGATE_ONLY_ENTITY_TYPES,
    EntityRef,
    destination_key,
    file_key,
    indicator_key,
    indicator_ref_for_value,
    process_destination_key,
)


def test_entity_types_include_every_baseline_type_unchanged():
    for t in BASELINE_ENTITY_TYPES:
        assert t in ENTITY_TYPES


def test_entity_types_include_investigate_only_types():
    assert DESTINATION in ENTITY_TYPES
    assert FILE in ENTITY_TYPES
    assert INDICATOR in ENTITY_TYPES
    assert set(INVESTIGATE_ONLY_ENTITY_TYPES) == {DESTINATION, FILE, INDICATOR}


def test_entity_ref_rejects_unknown_type():
    try:
        EntityRef(entity_type="not_a_real_type", entity_key="x")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_entity_ref_rejects_empty_key():
    try:
        EntityRef(entity_type=DESTINATION, entity_key="")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_entity_ref_equality_is_field_equality():
    a = EntityRef(entity_type=DESTINATION, entity_key="203.0.113.5:443/tcp")
    b = EntityRef(entity_type=DESTINATION, entity_key="203.0.113.5:443/tcp")
    c = EntityRef(entity_type=DESTINATION, entity_key="203.0.113.6:443/tcp")
    assert a == b
    assert a != c


def test_destination_key_excludes_process_name():
    # Deliberately different from baseline's process_destination_key —
    # a DESTINATION entity is process-agnostic.
    key = destination_key("203.0.113.5", 443, "tcp")
    assert "203.0.113.5" in key
    assert "443" in key
    assert "tcp" in key
    # process_destination_key's own format includes "::" before the address
    pd_key = process_destination_key("curl", "203.0.113.5", 443, "tcp")
    assert key != pd_key
    assert pd_key.endswith(key)  # pd_key is "curl::" + destination_key


def test_file_key_is_the_bare_path():
    assert file_key("/etc/hosts") == "/etc/hosts"


def test_indicator_key_reuses_threatintel_normalization():
    # An IP should normalize the same way normalize_indicator() does.
    key = indicator_key("ip", "8.8.8.8")
    assert key == "ip:8.8.8.8"
    # A hash/domain should lowercase, matching normalize_indicator()'s own rule.
    key2 = indicator_key("domain", "Example.COM")
    assert key2 == "domain:example.com"


def test_indicator_ref_for_value_classifies_correctly():
    ip_ref = indicator_ref_for_value("8.8.8.8")
    assert ip_ref is not None
    assert ip_ref.entity_type == INDICATOR
    assert ip_ref.entity_key == "ip:8.8.8.8"

    hash_ref = indicator_ref_for_value("a" * 64)  # sha256-shaped
    assert hash_ref is not None
    assert hash_ref.entity_key.startswith("hash:")


def test_indicator_ref_for_value_returns_none_for_unusable_string():
    assert indicator_ref_for_value("not an indicator at all!!") is None
    assert indicator_ref_for_value("") is None


def test_str_representation():
    ref = EntityRef(entity_type=FILE, entity_key="/etc/hosts")
    assert str(ref) == "file:/etc/hosts"
