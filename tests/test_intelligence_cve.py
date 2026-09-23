"""Tests for CVE integrator (Phase 50.1)."""

import json
import tempfile
from pathlib import Path

from secure.intelligence.cve_integrator import CveIntegrator
from secure.intelligence.models import (
    MATCH_EXACT, MATCH_RANGE, MATCH_PRODUCT_ONLY, MATCH_NONE
)


def test_integrator_uninitialized_when_no_path():
    """Integrator is inert when given no path."""
    integrator = CveIntegrator()
    assert integrator.available is False
    assert len(integrator.match_finding("f1", "type1", "product", "1.0")) == 0


def test_integrator_loads_database():
    """Integrator loads CVE database from JSON."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-001",
                "product": "OpenSSL",
                "affected_versions": ["1.1.1", "1.1.2"],
                "cvss": {
                    "version": "3.1",
                    "base_score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "critical",
                },
                "published": "2024-01-15",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        assert integrator.available is True
        assert "CVE-2024-001" in integrator.cves
    finally:
        Path(db_path).unlink()


def test_match_exact_version():
    """Exact version match returns MATCH_EXACT."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-001",
                "product": "OpenSSL",
                "affected_versions": ["1.1.1"],
                "cvss": {
                    "version": "3.1",
                    "base_score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "critical",
                },
                "published": "2024-01-15",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "OpenSSL", "1.1.1")
        assert len(matches) == 1
        assert matches[0].cve_id == "CVE-2024-001"
        assert matches[0].match_type == MATCH_EXACT
        assert matches[0].cvss.severity == "critical"
    finally:
        Path(db_path).unlink()


def test_match_version_range():
    """Version in range returns MATCH_RANGE."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-002",
                "product": "Apache",
                "affected_versions": [{"min": "2.4.0", "max": "2.4.10"}],
                "cvss": {
                    "version": "3.1",
                    "base_score": 7.5,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "severity": "high",
                },
                "published": "2024-02-01",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "Apache", "2.4.5")
        assert len(matches) == 1
        assert matches[0].match_type == MATCH_RANGE
        assert matches[0].cvss.base_score == 7.5
    finally:
        Path(db_path).unlink()


def test_match_product_only():
    """Product match with no version returns MATCH_PRODUCT_ONLY."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-003",
                "product": "NodeJS",
                "affected_versions": ["16.0.0", "17.0.0"],
                "cvss": {
                    "version": "3.1",
                    "base_score": 8.0,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    "severity": "high",
                },
                "published": "2024-03-10",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "NodeJS", "")
        assert len(matches) == 1
        assert matches[0].match_type == MATCH_PRODUCT_ONLY
    finally:
        Path(db_path).unlink()


def test_no_match_different_product():
    """Different product yields no matches."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-001",
                "product": "OpenSSL",
                "affected_versions": ["1.1.1"],
                "published": "2024-01-15",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "Apache", "2.4.0")
        assert len(matches) == 0
    finally:
        Path(db_path).unlink()


def test_no_match_version_outside_range():
    """Version outside range yields no matches."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-002",
                "product": "Apache",
                "affected_versions": [{"min": "2.4.0", "max": "2.4.10"}],
                "published": "2024-02-01",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "Apache", "2.4.20")
        assert len(matches) == 0
    finally:
        Path(db_path).unlink()


def test_cvss_none_when_absent():
    """CVSS is None when source published no score."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-004",
                "product": "Unknown",
                "affected_versions": ["1.0"],
                "published": "2024-04-01",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "Unknown", "1.0")
        assert len(matches) == 1
        assert matches[0].cvss is None
    finally:
        Path(db_path).unlink()


def test_unparseable_version_ignored():
    """Unparseable version strings in database don't crash, just don't match."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-005",
                "product": "Product",
                "affected_versions": ["v1.alpha", "2.0"],
                "published": "2024-05-01",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "Product", "v1.alpha")
        assert len(matches) == 0
    finally:
        Path(db_path).unlink()


def test_case_insensitive_product_match():
    """Product matching is case-insensitive."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-006",
                "product": "OpenSSL",
                "affected_versions": ["1.0"],
                "published": "2024-06-01",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "openssl", "1.0")
        assert len(matches) == 1
    finally:
        Path(db_path).unlink()


def test_multiple_cves_same_product():
    """Multiple CVEs for same product all returned."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-001",
                "product": "Apache",
                "affected_versions": ["2.4.0"],
                "cvss": {"version": "3.1", "base_score": 7.0, "vector": "", "severity": "high"},
                "published": "2024-01-01",
            },
            {
                "cve_id": "CVE-2024-002",
                "product": "Apache",
                "affected_versions": ["2.4.0"],
                "cvss": {"version": "3.1", "base_score": 8.0, "vector": "", "severity": "high"},
                "published": "2024-02-01",
            },
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("f1", "type1", "Apache", "2.4.0")
        assert len(matches) == 2
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2024-001" in cve_ids
        assert "CVE-2024-002" in cve_ids
    finally:
        Path(db_path).unlink()


def test_finding_metadata_preserved():
    """Finding ID and type are preserved in match."""
    db_content = {
        "cves": [
            {
                "cve_id": "CVE-2024-001",
                "product": "OpenSSL",
                "affected_versions": ["1.0"],
                "published": "2024-01-01",
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(db_content, f)
        db_path = f.name

    try:
        integrator = CveIntegrator(db_path)
        matches = integrator.match_finding("finding_xyz", "persistence.unsigned", "OpenSSL", "1.0")
        assert len(matches) == 1
        assert matches[0].finding_id == "finding_xyz"
        assert matches[0].finding_type == "persistence.unsigned"
    finally:
        Path(db_path).unlink()
