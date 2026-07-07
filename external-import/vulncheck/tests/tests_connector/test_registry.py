"""Tests for the data-source registry (replaces the old DataSource enum)."""

from unittest.mock import MagicMock

import pytest
from connector.sources import names, registry


def test_all_sources_registered():
    expected = {
        names.BOTNETS,
        names.EPSS,
        names.EXPLOITS,
        names.INITIAL_ACCESS,
        names.IPINTEL,
        names.NIST_NVD2,
        names.RANSOMWARE,
        names.SNORT,
        names.SURICATA,
        names.THREAT_ACTORS,
        names.VULNCHECK_KEV,
        names.VULNCHECK_NVD2,
    }
    assert set(registry.SOURCES) == expected


def test_resolve_returns_specs_with_api_prefix():
    by_name = {s.name: s for s in registry.resolve([names.BOTNETS, names.SNORT])}
    assert by_name[names.BOTNETS].api_prefix == names.INDEX_URL_PREFIX
    assert by_name[names.SNORT].api_prefix == names.RULES_URL_PREFIX
    assert callable(by_name[names.BOTNETS].collect)


def test_resolve_unknown_name_raises():
    with pytest.raises(ValueError, match="Unknown Data Source name: bogus"):
        registry.resolve(["bogus"])


def test_resolve_prefers_vulncheck_nvd2_over_nist():
    logger = MagicMock()
    specs = registry.resolve(
        [names.VULNCHECK_NVD2, names.NIST_NVD2, names.BOTNETS], logger
    )
    resolved = [s.name for s in specs]
    assert names.NIST_NVD2 not in resolved
    assert names.VULNCHECK_NVD2 in resolved
    assert names.BOTNETS in resolved
    logger.warning.assert_called_once()


def test_resolve_keeps_nist_when_vulncheck_nvd2_absent():
    specs = registry.resolve([names.NIST_NVD2, names.BOTNETS])
    assert names.NIST_NVD2 in [s.name for s in specs]
