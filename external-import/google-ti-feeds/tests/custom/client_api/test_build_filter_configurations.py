"""Tests for the extra_filters feature in _build_filter_configurations.

Covers the extra_filters parameter added to BaseClientAPI._build_filter_configurations
and the subclass wiring that reads extra_filters from config when not explicitly passed.
"""

import logging
from unittest.mock import MagicMock

import pytest
from connector.src.custom.client_api.client_api_base import BaseClientAPI
from connector.src.custom.client_api.report.client_api_report import ClientAPIReport


@pytest.fixture
def base_client():
    """Create a BaseClientAPI instance with mocked dependencies."""
    config = MagicMock()
    logger = logging.getLogger("test")
    api_client = MagicMock()
    fetcher_factory = MagicMock()
    return BaseClientAPI(
        config=config,
        logger=logger,
        api_client=api_client,
        fetcher_factory=fetcher_factory,
    )


@pytest.fixture
def report_client():
    """Create a ClientAPIReport instance with mocked dependencies."""
    config = MagicMock()
    config.report_types = ["All"]
    config.report_origins = ["All"]
    config.report_extra_filters = []
    logger = logging.getLogger("test")
    api_client = MagicMock()
    fetcher_factory = MagicMock()
    return ClientAPIReport(
        config=config,
        logger=logger,
        api_client=api_client,
        fetcher_factory=fetcher_factory,
    )


class TestBaseExtraFiltersAppending:
    """Test extra_filters appending in BaseClientAPI._build_filter_configurations."""

    def test_extra_filters_appended_to_query(self, base_client):
        """Extra filters are appended after base and type/origin filters."""
        configs = base_client._build_filter_configurations(
            collection_type="report",
            start_date="2026-01-01T00:00:00",
            types=["Actor Profile"],
            origins=["partner"],
            extra_filters=["name:CVE-2024", "cvss_3x_base_score:4+"],
        )
        filter_str = configs[0]["params"]["filter"]
        assert "name:CVE-2024" in filter_str
        assert "cvss_3x_base_score:4+" in filter_str
        # Extra filters come after type/origin filters
        assert filter_str.index("origin:'partner'") < filter_str.index("name:CVE-2024")

    def test_extra_filters_applied_to_all_cartesian_configs(self, base_client):
        """Extra filters appear in every config of the cartesian product."""
        configs = base_client._build_filter_configurations(
            collection_type="report",
            start_date="2026-01-01T00:00:00",
            types=["Actor Profile", "Malware Profile"],
            origins=["partner"],
            extra_filters=["name:phishing"],
        )
        assert len(configs) == 2
        for config in configs:
            assert "name:phishing" in config["params"]["filter"]


class TestSubclassExtraFiltersWiring:
    """Test that subclasses read extra_filters from config and pass them through."""

    def test_report_reads_extra_filters_from_config(self, report_client):
        """ClientAPIReport uses config.report_extra_filters when not explicitly passed."""
        report_client.config.report_extra_filters = ["name:phishing"]
        configs = report_client._build_filter_configurations(
            collection_type="report",
            start_date="2026-01-01T00:00:00",
        )
        assert "name:phishing" in configs[0]["params"]["filter"]

    def test_report_explicit_extra_filters_overrides_config(self, report_client):
        """Explicit extra_filters argument takes precedence over config."""
        report_client.config.report_extra_filters = ["name:should_not_appear"]
        configs = report_client._build_filter_configurations(
            collection_type="report",
            start_date="2026-01-01T00:00:00",
            extra_filters=["name:explicit"],
        )
        assert "name:explicit" in configs[0]["params"]["filter"]
        assert "name:should_not_appear" not in configs[0]["params"]["filter"]
