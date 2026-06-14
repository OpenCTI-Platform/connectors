"""Tests for ClientAPISoftwareToolkit: _build_filter_configurations, _build_log_message, fetch_software_toolkits."""

import logging
from unittest.mock import MagicMock

import pytest
from connector.src.custom.client_api.software_toolkit.client_api_software_toolkit import (
    ClientAPISoftwareToolkit,
)

# =====================
# Fixtures
# =====================


@pytest.fixture
def software_toolkit_client():
    """Create a ClientAPISoftwareToolkit instance with mocked dependencies."""
    config = MagicMock()
    config.software_toolkit_origins = ["google threat intelligence"]
    config.software_toolkit_extra_filters = []
    config.software_toolkit_import_start_date = MagicMock()
    config.api_url.unicode_string.return_value = "https://fake-gti.api"
    logger = logging.getLogger("test_software_toolkit")
    api_client = MagicMock()
    fetcher_factory = MagicMock()
    return ClientAPISoftwareToolkit(
        config=config,
        logger=logger,
        api_client=api_client,
        fetcher_factory=fetcher_factory,
    )


# =====================
# _build_filter_configurations tests
# =====================


class TestBuildFilterConfigurations:
    """Tests for ClientAPISoftwareToolkit._build_filter_configurations."""

    def test_given_default_origins_when_build_filter_configs_then_uses_config_origins(
        self, software_toolkit_client
    ):
        """When origins not passed, reads software_toolkit_origins from config."""
        software_toolkit_client.config.software_toolkit_origins = ["custom-origin"]
        configs = software_toolkit_client._build_filter_configurations(
            collection_type="software-toolkit",
            start_date="2024-01-01T00:00:00",
        )
        assert len(configs) >= 1
        assert any(
            "custom-origin" in cfg.get("params", {}).get("filter", "")
            for cfg in configs
        )

    def test_given_explicit_origins_when_build_filter_configs_then_uses_explicit_origins(
        self, software_toolkit_client
    ):
        """When origins explicitly passed, uses them instead of config."""
        software_toolkit_client.config.software_toolkit_origins = ["should-not-appear"]
        configs = software_toolkit_client._build_filter_configurations(
            collection_type="software-toolkit",
            start_date="2024-01-01T00:00:00",
            origins=["explicit-origin"],
        )
        assert any(
            "explicit-origin" in cfg.get("params", {}).get("filter", "")
            for cfg in configs
        )
        for cfg in configs:
            assert "should-not-appear" not in cfg.get("params", {}).get("filter", "")

    def test_given_extra_filters_from_config_when_build_filter_configs_then_included(
        self, software_toolkit_client
    ):
        """Reads software_toolkit_extra_filters from config when not explicitly passed."""
        software_toolkit_client.config.software_toolkit_extra_filters = [
            "name:some-filter"
        ]
        configs = software_toolkit_client._build_filter_configurations(
            collection_type="software-toolkit",
            start_date="2024-01-01T00:00:00",
        )
        assert any(
            "name:some-filter" in cfg.get("params", {}).get("filter", "")
            for cfg in configs
        )

    def test_given_super_raises_when_build_filter_configs_then_returns_fallback(
        self, software_toolkit_client, monkeypatch
    ):
        """When super()._build_filter_configurations raises, returns fallback config."""
        from connector.src.custom.client_api.client_api_base import BaseClientAPI

        def _raise(*args, **kwargs):
            raise RuntimeError("simulated failure")

        monkeypatch.setattr(
            BaseClientAPI, "_build_filter_configurations", _raise, raising=True
        )
        configs = software_toolkit_client._build_filter_configurations(
            collection_type="software-toolkit",
            start_date="2024-01-01T00:00:00",
        )
        assert len(configs) == 1
        assert configs[0]["description"] == "fallback all software_toolkits"
        assert "collection_type:software-toolkit" in configs[0]["params"]["filter"]

    def test_given_super_raises_with_initial_state_when_build_filter_configs_then_fallback_uses_cursor(
        self, software_toolkit_client, monkeypatch
    ):
        """Fallback config includes cursor from initial_state when super raises."""
        from connector.src.custom.client_api.client_api_base import BaseClientAPI

        def _raise(*args, **kwargs):
            raise RuntimeError("simulated failure")

        monkeypatch.setattr(
            BaseClientAPI, "_build_filter_configurations", _raise, raising=True
        )
        configs = software_toolkit_client._build_filter_configurations(
            collection_type="software-toolkit",
            start_date="2024-01-01T00:00:00",
            initial_state={"cursor": "abc123xyz"},
        )
        assert configs[0]["cursor"] == "abc123xyz"

    def test_given_super_raises_without_initial_state_when_build_filter_configs_then_cursor_is_none(
        self, software_toolkit_client, monkeypatch
    ):
        """Fallback config has None cursor when no initial_state and super raises."""
        from connector.src.custom.client_api.client_api_base import BaseClientAPI

        def _raise(*args, **kwargs):
            raise RuntimeError("simulated failure")

        monkeypatch.setattr(
            BaseClientAPI, "_build_filter_configurations", _raise, raising=True
        )
        configs = software_toolkit_client._build_filter_configurations(
            collection_type="software-toolkit",
            start_date="2024-01-01T00:00:00",
            initial_state=None,
        )
        assert configs[0]["cursor"] is None


# =====================
# _build_log_message tests
# =====================


class TestBuildLogMessage:
    """Tests for ClientAPISoftwareToolkit._build_log_message."""

    def test_given_software_toolkits_with_total_when_build_log_message_then_updates_real_total(
        self, software_toolkit_client
    ):
        """When entity_description is 'software_toolkits' and total_items given, updates real_total."""
        software_toolkit_client._build_log_message(
            data_count=5,
            entity_description="software_toolkits",
            page_nb=1,
            total_pages=None,
            total_items=42,
            cursor=None,
        )
        assert software_toolkit_client.real_total_software_toolkits == 42

    def test_given_other_entity_description_when_build_log_message_then_does_not_update_real_total(
        self, software_toolkit_client
    ):
        """When entity_description is not 'software_toolkits', real_total is not updated."""
        software_toolkit_client.real_total_software_toolkits = 0
        software_toolkit_client._build_log_message(
            data_count=3,
            entity_description="other_entities",
            page_nb=1,
            total_pages=None,
            total_items=99,
            cursor=None,
        )
        assert software_toolkit_client.real_total_software_toolkits == 0

    def test_given_cursor_when_build_log_message_then_includes_cursor_info(
        self, software_toolkit_client
    ):
        """When cursor is provided, log message includes cursor prefix."""
        msg = software_toolkit_client._build_log_message(
            data_count=5,
            entity_description="software_toolkits",
            page_nb=1,
            total_pages=None,
            total_items=None,
            cursor="abcdef1234",
        )
        assert "(cursor: abcdef...)" in msg

    def test_given_no_cursor_when_build_log_message_then_no_cursor_info(
        self, software_toolkit_client
    ):
        """When no cursor, log message has no cursor info."""
        msg = software_toolkit_client._build_log_message(
            data_count=5,
            entity_description="software_toolkits",
            page_nb=1,
            total_pages=None,
            total_items=None,
            cursor=None,
        )
        assert "cursor" not in msg

    def test_given_multiple_pages_when_build_log_message_then_includes_page_info(
        self, software_toolkit_client
    ):
        """When total_pages > 1, log message includes page N/M info."""
        msg = software_toolkit_client._build_log_message(
            data_count=5,
            entity_description="software_toolkits",
            page_nb=2,
            total_pages=5,
            total_items=100,
            cursor=None,
        )
        assert "page 2/5" in msg
        assert "100" in msg

    def test_given_single_page_with_total_when_build_log_message_then_includes_total(
        self, software_toolkit_client
    ):
        """When total_pages <= 1 but total_items given, log message includes total."""
        msg = software_toolkit_client._build_log_message(
            data_count=5,
            entity_description="software_toolkits",
            page_nb=1,
            total_pages=1,
            total_items=50,
            cursor=None,
        )
        assert "50" in msg
        assert "page" not in msg

    def test_given_no_pages_no_total_when_build_log_message_then_basic_message(
        self, software_toolkit_client
    ):
        """When no pagination info, returns basic fetch message."""
        msg = software_toolkit_client._build_log_message(
            data_count=3,
            entity_description="software_toolkits",
            page_nb=1,
            total_pages=None,
            total_items=None,
            cursor=None,
        )
        assert "Fetched 3 software_toolkits from API" == msg


# =====================
# fetch_software_toolkits tests
# =====================


class TestFetchSoftwareToolkits:
    """Tests for ClientAPISoftwareToolkit.fetch_software_toolkits."""

    @pytest.mark.asyncio
    async def test_given_valid_state_when_fetch_software_toolkits_then_yields_data(
        self, software_toolkit_client
    ):
        """When initial_state is provided, yields data from paginate_with_cursor."""
        from datetime import timedelta

        software_toolkit_client.config.software_toolkit_import_start_date = timedelta(
            days=1
        )
        fake_fetcher = MagicMock()
        software_toolkit_client.fetcher_factory.create_fetcher_by_name.return_value = (
            fake_fetcher
        )

        expected_item = {"id": "tool--123", "type": "tool"}

        async def fake_paginate(fetcher, params, entity_name):
            yield expected_item

        software_toolkit_client._paginate_with_cursor = fake_paginate

        results = []
        async for item in software_toolkit_client.fetch_software_toolkits(
            initial_state=None
        ):
            results.append(item)

        assert results == [expected_item]

    @pytest.mark.asyncio
    async def test_given_none_state_when_fetch_software_toolkits_then_uses_config_start_date(
        self, software_toolkit_client
    ):
        """When no initial_state, calculates start date from config."""
        from datetime import timedelta

        software_toolkit_client.config.software_toolkit_import_start_date = timedelta(
            hours=24
        )
        fake_fetcher = MagicMock()
        software_toolkit_client.fetcher_factory.create_fetcher_by_name.return_value = (
            fake_fetcher
        )

        async def fake_paginate(fetcher, params, entity_name):
            return
            yield  # make it a generator

        software_toolkit_client._paginate_with_cursor = fake_paginate

        results = []
        async for item in software_toolkit_client.fetch_software_toolkits(
            initial_state=None
        ):
            results.append(item)

        software_toolkit_client.fetcher_factory.create_fetcher_by_name.assert_called_once_with(
            "main_software_toolkits", base_url="https://fake-gti.api"
        )

    @pytest.mark.asyncio
    async def test_given_multiple_filter_configs_when_fetch_software_toolkits_then_iterates_all(
        self, software_toolkit_client
    ):
        """All filter configs are iterated and items from each are yielded."""
        from datetime import timedelta
        from unittest.mock import patch

        software_toolkit_client.config.software_toolkit_import_start_date = timedelta(
            days=1
        )
        fake_fetcher = MagicMock()
        software_toolkit_client.fetcher_factory.create_fetcher_by_name.return_value = (
            fake_fetcher
        )

        call_count = 0

        async def fake_paginate(fetcher, params, entity_name):
            nonlocal call_count
            call_count += 1
            yield {"id": f"tool--{call_count}"}

        software_toolkit_client._paginate_with_cursor = fake_paginate

        two_configs = [
            {"params": {"filter": "collection_type:software-toolkit", "limit": 40}},
            {"params": {"filter": "collection_type:software-toolkit", "limit": 40}},
        ]
        with patch.object(
            software_toolkit_client,
            "_build_filter_configurations",
            return_value=two_configs,
        ):
            results = []
            async for item in software_toolkit_client.fetch_software_toolkits(
                initial_state=None
            ):
                results.append(item)

        assert len(results) == 2
        assert call_count == 2
