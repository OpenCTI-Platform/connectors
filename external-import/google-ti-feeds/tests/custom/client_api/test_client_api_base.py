"""Test module for BaseClientAPI pagination behavior."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.custom.client_api.client_api_base import BaseClientAPI

# =====================
# Fixtures
# =====================


@pytest.fixture
def base_client() -> BaseClientAPI:
    """Fixture for BaseClientAPI with mocked dependencies."""
    return BaseClientAPI(
        config=SimpleNamespace(),
        logger=MagicMock(),
        api_client=MagicMock(),
        fetcher_factory=MagicMock(),
    )


# =====================
# Scenario: Pagination behavior
# =====================


@pytest.mark.asyncio
async def test_paginate_with_cursor_reraises_fetch_errors(
    base_client: BaseClientAPI,
) -> None:
    """Test that pagination errors are propagated to callers."""
    # Given: A fetcher that fails with a quota error
    fetcher = MagicMock()
    fetcher.config = SimpleNamespace(
        endpoint="/collections",
    )
    fetcher.fetch_single = AsyncMock(side_effect=RuntimeError("Quota exceeded"))

    # When: Pagination is executed
    results, exception = await _when_paginate_called(
        client=base_client,
        fetcher=fetcher,
        initial_params={"limit": 40},
        entity_description="reports",
    )

    # Then: The quota error is re-raised and no results are yielded
    _then_pagination_failed_with_error(exception)
    _then_results_are(results, [])


@pytest.mark.asyncio
async def test_paginate_with_cursor_yields_data_on_success(
    base_client: BaseClientAPI,
) -> None:
    """Test that normal pagination flow yields API data."""
    # Given: A fetcher returning two successful pages
    fetcher = MagicMock()
    fetcher.config = SimpleNamespace(
        endpoint="/collections",
    )
    fetcher.fetch_single = AsyncMock(
        side_effect=[
            {
                "data": [{"id": "item-1"}],
                "meta": {"cursor": "next-page", "count": 2},
            },
            {
                "data": [{"id": "item-2"}],
                "meta": {"count": 2},
            },
        ]
    )

    # When: Pagination is executed
    results, exception = await _when_paginate_called(
        client=base_client,
        fetcher=fetcher,
        initial_params={"limit": 40},
        entity_description="reports",
    )

    # Then: Results from both pages are returned in order
    _then_pagination_succeeded(exception)
    _then_results_are(results, [{"id": "item-1"}, {"id": "item-2"}])


# =====================
# GWT Helper Functions
# =====================


async def _when_paginate_called(
    client: BaseClientAPI,
    fetcher: Any,
    initial_params: dict[str, Any],
    entity_description: str,
) -> tuple[list[Any], Exception | None]:
    """Execute pagination and capture yielded results and exceptions."""
    results: list[Any] = []
    try:
        async for page_data in client._paginate_with_cursor(
            fetcher=fetcher,
            initial_params=initial_params,
            entity_description=entity_description,
        ):
            results.extend(page_data)
        return results, None
    except Exception as exc:
        return results, exc


def _then_pagination_failed_with_error(exception: Exception | None) -> None:
    """Assert that pagination failed with the expected error."""
    assert exception is not None  # noqa: S101
    assert isinstance(exception, RuntimeError)  # noqa: S101
    assert len(str(exception)) > 0  # noqa: S101


def _then_pagination_succeeded(exception: Exception | None) -> None:
    """Assert that pagination completed without errors."""
    assert exception is None  # noqa: S101


def _then_results_are(results: list[Any], expected_results: list[Any]) -> None:
    """Assert that pagination results match expected values."""
    assert results == expected_results  # noqa: S101
