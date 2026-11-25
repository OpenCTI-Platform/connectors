"""Test module for the GTI page sizes (large collections are fetched in smaller pages)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.src.custom.client_api.client_api_base import BaseClientAPI
from connector.src.custom.client_api.page_limits import (
    DEFAULT_PAGE_LIMIT,
    collection_page_limit,
    subentity_page_limit,
)


@pytest.mark.parametrize(
    ("collection_type", "expected"),
    [
        ("threat-actor", 10),
        ("malware-family", 10),
        ("report", DEFAULT_PAGE_LIMIT),
        ("campaign", DEFAULT_PAGE_LIMIT),
        ("vulnerability", DEFAULT_PAGE_LIMIT),
        ("software-toolkit", DEFAULT_PAGE_LIMIT),
    ],
)
def test_collection_page_limit(collection_type: str, expected: int) -> None:
    """Large collection types get a smaller page, the others keep the default."""
    assert collection_page_limit(collection_type) == expected  # noqa: S101


@pytest.mark.parametrize(
    ("subentity_type", "expected"),
    [
        ("threat_actors", 10),
        ("malware_families", 10),
        ("attack_techniques", DEFAULT_PAGE_LIMIT),
        ("files", DEFAULT_PAGE_LIMIT),
    ],
)
def test_subentity_page_limit(subentity_type: str, expected: int) -> None:
    """Large sub-entity types get a smaller page, the others keep the default."""
    assert subentity_page_limit(subentity_type) == expected  # noqa: S101


@pytest.mark.parametrize(
    ("collection_type", "expected"),
    [("threat-actor", 10), ("malware-family", 10), ("report", 40)],
)
def test_filter_configurations_use_the_collection_page_limit(
    collection_type: str, expected: int
) -> None:
    """The collection request carries the page size of its collection type."""
    # Given a base client
    client = BaseClientAPI(
        config=SimpleNamespace(),
        logger=MagicMock(),
        api_client=MagicMock(),
        fetcher_factory=MagicMock(),
    )

    # When the filter configurations are built
    configs = client._build_filter_configurations(
        collection_type=collection_type, start_date="2026-11-18T00:00:00"
    )

    # Then every request uses the collection page size
    assert configs  # noqa: S101
    assert all(c["params"]["limit"] == expected for c in configs)  # noqa: S101
