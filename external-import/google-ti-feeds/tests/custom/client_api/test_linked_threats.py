"""Test module for the threats a GTI report links to in its text."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.custom.client_api.client_api_shared import ClientAPIShared
from connector.src.custom.client_api.linked_threats import (
    linked_threat_ids,
    subentity_type_of,
)

ACTOR = "threat-actor--2930cc24-2abe-59a4-80f4-8a6dec724e65"
MALWARE = "malware--4da11b43-e57e-5206-b255-5d8fb388178c"
TOOLKIT = "malware--e7aef043-d8d6-58e6-a951-20ec27c246f0"
CAMPAIGN = "campaign--27122d67-63bd-53e4-9df8-5e4a2c745a73"
GUI = "https://www.virustotal.com/gui/collection/"


def test_linked_threat_ids_in_order_once_each() -> None:
    """Threat links are collected across texts, in order, without duplicates."""
    # Given an HTML content and a Markdown comment linking threats
    content = (
        f'<p><a href="{GUI}{ACTOR}">UNC6240</a> uses <a href="{GUI}{MALWARE}">X</a></p>'
    )
    comment = f"See [UNC6240]({GUI}{ACTOR}/summary) and [C]({GUI}{CAMPAIGN})."

    # When the linked threat IDs are collected
    ids = linked_threat_ids([content, None, comment])

    # Then each threat is listed once, in order of appearance
    assert ids == [ACTOR, MALWARE, CAMPAIGN]  # noqa: S101


def test_linked_threat_ids_ignore_other_collections() -> None:
    """Links to reports, vulnerabilities and other sites are not threats."""
    text = (
        f"{GUI}report--26-10102613 {GUI}vulnerability--cve-2025-32433 "
        f"https://example.com/collection/{ACTOR}"
    )
    assert linked_threat_ids([text]) == []  # noqa: S101


@pytest.mark.parametrize(
    "url",
    [
        f"https://notvirustotal.com/gui/collection/{ACTOR}",
        f"https://www.notvirustotal.com/gui/collection/{ACTOR}",
        f"https://virustotal.com.example.com/gui/collection/{ACTOR}",
    ],
)
def test_linked_threat_ids_ignore_lookalike_hosts(url: str) -> None:
    """Only links to the VirusTotal host are GTI links, not lookalike hosts."""
    assert linked_threat_ids([f'<a href="{url}">UNC6240</a>']) == []  # noqa: S101


@pytest.mark.parametrize(
    ("collection_type", "expected"),
    [
        ("threat-actor", "threat_actors"),
        ("malware-family", "malware_families"),
        ("campaign", "campaigns"),
        ("software-toolkit", "software_toolkits"),
        ("report", None),
        (None, None),
    ],
)
def test_subentity_type_of(collection_type: str | None, expected: str | None) -> None:
    """The sub-entity type comes from the collection_type of the fetched collection."""
    collection = {"id": "x", "attributes": {"collection_type": collection_type}}
    assert subentity_type_of(collection) == expected  # noqa: S101


def _collection(collection_id: str, collection_type: str) -> dict[str, Any]:
    return {
        "id": collection_id,
        "type": "collection",
        "attributes": {"collection_type": collection_type},
    }


def _client(
    collections: list[dict[str, Any]], invalid_ids: frozenset[str] = frozenset()
) -> tuple[ClientAPIShared, MagicMock]:
    """Client fetching the given raw collections; the model rejects invalid_ids."""
    collections_fetcher = MagicMock()
    collections_fetcher.fetch_multiple = AsyncMock(return_value=collections)

    def model_validate(collection: dict[str, Any]) -> SimpleNamespace:
        if collection["id"] in invalid_ids:
            raise ValueError("invalid collection")
        return SimpleNamespace(id=collection["id"])

    typed_fetcher = MagicMock()
    typed_fetcher.config.response_model.model_validate.side_effect = model_validate

    def create_fetcher_by_name(name: str, base_url: str) -> Any:
        return collections_fetcher if name == "collections" else typed_fetcher

    factory = MagicMock()
    factory.create_fetcher_by_name.side_effect = create_fetcher_by_name
    client = ClientAPIShared(
        config=SimpleNamespace(api_url=MagicMock()),
        logger=MagicMock(),
        api_client=MagicMock(),
        fetcher_factory=factory,
    )
    return client, collections_fetcher


@pytest.mark.asyncio
async def test_fetch_linked_threats_groups_by_type_and_filters() -> None:
    """Fetched collections are grouped by their type; disabled types are dropped."""
    # Given GTI returning a threat actor, a malware family and a software toolkit
    # (both with malware-- IDs)
    client, collections_fetcher = _client(
        [
            _collection(ACTOR, "threat-actor"),
            _collection(MALWARE, "malware-family"),
            _collection(TOOLKIT, "software-toolkit"),
        ]
    )

    # When the linked threats are fetched, software toolkits disabled
    result = await client.fetch_linked_threats(
        [ACTOR, MALWARE, TOOLKIT], ["threat_actors", "malware_families"]
    )

    # Then the collections are grouped by sub-entity type, the toolkit dropped
    assert {k: [c.id for c in v] for k, v in result.items()} == {  # noqa: S101
        "threat_actors": [ACTOR],
        "malware_families": [MALWARE],
    }
    collections_fetcher.fetch_multiple.assert_awaited_once_with(
        [ACTOR, MALWARE, TOOLKIT]
    )


@pytest.mark.asyncio
async def test_fetch_linked_threats_skips_collections_failing_validation() -> None:
    """Collections that fail model validation are skipped, not returned as raw dicts."""
    # Given GTI returning a valid threat actor and a malware family the model rejects
    client, _ = _client(
        [_collection(ACTOR, "threat-actor"), _collection(MALWARE, "malware-family")],
        invalid_ids=frozenset({MALWARE}),
    )

    # When the linked threats are fetched
    result = await client.fetch_linked_threats(
        [ACTOR, MALWARE], ["threat_actors", "malware_families"]
    )

    # Then only the validated threat actor is returned, the empty type omitted
    assert {k: [c.id for c in v] for k, v in result.items()} == {  # noqa: S101
        "threat_actors": [ACTOR]
    }
    client.logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_fetch_linked_threats_without_ids_makes_no_call() -> None:
    """No API call is made without linked IDs."""
    factory = MagicMock()
    client = ClientAPIShared(
        config=SimpleNamespace(api_url=MagicMock()),
        logger=MagicMock(),
        api_client=MagicMock(),
        fetcher_factory=factory,
    )
    assert await client.fetch_linked_threats([], ["threat_actors"]) == {}  # noqa: S101
    factory.create_fetcher_by_name.assert_not_called()
