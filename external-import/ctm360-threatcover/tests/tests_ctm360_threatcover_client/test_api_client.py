from unittest.mock import MagicMock, PropertyMock

import pytest
from ctm360_threatcover_client import (
    Ctm360ThreatcoverAPIError,
    Ctm360ThreatcoverClient,
)
from taxii2client.exceptions import TAXIIServiceException

INDICATOR_A = {"type": "indicator", "id": "indicator--a"}
INDICATOR_B = {"type": "indicator", "id": "indicator--b"}


def _make_client() -> Ctm360ThreatcoverClient:
    client = Ctm360ThreatcoverClient(
        MagicMock(),
        api_root_url="https://taxii.example.com/taxii2/api",
        api_token="token",
        collection_id="observables",
    )
    client.collection = MagicMock()
    return client


def test_collection_url_built():
    client = _make_client()
    assert client.collection_url == (
        "https://taxii.example.com/taxii2/api/collections/observables/"
    )


def test_get_objects_single_page():
    client = _make_client()
    client.collection.get_objects.return_value = {
        "objects": [INDICATOR_A],
        "more": False,
    }
    assert client.get_objects() == [INDICATOR_A]


def test_get_objects_paginates():
    client = _make_client()
    client.collection.get_objects.side_effect = [
        {"objects": [INDICATOR_A], "more": True, "next": "cursor-1"},
        {"objects": [INDICATOR_B], "more": False},
    ]

    result = client.get_objects()
    assert result == [INDICATOR_A, INDICATOR_B]
    assert client.collection.get_objects.call_args.kwargs == {"next": "cursor-1"}


def test_get_objects_passes_added_after():
    client = _make_client()
    client.collection.get_objects.return_value = {"objects": [], "more": False}

    client.get_objects(added_after="2024-01-01T00:00:00.000Z")
    assert (
        client.collection.get_objects.call_args.kwargs["added_after"]
        == "2024-01-01T00:00:00.000Z"
    )


def test_get_objects_raises_on_taxii_error():
    client = _make_client()
    client.collection.get_objects.side_effect = TAXIIServiceException("boom")

    with pytest.raises(Ctm360ThreatcoverAPIError):
        client.get_objects()


def test_ping_returns_title():
    client = _make_client()
    client.collection.title = "ThreatCover Observables"
    assert client.ping() == "ThreatCover Observables"


def test_ping_raises_on_taxii_error():
    client = _make_client()
    collection = MagicMock()
    type(collection).title = PropertyMock(side_effect=TAXIIServiceException("down"))
    client.collection = collection

    with pytest.raises(Ctm360ThreatcoverAPIError):
        client.ping()
