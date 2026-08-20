from unittest.mock import MagicMock

import pytest
from ctm360_threatcover_client import (
    Ctm360ThreatcoverAPIError,
    Ctm360ThreatcoverClient,
)
from ctm360_threatcover_client.api_client import ApiKeyAuth
from requests.auth import HTTPBasicAuth
from taxii2client.common import TokenAuth
from taxii2client.exceptions import TAXIIServiceException

INDICATOR_A = {"type": "indicator", "id": "indicator--a"}
INDICATOR_B = {"type": "indicator", "id": "indicator--b"}


def _make_client(**kwargs) -> Ctm360ThreatcoverClient:
    params = dict(
        discovery_url="https://taxii.example.com/taxii2/",
        collection="observables",
        use_token=True,
        token="token",
    )
    params.update(kwargs)
    return Ctm360ThreatcoverClient(MagicMock(), **params)


def _attach_collection(client, coll_id="observables", title="Observables"):
    collection = MagicMock()
    collection.id = coll_id
    collection.title = title
    root = MagicMock()
    root.collections = [collection]
    server = MagicMock()
    server.api_roots = [root]
    client._server = server
    client._collection = None
    return collection


def test_build_auth_token():
    auth = Ctm360ThreatcoverClient._build_auth(
        use_token=True,
        token="t",
        use_apikey=False,
        apikey_key=None,
        apikey_value=None,
        username=None,
        password=None,
    )
    assert isinstance(auth, TokenAuth)


def test_build_auth_apikey():
    auth = Ctm360ThreatcoverClient._build_auth(
        use_token=False,
        token=None,
        use_apikey=True,
        apikey_key="X-Api-Key",
        apikey_value="v",
        username=None,
        password=None,
    )
    assert isinstance(auth, ApiKeyAuth)


def test_build_auth_basic():
    auth = Ctm360ThreatcoverClient._build_auth(
        use_token=False,
        token=None,
        use_apikey=False,
        apikey_key=None,
        apikey_value=None,
        username="user",
        password="pass",
    )
    assert isinstance(auth, HTTPBasicAuth)


def test_build_auth_raises_when_token_missing():
    with pytest.raises(Ctm360ThreatcoverAPIError):
        Ctm360ThreatcoverClient._build_auth(
            use_token=True,
            token=None,
            use_apikey=False,
            apikey_key=None,
            apikey_value=None,
            username=None,
            password=None,
        )


def test_build_auth_apikey_missing_raises():
    with pytest.raises(Ctm360ThreatcoverAPIError):
        Ctm360ThreatcoverClient._build_auth(
            use_token=False,
            token=None,
            use_apikey=True,
            apikey_key=None,
            apikey_value=None,
            username=None,
            password=None,
        )


def test_build_auth_basic_missing_raises():
    with pytest.raises(Ctm360ThreatcoverAPIError):
        Ctm360ThreatcoverClient._build_auth(
            use_token=False,
            token=None,
            use_apikey=False,
            apikey_key=None,
            apikey_value=None,
            username=None,
            password=None,
        )


def test_apikey_auth_sets_header():
    request = MagicMock()
    request.headers = {}
    ApiKeyAuth("X-Api-Key", "secret")(request)
    assert request.headers["X-Api-Key"] == "secret"


def test_resolve_collection_by_id():
    client = _make_client()
    collection = _attach_collection(client, coll_id="observables")
    assert client._resolve_collection() is collection


def test_resolve_collection_not_found():
    client = _make_client(collection="missing")
    _attach_collection(client, coll_id="observables", title="Observables")
    with pytest.raises(Ctm360ThreatcoverAPIError):
        client._resolve_collection()


def test_get_objects_single_page():
    client = _make_client()
    collection = _attach_collection(client)
    collection.get_objects.return_value = {"objects": [INDICATOR_A], "more": False}
    assert client.get_objects() == [INDICATOR_A]


def test_get_objects_paginates():
    client = _make_client()
    collection = _attach_collection(client)
    collection.get_objects.side_effect = [
        {"objects": [INDICATOR_A], "more": True, "next": "cursor-1"},
        {"objects": [INDICATOR_B], "more": False},
    ]
    result = client.get_objects()
    assert result == [INDICATOR_A, INDICATOR_B]
    assert collection.get_objects.call_args.kwargs == {"next": "cursor-1"}


def test_get_objects_raises_when_more_without_next():
    # more=True but no next cursor must raise, not silently return a partial page
    # (which would let the connector advance added_after and skip data).
    client = _make_client()
    collection = _attach_collection(client)
    collection.get_objects.return_value = {"objects": [INDICATOR_A], "more": True}
    with pytest.raises(Ctm360ThreatcoverAPIError):
        client.get_objects()


def test_get_objects_passes_added_after():
    client = _make_client()
    collection = _attach_collection(client)
    collection.get_objects.return_value = {"objects": [], "more": False}
    client.get_objects(added_after="2024-01-01T00:00:00.000Z")
    assert (
        collection.get_objects.call_args.kwargs["added_after"]
        == "2024-01-01T00:00:00.000Z"
    )


def test_get_objects_raises_on_taxii_error():
    client = _make_client()
    collection = _attach_collection(client)
    collection.get_objects.side_effect = TAXIIServiceException("boom")
    with pytest.raises(Ctm360ThreatcoverAPIError):
        client.get_objects()


def test_ping_resolves_collection():
    client = _make_client()
    _attach_collection(client)
    client.ping()  # must not raise
