from unittest.mock import Mock, call

import pytest
from connector.client_taxii import Taxii2

FIRST_DATE = "2026-01-01T00:00:00.000Z"
SECOND_DATE = "2026-01-02T00:00:00.000Z"


@pytest.fixture
def client():
    # Polling needs only filters and logging; skip server discovery/network I/O.
    client = Taxii2.__new__(Taxii2)
    client.filters = {}
    client.helper = Mock()
    return client


@pytest.fixture
def collection():
    collection = Mock()
    collection.title = "Test collection"
    # Finite responses make an unexpected extra request fail instead of hanging.
    collection.get_objects.side_effect = []
    collection.get_manifest.side_effect = []
    return collection


def page(identifier, version="2.0", **kwargs):
    obj = {"id": identifier}
    if version is not None:
        obj["spec_version"] = version
    return {"objects": [obj], **kwargs}


def manifest(date_added):
    return {"objects": [{"date_added": date_added}]}


def test_poll_stops_when_added_after_does_not_advance(client, collection):
    first_page = page("first")
    second_page = page("second")
    collection.get_objects.side_effect = [first_page, second_page]
    collection.get_manifest.side_effect = [manifest(FIRST_DATE), manifest(FIRST_DATE)]

    assert client.poll(collection) == first_page["objects"] + second_page["objects"]

    assert collection.get_objects.call_args_list == [
        call(),
        call(added_after=FIRST_DATE),
    ]
    assert collection.get_manifest.call_args_list == [
        call(id="first"),
        call(id="second"),
    ]
    assert client.filters["added_after"] == FIRST_DATE


@pytest.mark.parametrize("version", ["2.0", None], ids=["explicit", "default"])
def test_poll_stops_when_manifest_matches_existing_cursor(client, collection, version):
    response = page("first", version)
    client.filters["added_after"] = FIRST_DATE
    collection.get_objects.side_effect = [response]
    collection.get_manifest.side_effect = [manifest(FIRST_DATE)]

    assert client.poll(collection) == response["objects"]

    collection.get_objects.assert_called_once_with(added_after=FIRST_DATE)
    collection.get_manifest.assert_called_once_with(id="first")
    assert client.filters["added_after"] == FIRST_DATE


def test_poll_continues_while_added_after_advances(client, collection):
    first_page = page("first")
    second_page = page("second")
    collection.get_objects.side_effect = [first_page, second_page, {"objects": []}]
    collection.get_manifest.side_effect = [manifest(FIRST_DATE), manifest(SECOND_DATE)]

    assert client.poll(collection) == first_page["objects"] + second_page["objects"]

    assert collection.get_objects.call_args_list == [
        call(),
        call(added_after=FIRST_DATE),
        call(added_after=SECOND_DATE),
    ]
    assert collection.get_manifest.call_args_list == [
        call(id="first"),
        call(id="second"),
    ]
    assert client.filters["added_after"] == SECOND_DATE


@pytest.mark.parametrize("response", [{}, {"objects": []}])
def test_poll_stops_when_manifest_has_no_objects(client, collection, response):
    first_page = page("first")
    collection.get_objects.side_effect = [first_page]
    collection.get_manifest.side_effect = [response]

    assert client.poll(collection) == first_page["objects"]

    collection.get_objects.assert_called_once_with()
    collection.get_manifest.assert_called_once_with(id="first")
    assert client.filters == {}


@pytest.mark.parametrize("response", [None, {}, {"objects": []}])
def test_poll_returns_empty_without_requesting_manifest(client, collection, response):
    collection.get_objects.side_effect = [response]

    assert client.poll(collection) == []

    collection.get_objects.assert_called_once_with()
    collection.get_manifest.assert_not_called()


def test_poll_uses_next_token_for_taxii21(client, collection):
    first_page = page("first", "2.1", more=True, next="next-page")
    second_page = page("second", "2.1", more=False)
    client.filters = {"added_after": FIRST_DATE, "limit": 100}
    collection.get_objects.side_effect = [first_page, second_page]

    assert client.poll(collection) == first_page["objects"] + second_page["objects"]

    assert collection.get_objects.call_args_list == [
        call(added_after=FIRST_DATE, limit=100),
        call(next="next-page", limit=100),
    ]
    collection.get_manifest.assert_not_called()
    assert client.filters == {"next": "next-page", "limit": 100}
