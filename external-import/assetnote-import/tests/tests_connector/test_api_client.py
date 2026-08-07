from unittest.mock import MagicMock

import pytest
import requests
from assetnote_import_client.api_client import AssetnoteImportClient
from connector.settings import AssetnoteImportConfig


def _make_client():
    helper = MagicMock()
    config = AssetnoteImportConfig(api_base_url="http://test.com", api_key="test-key")
    client = AssetnoteImportClient(helper, config.api_base_url, config.api_key)
    client.session = MagicMock()
    return client


def _fake_response(json_body):
    response = MagicMock()
    response.json.return_value = json_body
    return response


def test_graphql_query_unwraps_edges_to_nodes():
    """
    Ensure that the unravelling and mapping of the GraphQL response works correctly
    under data -> {root} -> edges -> node, which should be unwrapped into a list of
    dictionaries with each encompassing the contents of a node.
    """
    client = _make_client()
    client.session.post.return_value = _fake_response(
        {
            "data": {
                "exposures": {"edges": [{"node": {"id": "1"}}, {"node": {"id": "2"}}]}
            }
        }
    )
    result = client._graphql_query("query", "exposures", since="2020-01-01", page=1)
    assert result == [{"id": "1"}, {"id": "2"}]


def test_graphql_query_raises_on_http_error():
    """
    HTTP Errors should be propagated to the root of the connector
    """
    client = _make_client()
    response = _fake_response({})

    response.raise_for_status.side_effect = requests.HTTPError("error")
    client.session.post.return_value = response
    with pytest.raises(requests.HTTPError):
        client._graphql_query("query", "exposures", since="2020-01-01", page=1)


def test_graphql_query_raises_on_graphql_errors():
    """
    GraphQL errors can still exist even in a successful HTTP response thus
    the connector should be able to handle the presence of the error field
    by raising an exception
    """
    client = _make_client()
    client.session.post.return_value = _fake_response({"errors": ["error"]})
    with pytest.raises(RuntimeError):
        client._graphql_query("query", "exposures", since="2020-01-01", page=1)


def test_graphql_query_raises_on_non_json_response():
    """
    If response body isn't valid JSON a ValueError should propogate.
    """
    client = _make_client()
    response = _fake_response(None)
    response.json.side_effect = ValueError("not json")
    client.session.post.return_value = response
    with pytest.raises(ValueError):
        client._graphql_query("query", "exposures", since="2020-01-01", page=1)


def test_get_exposures_returns_unwrapped_nodes():
    """
    get_exposures should return the same unwrapped list of nodes based on an
    exposure index
    """
    client = _make_client()
    client.session.post.return_value = _fake_response(
        {"data": {"exposures": {"edges": [{"node": {"id": "1"}}]}}}
    )
    result = client.get_exposures(since="2020-01-01", page=1)
    assert result == [{"id": "1"}]


def test_get_assets_returns_unwrapped_nodes():
    """
    get_assets should return the same unwrapped list of nodes based on an
    asset index
    """
    client = _make_client()
    client.session.post.return_value = _fake_response(
        {"data": {"assets": {"edges": [{"node": {"id": "1"}}]}}}
    )
    result = client.get_assets(since="2020-01-01", page=1)
    assert result == [{"id": "1"}]
