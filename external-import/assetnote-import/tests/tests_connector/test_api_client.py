from unittest.mock import MagicMock

import pytest
from assetnote_import_client.api_client import AssetnoteImportClient
from connector.settings import AssetnoteImportConfig
from connectors_sdk import ApiClientError


def _make_client():
    config = AssetnoteImportConfig(api_base_url="http://test.com", api_key="test-key")
    client = AssetnoteImportClient(config.api_base_url, config.api_key)
    client._post = MagicMock()
    return client


def test_graphql_query_unwraps_edges_to_nodes():
    """
    Ensure that the unravelling and mapping of the GraphQL response works correctly
    under data -> {root} -> edges -> node, which should be unwrapped into a list of
    dictionaries with each encompassing the contents of a node.
    """
    client = _make_client()
    client._post.return_value = {
        "data": {"exposures": {"edges": [{"node": {"id": "1"}}, {"node": {"id": "2"}}]}}
    }
    result = client._graphql_query("query", "exposures", since="2020-01-01", page=1)
    assert result == [{"id": "1"}, {"id": "2"}]


def test_graphql_query_raises_on_http_error():
    """
    HTTP Errors should be propagated to the root of the connector
    """
    client = _make_client()
    client._post.side_effect = ApiClientError("error")
    with pytest.raises(ApiClientError):
        client._graphql_query("query", "exposures", since="2020-01-01", page=1)


def test_graphql_query_raises_on_graphql_errors():
    """
    GraphQL errors can still exist even in a successful HTTP response thus
    the connector should be able to handle the presence of the error field
    by raising an exception
    """
    client = _make_client()
    client._post.return_value = {"errors": ["error"]}
    with pytest.raises(RuntimeError):
        client._graphql_query("query", "exposures", since="2020-01-01", page=1)


def test_get_exposures_returns_unwrapped_nodes():
    """
    get_exposures should return the same unwrapped list of nodes based on an
    exposure index
    """
    client = _make_client()
    client._post.return_value = {
        "data": {"exposures": {"edges": [{"node": {"id": "1"}}]}}
    }
    result = client.get_exposures(since="2020-01-01", page=1)
    assert result == [{"id": "1"}]


def test_get_assets_returns_unwrapped_nodes():
    """
    get_assets should return the same unwrapped list of nodes based on an
    asset index
    """
    client = _make_client()
    client._post.return_value = {"data": {"assets": {"edges": [{"node": {"id": "1"}}]}}}
    result = client.get_assets(since="2020-01-01", page=1)
    assert result == [{"id": "1"}]
