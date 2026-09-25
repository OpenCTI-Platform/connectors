"""Unit tests for the GreedyBear HTTP client.

The network layer is mocked: ``session.get`` for the retry/parse logic in
``_get``, and ``_get`` itself for the per-feed parameter building and response
unwrapping.
"""

from unittest.mock import MagicMock, patch

import requests
from greedybear_client.api_client import GreedyBearClient


def _client(api_key=None):
    return GreedyBearClient(
        helper=MagicMock(),
        base_url="https://gb.example.com/",
        api_key=api_key,
    )


def _response(json_value=None, raise_exc=None, http_error=False):
    resp = MagicMock()
    if http_error:
        resp.raise_for_status.side_effect = requests.HTTPError("500")
    else:
        resp.raise_for_status.return_value = None
    if raise_exc is not None:
        resp.json.side_effect = raise_exc
    else:
        resp.json.return_value = json_value
    return resp


def test_init_authenticated_sets_token_header():
    client = _client(api_key="secret")
    assert client.authenticated is True
    assert client.session.headers["Authorization"] == "Token secret"
    # base_url trailing slash stripped
    assert client.base_url == "https://gb.example.com"


def test_init_unauthenticated_has_no_token_header():
    client = _client(api_key=None)
    assert client.authenticated is False
    assert "Authorization" not in client.session.headers


def test_get_success_returns_json():
    client = _client()
    client.session.get = MagicMock(return_value=_response({"iocs": [1, 2]}))
    assert client._get("/x") == {"iocs": [1, 2]}


@patch("greedybear_client.api_client.time.sleep", lambda *_: None)
def test_get_retries_then_returns_none_on_request_error():
    client = _client()
    client.session.get = MagicMock(side_effect=requests.ConnectionError("boom"))
    assert client._get("/x") is None
    assert client.session.get.call_count == 3  # MAX_RETRIES


@patch("greedybear_client.api_client.time.sleep", lambda *_: None)
def test_get_handles_json_value_error():
    client = _client()
    client.session.get = MagicMock(return_value=_response(raise_exc=ValueError("bad")))
    assert client._get("/x") is None


def test_advanced_feed_empty_without_auth():
    client = _client(api_key=None)
    client._get = MagicMock()
    assert client.get_advanced_feeds() == []
    client._get.assert_not_called()


def test_advanced_feed_builds_params_and_unwraps():
    client = _client(api_key="k")
    client._get = MagicMock(return_value={"iocs": [{"value": "1.2.3.4"}]})
    result = client.get_advanced_feeds(
        min_score=0.3,
        ioc_type="ip",
        feed_type="cowrie",
        attack_type="scanner",
        include_mass_scanners=False,
        include_tor_exit_nodes=False,
    )
    assert result == [{"value": "1.2.3.4"}]
    _, kwargs = client._get.call_args
    params = kwargs["params"]
    assert params["ioc_type"] == "ip"
    assert params["feed_type"] == "cowrie"
    assert params["attack_type"] == "scanner"
    assert params["min_score"] == 0.3
    assert "mass scanner" in params["exclude_reputation"]
    assert "tor exit node" in params["exclude_reputation"]


def test_advanced_feed_none_result_returns_empty():
    client = _client(api_key="k")
    client._get = MagicMock(return_value=None)
    assert client.get_advanced_feeds() == []


def test_advanced_feed_bare_list_result():
    client = _client(api_key="k")
    client._get = MagicMock(return_value=[{"value": "9.9.9.9"}])
    assert client.get_advanced_feeds() == [{"value": "9.9.9.9"}]


def test_standard_feed_comma_feed_type_falls_back_to_all():
    client = _client()
    client._get = MagicMock(return_value={"iocs": []})
    client.get_standard_feeds(feed_type="cowrie,dionaea", attack_type="all")
    path = client._get.call_args[0][0]
    assert path.startswith("/api/feeds/all/")


def test_standard_feed_unwraps_dict_and_list():
    client = _client()
    client._get = MagicMock(return_value={"iocs": [1]})
    assert client.get_standard_feeds() == [1]
    client._get = MagicMock(return_value=[2])
    assert client.get_standard_feeds() == [2]
    client._get = MagicMock(return_value=None)
    assert client.get_standard_feeds() == []


def test_asn_feed_empty_without_auth():
    client = _client(api_key=None)
    client._get = MagicMock()
    assert client.get_asn_feeds() == []
    client._get.assert_not_called()


def test_asn_feed_unwraps_list_and_dict():
    client = _client(api_key="k")
    client._get = MagicMock(return_value=[{"asn": 1}])
    assert client.get_asn_feeds(feed_type="cowrie", attack_type="scanner") == [
        {"asn": 1}
    ]
    client._get = MagicMock(return_value={"results": [{"asn": 2}]})
    assert client.get_asn_feeds() == [{"asn": 2}]
    client._get = MagicMock(return_value=None)
    assert client.get_asn_feeds() == []


def test_enrichment_passes_query():
    client = _client()
    client._get = MagicMock(return_value={"found": True})
    assert client.get_enrichment("1.2.3.4") == {"found": True}
    assert client._get.call_args[1]["params"] == {"query": "1.2.3.4"}
