"""Tests of the Splunk REST client: pagination, namespace, retries, links."""

from unittest.mock import MagicMock

import pytest
import requests_mock as requests_mock_module
from connectors_sdk import ApiClientError, ApiForbiddenError, ApiServerError
from splunk_client import SplunkSavedSearchesClient

API = "https://splunk.example.com:8089"
ALL = f"{API}/servicesNS/-/-/saved/searches"


def _client(sleep=None, **kwargs) -> SplunkSavedSearchesClient:
    return SplunkSavedSearchesClient(
        API + "/",
        "splunk-token",
        logger=MagicMock(),
        sleep=sleep or MagicMock(),
        **kwargs,
    )


@pytest.fixture
def http():
    with requests_mock_module.Mocker() as mocker:
        yield mocker


def _page(names, total, offset=0):
    return {
        "entry": [{"name": name} for name in names],
        "paging": {"total": total, "perPage": 2, "offset": offset},
    }


def test_pages_through_every_saved_search(http):
    http.get(
        ALL,
        [{"json": _page(["a", "b"], 3)}, {"json": _page(["c"], 3, offset=2)}],
    )
    names = [e["name"] for e in _client(page_size=2).iter_saved_searches()]
    assert names == ["a", "b", "c"]
    first, second = http.request_history
    assert first.qs == {"output_mode": ["json"], "count": ["2"], "offset": ["0"]}
    assert second.qs["offset"] == ["2"]
    assert first.headers["Authorization"] == "Bearer splunk-token"


def test_namespace(http):
    http.get(
        f"{API}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches",
        json=_page(["a"], 1),
    )
    client = _client(app="SplunkEnterpriseSecuritySuite", owner="nobody")
    assert [e["name"] for e in client.iter_saved_searches()] == ["a"]


def test_empty_namespace_has_no_saved_searches(http):
    http.get(ALL, json=_page([], 0))
    assert list(_client().iter_saved_searches()) == []
    assert http.call_count == 1


def test_empty_page_before_the_total_fails_the_listing(http):
    http.get(
        ALL,
        [{"json": _page(["a", "b"], 5)}, {"json": _page([], 5, offset=2)}],
    )
    with pytest.raises(ApiClientError, match="offset 2 of 5 entries"):
        list(_client(page_size=2).iter_saved_searches())
    assert http.call_count == 2


def test_busy_server_is_retried(http):
    sleep = MagicMock()
    http.get(ALL, [{"status_code": 503}, {"json": _page(["a"], 1)}])
    assert len(list(_client(sleep=sleep).iter_saved_searches())) == 1
    sleep.assert_called_once()


def test_server_errors_give_up(http):
    http.get(ALL, status_code=500)
    with pytest.raises(ApiServerError):
        list(_client(max_retries=0).iter_saved_searches())


def test_missing_capability_is_not_retried(http):
    sleep = MagicMock()
    http.get(ALL, status_code=403, json={"messages": [{"type": "ERROR"}]})
    with pytest.raises(ApiForbiddenError):
        list(_client(sleep=sleep).iter_saved_searches())
    sleep.assert_not_called()


def test_unexpected_payload(http):
    http.get(ALL, json={"messages": []})
    with pytest.raises(ApiClientError, match="Unexpected response"):
        list(_client().iter_saved_searches())


def test_saved_search_url():
    client = _client(web_url="https://splunk.example.com:8000/")
    search = {
        "id": f"{API}/servicesNS/nobody/search/saved/searches/My%20Search",
        "acl": {"app": "search"},
    }
    assert client.saved_search_url(search) == (
        "https://splunk.example.com:8000/app/search/search?s="
        "%2FservicesNS%2Fnobody%2Fsearch%2Fsaved%2Fsearches%2FMy%2520Search"
    )
    assert client.saved_search_url({"id": "", "acl": {"app": "search"}}) is None
    assert _client().saved_search_url(search) is None
