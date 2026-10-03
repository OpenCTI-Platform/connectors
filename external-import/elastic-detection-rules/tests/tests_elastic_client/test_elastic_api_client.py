"""Tests of the Kibana client: pagination, authentication, retries, errors."""

from unittest.mock import MagicMock

import pytest
import requests
import requests_mock as requests_mock_module
from connectors_sdk import (
    ApiClientError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from elastic_client import ElasticDetectionRulesClient

KIBANA = "https://kibana.example.com:5601"
FIND = f"{KIBANA}/api/detection_engine/rules/_find"


def _client(sleep=None, **kwargs) -> ElasticDetectionRulesClient:
    return ElasticDetectionRulesClient(
        KIBANA + "/",
        "ZWxhc3RpYzpzZWNyZXQ=",
        logger=MagicMock(),
        sleep=sleep or MagicMock(),
        **kwargs,
    )


@pytest.fixture
def http():
    with requests_mock_module.Mocker() as mocker:
        yield mocker


def _page(rules, total):
    return {"page": 1, "perPage": 2, "total": total, "data": rules}


def test_pages_through_every_rule(http):
    http.get(
        FIND,
        [
            {"json": _page([{"rule_id": "a"}, {"rule_id": "b"}], 3)},
            {"json": _page([{"rule_id": "c"}], 3)},
        ],
    )
    rules = list(_client(page_size=2).iter_rules())
    assert [r["rule_id"] for r in rules] == ["a", "b", "c"]
    first, second = http.request_history
    assert first.qs == {
        "page": ["1"],
        "per_page": ["2"],
        "sort_field": ["created_at"],
        "sort_order": ["asc"],
    }
    assert second.qs["page"] == ["2"]
    headers = first.headers
    assert headers["Authorization"] == "ApiKey ZWxhc3RpYzpzZWNyZXQ="
    assert headers["elastic-api-version"] == "2023-10-31"
    assert first.method == "GET"


def test_stops_on_an_empty_page(http):
    http.get(FIND, json=_page([], 10))
    assert list(_client().iter_rules()) == []
    assert http.call_count == 1


def test_space_and_filter(http):
    http.get(
        f"{KIBANA}/s/soc/api/detection_engine/rules/_find",
        json=_page([{"rule_id": "a"}], 1),
    )
    client = _client(space_id="soc")
    assert list(client.iter_rules('alert.attributes.tags:"Prod"')) == [{"rule_id": "a"}]
    assert http.last_request.qs["filter"] == ['alert.attributes.tags:"prod"']
    assert client.rule_url("abc") == f"{KIBANA}/s/soc/app/security/rules/id/abc"


def test_default_space_has_no_prefix():
    assert _client(space_id="default").rule_url("abc") == (
        f"{KIBANA}/app/security/rules/id/abc"
    )
    assert _client().space_prefix == ""


def test_rate_limit_waits_as_asked_then_retries(http):
    sleep = MagicMock()
    http.get(
        FIND,
        [
            {"status_code": 429, "headers": {"Retry-After": "7"}, "json": {}},
            {"json": _page([{"rule_id": "a"}], 1)},
        ],
    )
    assert len(list(_client(sleep=sleep).iter_rules())) == 1
    sleep.assert_called_once_with(7.0)


def test_server_errors_back_off_exponentially(http):
    sleep = MagicMock()
    http.get(
        FIND,
        [
            {"status_code": 503},
            {"status_code": 502},
            {"json": _page([{"rule_id": "a"}], 1)},
        ],
    )
    assert len(list(_client(sleep=sleep).iter_rules())) == 1
    first, second = (call.args[0] for call in sleep.call_args_list)
    assert 1 <= first <= 2
    assert 2 <= second <= 3


def test_retry_delay_is_capped(http):
    sleep = MagicMock()
    http.get(
        FIND,
        [
            {"status_code": 429, "headers": {"Retry-After": "3600"}},
            {"json": _page([], 0)},
        ],
    )
    list(_client(sleep=sleep).iter_rules())
    sleep.assert_called_once_with(60.0)


@pytest.mark.parametrize(
    "status,error",
    [(429, ApiRateLimitError), (500, ApiServerError)],
)
def test_gives_up_after_max_retries(http, status, error):
    sleep = MagicMock()
    http.get(FIND, status_code=status, json={"message": "busy"})
    with pytest.raises(error):
        list(_client(sleep=sleep, max_retries=2).iter_rules())
    assert http.call_count == 3
    assert sleep.call_count == 2


def test_network_errors_are_retried(http):
    sleep = MagicMock()
    http.get(
        FIND,
        [
            {"exc": requests.exceptions.ConnectTimeout},
            {"json": _page([{"rule_id": "a"}], 1)},
        ],
    )
    assert len(list(_client(sleep=sleep).iter_rules())) == 1
    sleep.assert_called_once()


def test_network_errors_give_up(http):
    http.get(FIND, exc=requests.exceptions.ConnectionError("refused"))
    with pytest.raises(ApiClientError, match="failed after 2 attempt"):
        list(_client(max_retries=1).iter_rules())


def test_authentication_errors_are_not_retried(http):
    sleep = MagicMock()
    http.get(FIND, status_code=401, json={"message": "unauthorized"})
    with pytest.raises(ApiUnauthorizedError):
        list(_client(sleep=sleep).iter_rules())
    assert http.call_count == 1
    sleep.assert_not_called()


def test_unexpected_payload(http):
    http.get(FIND, json={"error": "nope"})
    with pytest.raises(ApiClientError, match="Unexpected response"):
        list(_client().iter_rules())
