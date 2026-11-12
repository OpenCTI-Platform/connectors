"""Tests of the retry policy: server delays, backoff cap, retry limit."""

from unittest.mock import MagicMock

import pytest
import requests_mock as requests_mock_module
from connectors_sdk import ApiRateLimitError, ApiServerError
from splunk_client.retrying_client import RetryingApiClient

API = "https://api.example.com"
PING = f"{API}/ping"


class _Client(RetryingApiClient):
    def ping(self):
        return self._get("/ping")


def _client(sleep, **kwargs) -> _Client:
    return _Client(API, logger=MagicMock(), sleep=sleep, **kwargs)


@pytest.fixture
def http():
    with requests_mock_module.Mocker() as mocker:
        yield mocker


def test_server_delay_is_waited_in_full(http):
    sleep = MagicMock()
    http.get(
        PING,
        [
            {"status_code": 429, "headers": {"Retry-After": "600"}},
            {"json": {"ok": True}},
        ],
    )
    assert _client(sleep).ping() == {"ok": True}
    sleep.assert_called_once_with(600.0)


def test_server_delay_beyond_the_limit_is_not_retried(http):
    sleep = MagicMock()
    http.get(PING, status_code=429, headers={"Retry-After": "7200"})
    with pytest.raises(ApiRateLimitError) as raised:
        _client(sleep).ping()
    assert raised.value.retry_after == 7200.0
    assert http.call_count == 1
    sleep.assert_not_called()


def test_computed_backoff_is_capped(http):
    sleep = MagicMock()
    http.get(PING, [{"status_code": 503}] * 3 + [{"json": {}}])
    _client(sleep, backoff_factor=40.0).ping()
    delays = [call.args[0] for call in sleep.call_args_list]
    assert 40.0 <= delays[0] <= 60.0
    assert delays[1:] == [60.0, 60.0]


def test_retry_budget_is_respected(http):
    sleep = MagicMock()
    http.get(PING, status_code=503)
    with pytest.raises(ApiServerError):
        _client(sleep, max_retries=2).ping()
    assert http.call_count == 3
    assert sleep.call_count == 2
