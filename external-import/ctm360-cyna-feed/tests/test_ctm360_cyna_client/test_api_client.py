"""Tests for the CTM360 CYNA HTTP client."""

from unittest.mock import MagicMock

import pytest
import requests
from ctm360_cyna_client.api_client import CTM360CynaAPIError, CTM360CynaClient


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = {} if json_data is None else json_data
        self.headers = headers or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.exceptions.HTTPError(f"HTTP {self.status_code}")
            error.response = self
            raise error


@pytest.fixture
def client():
    return CTM360CynaClient(
        helper=MagicMock(), base_url="https://cyna.example.com/", api_key="secret"
    )


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("ctm360_cyna_client.api_client.time.sleep", lambda *_: None)


class TestClientInit:
    def test_base_url_trailing_slash_stripped(self, client):
        assert client.base_url == "https://cyna.example.com"

    def test_api_key_header(self, client):
        assert client.session.headers["api-key"] == "secret"


class TestRequest:
    def test_success(self, client):
        client.session.request = MagicMock(
            return_value=FakeResponse(200, {"success": True})
        )
        assert client._request("GET", "/x") == {"success": True}

    def test_429_then_success(self, client):
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(429, headers={"Retry-After": "1"}),
                FakeResponse(200, {"ok": 1}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": 1}

    def test_429_default_backoff(self, client):
        client.session.request = MagicMock(
            side_effect=[FakeResponse(429), FakeResponse(200, {"ok": 1})]
        )
        assert client._request("GET", "/x") == {"ok": 1}

    def test_429_with_invalid_retry_after_header(self, client):
        # A malformed Retry-After value must not raise; it falls back to the
        # configured backoff and the request still completes.
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(429, headers={"Retry-After": "not-a-number"}),
                FakeResponse(200, {"ok": 1}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": 1}

    def test_429_with_http_date_retry_after_header(self, client):
        # An HTTP-date Retry-After value (RFC 7231) must be parsed, not crash.
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(
                    429, headers={"Retry-After": "Wed, 21 Oct 2099 07:28:00 GMT"}
                ),
                FakeResponse(200, {"ok": 1}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": 1}

    def test_429_exhausted(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(429))
        with pytest.raises(CTM360CynaAPIError, match="Max retries exceeded"):
            client._request("GET", "/x")

    def test_5xx_then_success(self, client):
        client.session.request = MagicMock(
            side_effect=[FakeResponse(502), FakeResponse(200, {"ok": 1})]
        )
        assert client._request("GET", "/x") == {"ok": 1}

    def test_504_is_retried(self, client):
        # 504 (and any 5xx) must be treated as a transient, retryable failure.
        client.session.request = MagicMock(
            side_effect=[FakeResponse(504), FakeResponse(200, {"ok": 1})]
        )
        assert client._request("GET", "/x") == {"ok": 1}
        assert client.session.request.call_count == 2

    def test_non_retryable_http_error(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(404))
        with pytest.raises(CTM360CynaAPIError) as exc:
            client._request("GET", "/x")
        assert exc.value.status_code == 404

    def test_connection_error(self, client):
        client.session.request = MagicMock(
            side_effect=requests.exceptions.ConnectionError("boom")
        )
        with pytest.raises(CTM360CynaAPIError, match="Connection error"):
            client._request("GET", "/x")

    def test_timeout(self, client):
        client.session.request = MagicMock(
            side_effect=requests.exceptions.Timeout("slow")
        )
        with pytest.raises(CTM360CynaAPIError, match="Request timeout"):
            client._request("GET", "/x")


class TestPing:
    def test_ping_success(self, client):
        client._request = MagicMock(
            return_value={"success": True, "total": {"value": 3}}
        )
        client.ping()
        client._request.assert_called_once_with(
            "GET", "/api/v1/news", params={"size": 1}
        )

    def test_ping_failure(self, client):
        client._request = MagicMock(return_value={"success": False, "message": "no"})
        with pytest.raises(CTM360CynaAPIError, match="API ping failed"):
            client.ping()


class TestGetNewsPage:
    def test_success(self, client):
        client._request = MagicMock(return_value={"success": True, "data": [1]})
        assert client.get_news_page(size=10) == {"success": True, "data": [1]}

    def test_search_after_param(self, client):
        client._request = MagicMock(return_value={"success": True, "data": []})
        client.get_news_page(size=10, search_after="cursor-1")
        _, kwargs = client._request.call_args
        assert kwargs["params"]["searchAfter"] == "cursor-1"

    def test_failure_raises(self, client):
        client._request = MagicMock(return_value={"success": False, "message": "bad"})
        with pytest.raises(CTM360CynaAPIError, match="API error"):
            client.get_news_page()


class TestGetAllNews:
    def test_single_page(self, client):
        client.get_news_page = MagicMock(
            return_value={"success": True, "data": [{"_id": "a"}], "hasMore": False}
        )
        assert client.get_all_news() == [{"_id": "a"}]
        client.get_news_page.assert_called_once()

    def test_paginates_until_no_more(self, client):
        client.get_news_page = MagicMock(
            side_effect=[
                {"data": [{"_id": "a"}], "hasMore": True, "nextSearchAfter": "c1"},
                {"data": [{"_id": "b"}], "hasMore": False, "nextSearchAfter": None},
            ]
        )
        result = client.get_all_news(page_size=1)
        assert [i["_id"] for i in result] == ["a", "b"]
        assert client.get_news_page.call_count == 2

    def test_stops_when_no_cursor(self, client):
        client.get_news_page = MagicMock(
            return_value={
                "data": [{"_id": "a"}],
                "hasMore": True,
                "nextSearchAfter": None,
            }
        )
        result = client.get_all_news()
        assert len(result) == 1
        client.get_news_page.assert_called_once()

    def test_respects_max_pages(self, client):
        client.get_news_page = MagicMock(
            return_value={
                "data": [{"_id": "x"}],
                "hasMore": True,
                "nextSearchAfter": "c",
            }
        )
        result = client.get_all_news(page_size=1, max_pages=3)
        assert client.get_news_page.call_count == 3
        assert len(result) == 3


class TestParseRetryAfter:
    def test_none_returns_fallback(self, client):
        assert client._parse_retry_after(None, 7) == 7

    def test_integer_seconds(self, client):
        assert client._parse_retry_after("10", 7) == 10

    def test_negative_seconds_clamped_to_zero(self, client):
        assert client._parse_retry_after("-5", 7) == 0

    def test_malformed_value_returns_fallback(self, client):
        assert client._parse_retry_after("soon", 7) == 7

    def test_future_http_date_returns_positive_delay(self, client):
        assert client._parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT", 7) > 0

    def test_far_future_http_date_capped_at_max(self, client):
        # A far-future HTTP-date must not pin the connector sleeping for years;
        # the computed delay is capped at the configured maximum.
        assert (
            client._parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT", 7)
            == client._max_retry_after
        )

    def test_huge_integer_seconds_capped_at_max(self, client):
        # An absurdly large delay-seconds value is also capped.
        assert client._parse_retry_after("999999999", 7) == client._max_retry_after

    def test_past_http_date_clamped_to_zero(self, client):
        assert client._parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", 7) == 0

    def test_unparseable_date_returning_none_uses_fallback(self, client, monkeypatch):
        # Some Python versions return None (instead of raising) for an
        # unparseable HTTP-date; that path must also fall back to the backoff.
        monkeypatch.setattr(
            "ctm360_cyna_client.api_client.parsedate_to_datetime",
            lambda _value: None,
        )
        assert client._parse_retry_after("whenever", 7) == 7


class TestApiError:
    def test_attributes(self):
        err = CTM360CynaAPIError("nope", status_code=500)
        assert err.status_code == 500
        assert str(err) == "nope"

    def test_default_status(self):
        assert CTM360CynaAPIError("nope").status_code is None
