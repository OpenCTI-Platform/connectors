"""Tests for the CTM360 HackerView HTTP client."""

from unittest.mock import MagicMock

import pytest
import requests
from ctm360_hv_client.api_client import CTM360HvAPIError, CTM360HvClient


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
    return CTM360HvClient(
        helper=MagicMock(), base_url="https://hackerview.example.com/", api_key="secret"
    )


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("ctm360_hv_client.api_client.time.sleep", lambda *_: None)


class TestInit:
    def test_base_url_stripped(self, client):
        assert client.base_url == "https://hackerview.example.com"

    def test_api_key_header(self, client):
        assert client.session.headers["api-key"] == "secret"


class TestRequest:
    def test_success_dict(self, client):
        client.session.request = MagicMock(
            return_value=FakeResponse(200, {"issues": [], "count": 0})
        )
        assert client._request("GET", "/x") == {"issues": [], "count": 0}

    def test_success_list_wrapped(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(200, [1, 2]))
        assert client._request("GET", "/x") == {"data": [1, 2]}

    def test_204(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(204))
        assert client._request("GET", "/x") == {"issues": [], "count": 0}

    def test_429_then_success(self, client):
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(429, headers={"Retry-After": "1"}),
                FakeResponse(200, {"ok": True}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_429_exhausted(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(429))
        with pytest.raises(CTM360HvAPIError, match="Max retries exceeded"):
            client._request("GET", "/x")

    def test_5xx_then_success(self, client):
        client.session.request = MagicMock(
            side_effect=[FakeResponse(503), FakeResponse(200, {"ok": True})]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_504_then_success(self, client):
        # 504 is part of the 5xx range and must be retried (status >= 500).
        client.session.request = MagicMock(
            side_effect=[FakeResponse(504), FakeResponse(200, {"ok": True})]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_429_http_date_retry_after_does_not_crash(self, client):
        # An HTTP-date Retry-After must not raise ValueError and abort the loop.
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(
                    429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
                ),
                FakeResponse(200, {"ok": True}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_non_retryable_http_error(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(404))
        with pytest.raises(CTM360HvAPIError) as exc:
            client._request("GET", "/x")
        assert exc.value.status_code == 404

    def test_connection_error(self, client):
        client.session.request = MagicMock(
            side_effect=requests.exceptions.ConnectionError("boom")
        )
        with pytest.raises(CTM360HvAPIError, match="Connection error"):
            client._request("GET", "/x")

    def test_timeout(self, client):
        client.session.request = MagicMock(
            side_effect=requests.exceptions.Timeout("slow")
        )
        with pytest.raises(CTM360HvAPIError, match="Request timeout"):
            client._request("GET", "/x")


class TestParseRetryAfter:
    def test_integer_seconds(self, client):
        assert client._parse_retry_after("3", 9) == 3

    def test_float_seconds(self, client):
        assert client._parse_retry_after("2.5", 9) == 2

    def test_http_date_falls_back(self, client):
        assert client._parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", 9) == 9

    def test_missing_falls_back(self, client):
        assert client._parse_retry_after(None, 9) == 9

    def test_negative_is_clamped(self, client):
        assert client._parse_retry_after("-5", 9) == 0


class TestExtractItems:
    def test_issues(self, client):
        assert client._extract_items({"issues": [1, 2]}) == [1, 2]

    def test_issues_non_list_ignored(self, client):
        # A non-list `issues` payload must not be returned (it would break
        # list.extend downstream).
        assert client._extract_items({"issues": {"not": "a list"}}) == []

    def test_data_list(self, client):
        assert client._extract_items({"data": [3]}) == [3]

    def test_empty(self, client):
        assert client._extract_items({}) == []


class TestPaginatedRequest:
    def test_single_page(self, client):
        client._request = MagicMock(return_value={"issues": [1, 2], "count": 2})
        assert client._paginated_request("GET", "/api/v2/issues") == [1, 2]
        client._request.assert_called_once()

    def test_multiple_pages(self, client):
        client._request = MagicMock(
            side_effect=[
                {"data": list(range(100)), "count": 150},
                {"data": list(range(50)), "count": 150},
            ]
        )
        result = client._paginated_request(
            "GET", "/api/v2/assets/domain", page_size=100
        )
        assert len(result) == 150
        assert client._request.call_count == 2

    def test_count_absent_does_not_truncate(self, client):
        # A full first page with no `count` must not stop pagination after the
        # first page (regression: total defaulted to 0 -> always stopped).
        client._request = MagicMock(
            side_effect=[
                {"issues": list(range(100))},  # full page, no count
                {"issues": list(range(10))},  # short page -> stop
            ]
        )
        result = client._paginated_request("GET", "/api/v2/issues", page_size=100)
        assert len(result) == 110
        assert client._request.call_count == 2


class TestEndpoints:
    def test_ping(self, client):
        client._request = MagicMock(return_value={})
        client.ping()
        client._request.assert_called_once_with(
            "GET", "/api/v2/issues", params={"size": "1"}
        )

    def test_get_issues_with_first_seen(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_issues(first_seen="2026-01-01")
        _, kwargs = client._paginated_request.call_args
        assert kwargs["params"]["first_seen"] == "2026-01-01"

    def test_get_resolved_issues(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_resolved_issues(from_date="2026-01-01", to_date="2026-02-01")
        args, kwargs = client._paginated_request.call_args
        assert args[1] == "/api/v2/resolved_issues"
        assert kwargs["params"]["from_date"] == "2026-01-01"
        assert kwargs["params"]["to_date"] == "2026-02-01"

    def test_get_domain_assets(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_domain_assets()
        args, _ = client._paginated_request.call_args
        assert args[1] == "/api/v2/assets/domain"

    def test_get_host_assets(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_host_assets()
        args, _ = client._paginated_request.call_args
        assert args[1] == "/api/v2/assets/host"

    def test_get_ip_assets(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_ip_assets()
        args, _ = client._paginated_request.call_args
        assert args[1] == "/api/v2/assets/ip_address"

    def test_get_issue_issues_wrapper(self, client):
        client._request = MagicMock(return_value={"issues": [{"ticket_id": "1"}]})
        assert client.get_issue("1") == {"ticket_id": "1"}

    def test_get_issue_data_wrapper(self, client):
        client._request = MagicMock(return_value={"data": {"id": "1"}})
        assert client.get_issue("1") == {"id": "1"}

    def test_get_issue_flat(self, client):
        client._request = MagicMock(return_value={"ticket_id": "1", "status": "open"})
        assert client.get_issue("1") == {"ticket_id": "1", "status": "open"}

    def test_get_issue_empty_issues(self, client):
        client._request = MagicMock(return_value={"issues": []})
        assert client.get_issue("1") == {}


class TestApiError:
    def test_attributes(self):
        err = CTM360HvAPIError("nope", status_code=500)
        assert err.status_code == 500
        assert str(err) == "nope"

    def test_default_status(self):
        assert CTM360HvAPIError("nope").status_code is None
