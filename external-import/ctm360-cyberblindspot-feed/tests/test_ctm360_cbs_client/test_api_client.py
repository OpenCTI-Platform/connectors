"""Tests for the CTM360 CyberBlindSpot HTTP client."""

from unittest.mock import MagicMock

import pytest
import requests
from ctm360_cbs_client.api_client import CTM360CbsAPIError, CTM360CbsClient


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
    return CTM360CbsClient(
        helper=MagicMock(), base_url="https://cbs.example.com/", api_key="secret"
    )


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("ctm360_cbs_client.api_client.time.sleep", lambda *_: None)


class TestClientInit:
    def test_base_url_trailing_slash_stripped(self, client):
        assert client.base_url == "https://cbs.example.com"

    def test_api_key_header_set(self, client):
        assert client.session.headers["api-key"] == "secret"


class TestRequest:
    def test_success_dict(self, client):
        client.session.request = MagicMock(
            return_value=FakeResponse(200, {"count": 1, "incident_list": []})
        )
        assert client._request("GET", "/x") == {"count": 1, "incident_list": []}

    def test_success_list_wrapped(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(200, [1, 2, 3]))
        assert client._request("GET", "/x") == {"data": [1, 2, 3]}

    def test_204_returns_empty_payload(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(204))
        assert client._request("GET", "/x") == {"incident_list": [], "count": 0}

    def test_429_then_success(self, client):
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(429, headers={"Retry-After": "1"}),
                FakeResponse(200, {"ok": True}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_429_without_retry_after_header(self, client):
        client.session.request = MagicMock(
            side_effect=[FakeResponse(429), FakeResponse(200, {"ok": True})]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_429_http_date_retry_after_does_not_crash(self, client):
        # An HTTP-date Retry-After is valid per RFC 9110 but not an int; the
        # client must fall back to the computed backoff instead of raising.
        client.session.request = MagicMock(
            side_effect=[
                FakeResponse(
                    429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
                ),
                FakeResponse(200, {"ok": True}),
            ]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_429_exhausts_retries(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(429))
        with pytest.raises(CTM360CbsAPIError, match="Max retries exceeded"):
            client._request("GET", "/x")

    def test_5xx_then_success(self, client):
        client.session.request = MagicMock(
            side_effect=[FakeResponse(503), FakeResponse(200, {"ok": True})]
        )
        assert client._request("GET", "/x") == {"ok": True}

    def test_504_is_retried(self, client):
        # 504 (and any 5xx) must be treated as a transient, retryable failure.
        client.session.request = MagicMock(
            side_effect=[FakeResponse(504), FakeResponse(200, {"ok": True})]
        )
        assert client._request("GET", "/x") == {"ok": True}
        assert client.session.request.call_count == 2

    def test_non_retryable_http_error(self, client):
        client.session.request = MagicMock(return_value=FakeResponse(404))
        with pytest.raises(CTM360CbsAPIError) as exc:
            client._request("GET", "/x")
        assert exc.value.status_code == 404

    def test_connection_error_retries_then_raises(self, client):
        client.session.request = MagicMock(
            side_effect=requests.exceptions.ConnectionError("boom")
        )
        with pytest.raises(CTM360CbsAPIError, match="Connection error"):
            client._request("GET", "/x")

    def test_timeout_retries_then_raises(self, client):
        client.session.request = MagicMock(
            side_effect=requests.exceptions.Timeout("slow")
        )
        with pytest.raises(CTM360CbsAPIError, match="Request timeout"):
            client._request("GET", "/x")


class TestParseRetryAfter:
    def test_integer_seconds(self, client):
        assert client._parse_retry_after("5", default=99) == 5

    def test_float_seconds_truncated(self, client):
        assert client._parse_retry_after("2.9", default=99) == 2

    def test_missing_value_uses_default(self, client):
        assert client._parse_retry_after(None, default=42) == 42

    def test_http_date_uses_default(self, client):
        assert (
            client._parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", default=7) == 7
        )

    def test_negative_clamped_to_zero(self, client):
        assert client._parse_retry_after("-10", default=99) == 0


class TestExtractItems:
    def test_incident_list(self, client):
        assert client._extract_items({"incident_list": [1, 2]}) == [1, 2]

    def test_data_list(self, client):
        assert client._extract_items({"data": [3, 4]}) == [3, 4]

    def test_data_not_a_list(self, client):
        assert client._extract_items({"data": "nope"}) == []

    def test_incident_list_not_a_list(self, client):
        # A non-list incident_list must not be returned (would break extend()).
        assert client._extract_items({"incident_list": None}) == []
        assert client._extract_items({"incident_list": {"x": 1}}) == []

    def test_empty(self, client):
        assert client._extract_items({}) == []


class TestPaginatedRequest:
    def test_single_page(self, client):
        client._request = MagicMock(
            return_value={"incident_list": [1, 2, 3], "count": 3}
        )
        result = client._paginated_request("GET", "/api/v2/incidents")
        assert result == [1, 2, 3]
        client._request.assert_called_once()

    def test_multiple_pages(self, client):
        page1 = {"data": list(range(200)), "count": 250}
        page2 = {"data": list(range(50)), "count": 250}
        client._request = MagicMock(side_effect=[page1, page2])
        result = client._paginated_request("GET", "/api/v2/leaks/x", page_size=200)
        assert len(result) == 250
        assert client._request.call_count == 2

    def test_paginates_when_count_absent(self, client):
        # Without a `count` field, pagination must continue on a full page and
        # only stop on a short page (previously total defaulted to 0 and
        # pagination wrongly stopped after the first page).
        page1 = {"data": list(range(200))}
        page2 = {"data": list(range(10))}
        client._request = MagicMock(side_effect=[page1, page2])
        result = client._paginated_request("GET", "/api/v2/leaks/x", page_size=200)
        assert len(result) == 210
        assert client._request.call_count == 2


class TestEndpoints:
    def test_ping(self, client):
        client._request = MagicMock(return_value={})
        client.ping()
        client._request.assert_called_once_with(
            "GET", "/api/v2/incidents", params={"size": 1}
        )

    def test_get_incidents_with_dates(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_incidents(date_from="2026-01-01", date_to="2026-02-01")
        _, kwargs = client._paginated_request.call_args
        assert kwargs["params"]["date_field"] == "updated"
        assert kwargs["params"]["date_from"] == "2026-01-01"
        assert kwargs["params"]["date_to"] == "2026-02-01"

    def test_get_malware_logs(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_malware_logs(date_from="2026-01-01")
        args, kwargs = client._paginated_request.call_args
        assert args[1] == "/api/v2/leaks/malware_logs"
        assert kwargs["page_size"] == 5000

    def test_get_breached_credentials(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_breached_credentials()
        args, _ = client._paginated_request.call_args
        assert args[1] == "/api/v2/leaks/breached_credentials"

    def test_get_card_leaks(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_card_leaks(date_to="2026-02-01")
        args, _ = client._paginated_request.call_args
        assert args[1] == "/api/v2/leaks/card_leaks"

    def test_get_domain_protection(self, client):
        client._paginated_request = MagicMock(return_value=[])
        client.get_domain_protection()
        args, _ = client._paginated_request.call_args
        assert args[1] == "/api/v2/domain_protection"

    def test_get_incident_wrapped(self, client):
        client._request = MagicMock(
            return_value={"incident": {"id": "1", "status": "x"}}
        )
        assert client.get_incident("INC 1") == {"id": "1", "status": "x"}

    def test_get_incident_list_wrapper(self, client):
        client._request = MagicMock(return_value={"incident_list": [{"id": "1"}]})
        assert client.get_incident("1") == {"id": "1"}

    def test_get_incident_empty_list(self, client):
        client._request = MagicMock(return_value={"incident_list": []})
        assert client.get_incident("1") == {}

    def test_get_incident_list_non_dict_element(self, client):
        # A non-dict element must not be returned: downstream callers call
        # .get(...) on the result and would crash on a string/list/None.
        client._request = MagicMock(return_value={"incident_list": ["oops"]})
        assert client.get_incident("1") == {}

    def test_get_incident_flat(self, client):
        client._request = MagicMock(return_value={"id": "1", "status": "open"})
        assert client.get_incident("1") == {"id": "1", "status": "open"}


class TestApiError:
    def test_error_attributes(self):
        error = CTM360CbsAPIError("nope", status_code=500)
        assert error.status_code == 500
        assert str(error) == "nope"

    def test_error_default_status(self):
        assert CTM360CbsAPIError("nope").status_code is None
