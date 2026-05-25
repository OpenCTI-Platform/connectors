"""Tests for BaseClientApi — targeting 100% coverage of base_client_api.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk.client.base_client_api import BaseClientApi
from connectors_sdk.client.exceptions import (
    ApiClientError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Create a BaseClientApi instance with retries disabled for fast tests."""
    return BaseClientApi("https://api.example.com", max_retries=0)


@pytest.fixture
def client_with_retries():
    """Create a BaseClientApi with 2 retries and minimal backoff."""
    return BaseClientApi("https://api.example.com", max_retries=2, backoff_factor=0.01)


def _mock_response(
    status_code: int = 200,
    json_data=None,
    text: str = "",
    headers: dict | None = None,
    ok: bool | None = None,
):
    """Create a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = ok if ok is not None else (200 <= status_code < 400)
    resp.json.return_value = json_data
    resp.text = text
    resp.headers = headers or {}
    resp.content = (text or "").encode()
    return resp


# ===========================================================================
# Initialization
# ===========================================================================


class TestInit:
    def test_base_url_trailing_slash_stripped(self):
        client = BaseClientApi("https://api.example.com/")
        assert client._base_url == "https://api.example.com"

    def test_default_headers(self):
        client = BaseClientApi("https://api.example.com")
        assert client._session.headers["Accept"] == "application/json"

    def test_custom_headers(self):
        client = BaseClientApi(
            "https://api.example.com", headers={"X-API-KEY": "secret"}
        )
        assert client._session.headers["X-API-KEY"] == "secret"

    def test_basic_auth(self):
        client = BaseClientApi("https://api.example.com", auth=("user", "pass"))
        assert client._session.auth == ("user", "pass")

    def test_ssl_verify_false(self):
        client = BaseClientApi("https://api.example.com", ssl_verify=False)
        assert client._session.verify is False

    def test_timeout_stored(self):
        client = BaseClientApi("https://api.example.com", timeout=30)
        assert client._timeout == 30


# ===========================================================================
# HTTP Methods
# ===========================================================================


class TestHttpMethods:
    def test_get(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"key": "value"})
            result = client._get("/endpoint", params={"q": "test"})
            assert result == {"key": "value"}
            mock_req.assert_called_once()
            args, kwargs = mock_req.call_args
            assert args[0] == "GET"
            assert kwargs["params"] == {"q": "test"}

    def test_post_json(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"id": 1})
            result = client._post("/endpoint", json={"name": "test"})
            assert result == {"id": 1}
            _, kwargs = mock_req.call_args
            assert kwargs["json"] == {"name": "test"}

    def test_post_data(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"ok": True})
            result = client._post("/endpoint", data=b"raw")
            assert result == {"ok": True}
            _, kwargs = mock_req.call_args
            assert kwargs["data"] == b"raw"

    def test_put(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"updated": True})
            result = client._put("/endpoint", json={"name": "new"})
            assert result == {"updated": True}
            args, _ = mock_req.call_args
            assert args[0] == "PUT"

    def test_patch(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"patched": True})
            result = client._patch("/endpoint", json={"field": "val"})
            assert result == {"patched": True}
            args, _ = mock_req.call_args
            assert args[0] == "PATCH"

    def test_delete(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"deleted": True})
            result = client._delete("/endpoint")
            assert result == {"deleted": True}
            args, _ = mock_req.call_args
            assert args[0] == "DELETE"

    def test_get_raw(self, client):
        raw_resp = _mock_response(status_code=200, text="binary content")
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = raw_resp
            result = client._get_raw("/download")
            assert result is raw_resp

    def test_get_raw_with_stream(self, client):
        raw_resp = _mock_response(status_code=200)
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = raw_resp
            client._get_raw("/download", stream=True)
            _, kwargs = mock_req.call_args
            assert kwargs["stream"] is True

    def test_204_returns_none(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(status_code=204)
            result = client._delete("/resource/1")
            assert result is None


# ===========================================================================
# Error Handling
# ===========================================================================


class TestErrorHandling:
    def test_401_raises_unauthorized(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=401, ok=False, json_data={"error": "unauthorized"}
            )
            with pytest.raises(ApiUnauthorizedError) as exc_info:
                client._get("/secure")
            assert exc_info.value.status_code == 401

    def test_403_raises_unauthorized(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=403, ok=False, json_data={"error": "forbidden"}
            )
            with pytest.raises(ApiUnauthorizedError) as exc_info:
                client._get("/secure")
            assert exc_info.value.status_code == 403

    def test_404_raises_not_found(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=404, ok=False, json_data={"error": "not found"}
            )
            with pytest.raises(ApiNotFoundError) as exc_info:
                client._get("/missing")
            assert exc_info.value.status_code == 404

    def test_429_raises_rate_limit_no_retries(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=429,
                ok=False,
                headers={"Retry-After": "30"},
                json_data={"error": "too many requests"},
            )
            with pytest.raises(ApiRateLimitError) as exc_info:
                client._get("/endpoint")
            assert exc_info.value.retry_after == 30.0

    def test_500_raises_server_error_no_retries(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=500, ok=False, text="Internal Server Error"
            )
            with pytest.raises(ApiServerError) as exc_info:
                client._get("/endpoint")
            assert exc_info.value.status_code == 500

    def test_422_raises_client_error(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=422, ok=False, json_data={"detail": "validation error"}
            )
            with pytest.raises(ApiClientError) as exc_info:
                client._post("/endpoint", json={})
            assert exc_info.value.status_code == 422

    def test_safe_response_body_json(self, client):
        resp = _mock_response(status_code=400, ok=False, json_data={"msg": "bad"})
        with patch.object(client._session, "request", return_value=resp):
            with pytest.raises(ApiClientError) as exc_info:
                client._get("/bad")
            assert exc_info.value.response_body == {"msg": "bad"}

    def test_safe_response_body_text_fallback(self, client):
        resp = _mock_response(status_code=400, ok=False, text="plain error")
        resp.json.side_effect = ValueError("No JSON")
        with patch.object(client._session, "request", return_value=resp):
            with pytest.raises(ApiClientError) as exc_info:
                client._get("/bad")
            assert exc_info.value.response_body == "plain error"

    def test_safe_response_body_empty(self, client):
        resp = _mock_response(status_code=400, ok=False, text="")
        resp.json.side_effect = ValueError("No JSON")
        with patch.object(client._session, "request", return_value=resp):
            with pytest.raises(ApiClientError) as exc_info:
                client._get("/bad")
            assert exc_info.value.response_body is None


# ===========================================================================
# Retry Logic
# ===========================================================================


class TestRetries:
    @patch("connectors_sdk.client.base_client_api.time.sleep")
    def test_429_retries_then_succeeds(self, mock_sleep, client_with_retries):
        rate_limited = _mock_response(
            status_code=429, ok=False, headers={"Retry-After": "1"}
        )
        success = _mock_response(json_data={"ok": True})
        with patch.object(
            client_with_retries._session, "request", side_effect=[rate_limited, success]
        ):
            result = client_with_retries._get("/endpoint")
            assert result == {"ok": True}
            mock_sleep.assert_called_once_with(1.0)

    @patch("connectors_sdk.client.base_client_api.time.sleep")
    def test_429_exhausts_retries(self, mock_sleep, client_with_retries):
        rate_limited = _mock_response(
            status_code=429, ok=False, headers={"Retry-After": "5"}
        )
        with patch.object(
            client_with_retries._session,
            "request",
            return_value=rate_limited,
        ):
            with pytest.raises(ApiRateLimitError):
                client_with_retries._get("/endpoint")
            # 2 retries = 2 sleeps before raising
            assert mock_sleep.call_count == 2

    @patch("connectors_sdk.client.base_client_api.time.sleep")
    def test_500_retries_then_succeeds(self, mock_sleep, client_with_retries):
        error_resp = _mock_response(status_code=500, ok=False, text="error")
        success = _mock_response(json_data={"ok": True})
        with patch.object(
            client_with_retries._session,
            "request",
            side_effect=[error_resp, success],
        ):
            result = client_with_retries._get("/endpoint")
            assert result == {"ok": True}
            mock_sleep.assert_called_once()

    @patch("connectors_sdk.client.base_client_api.time.sleep")
    def test_500_exhausts_retries(self, mock_sleep, client_with_retries):
        error_resp = _mock_response(status_code=503, ok=False, text="unavailable")
        with patch.object(
            client_with_retries._session,
            "request",
            return_value=error_resp,
        ):
            with pytest.raises(ApiServerError) as exc_info:
                client_with_retries._get("/endpoint")
            assert exc_info.value.status_code == 503
            assert mock_sleep.call_count == 2

    @patch("connectors_sdk.client.base_client_api.time.sleep")
    def test_429_backoff_without_retry_after_header(self, mock_sleep):
        client = BaseClientApi(
            "https://api.example.com", max_retries=1, backoff_factor=0.5
        )
        rate_limited = _mock_response(status_code=429, ok=False)
        success = _mock_response(json_data={"ok": True})
        with patch.object(
            client._session, "request", side_effect=[rate_limited, success]
        ):
            result = client._get("/endpoint")
            assert result == {"ok": True}
            # backoff_factor * 2^(attempt-1) = 0.5 * 1 = 0.5
            mock_sleep.assert_called_once_with(0.5)

    @patch("connectors_sdk.client.base_client_api.time.sleep")
    def test_retry_after_non_numeric_ignored(self, mock_sleep):
        client = BaseClientApi(
            "https://api.example.com", max_retries=1, backoff_factor=0.1
        )
        rate_limited = _mock_response(
            status_code=429, ok=False, headers={"Retry-After": "not-a-number"}
        )
        success = _mock_response(json_data={"ok": True})
        with patch.object(
            client._session, "request", side_effect=[rate_limited, success]
        ):
            result = client._get("/endpoint")
            assert result == {"ok": True}
            # Falls back to backoff: 0.1 * 2^0 = 0.1
            mock_sleep.assert_called_once_with(0.1)


# ===========================================================================
# Rate Limiting (interval between requests)
# ===========================================================================


class TestRateLimit:
    @patch("connectors_sdk.client.base_client_api.time.sleep")
    @patch("connectors_sdk.client.base_client_api.time.monotonic")
    def test_rate_limit_interval_enforced(self, mock_monotonic, mock_sleep):
        client = BaseClientApi(
            "https://api.example.com", rate_limit_interval=2.0, max_retries=0
        )
        # First request: _last_request_time = 0, monotonic returns 0.5
        # elapsed = 0.5, need to wait 1.5s
        mock_monotonic.return_value = 0.5
        client._last_request_time = 0.1  # Simulate a previous request

        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={})
            client._get("/endpoint")
            # elapsed = 0.5 - 0.1 = 0.4 < 2.0 => sleep(1.6)
            mock_sleep.assert_called_once_with(pytest.approx(1.6, abs=0.01))

    @patch("connectors_sdk.client.base_client_api.time.sleep")
    @patch("connectors_sdk.client.base_client_api.time.monotonic")
    def test_rate_limit_not_applied_when_enough_time_passed(
        self, mock_monotonic, mock_sleep
    ):
        client = BaseClientApi(
            "https://api.example.com", rate_limit_interval=1.0, max_retries=0
        )
        mock_monotonic.return_value = 10.0
        client._last_request_time = 5.0  # 5 seconds ago

        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={})
            client._get("/endpoint")
            mock_sleep.assert_not_called()

    def test_rate_limit_zero_interval_skipped(self):
        client = BaseClientApi(
            "https://api.example.com", rate_limit_interval=0, max_retries=0
        )
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={})
            with patch(
                "connectors_sdk.client.base_client_api.time.sleep"
            ) as mock_sleep:
                client._get("/endpoint")
                mock_sleep.assert_not_called()


# ===========================================================================
# URL Building
# ===========================================================================


class TestUrlBuilding:
    def test_build_url_with_leading_slash(self):
        client = BaseClientApi("https://api.example.com")
        assert (
            client._build_url("/v1/endpoint") == "https://api.example.com/v1/endpoint"
        )

    def test_build_url_without_leading_slash(self):
        client = BaseClientApi("https://api.example.com")
        assert client._build_url("v1/endpoint") == "https://api.example.com/v1/endpoint"

    def test_build_url_absolute_url_passed(self):
        client = BaseClientApi("https://api.example.com")
        # urljoin with absolute URLs keeps the absolute
        url = client._build_url("https://other.com/path")
        assert url == "https://other.com/path"


# ===========================================================================
# Response Parsing
# ===========================================================================


class TestParseResponse:
    def test_parse_response_returns_json(self, client):
        resp = _mock_response(json_data={"data": [1, 2, 3]})
        result = client._parse_response(resp)
        assert result == {"data": [1, 2, 3]}

    def test_parse_response_can_be_overridden(self):
        class TextClient(BaseClientApi):
            def _parse_response(self, response):
                return response.text

        tc = TextClient("https://api.example.com", max_retries=0)
        with patch.object(tc._session, "request") as mock_req:
            mock_req.return_value = _mock_response(text="hello")
            result = tc._get("/text")
            assert result == "hello"


# ===========================================================================
# Pagination: Offset
# ===========================================================================


class TestPaginateOffset:
    def test_single_page(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data=[{"id": 1}, {"id": 2}])
            pages = list(client._paginate_offset("/items", page_size=10))
            assert pages == [[{"id": 1}, {"id": 2}]]

    def test_multiple_pages(self, client):
        page1 = [{"id": i} for i in range(10)]
        page2 = [{"id": i} for i in range(10, 15)]
        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [
                _mock_response(json_data=page1),
                _mock_response(json_data=page2),
            ]
            pages = list(client._paginate_offset("/items", page_size=10))
            assert len(pages) == 2
            assert pages[0] == page1
            assert pages[1] == page2

    def test_empty_first_page(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data=[])
            pages = list(client._paginate_offset("/items", page_size=10))
            assert pages == []

    def test_results_key(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"results": [{"id": 1}], "total": 1}
            )
            pages = list(
                client._paginate_offset("/items", page_size=10, results_key="results")
            )
            assert pages == [[{"id": 1}]]

    def test_custom_params(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data=[])
            list(
                client._paginate_offset(
                    "/items",
                    params={"filter": "active"},
                    page_param="p",
                    page_size_param="size",
                    page_size=50,
                    start_page=0,
                )
            )
            _, kwargs = mock_req.call_args
            assert kwargs["params"]["filter"] == "active"
            assert kwargs["params"]["p"] == 0
            assert kwargs["params"]["size"] == 50


# ===========================================================================
# Pagination: Cursor
# ===========================================================================


class TestPaginateCursor:
    def test_single_page_no_cursor(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"data": [{"id": 1}], "next": None}
            )
            pages = list(client._paginate_cursor("/items", results_key="data"))
            assert pages == [[{"id": 1}]]

    def test_multiple_pages_with_next_cursor(self, client):
        resp1 = _mock_response(json_data={"data": [{"id": 1}], "next": "cursor_abc"})
        resp2 = _mock_response(json_data={"data": [{"id": 2}], "next": None})
        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [resp1, resp2]
            pages = list(client._paginate_cursor("/items", results_key="data"))
            assert pages == [[{"id": 1}], [{"id": 2}]]
            # Verify cursor was sent in second request
            _, kwargs2 = mock_req.call_args_list[1]
            assert kwargs2["params"]["cursor"] == "cursor_abc"

    def test_meta_next_cursor(self, client):
        resp1 = _mock_response(
            json_data={
                "data": [{"id": 1}],
                "meta": {"next_cursor": "xyz"},
            }
        )
        resp2 = _mock_response(
            json_data={"data": [{"id": 2}], "meta": {"next_cursor": None}}
        )
        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [resp1, resp2]
            pages = list(client._paginate_cursor("/items", results_key="data"))
            assert len(pages) == 2

    def test_custom_cursor_extractor(self, client):
        resp1 = _mock_response(
            json_data={"items": [1, 2], "pagination": {"token": "next1"}}
        )
        resp2 = _mock_response(json_data={"items": [3], "pagination": {"token": None}})

        def extract(resp):
            return resp.get("pagination", {}).get("token")

        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [resp1, resp2]
            pages = list(
                client._paginate_cursor(
                    "/items",
                    results_key="items",
                    cursor_extractor=extract,
                )
            )
            assert pages == [[1, 2], [3]]

    def test_empty_results_stops(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"data": [], "next": "something"}
            )
            pages = list(client._paginate_cursor("/items", results_key="data"))
            assert pages == []

    def test_response_is_list(self, client):
        resp1 = _mock_response(json_data=[{"id": 1}])
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = resp1
            pages = list(client._paginate_cursor("/items"))
            # List response, no cursor extraction possible -> 1 page
            assert pages == [[{"id": 1}]]

    def test_response_dict_auto_detect_results_key(self, client):
        """When results_key is None and response is a dict, try common keys."""
        resp = _mock_response(json_data={"results": [{"id": 1}], "next": None})
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = resp
            pages = list(client._paginate_cursor("/items"))
            assert pages == [[{"id": 1}]]

    def test_response_dict_no_common_key_returns_empty(self, client):
        """When no common key matches, empty list stops pagination."""
        resp = _mock_response(json_data={"foo": "bar"})
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = resp
            pages = list(client._paginate_cursor("/items"))
            assert pages == []

    def test_custom_cursor_param(self, client):
        resp1 = _mock_response(json_data={"data": [1], "next": "tok"})
        resp2 = _mock_response(json_data={"data": [], "next": None})
        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [resp1, resp2]
            list(
                client._paginate_cursor(
                    "/items", results_key="data", cursor_param="page_token"
                )
            )
            _, kwargs2 = mock_req.call_args_list[1]
            assert kwargs2["params"]["page_token"] == "tok"

    def test_response_non_dict_non_list(self, client):
        """When response is neither list nor dict, wrap in a list."""
        with patch.object(client._session, "request") as mock_req:
            # Simulate a response that's a plain string (unusual but possible)
            mock_req.return_value = _mock_response(json_data="just-a-string")
            pages = list(client._paginate_cursor("/items"))
            assert pages == [["just-a-string"]]


# ===========================================================================
# Pagination: Links (HATEOAS)
# ===========================================================================


class TestPaginateLinks:
    def test_single_page_no_next(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"items": [{"id": 1}], "_links": {"next": None}}
            )
            pages = list(client._paginate_links("/items"))
            assert pages == [[{"id": 1}]]

    def test_multiple_pages_via_links(self, client):
        first_resp = _mock_response(
            json_data={
                "items": [{"id": 1}],
                "_links": {"next": {"href": "/items?page=2"}},
            }
        )
        second_resp = _mock_response(
            json_data={
                "items": [{"id": 2}],
                "_links": {"next": None},
            }
        )

        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [first_resp, second_resp]
            pages = list(client._paginate_links("/items"))
            assert pages == [[{"id": 1}], [{"id": 2}]]

    def test_next_url_extractor(self, client):
        first_resp = _mock_response(
            json_data={
                "data": [1, 2],
                "pagination": {"next_page": "/items?after=2"},
            }
        )
        second_resp = _mock_response(
            json_data={
                "data": [3],
                "pagination": {"next_page": None},
            }
        )

        def extractor(resp):
            return resp.get("pagination", {}).get("next_page")

        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [first_resp, second_resp]
            pages = list(
                client._paginate_links(
                    "/items",
                    results_key="data",
                    next_url_extractor=extractor,
                )
            )
            assert pages == [[1, 2], [3]]

    def test_next_url_field(self, client):
        first_resp = _mock_response(
            json_data={"items": [1], "next_url": "/items?page=2"}
        )
        second_resp = _mock_response(json_data={"items": [2], "next_url": None})

        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [first_resp, second_resp]
            pages = list(client._paginate_links("/items"))
            assert pages == [[1], [2]]

    def test_response_is_list(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data=[{"id": 1}])
            pages = list(client._paginate_links("/items"))
            # List response, no links -> single page
            assert pages == [[{"id": 1}]]

    def test_empty_results_stops(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"items": [], "_links": {"next": {"href": "/next"}}}
            )
            pages = list(client._paginate_links("/items"))
            assert pages == []

    def test_second_page_error_raises(self, client):
        first_resp = _mock_response(
            json_data={
                "items": [{"id": 1}],
                "_links": {"next": {"href": "/items?page=2"}},
            }
        )
        error_resp = _mock_response(status_code=500, ok=False, text="Server Error")
        error_resp.json.side_effect = ValueError("no json")

        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [first_resp, error_resp]
            with pytest.raises(ApiServerError) as exc_info:
                list(client._paginate_links("/items"))
            assert exc_info.value.status_code == 500

    def test_response_dict_auto_detect_data_key(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"data": [1, 2, 3]})
            pages = list(client._paginate_links("/items"))
            assert pages == [[1, 2, 3]]

    def test_response_dict_no_common_key(self, client):
        """Dict with no common results key returns empty, stopping pagination."""
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data={"custom_field": [1, 2]})
            pages = list(client._paginate_links("/items"))
            assert pages == []

    def test_response_non_dict_non_list(self, client):
        """When response is neither list nor dict, wrap in a list."""
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(json_data="a-string")
            pages = list(client._paginate_links("/items"))
            assert pages == [["a-string"]]


# ===========================================================================
# Exceptions module
# ===========================================================================


class TestExceptions:
    def test_api_client_error_attributes(self):
        err = ApiClientError("test", status_code=418, response_body={"x": 1})
        assert str(err) == "test"
        assert err.status_code == 418
        assert err.response_body == {"x": 1}

    def test_api_rate_limit_error_retry_after(self):
        err = ApiRateLimitError("limited", retry_after=60.0)
        assert err.retry_after == 60.0
        assert err.status_code == 429

    def test_api_rate_limit_error_defaults(self):
        err = ApiRateLimitError("limited")
        assert err.retry_after is None
        assert err.status_code == 429

    def test_api_unauthorized_error(self):
        err = ApiUnauthorizedError("no access", status_code=401)
        assert isinstance(err, ApiClientError)

    def test_api_not_found_error(self):
        err = ApiNotFoundError("missing", status_code=404)
        assert isinstance(err, ApiClientError)

    def test_api_server_error(self):
        err = ApiServerError("down", status_code=502)
        assert isinstance(err, ApiClientError)
        assert err.status_code == 502
