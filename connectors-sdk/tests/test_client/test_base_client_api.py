"""Tests for BaseClientApi — targeting 100% coverage of base_client_api.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk.client.base_client_api import BaseClientApi
from connectors_sdk.client.exceptions import (
    ApiClientError,
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from connectors_sdk.client.rate_limit import RateLimit, _RateLimitAdapter

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
    content_type: str | None = None,
):
    """Create a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = ok if ok is not None else (200 <= status_code < 400)
    resp.json.return_value = json_data
    resp.text = text
    h = dict(headers or {})
    if content_type:
        h["Content-Type"] = content_type
    resp.headers = h
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
        class CustomClient(BaseClientApi):
            @property
            def session_headers(self):
                return {"X-API-KEY": "secret"}

        client = CustomClient("https://api.example.com")
        assert client._session.headers["X-API-KEY"] == "secret"

    def test_basic_auth(self):
        class BasicAuthClient(BaseClientApi):
            def __init__(self, base_url, user, password):
                super().__init__(base_url)
                self._user = user
                self._password = password

            @property
            def _session(self):
                session = super()._session
                session.auth = (self._user, self._password)
                return session

        client = BasicAuthClient("https://api.example.com", "user", "pass")
        assert client._session.auth == ("user", "pass")

    def test_ssl_verify_false(self):
        client = BaseClientApi("https://api.example.com", ssl_verify=False)
        assert client._session.verify is False

    def test_timeout_stored(self):
        client = BaseClientApi("https://api.example.com", timeout=30)
        assert client._timeout == 30

    def test_session_is_lazy(self):
        """Session is not created until first access."""
        client = BaseClientApi("https://api.example.com")
        assert client._BaseClientApi__session is None
        # Access triggers creation
        _ = client._session
        assert client._BaseClientApi__session is not None

    def test_session_reused(self):
        """Same session object is returned on repeated access."""
        client = BaseClientApi("https://api.example.com")
        s1 = client._session
        s2 = client._session
        assert s1 is s2

    def test_session_headers_hook(self):
        """Subclass can provide dynamic headers via session_headers property."""

        class TokenClient(BaseClientApi):
            @property
            def session_headers(self):
                return {"Authorization": "Bearer dynamic-token"}

        tc = TokenClient("https://api.example.com")
        assert tc._session.headers["Authorization"] == "Bearer dynamic-token"

    def test_retry_strategy_configured(self):
        """Adapter has retry strategy with correct max_retries."""
        client = BaseClientApi("https://api.example.com", max_retries=5)
        adapter = client._session.get_adapter("https://example.com")
        assert adapter.max_retries.total == 5


# ===========================================================================
# HTTP Methods
# ===========================================================================


class TestHttpMethods:
    def test_get(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"key": "value"}, content_type="application/json"
            )
            result = client._get("/endpoint", params={"q": "test"})
            assert result == {"key": "value"}
            mock_req.assert_called_once()
            args, kwargs = mock_req.call_args
            assert args[0] == "GET"
            assert kwargs["params"] == {"q": "test"}

    def test_post_json(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"id": 1}, content_type="application/json"
            )
            result = client._post("/endpoint", json={"name": "test"})
            assert result == {"id": 1}
            _, kwargs = mock_req.call_args
            assert kwargs["json"] == {"name": "test"}

    def test_post_data(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"ok": True}, content_type="application/json"
            )
            result = client._post("/endpoint", data=b"raw")
            assert result == {"ok": True}
            _, kwargs = mock_req.call_args
            assert kwargs["data"] == b"raw"

    def test_put(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"updated": True}, content_type="application/json"
            )
            result = client._put("/endpoint", json={"name": "new"})
            assert result == {"updated": True}
            args, _ = mock_req.call_args
            assert args[0] == "PUT"

    def test_patch(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"patched": True}, content_type="application/json"
            )
            result = client._patch("/endpoint", json={"field": "val"})
            assert result == {"patched": True}
            args, _ = mock_req.call_args
            assert args[0] == "PATCH"

    def test_delete(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"deleted": True}, content_type="application/json"
            )
            result = client._delete("/endpoint")
            assert result == {"deleted": True}
            args, _ = mock_req.call_args
            assert args[0] == "DELETE"

    def test_raw_request_returns_response_directly(self, client):
        """_raw_request returns the Response without parsing or error raising."""
        raw_resp = _mock_response(status_code=200, text="binary content")
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = raw_resp
            result = client._raw_request("GET", "/download", stream=True)
            assert result is raw_resp
            _, kwargs = mock_req.call_args
            assert kwargs["stream"] is True

    def test_raw_request_does_not_raise_on_error(self, client):
        """_raw_request bypasses error handling entirely."""
        error_resp = _mock_response(status_code=500, ok=False, text="error")
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = error_resp
            result = client._raw_request("GET", "/bad")
            assert result is error_resp

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

    def test_403_raises_forbidden(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=403, ok=False, json_data={"error": "forbidden"}
            )
            with pytest.raises(ApiForbiddenError) as exc_info:
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

    def test_429_raises_rate_limit(self, client):
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

    def test_429_without_retry_after_header(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=429,
                ok=False,
                json_data={"error": "too many requests"},
            )
            with pytest.raises(ApiRateLimitError) as exc_info:
                client._get("/endpoint")
            assert exc_info.value.retry_after is None

    def test_429_with_invalid_retry_after(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=429,
                ok=False,
                headers={"Retry-After": "not-a-number"},
                json_data={"error": "too many requests"},
            )
            with pytest.raises(ApiRateLimitError) as exc_info:
                client._get("/endpoint")
            assert exc_info.value.retry_after is None

    def test_429_with_http_date_retry_after(self, client):
        """Retry-After as HTTP-date is parsed into seconds."""
        from datetime import datetime, timezone

        future = datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
        http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=429,
                ok=False,
                headers={"Retry-After": http_date},
                json_data={"error": "too many requests"},
            )
            with pytest.raises(ApiRateLimitError) as exc_info:
                client._get("/endpoint")
            # Should be a non-negative float (the delta from now to the date)
            assert exc_info.value.retry_after is not None
            assert exc_info.value.retry_after >= 0

    def test_500_raises_server_error(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=500, ok=False, text="Internal Server Error"
            )
            with pytest.raises(ApiServerError) as exc_info:
                client._get("/endpoint")
            assert exc_info.value.status_code == 500

    def test_503_raises_server_error(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                status_code=503, ok=False, text="Service Unavailable"
            )
            with pytest.raises(ApiServerError) as exc_info:
                client._get("/endpoint")
            assert exc_info.value.status_code == 503

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
# RateLimit dataclass
# ===========================================================================


class TestRateLimitDataclass:
    def test_str_conversion(self):
        assert str(RateLimit(100, "minute")) == "100/minute"
        assert str(RateLimit(5000, "hour")) == "5000/hour"
        assert str(RateLimit(10, "second")) == "10/second"
        assert str(RateLimit(1, "day")) == "1/day"

    def test_adapter_accepts_rate_limit_instance(self):
        """_RateLimitAdapter accepts a RateLimit dataclass."""
        adapter = _RateLimitAdapter(
            rate_limit=RateLimit(1, "minute"), rate_limit_key="test"
        )
        mock_request = MagicMock(spec=requests.PreparedRequest)
        mock_request.url = "https://api.example.com/test"
        with patch.object(requests.adapters.HTTPAdapter, "send") as mock_send:
            mock_send.return_value = _mock_response()
            adapter.send(mock_request)
            # Second call hits the limit
            with pytest.raises(ApiRateLimitError):
                adapter.send(mock_request)


# ===========================================================================
# Rate Limiting (via limits library)
# ===========================================================================


class TestRateLimit:
    def test_rate_limit_not_configured(self):
        """No rate limit means adapter does not block."""
        adapter = _RateLimitAdapter(rate_limit=None)
        mock_request = MagicMock(spec=requests.PreparedRequest)
        mock_request.url = "https://api.example.com/test"
        with patch.object(requests.adapters.HTTPAdapter, "send") as mock_send:
            mock_send.return_value = _mock_response()
            adapter.send(mock_request)
            mock_send.assert_called_once()

    def test_rate_limit_blocks_when_exceeded(self):
        """Rate limit raises ApiRateLimitError when exceeded."""
        adapter = _RateLimitAdapter(rate_limit="1/minute", rate_limit_key="test")
        mock_request = MagicMock(spec=requests.PreparedRequest)
        mock_request.url = "https://api.example.com/test"

        with patch.object(requests.adapters.HTTPAdapter, "send") as mock_send:
            mock_send.return_value = _mock_response()
            # First call should succeed
            adapter.send(mock_request)
            # Second call should be rate limited
            with pytest.raises(ApiRateLimitError):
                adapter.send(mock_request)

    def test_client_with_rate_limit(self):
        """Client configured with rate_limit passes it to adapter."""
        client = BaseClientApi(
            "https://api.example.com", rate_limit="10/second", max_retries=0
        )
        session = client._session
        adapter = session.get_adapter("https://api.example.com/test")
        assert isinstance(adapter, _RateLimitAdapter)
        assert adapter._rate_limit_item is not None

    def test_client_with_rate_limit_dataclass(self):
        """Client configured with RateLimit dataclass passes it to adapter."""
        client = BaseClientApi(
            "https://api.example.com",
            rate_limit=RateLimit(10, "second"),
            max_retries=0,
        )
        session = client._session
        adapter = session.get_adapter("https://api.example.com/test")
        assert isinstance(adapter, _RateLimitAdapter)
        assert adapter._rate_limit_item is not None

    def test_client_without_rate_limit(self):
        """Client without rate_limit still uses _RateLimitAdapter (no limit set)."""
        client = BaseClientApi("https://api.example.com", max_retries=0)
        session = client._session
        adapter = session.get_adapter("https://api.example.com/test")
        assert isinstance(adapter, _RateLimitAdapter)
        assert adapter._rate_limit_item is None


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
        url = client._build_url("https://other.com/path")
        assert url == "https://other.com/path"


# ===========================================================================
# Response Parsing
# ===========================================================================


class TestParseResponse:
    def test_parse_response_json_content_type(self, client):
        resp = _mock_response(
            json_data={"data": [1, 2, 3]}, content_type="application/json"
        )
        result = client._parse_response(resp)
        assert result == {"data": [1, 2, 3]}

    def test_parse_response_json_charset(self, client):
        resp = _mock_response(
            json_data={"ok": True},
            content_type="application/json; charset=utf-8",
        )
        result = client._parse_response(resp)
        assert result == {"ok": True}

    def test_parse_response_no_content_type_tries_json(self, client):
        """When Content-Type is missing, tries JSON parsing."""
        resp = _mock_response(json_data={"fallback": True}, text='{"fallback": true}')
        result = client._parse_response(resp)
        assert result == {"fallback": True}

    def test_parse_response_no_content_type_falls_back_to_text(self, client):
        """When Content-Type is missing and JSON fails, returns text."""
        resp = _mock_response(text="plain text")
        resp.json.side_effect = ValueError("no json")
        result = client._parse_response(resp)
        assert result == "plain text"

    def test_parse_response_text_content_type(self, client):
        resp = _mock_response(text="hello world", content_type="text/plain")
        result = client._parse_response(resp)
        assert result == "hello world"

    def test_parse_response_text_xml_content_type(self, client):
        resp = _mock_response(text="<root/>", content_type="text/xml")
        result = client._parse_response(resp)
        assert result == "<root/>"

    def test_parse_response_binary_content_type(self, client):
        """Binary content-types (pdf, zip, octet-stream) return bytes."""
        resp = _mock_response(text="", content_type="application/pdf")
        resp.content = b"\x00PDF-binary"
        result = client._parse_response(resp)
        assert result == b"\x00PDF-binary"

    def test_parse_response_octet_stream(self, client):
        resp = _mock_response(text="", content_type="application/octet-stream")
        resp.content = b"\x89PNG"
        result = client._parse_response(resp)
        assert result == b"\x89PNG"

    def test_parse_response_image_content_type(self, client):
        resp = _mock_response(text="", content_type="image/png")
        resp.content = b"\x89PNG\r\n"
        result = client._parse_response(resp)
        assert result == b"\x89PNG\r\n"

    def test_parse_response_empty_body(self, client):
        resp = _mock_response(text="", content_type="text/plain")
        result = client._parse_response(resp)
        assert result is None

    def test_parse_response_no_content_type_no_body(self, client):
        """No Content-Type and empty body returns None."""
        resp = _mock_response(text="")
        result = client._parse_response(resp)
        assert result is None

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
            mock_req.return_value = _mock_response(
                json_data=[{"id": 1}, {"id": 2}], content_type="application/json"
            )
            pages = list(client._paginate_offset("/items", page_size=10))
            assert pages == [[{"id": 1}, {"id": 2}]]

    def test_multiple_pages(self, client):
        page1 = [{"id": i} for i in range(10)]
        page2 = [{"id": i} for i in range(10, 15)]
        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = [
                _mock_response(json_data=page1, content_type="application/json"),
                _mock_response(json_data=page2, content_type="application/json"),
            ]
            pages = list(client._paginate_offset("/items", page_size=10))
            assert len(pages) == 2
            assert pages[0] == page1
            assert pages[1] == page2

    def test_empty_first_page(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data=[], content_type="application/json"
            )
            pages = list(client._paginate_offset("/items", page_size=10))
            assert pages == []

    def test_results_key_str(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"results": [{"id": 1}], "total": 1},
                content_type="application/json",
            )
            pages = list(
                client._paginate_offset(
                    "/items", page_size=10, results_extractor="results"
                )
            )
            assert pages == [[{"id": 1}]]

    def test_results_key_callable(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data={"_embedded": {"items": [{"id": 1}]}},
                content_type="application/json",
            )
            pages = list(
                client._paginate_offset(
                    "/items",
                    page_size=10,
                    results_extractor=lambda r: r["_embedded"]["items"],
                )
            )
            assert pages == [[{"id": 1}]]

    def test_custom_params(self, client):
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _mock_response(
                json_data=[], content_type="application/json"
            )
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

    def test_api_forbidden_error(self):
        err = ApiForbiddenError("forbidden", status_code=403)
        assert isinstance(err, ApiClientError)

    def test_api_not_found_error(self):
        err = ApiNotFoundError("missing", status_code=404)
        assert isinstance(err, ApiClientError)

    def test_api_server_error(self):
        err = ApiServerError("down", status_code=502)
        assert isinstance(err, ApiClientError)
        assert err.status_code == 502


# ===========================================================================
# Rate Limit Block Mode
# ===========================================================================


class TestRateLimitBlock:
    def test_rate_limit_block_calls_wait_or_raise(self):
        """When raise_on_limit_exceeded=False, adapter calls _wait_or_raise instead of raising."""
        adapter = _RateLimitAdapter(
            rate_limit="1/second",
            rate_limit_key="block-test",
            raise_on_limit_exceeded=False,
        )
        mock_request = MagicMock(spec=requests.PreparedRequest)
        mock_request.url = "https://api.example.com/test"

        with patch.object(requests.adapters.HTTPAdapter, "send") as mock_send:
            mock_send.return_value = _mock_response()
            # First call succeeds (consumes the 1 token)
            adapter.send(mock_request)
            # Second call triggers _wait_or_raise
            with patch.object(adapter, "_wait_or_raise") as mock_wait:
                adapter.send(mock_request)
                mock_wait.assert_called_once()

    def test_wait_or_raise_sleeps_and_retries(self):
        """_wait_or_raise loops sleeping until a token is available in block mode."""
        adapter = _RateLimitAdapter(
            rate_limit="1/second",
            rate_limit_key="wait-test",
            raise_on_limit_exceeded=False,
        )

        # Mock get_window_stats to return a fixed reset_time
        mock_stats = MagicMock()
        mock_stats.reset_time = 1000.5
        adapter._limiter.get_window_stats = MagicMock(return_value=mock_stats)

        # hit() succeeds on first attempt inside _wait_or_raise (window reset)
        adapter._limiter.hit = MagicMock(return_value=True)

        with patch("connectors_sdk.client.rate_limit.time.sleep") as mock_sleep:
            with patch(
                "connectors_sdk.client.rate_limit.time.time", return_value=1000.0
            ):
                adapter._wait_or_raise()

        mock_sleep.assert_called_once()
        sleep_duration = mock_sleep.call_args[0][0]
        assert sleep_duration == pytest.approx(0.5, abs=0.01)

    def test_wait_or_raise_retries_on_failed_hit(self):
        """_wait_or_raise retries if hit() still fails after sleeping."""
        adapter = _RateLimitAdapter(
            rate_limit="1/second",
            rate_limit_key="retry-test",
            raise_on_limit_exceeded=False,
        )

        mock_stats = MagicMock()
        mock_stats.reset_time = 1000.5
        adapter._limiter.get_window_stats = MagicMock(return_value=mock_stats)

        # hit() fails once then succeeds (simulates timing edge case)
        adapter._limiter.hit = MagicMock(side_effect=[False, True])

        with patch("connectors_sdk.client.rate_limit.time.sleep") as mock_sleep:
            with patch(
                "connectors_sdk.client.rate_limit.time.time", return_value=1000.0
            ):
                adapter._wait_or_raise()

        # Should have slept twice (retry loop)
        assert mock_sleep.call_count == 2

    def test_client_with_raise_on_limit_exceeded_false(self):
        """Client passes raise_on_limit_exceeded to adapter."""
        client = BaseClientApi(
            "https://api.example.com",
            rate_limit="10/second",
            raise_on_limit_exceeded=False,
            max_retries=0,
        )
        adapter = client._session.get_adapter("https://api.example.com/test")
        assert adapter._raise_on_limit_exceeded is False


# ===========================================================================
# Safe Response Body Truncation
# ===========================================================================


class TestSafeResponseBody:
    def test_truncation_adds_suffix(self):
        long_text = "x" * 3000
        resp = _mock_response(status_code=400, ok=False, text=long_text)
        resp.json.side_effect = ValueError("No JSON")
        client = BaseClientApi("https://api.example.com", max_retries=0)
        with patch.object(client._session, "request", return_value=resp):
            with pytest.raises(ApiClientError) as exc_info:
                client._get("/bad")
            body = exc_info.value.response_body
            assert body.endswith("...[truncated]")
            assert len(body) == 2000 + len("...[truncated]")

    def test_short_text_not_truncated(self):
        resp = _mock_response(status_code=400, ok=False, text="short error")
        resp.json.side_effect = ValueError("No JSON")
        client = BaseClientApi("https://api.example.com", max_retries=0)
        with patch.object(client._session, "request", return_value=resp):
            with pytest.raises(ApiClientError) as exc_info:
                client._get("/bad")
            assert exc_info.value.response_body == "short error"
