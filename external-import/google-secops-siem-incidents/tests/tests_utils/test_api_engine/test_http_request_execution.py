"""RED tests for Feature: HTTP Request Execution.

Tests that AioHttpClient sends async HTTP requests, parses JSON responses,
and classifies errors by type (HTTP, timeout, network).

All tests MUST fail with ImportError until the implementation exists.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from google_secops_siem_incidents.utils.api_engine.aio_http_client import AioHttpClient
from google_secops_siem_incidents.utils.api_engine.exceptions import (
    ApiHttpError,
    ApiNetworkError,
    ApiRateLimitError,
    ApiTimeoutError,
)


# ---------------------------------------------------------------------------
# Scenario: Successful GET request returns parsed JSON body
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_successful_get_request_returns_parsed_json_body():
    """GET to a reachable endpoint returns the parsed JSON body."""

    async def _given_http_client():
        return AioHttpClient(default_timeout=30)

    async def _when_get_request_sent_to_reachable_endpoint(client):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"key": "value"})
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.request = MagicMock(return_value=mock_response)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            return await client.request("GET", "https://example.com/api")

    def _then_response_is_parsed_json(response):
        assert response == {"key": "value"}

    client = await _given_http_client()
    response = await _when_get_request_sent_to_reachable_endpoint(client)
    _then_response_is_parsed_json(response)


# ---------------------------------------------------------------------------
# Scenario Outline: HTTP error status codes are classified with their code
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500, 503])
async def test_http_error_status_codes_are_classified(status_code):
    """Server responding with <status_code> raises ApiHttpError carrying that code."""

    async def _given_http_client():
        return AioHttpClient(default_timeout=30)

    async def _when_get_request_returns_error_status(client, code):
        mock_response = AsyncMock()
        mock_response.status = code
        mock_response.text = AsyncMock(return_value="error")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.request = MagicMock(return_value=mock_response)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            return await client.request("GET", "https://example.com/api")

    def _then_http_error_carries_status_code(exc_info, code):
        assert exc_info.value.status_code == code

    client = await _given_http_client()
    with pytest.raises(ApiHttpError) as exc_info:
        await _when_get_request_returns_error_status(client, status_code)
    _then_http_error_carries_status_code(exc_info, status_code)


# ---------------------------------------------------------------------------
# Scenario: HTTP 429 raises ApiRateLimitError instead of ApiHttpError
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rate_limit_status_429_raises_rate_limit_error():
    """Server responding with 429 raises ApiRateLimitError."""

    async def _given_http_client():
        return AioHttpClient(default_timeout=30)

    async def _when_get_request_returns_429(client):
        mock_response = AsyncMock()
        mock_response.status = 429
        mock_response.text = AsyncMock(return_value="Too Many Requests")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.request = MagicMock(return_value=mock_response)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            return await client.request("GET", "https://example.com/api")

    client = await _given_http_client()
    with pytest.raises(ApiRateLimitError):
        await _when_get_request_returns_429(client)


@pytest.mark.asyncio
async def test_request_timeout_raises_timeout_error():
    """Connection timeout raises ApiTimeoutError."""

    async def _given_http_client():
        return AioHttpClient(default_timeout=1)

    async def _when_get_request_times_out(client):
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.request = MagicMock(side_effect=asyncio.TimeoutError())

        with patch("aiohttp.ClientSession", return_value=mock_session):
            return await client.request("GET", "https://example.com/api")

    def _then_timeout_error_is_raised():
        pass  # assertion via pytest.raises context

    client = await _given_http_client()
    with pytest.raises(ApiTimeoutError):
        await _when_get_request_times_out(client)
    _then_timeout_error_is_raised()


# ---------------------------------------------------------------------------
# Scenario: Network connectivity fails — network error is raised
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_network_failure_raises_network_error():
    """Unreachable network raises ApiNetworkError."""

    async def _given_http_client():
        return AioHttpClient(default_timeout=30)

    async def _when_network_is_unreachable(client):
        import aiohttp

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.request = MagicMock(
            side_effect=aiohttp.ClientConnectorError(
                connection_key=MagicMock(), os_error=OSError("Network unreachable")
            )
        )

        with patch("aiohttp.ClientSession", return_value=mock_session):
            return await client.request("GET", "https://example.com/api")

    def _then_network_error_is_raised():
        pass  # assertion via pytest.raises context

    client = await _given_http_client()
    with pytest.raises(ApiNetworkError):
        await _when_network_is_unreachable(client)
    _then_network_error_is_raised()
