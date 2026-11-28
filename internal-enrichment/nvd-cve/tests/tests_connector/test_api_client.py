from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.services.client.api import CVEClient
from src.services.utils.rate_limiter import AsyncRateLimiter


def _build_client() -> CVEClient:
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return CVEClient(
        api_key="fake-key",
        helper=helper,
        header="test/1.0",
        rate_limiter=AsyncRateLimiter(),
    )


def _build_context_manager_response(
    *,
    status: int,
    json_body=None,
    text_body: str = "",
):
    response = MagicMock()
    response.status = status
    response.headers = {}
    response.json = AsyncMock(return_value=json_body)
    response.text = AsyncMock(return_value=text_body)

    context_manager = MagicMock()
    context_manager.__aenter__ = AsyncMock(return_value=response)
    context_manager.__aexit__ = AsyncMock(return_value=False)
    return context_manager


async def test_request_raises_invalid_key_on_403():
    client = _build_client()
    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.get = MagicMock(
        return_value=_build_context_manager_response(
            status=403, json_body={"message": "Invalid apiKey."}
        )
    )

    with patch.object(client, "_get_session", AsyncMock(return_value=mock_session)):
        with pytest.raises(Exception, match="Invalid API Key provided"):
            await client.request("https://fake.url")


async def test_request_404_uses_error_message_from_body():
    client = _build_client()
    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.get = MagicMock(
        return_value=_build_context_manager_response(
            status=404,
            json_body={"message": "CVE not found"},
            text_body="CVE not found",
        )
    )

    with patch.object(client, "_get_session", AsyncMock(return_value=mock_session)):
        with pytest.raises(Exception, match="CVE not found"):
            await client.request("https://fake.url")


async def test_timeout_error_is_retried_not_silenced():
    """TimeoutError from aiohttp must be retried by request(), not swallowed
    as None by get_complete_collection() which would crash the TaskGroup.

    We mock at the aiohttp session level so the real retry loop in request()
    runs and catches the TimeoutError.
    """

    mock_helper = MagicMock()
    mock_helper.connector_logger = MagicMock()

    rate_limiter = AsyncRateLimiter()
    client = CVEClient(
        api_key="fake-key",
        helper=mock_helper,
        header="test/1.0",
        rate_limiter=rate_limiter,
    )

    call_count = 0
    success_payload = {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0}

    def make_response():
        """Build an async context manager that fakes aiohttp response."""
        nonlocal call_count
        call_count += 1

        if call_count < 3:
            # Simulate timeout while reading response body
            cm = MagicMock()
            cm.__aenter__ = AsyncMock(side_effect=TimeoutError("simulated timeout"))
            cm.__aexit__ = AsyncMock(return_value=False)
            return cm

        # Success on 3rd attempt
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=success_payload)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.get = MagicMock(side_effect=lambda *a, **kw: make_response())

    with patch.object(client, "_get_session", AsyncMock(return_value=mock_session)):
        with patch("src.services.client.api.asyncio.sleep", AsyncMock()):
            result = await client.get_complete_collection("https://fake.url")

    # Should have retried and eventually succeeded — not returned None
    assert result is not None, "TimeoutError should be retried, not silenced as None"
    assert result == success_payload
    assert call_count == 3
