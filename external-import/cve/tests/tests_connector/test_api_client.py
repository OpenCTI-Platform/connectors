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
