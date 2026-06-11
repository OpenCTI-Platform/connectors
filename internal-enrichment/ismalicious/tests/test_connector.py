"""Tests for isMalicious connector API client."""

from unittest.mock import MagicMock, patch

import requests
from connector import IsMaliciousConnector
from connector.models import (
    ConfigLoader,
    ConnectorConfig,
    IsMaliciousConfig,
    OpenCTIConfig,
)
from pydantic import SecretStr


def _make_connector(
    api_key: str = "test-credential",
) -> tuple[IsMaliciousConnector, MagicMock]:
    config = ConfigLoader(
        opencti=OpenCTIConfig(
            url="http://localhost:8080",
            token=SecretStr("opencti-token"),
        ),
        connector=ConnectorConfig(id="ismalicious-enrichment"),
        ismalicious=IsMaliciousConfig(api_key=SecretStr(api_key)),
    )
    helper = MagicMock()
    helper.api.label.read_or_create_unchecked = MagicMock()
    return IsMaliciousConnector(config, helper), helper


@patch("connector.ismalicious.requests.get")
def test_call_api_uses_check_endpoint_and_x_api_key(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"malicious": False}
    mock_get.return_value = mock_response

    connector, _helper = _make_connector(api_key="base64-credential")

    result = connector._call_api("8.8.8.8")

    mock_get.assert_called_once_with(
        "https://api.ismalicious.com/check",
        params={"query": "8.8.8.8", "enrichment": "standard"},
        headers={
            "X-API-KEY": "base64-credential",
            "Accept": "application/json",
        },
        timeout=30,
    )
    assert result == {"malicious": False}


@patch("connector.ismalicious.requests.get")
def test_call_api_strips_trailing_slash_from_api_url(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"malicious": True}
    mock_get.return_value = mock_response

    config = ConfigLoader(
        opencti=OpenCTIConfig(
            url="http://localhost:8080",
            token=SecretStr("opencti-token"),
        ),
        connector=ConnectorConfig(id="ismalicious-enrichment"),
        ismalicious=IsMaliciousConfig(
            api_url="https://api.ismalicious.com/",
            api_key=SecretStr("test-key"),
        ),
    )
    helper = MagicMock()
    helper.api.label.read_or_create_unchecked = MagicMock()
    connector = IsMaliciousConnector(config, helper)

    connector._call_api("evil.example")

    mock_get.assert_called_once_with(
        "https://api.ismalicious.com/check",
        params={"query": "evil.example", "enrichment": "standard"},
        headers={
            "X-API-KEY": "test-key",
            "Accept": "application/json",
        },
        timeout=30,
    )


@patch("connector.ismalicious.requests.get")
def test_call_api_returns_none_on_request_error(mock_get, capsys):
    mock_get.side_effect = requests.exceptions.HTTPError("401 Unauthorized")

    connector, helper = _make_connector()

    result = connector._call_api("8.8.8.8")

    assert result is None
    helper.log_error.assert_called_once()
