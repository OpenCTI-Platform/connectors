from unittest.mock import MagicMock, patch
import pytest
import requests
from cyfirma_client import CyfirmaClient
from pydantic import HttpUrl


def test_cyfirma_client_get_entities_success():
    mock_helper = MagicMock()
    client = CyfirmaClient(
        helper=mock_helper,
        base_url=HttpUrl("https://api.cyfirma.com"),
        api_key="test_key",
    )

    with patch.object(client.session, "get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {"objects": [{"id": "indicator--1"}]}
        mock_get.return_value = mock_response

        res = client.get_entities()
        assert res == {"objects": [{"id": "indicator--1"}]}
        mock_helper.connector_logger.info.assert_called_once()


def test_cyfirma_client_get_entities_error_handling():
    mock_helper = MagicMock()
    client = CyfirmaClient(
        helper=mock_helper,
        base_url=HttpUrl("https://api.cyfirma.com"),
        api_key="test_key",
    )

    with patch.object(client.session, "get") as mock_get:
        mock_get.side_effect = requests.RequestException("API connection error")

        res = client.get_entities()
        assert res == {}
        # Ensure error logging works without serialization crashes
        mock_helper.connector_logger.error.assert_called()
