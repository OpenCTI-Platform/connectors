from unittest.mock import MagicMock, patch
from xmlrpc import client
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

    with patch.object(client, "_request_data") as mock_request:
        mock_request.side_effect = [
            {"objects": [{"id": "indicator--1"}]},
            {"objects": []},
        ]


        res = client.get_entities()
        assert res == [{"id": "indicator--1"}]
        mock_helper.connector_logger.info.assert_called()


def test_cyfirma_client_get_entities_error_handling():
    mock_helper = MagicMock()
    client = CyfirmaClient(
        helper=mock_helper,
        base_url=HttpUrl("https://api.cyfirma.com"),
        api_key="test_key",
    )

    with patch.object(client, "_request_data") as mock_request:
        mock_request.side_effect = requests.RequestException("API connection error")

        res = client.get_entities()
        assert res == []
        # Ensure error logging works without serialization crashes
        mock_helper.connector_logger.error.assert_called()
