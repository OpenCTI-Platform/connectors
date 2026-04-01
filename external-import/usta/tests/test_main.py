"""Tests for the main entry point module."""

# pylint: disable=missing-function-docstring

import os
from unittest.mock import MagicMock, patch

from connector import ConnectorSettings, ConverterToStix, UstaConnector
from usta_client import UstaClient, UstaClientError


def test_connector_imports():
    assert ConnectorSettings is not None
    assert ConverterToStix is not None
    assert UstaConnector is not None


def test_usta_client_imports():
    assert UstaClient is not None
    assert UstaClientError is not None


def test_usta_connector_init():
    env_vars = {
        "OPENCTI_URL": "https://opencti:8080",
        "OPENCTI_TOKEN": "fake-token",
        "CONNECTOR_ID": "12345678-1234-1234-1234-123456789012",
        "USTA_API_KEY": "test-key",
    }

    with patch.dict(os.environ, env_vars):
        settings = ConnectorSettings()

        # Mock OpenCTI helper to prevent AttributeError during dereferencing
        mock_helper = MagicMock()
        mock_helper.connector_logger = MagicMock()

        uc = UstaConnector(config=settings, helper=mock_helper)

        assert isinstance(uc.config, ConnectorSettings)
        assert isinstance(uc.client, UstaClient)
        assert isinstance(uc.converter, ConverterToStix)
        assert uc.helper == mock_helper
