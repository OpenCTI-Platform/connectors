"""Tests for the main entry point module."""

import os
from unittest.mock import patch
from pycti import OpenCTIConnectorHelper 
from connector import ConnectorSettings, ConverterToStix, UstaProdaftConnector
from usta_client import UstaClient, UstaClientError


def test_connector_imports():
    assert ConnectorSettings is not None
    assert ConverterToStix is not None
    assert UstaProdaftConnector is not None


def test_usta_client_imports():
    assert UstaClient is not None
    assert UstaClientError is not None


def test_usta_connector_init():
    env_vars = {
        "OPENCTI_URL": "https://opencti:8080",
        "OPENCTI_TOKEN": "fake-token",
        "CONNECTOR_ID": "12345678-1234-1234-1234-123456789012",
        "USTA_PRODAFT_API_KEY": "test-key",
    }

    with patch.dict(os.environ, env_vars):
        settings = ConnectorSettings()

        uc = UstaProdaftConnector(config=settings, helper=None)
        
        assert isinstance(uc.config, ConnectorSettings)
        assert uc.work_id is None or isinstance(uc.work_id, str)
        assert isinstance(uc.client, UstaClient)
        assert isinstance(uc.converter, ConverterToStix)

