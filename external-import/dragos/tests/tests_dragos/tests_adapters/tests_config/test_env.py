"""Offer tests for the environment variable configuration loader."""

import os
from unittest import mock

import pytest
from dragos.adapters.config.env import ConfigLoaderEnv
from dragos.interfaces.config import ConfigRetrievalError


@pytest.fixture()
def valid_config(monkeypatch):
    """Create a simulated environment variable configuration."""
    with mock.patch.dict(os.environ, clear=True):
        envvars = {
            "OPENCTI_URL": "https://example.com",
            "OPENCTI_TOKEN": "example_token",
            "CONNECTOR_ID": "connector_123",
            "CONNECTOR_NAME": "ExampleConnector",
            "CONNECTOR_SCOPE": "scope1,scope2",
            "CONNECTOR_LOG_LEVEL": "info",
            "CONNECTOR_DURATION_PERIOD": "PT30M",
            "CONNECTOR_QUEUE_THRESHOLD": "10",
            "CONNECTOR_RUN_AND_TERMINATE": "false",
            "CONNECTOR_SEND_TO_QUEUE": "true",
            "CONNECTOR_SEND_TO_DIRECTORY": "false",
            "DRAGOS_API_BASE_URL": "https://api.dragos.com",
            "DRAGOS_API_TOKEN": "dragos_token",
            "DRAGOS_API_SECRET": "dragos_secret",
            "DRAGOS_IMPORT_START_DATE": "2023-01-01T00:00:00Z",
            "DRAGOS_TLP_LEVEL": "amber",
        }
        for k, v in envvars.items():
            monkeypatch.setenv(k, v)
        yield
        # implicit teardown


def test_config_loader_env_loads_correctly(valid_config):
    """Test that the ConfigLoaderEnv loads the configuration from environnemnt variables."""
    # Given a valid environment variable configuration
    # When loading the configuration
    # Then the configuration should be loaded without error
    _ = ConfigLoaderEnv()


def test_config_loader_env_missing_variables():
    """Test that the ConfigLoaderEnv raises ConfigRetrievalError when required variables are missing."""
    # Given a missing environment variable
    with mock.patch.dict(
        os.environ, {"OPENCTI_URL": "https://example.com"}, clear=True
    ):
        # When loading the configuration
        with pytest.raises(ConfigRetrievalError):
            _ = ConfigLoaderEnv()
