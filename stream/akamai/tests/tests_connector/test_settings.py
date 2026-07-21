"""Tests for Akamai connector settings."""

import os
from unittest.mock import patch

import pytest
from akamai_connector.settings import AkamaiConfig, ConnectorSettings


class TestAkamaiConfig:
    """Validate the AkamaiConfig Pydantic model."""

    def test_valid_config(self):
        config = AkamaiConfig(
            base_url="https://example.akamaiapis.net",
            client_token="ct-token",
            client_secret="cs-secret",
            access_token="at-token",
            client_list_id="12345_MYLIST",
        )
        assert str(config.base_url).startswith("https://")
        assert config.client_token.get_secret_value() == "ct-token"
        assert config.client_secret.get_secret_value() == "cs-secret"
        assert config.access_token.get_secret_value() == "at-token"
        assert config.client_list_id == "12345_MYLIST"

    def test_missing_required_field(self):
        with pytest.raises(Exception):
            AkamaiConfig(
                base_url="https://example.akamaiapis.net",
                client_token="ct-token",
                # missing client_secret, access_token, client_list_id
            )


class TestConnectorSettings:
    """Validate ConnectorSettings loads from environment."""

    MINIMAL_ENV = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_ID": "test-id",
        "CONNECTOR_LIVE_STREAM_ID": "live",
        "AKAMAI_BASE_URL": "https://example.akamaiapis.net",
        "AKAMAI_CLIENT_TOKEN": "ct-token",
        "AKAMAI_CLIENT_SECRET": "cs-secret",
        "AKAMAI_ACCESS_TOKEN": "at-token",
        "AKAMAI_CLIENT_LIST_ID": "12345_MYLIST",
    }

    @patch.dict(os.environ, MINIMAL_ENV, clear=False)
    def test_settings_from_env(self):
        settings = ConnectorSettings()
        assert settings.akamai.client_list_id == "12345_MYLIST"
        assert settings.connector.name == "Akamai Connector"

    @patch.dict(os.environ, MINIMAL_ENV, clear=False)
    def test_to_helper_config(self):
        settings = ConnectorSettings()
        config = settings.to_helper_config()
        assert "opencti" in config
        assert "connector" in config
