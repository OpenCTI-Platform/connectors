"""Tests for Akamai connector settings."""

import os
from unittest.mock import patch

import pytest
from akamai_connector.settings import AkamaiConfig, ConnectorSettings


class TestAkamaiConfig:
    """Validate the AkamaiConfig Pydantic model."""

    def test_valid_config_with_asn(self):
        config = AkamaiConfig(
            base_url="https://example.akamaiapis.net",
            client_token="ct-token",
            client_secret="cs-secret",
            access_token="at-token",
            client_list_id="12345_MYLIST",
            asn_client_list_id="12345_ASN_LIST",
        )

        assert str(config.base_url).startswith("https://")
        assert config.client_token.get_secret_value() == "ct-token"
        assert config.client_secret.get_secret_value() == "cs-secret"
        assert config.access_token.get_secret_value() == "at-token"
        assert config.client_list_id == "12345_MYLIST"
        assert config.asn_client_list_id == "12345_ASN_LIST"

    def test_valid_ipv4_only_config(self):
        config = AkamaiConfig(
            base_url="https://example.akamaiapis.net",
            client_token="ct-token",
            client_secret="cs-secret",
            access_token="at-token",
            client_list_id="12345_MYLIST",
        )

        assert config.client_list_id == "12345_MYLIST"
        assert config.asn_client_list_id is None

    def test_missing_required_field(self):
        with pytest.raises(Exception):
            AkamaiConfig(
                base_url="https://example.akamaiapis.net",
                client_token="ct-token",
                # missing client_secret, access_token and client_list_id
            )


class TestConnectorSettings:
    """Validate ConnectorSettings loads from environment."""

    IPV4_ONLY_ENV = {
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

    ASN_ENV = {
        **IPV4_ONLY_ENV,
        "AKAMAI_ASN_CLIENT_LIST_ID": "12345_ASN_LIST",
    }

    @patch.dict(os.environ, IPV4_ONLY_ENV, clear=True)
    def test_settings_from_env_ipv4_only(self):
        settings = ConnectorSettings()

        assert settings.akamai.client_list_id == "12345_MYLIST"
        assert settings.akamai.asn_client_list_id is None
        assert settings.connector.name == "Akamai Connector"

    @patch.dict(os.environ, ASN_ENV, clear=True)
    def test_settings_from_env_with_asn(self):
        settings = ConnectorSettings()

        assert settings.akamai.client_list_id == "12345_MYLIST"
        assert settings.akamai.asn_client_list_id == "12345_ASN_LIST"
        assert settings.connector.name == "Akamai Connector"

    @patch.dict(os.environ, IPV4_ONLY_ENV, clear=True)
    def test_to_helper_config(self):
        settings = ConnectorSettings()
        config = settings.to_helper_config()

        assert "opencti" in config
        assert "connector" in config
