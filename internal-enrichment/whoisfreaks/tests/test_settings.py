"""
Unit tests for the WhoisFreaks ConnectorSettings (SDK-based configuration).

These tests validate that:
  - A valid configuration is correctly loaded.
  - A missing WHOISFREAKS_API_KEY raises a validation error.
  - Default values are applied correctly.
"""

import os

import pytest
from settings import ConnectorSettings

VALID_ENV = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "test-opencti-token",
    "CONNECTOR_ID": "11111111-1111-1111-1111-111111111111",
    "WHOISFREAKS_API_KEY": "test-whoisfreaks-key",
}


def _load_settings(env_overrides: dict) -> ConnectorSettings:
    """Set environment variables and return a fresh ConnectorSettings instance."""
    for key, value in env_overrides.items():
        os.environ[key] = value
    try:
        return ConnectorSettings()
    finally:
        for key in env_overrides:
            os.environ.pop(key, None)


class TestConnectorSettings:
    """Tests for ConnectorSettings loading and validation."""

    def test_valid_configuration_loads_correctly(self):
        """Full valid configuration should load without errors."""
        settings = _load_settings(VALID_ENV)

        assert str(settings.opencti.url).rstrip("/") == "http://localhost:8080"
        assert settings.opencti.token == "test-opencti-token"
        assert settings.connector.id == "11111111-1111-1111-1111-111111111111"
        assert settings.whoisfreaks.api_key.get_secret_value() == "test-whoisfreaks-key"

    def test_default_connector_name(self):
        """Connector name should default to 'WhoisFreaks'."""
        settings = _load_settings(VALID_ENV)
        assert settings.connector.name == "WhoisFreaks"

    def test_default_connector_scope(self):
        """Connector scope should default to Domain-Name,IPv4-Addr,IPv6-Addr."""
        settings = _load_settings(VALID_ENV)
        assert "Domain-Name" in settings.connector.scope

    def test_default_connector_auto(self):
        """Connector auto should default to False."""
        settings = _load_settings(VALID_ENV)
        assert settings.connector.auto is False

    def test_default_connector_log_level(self):
        """Connector log_level should default to 'error'."""
        settings = _load_settings(VALID_ENV)
        assert settings.connector.log_level.lower() == "error"

    def test_default_tlp_level(self):
        """WhoisFreaks TLP level should default to 'amber+strict'."""
        settings = _load_settings(VALID_ENV)
        assert settings.whoisfreaks.tlp_level == "amber+strict"

    def test_custom_tlp_level(self):
        """A custom TLP level passed via env should be honoured."""
        env = {**VALID_ENV, "WHOISFREAKS_TLP_LEVEL": "green"}
        settings = _load_settings(env)
        assert settings.whoisfreaks.tlp_level == "green"

    def test_missing_api_key_raises_error(self):
        """Missing WHOISFREAKS_API_KEY should raise a validation error."""
        env = {k: v for k, v in VALID_ENV.items() if k != "WHOISFREAKS_API_KEY"}
        from connectors_sdk import ConfigValidationError

        with pytest.raises((ConfigValidationError, Exception)):
            _load_settings(env)
