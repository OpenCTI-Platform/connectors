"""Tests for CTM360 CyberBlindSpot Feed connector settings."""

import pytest
from connector.settings import ConnectorSettings
from connectors_sdk import ConfigValidationError


class TestConnectorSettingsInstantiation:
    """Test that ConnectorSettings can be created with valid env vars."""

    def test_settings_instantiation(self):
        """Settings should load successfully when all required env vars are set."""
        settings = ConnectorSettings()
        assert settings.opencti.url is not None
        assert settings.connector.name == "CTM360-CyberBlindSpot"
        assert settings.ctm360_cbs.api_key == "test-api-key"

    def test_opencti_url(self):
        """OpenCTI URL should match the environment variable."""
        settings = ConnectorSettings()
        assert str(settings.opencti.url).rstrip("/") == "http://localhost:8080"

    def test_opencti_token(self):
        """OpenCTI token should match the environment variable."""
        settings = ConnectorSettings()
        assert (
            settings.opencti.token == "test-token-00000000-0000-0000-0000-000000000000"
        )

    def test_connector_id(self):
        """Connector ID should match the environment variable."""
        settings = ConnectorSettings()
        assert settings.connector.id == "00000000-0000-0000-0000-000000000000"

    def test_connector_type(self):
        """Connector type should be EXTERNAL_IMPORT."""
        settings = ConnectorSettings()
        assert settings.connector.type == "EXTERNAL_IMPORT"


class TestCTM360CbsConfigDefaults:
    """Test default values for CTM360CbsConfig fields."""

    def test_api_base_url_default(self):
        settings = ConnectorSettings()
        assert (
            str(settings.ctm360_cbs.api_base_url).rstrip("/")
            == "https://cbs.ctm360.com"
        )

    def test_import_interval_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_interval == 86400

    def test_import_incidents_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_incidents is True

    def test_import_malware_logs_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_malware_logs is True

    def test_import_breached_credentials_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_breached_credentials is True

    def test_import_card_leaks_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_card_leaks is True

    def test_import_domain_protection_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_domain_protection is True


class TestCTM360CbsConfigOverrides:
    """Test that default values can be overridden via env vars."""

    def test_override_import_interval(self, monkeypatch):
        monkeypatch.setenv("CTM360_CBS_IMPORT_INTERVAL", "3600")
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_interval == 3600

    def test_override_import_incidents(self, monkeypatch):
        monkeypatch.setenv("CTM360_CBS_IMPORT_INCIDENTS", "false")
        settings = ConnectorSettings()
        assert settings.ctm360_cbs.import_incidents is False

    def test_override_api_base_url(self, monkeypatch):
        monkeypatch.setenv("CTM360_CBS_API_BASE_URL", "https://custom.example.com")
        settings = ConnectorSettings()
        assert (
            str(settings.ctm360_cbs.api_base_url).rstrip("/")
            == "https://custom.example.com"
        )


class TestRequiredFieldValidation:
    """Test that missing required fields raise validation errors."""

    def test_missing_opencti_url(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_URL")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_opencti_token(self, monkeypatch):
        monkeypatch.delenv("OPENCTI_TOKEN")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_connector_id(self, monkeypatch):
        monkeypatch.delenv("CONNECTOR_ID")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_connector_scope(self, monkeypatch):
        monkeypatch.delenv("CONNECTOR_SCOPE")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_api_key(self, monkeypatch):
        monkeypatch.delenv("CTM360_CBS_API_KEY")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_duration_period(self, monkeypatch):
        monkeypatch.delenv("CONNECTOR_DURATION_PERIOD")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()
