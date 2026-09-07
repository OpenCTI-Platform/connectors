"""Tests for CTM360 CYNA Feed connector settings."""

import pytest
from connector.settings import ConnectorSettings
from connectors_sdk import ConfigValidationError


class TestConnectorSettingsInstantiation:
    """Test that ConnectorSettings can be created with valid env vars."""

    def test_settings_instantiation(self):
        """Settings should load successfully when all required env vars are set."""
        settings = ConnectorSettings()
        assert settings.opencti.url is not None
        assert settings.connector.name == "CTM360-CYNA"
        assert settings.ctm360_cyna.api_key.get_secret_value() == "test-api-key"

    def test_opencti_url(self):
        """OpenCTI URL should match the environment variable."""
        settings = ConnectorSettings()
        assert str(settings.opencti.url).rstrip("/") == "http://localhost:8080"

    def test_opencti_token(self):
        """OpenCTI token should match the environment variable."""
        settings = ConnectorSettings()
        assert (
            settings.opencti.token.get_secret_value()
            == "test-token-00000000-0000-0000-0000-000000000000"
        )

    def test_connector_id(self):
        """Connector ID should match the environment variable."""
        settings = ConnectorSettings()
        assert settings.connector.id == "00000000-0000-0000-0000-000000000000"

    def test_connector_type(self):
        """Connector type should be EXTERNAL_IMPORT."""
        settings = ConnectorSettings()
        assert settings.connector.type == "EXTERNAL_IMPORT"


class TestCTM360CynaConfigDefaults:
    """Test default values for CTM360CynaConfig fields."""

    def test_api_base_url_default(self):
        settings = ConnectorSettings()
        assert (
            str(settings.ctm360_cyna.api_base_url).rstrip("/")
            == "https://cyna.ctm360.com"
        )

    def test_import_interval_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cyna.import_interval == 86400

    def test_page_size_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cyna.page_size == 25

    def test_max_pages_default(self):
        settings = ConnectorSettings()
        assert settings.ctm360_cyna.max_pages == 100


class TestCTM360CynaConfigOverrides:
    """Test that default values can be overridden via env vars."""

    def test_override_import_interval(self, monkeypatch):
        monkeypatch.setenv("CTM360_CYNA_IMPORT_INTERVAL", "3600")
        settings = ConnectorSettings()
        assert settings.ctm360_cyna.import_interval == 3600

    def test_override_page_size(self, monkeypatch):
        monkeypatch.setenv("CTM360_CYNA_PAGE_SIZE", "50")
        settings = ConnectorSettings()
        assert settings.ctm360_cyna.page_size == 50

    def test_override_max_pages(self, monkeypatch):
        monkeypatch.setenv("CTM360_CYNA_MAX_PAGES", "200")
        settings = ConnectorSettings()
        assert settings.ctm360_cyna.max_pages == 200

    def test_override_api_base_url(self, monkeypatch):
        monkeypatch.setenv("CTM360_CYNA_API_BASE_URL", "https://custom.example.com")
        settings = ConnectorSettings()
        assert (
            str(settings.ctm360_cyna.api_base_url).rstrip("/")
            == "https://custom.example.com"
        )


class TestPositiveIntegerValidation:
    """Non-positive scheduling/pagination values must be rejected at load time."""

    @pytest.mark.parametrize("value", ["0", "-1"])
    def test_import_interval_must_be_positive(self, monkeypatch, value):
        monkeypatch.setenv("CTM360_CYNA_IMPORT_INTERVAL", value)
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    @pytest.mark.parametrize("value", ["0", "-10"])
    def test_page_size_must_be_positive(self, monkeypatch, value):
        monkeypatch.setenv("CTM360_CYNA_PAGE_SIZE", value)
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    @pytest.mark.parametrize("value", ["0", "-3"])
    def test_max_pages_must_be_positive(self, monkeypatch, value):
        monkeypatch.setenv("CTM360_CYNA_MAX_PAGES", value)
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()


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
        monkeypatch.delenv("CTM360_CYNA_API_KEY")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_duration_period(self, monkeypatch):
        monkeypatch.delenv("CONNECTOR_DURATION_PERIOD")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()
