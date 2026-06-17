import pytest
from _pytest.monkeypatch import MonkeyPatch
from connector.settings import ConnectorSettings
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import HttpUrl


@pytest.fixture
def required_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")
    monkeypatch.setenv("FLARE_API_KEY", "test-api-key")


class TestConnectorSettings:  # pylint: disable=redefined-outer-name,unused-argument
    def test_missing_opencti_token_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")
        monkeypatch.setenv("FLARE_API_KEY", "test-api-key")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_connector_id_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.delenv("CONNECTOR_ID", raising=False)
        monkeypatch.setenv("FLARE_API_KEY", "test-api-key")
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_missing_flare_api_key_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")
        monkeypatch.delenv("FLARE_API_KEY", raising=False)
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()

    def test_default_values(self, required_env: None) -> None:
        from datetime import timedelta

        settings = ConnectorSettings()
        assert settings.opencti.url == HttpUrl("http://opencti:8080")
        assert settings.connector.name == "Flare"
        assert settings.connector.scope == ["Incident", "Observable", "Indicator"]
        assert settings.connector.log_level == "info"
        assert settings.connector.duration_period == timedelta(hours=1)
        assert settings.flare.api_base_url == "api.flare.io"
        assert settings.flare.event_types == [
            "stealer_log",
            "domain",
            "ransomleak",
            "leak",
        ]
        assert settings.flare.event_actions == []
        assert settings.flare.lookback_days == 30
        assert settings.flare.tlp_level == "white"
        assert settings.flare.tenant_id is None

    def test_opencti_url_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://custom:9090")
        settings = ConnectorSettings()
        assert settings.opencti.url == HttpUrl("http://custom:9090")

    def test_flare_event_types_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_EVENT_TYPES", "stealer_log,leak")
        settings = ConnectorSettings()
        assert settings.flare.event_types == ["stealer_log", "leak"]

    def test_flare_event_actions_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_EVENT_ACTIONS", "created,updated")
        settings = ConnectorSettings()
        assert settings.flare.event_actions == ["created", "updated"]

    def test_flare_tenant_id_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_TENANT_ID", "42")
        settings = ConnectorSettings()
        assert settings.flare.tenant_id == 42

    def test_flare_lookback_days_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_LOOKBACK_DAYS", "7")
        settings = ConnectorSettings()
        assert settings.flare.lookback_days == 7

    def test_flare_tlp_level_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_TLP_LEVEL", "red")
        settings = ConnectorSettings()
        assert settings.flare.tlp_level == "red"

    def test_to_helper_config_structure(self, required_env: None) -> None:
        settings = ConnectorSettings()
        config = settings.to_helper_config()
        assert config["opencti"]["url"] == str(settings.opencti.url)
        assert config["opencti"]["token"] == settings.opencti.token
        assert config["connector"]["id"] == settings.connector.id
        assert config["connector"]["type"] == "EXTERNAL_IMPORT"
        assert config["connector"]["name"] == settings.connector.name
