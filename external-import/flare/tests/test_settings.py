from pathlib import Path

import pytest
import yaml
from _pytest.monkeypatch import MonkeyPatch

from connector.settings import ConnectorSettings


@pytest.fixture
def required_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")
    monkeypatch.setenv("FLARE_API_KEY", "test-api-key")


class TestConnectorSettings:  # pylint: disable=redefined-outer-name,unused-argument
    def test_missing_opencti_token_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")
        monkeypatch.setenv("FLARE_API_KEY", "test-api-key")
        with pytest.raises(ValueError, match="Missing OpenCTI Token"):
            ConnectorSettings(config_file_path="nonexistent.yml")

    def test_missing_connector_id_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.delenv("CONNECTOR_ID", raising=False)
        monkeypatch.setenv("FLARE_API_KEY", "test-api-key")
        with pytest.raises(ValueError, match="Missing Connector ID"):
            ConnectorSettings(config_file_path="nonexistent.yml")

    def test_missing_flare_api_key_raises(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "test-connector-id")
        monkeypatch.delenv("FLARE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="Missing Flare API Key"):
            ConnectorSettings(config_file_path="nonexistent.yml")

    def test_default_values(self, required_env: None) -> None:
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.opencti_url == "http://opencti:8080"
        assert settings.connector_name == "Flare"
        assert settings.connector_scope == "Incident,Observable,Indicator"
        assert settings.connector_log_level == "info"
        assert settings.connector_duration_period == "PT1H"
        assert settings.flare_api_domain == "api.flare.io"
        assert settings.flare_event_types == [
            "stealer_log",
            "domain",
            "ransomleak",
            "leak",
        ]
        assert settings.flare_event_actions is None
        assert settings.flare_lookback_days == 30
        assert settings.flare_tlp_level == "white"
        assert settings.flare_tenant_id is None

    def test_opencti_url_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://custom:9090")
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.opencti_url == "http://custom:9090"

    def test_flare_event_types_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_EVENT_TYPES", "stealer_log,leak")
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.flare_event_types == ["stealer_log", "leak"]

    def test_flare_event_actions_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_EVENT_ACTIONS", "created,updated")
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.flare_event_actions == ["created", "updated"]

    def test_flare_tenant_id_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_TENANT_ID", "42")
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.flare_tenant_id == 42

    def test_flare_lookback_days_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_LOOKBACK_DAYS", "7")
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.flare_lookback_days == 7

    def test_flare_tlp_level_override(
        self, required_env: None, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLARE_TLP_LEVEL", "red")
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        assert settings.flare_tlp_level == "red"

    def test_yaml_file_loading(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            yaml.dump(
                {
                    "opencti": {"token": "yaml-token", "url": "http://yaml:8080"},
                    "connector": {"id": "yaml-connector-id"},
                    "flare": {"api_key": "yaml-api-key"},
                }
            )
        )
        settings = ConnectorSettings(config_file_path=str(config_file))
        assert settings.opencti_token == "yaml-token"
        assert settings.opencti_url == "http://yaml:8080"
        assert settings.connector_id == "yaml-connector-id"
        assert settings.flare_api_key == "yaml-api-key"

    def test_to_helper_config_structure(self, required_env: None) -> None:
        settings = ConnectorSettings(config_file_path="nonexistent.yml")
        config = settings.to_helper_config()
        assert config["opencti"]["url"] == settings.opencti_url
        assert config["opencti"]["token"] == settings.opencti_token
        assert config["connector"]["id"] == settings.connector_id
        assert config["connector"]["type"] == "EXTERNAL_IMPORT"
        assert config["connector"]["name"] == settings.connector_name
