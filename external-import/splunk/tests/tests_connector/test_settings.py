from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from splunk_connector import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Splunk",
                    "scope": "indicator,identity,incident",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "splunk": {
                    "base_url": "https://splunk.example.com:8089",
                    "token": "splunk-token",
                    "scopes": "indicator,identity,incident",
                    "import_indicators": True,
                    "import_identities": True,
                    "import_incidents": True,
                    "indicators_search": "   ",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "indicator,identity,incident",
                },
                "splunk": {
                    "base_url": "https://splunk.example.com:8089",
                    "token": "splunk-token",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.splunk, BaseConfigModel) is True
    assert settings.splunk.scopes == ["indicator", "identity", "incident"]
    assert settings.splunk.indicators_search is None


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "indicator,identity,incident",
                },
                "splunk": {
                    "base_url": "https://splunk.example.com:8089",
                    "token": "splunk-token",
                    "scopes": "indicator,malware",
                },
            },
            id="invalid_scope",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "scope": "indicator,identity,incident",
                },
                "splunk": {
                    "base_url": "https://splunk.example.com:8089",
                    "token": "splunk-token",
                },
            },
            id="missing_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
